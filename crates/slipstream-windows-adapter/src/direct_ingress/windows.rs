//! Native owned-client relay for Windows direct ingress.
//!
//! The relay consumes one accepted client `TcpStream` and one validated ingress
//! plan. It owns both the client stream and direct connector until a terminal
//! event, applies bounded backpressure in both directions, and reports backend
//! payload only after those bytes have reached the client socket.

use super::{
    connector_event_to_ingress, WindowsDirectIngressClientCloseReason, WindowsDirectIngressEvent,
    WindowsDirectIngressPlan,
};
use crate::data_plane::{
    WindowsDataPlaneCommand, WindowsDataPlaneEffects, WindowsDataPlaneRequest,
};
use crate::direct_connector::{
    spawn_windows_direct_connector, WindowsDirectConnectorCancelReason,
    WindowsDirectConnectorEvent, WindowsDirectConnectorNativeError,
};
use slipstream_core::routing_recovery::ConnectionOutcome;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{
    sync_channel, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError,
};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const RELAY_POLL_INTERVAL: Duration = Duration::from_millis(1);
const WORKER_FAILURE_REPORT_TIMEOUT: Duration = Duration::from_millis(250);
const INGRESS_EVENT_QUEUE_CAPACITY: usize = 128;
const MAX_STAGED_DIRECT_INGRESSES: usize = 1_024;
const MAX_RETAINED_DIRECT_INGRESS_CLOSED_SESSIONS: usize = 1_024;
const MAX_RETAINED_DIRECT_INGRESS_OUTCOMES: usize = 1_024;
const CONTROL_RUNNING: u8 = 0;
const CONTROL_CANCEL: u8 = 1;
const CONTROL_SHUTDOWN: u8 = 2;

pub struct WindowsDirectOwnedClientStream {
    connection_id: u64,
    stream: TcpStream,
}

impl WindowsDirectOwnedClientStream {
    pub fn new(
        connection_id: u64,
        stream: TcpStream,
    ) -> Result<Self, WindowsDirectIngressNativeError> {
        if connection_id == 0 {
            return Err(WindowsDirectIngressNativeError::InvalidConnectionId);
        }
        Ok(Self {
            connection_id,
            stream,
        })
    }

    pub const fn connection_id(&self) -> u64 {
        self.connection_id
    }
}

pub struct WindowsDirectIngressHandle {
    request_id: String,
    session_id: u64,
    connection_id: u64,
    control: Arc<AtomicU8>,
    events: Receiver<WindowsDirectIngressEvent>,
    worker: Option<JoinHandle<Result<(), WindowsDirectIngressNativeError>>>,
}

impl WindowsDirectIngressHandle {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub const fn session_id(&self) -> u64 {
        self.session_id
    }

    pub const fn connection_id(&self) -> u64 {
        self.connection_id
    }

    pub fn cancel(&self) {
        set_control(&self.control, CONTROL_CANCEL);
    }

    pub fn shutdown(&self) {
        set_control(&self.control, CONTROL_SHUTDOWN);
    }

    pub fn recv_event(
        &self,
        timeout: Duration,
    ) -> Result<WindowsDirectIngressEvent, WindowsDirectIngressNativeError> {
        self.events
            .recv_timeout(timeout)
            .map_err(|error| match error {
                RecvTimeoutError::Timeout => WindowsDirectIngressNativeError::EventTimeout,
                RecvTimeoutError::Disconnected => WindowsDirectIngressNativeError::IngressStopped,
            })
    }

    pub fn try_recv_event(
        &self,
    ) -> Result<Option<WindowsDirectIngressEvent>, WindowsDirectIngressNativeError> {
        match self.events.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => Ok(None),
        }
    }

    pub fn finish(mut self) -> Result<(), WindowsDirectIngressNativeError> {
        self.shutdown();
        self.join_worker()
    }

    fn join_worker(&mut self) -> Result<(), WindowsDirectIngressNativeError> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        worker
            .join()
            .map_err(|_| WindowsDirectIngressNativeError::WorkerPanicked)?
    }
}

impl Drop for WindowsDirectIngressHandle {
    fn drop(&mut self) {
        if self.worker.is_some() {
            set_control(&self.control, CONTROL_SHUTDOWN);
            let _ = self.join_worker();
        }
    }
}

fn set_control(control: &AtomicU8, requested: u8) {
    let mut current = control.load(Ordering::Acquire);
    while current < requested {
        match control.compare_exchange_weak(current, requested, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

struct WindowsDirectIngressStart {
    plan: WindowsDirectIngressPlan,
    client: WindowsDirectOwnedClientStream,
}

pub struct WindowsDirectIngressSpawnError {
    error: WindowsDirectIngressNativeError,
    start: Box<WindowsDirectIngressStart>,
}

impl WindowsDirectIngressSpawnError {
    pub fn error(&self) -> &WindowsDirectIngressNativeError {
        &self.error
    }

    pub fn into_parts(
        self,
    ) -> (
        WindowsDirectIngressNativeError,
        WindowsDirectIngressPlan,
        WindowsDirectOwnedClientStream,
    ) {
        let start = *self.start;
        (self.error, start.plan, start.client)
    }
}

impl fmt::Debug for WindowsDirectIngressSpawnError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsDirectIngressSpawnError")
            .field("error", &self.error)
            .field("session_id", &self.start.plan.session_id())
            .field("connection_id", &self.start.client.connection_id())
            .finish()
    }
}

impl fmt::Display for WindowsDirectIngressSpawnError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.error)
    }
}

impl std::error::Error for WindowsDirectIngressSpawnError {}

pub fn spawn_windows_direct_ingress(
    plan: WindowsDirectIngressPlan,
    client: WindowsDirectOwnedClientStream,
) -> Result<WindowsDirectIngressHandle, WindowsDirectIngressSpawnError> {
    let start = WindowsDirectIngressStart { plan, client };
    if start.plan.connection_id != start.client.connection_id {
        return Err(WindowsDirectIngressSpawnError {
            error: WindowsDirectIngressNativeError::ClientIdentityMismatch,
            start: Box::new(start),
        });
    }

    let request_id = start.plan.request_id().to_owned();
    let session_id = start.plan.session_id();
    let connection_id = start.plan.connection_id();
    let control = Arc::new(AtomicU8::new(CONTROL_RUNNING));
    let worker_control = Arc::clone(&control);
    let (start_tx, start_rx) = sync_channel::<WindowsDirectIngressStart>(0);
    let (events_tx, events) = sync_channel(INGRESS_EVENT_QUEUE_CAPACITY);
    let worker = match thread::Builder::new()
        .name(format!("slipstream-ingress-{session_id}"))
        .spawn(move || {
            let start = start_rx
                .recv()
                .map_err(|_| WindowsDirectIngressNativeError::WorkerStartChannelClosed)?;
            let request_id = start.plan.request_id().to_owned();
            let session_id = start.plan.session_id();
            let connection_id = start.plan.connection_id();
            match run_ingress(start.plan, start.client, worker_control, events_tx.clone()) {
                Ok(()) => Ok(()),
                Err(error) => {
                    report_worker_failure(
                        &events_tx,
                        WindowsDirectIngressEvent::BackendReset {
                            request_id,
                            session_id,
                            connection_id,
                            reason: "direct ingress worker failed".to_owned(),
                        },
                    );
                    Err(error)
                }
            }
        }) {
        Ok(worker) => worker,
        Err(_) => {
            return Err(WindowsDirectIngressSpawnError {
                error: WindowsDirectIngressNativeError::WorkerSpawnFailed,
                start: Box::new(start),
            });
        }
    };

    if let Err(error) = start_tx.send(start) {
        let _ = worker.join();
        return Err(WindowsDirectIngressSpawnError {
            error: WindowsDirectIngressNativeError::WorkerStartChannelClosed,
            start: Box::new(error.0),
        });
    }

    Ok(WindowsDirectIngressHandle {
        request_id,
        session_id,
        connection_id,
        control,
        events,
        worker: Some(worker),
    })
}

struct StagedWindowsDirectIngress {
    plan: WindowsDirectIngressPlan,
    client: WindowsDirectOwnedClientStream,
}

#[derive(Default)]
pub struct WindowsDirectIngressDataPlaneEffects {
    staged: BTreeMap<u64, StagedWindowsDirectIngress>,
    relays: BTreeMap<u64, WindowsDirectIngressHandle>,
    request_ids: BTreeMap<u64, String>,
    closed: BTreeMap<u64, String>,
    first_payloads: BTreeSet<u64>,
    outcomes: VecDeque<(u64, ConnectionOutcome)>,
}

impl WindowsDirectIngressDataPlaneEffects {
    pub fn stage_ingress(
        &mut self,
        plan: WindowsDirectIngressPlan,
        client: WindowsDirectOwnedClientStream,
    ) -> Result<(), WindowsDirectIngressDataPlaneEffectError> {
        let session_id = plan.session_id();
        if plan.connection_id() != client.connection_id() {
            return Err(
                WindowsDirectIngressDataPlaneEffectError::ClientIdentityMismatch(session_id),
            );
        }
        if self.staged.contains_key(&session_id)
            || self.relays.contains_key(&session_id)
            || self.closed.contains_key(&session_id)
            || self
                .outcomes
                .iter()
                .any(|(recorded_session_id, _)| *recorded_session_id == session_id)
        {
            return Err(WindowsDirectIngressDataPlaneEffectError::DuplicateSession(
                session_id,
            ));
        }
        if self
            .staged
            .values()
            .any(|staged| staged.plan.request_id() == plan.request_id())
        {
            return Err(WindowsDirectIngressDataPlaneEffectError::DuplicateSession(
                session_id,
            ));
        }
        if self.staged.len() >= MAX_STAGED_DIRECT_INGRESSES {
            return Err(WindowsDirectIngressDataPlaneEffectError::CapacityReached);
        }
        self.staged
            .insert(session_id, StagedWindowsDirectIngress { plan, client });
        Ok(())
    }

    pub fn recv_event(
        &self,
        session_id: u64,
        timeout: Duration,
    ) -> Result<WindowsDirectIngressEvent, WindowsDirectIngressDataPlaneEffectError> {
        self.relays
            .get(&session_id)
            .ok_or(WindowsDirectIngressDataPlaneEffectError::UnknownSession(
                session_id,
            ))?
            .recv_event(timeout)
            .map_err(Into::into)
    }

    pub fn drain_events(
        &self,
    ) -> Result<Vec<WindowsDirectIngressEvent>, WindowsDirectIngressDataPlaneEffectError> {
        let mut events = Vec::new();
        for relay in self.relays.values() {
            while let Some(event) = relay.try_recv_event()? {
                events.push(event);
            }
        }
        events.sort_by(|left, right| {
            left.session_id()
                .cmp(&right.session_id())
                .then_with(|| left.request_id().cmp(right.request_id()))
        });
        Ok(events)
    }

    pub fn has_relay(&self, session_id: u64) -> bool {
        self.relays.contains_key(&session_id)
    }

    pub fn staged_ingress_count(&self) -> usize {
        self.staged.len()
    }

    pub fn outcomes(&self) -> impl Iterator<Item = &ConnectionOutcome> {
        self.outcomes.iter().map(|(_, outcome)| outcome)
    }

    fn require_active(
        &self,
        session_id: u64,
        request_id: &str,
    ) -> Result<&WindowsDirectIngressHandle, WindowsDirectIngressDataPlaneEffectError> {
        if self.request_ids.get(&session_id).map(String::as_str) != Some(request_id) {
            return Err(WindowsDirectIngressDataPlaneEffectError::UnknownSession(
                session_id,
            ));
        }
        self.relays.get(&session_id).ok_or(
            WindowsDirectIngressDataPlaneEffectError::UnknownSession(session_id),
        )
    }
}

impl WindowsDataPlaneEffects for WindowsDirectIngressDataPlaneEffects {
    type Error = WindowsDirectIngressDataPlaneEffectError;

    fn execute(&mut self, command: &WindowsDataPlaneCommand) -> Result<(), Self::Error> {
        match command {
            WindowsDataPlaneCommand::StartSession {
                session_id,
                request,
            } => {
                let staged = self.staged.remove(session_id).ok_or(
                    WindowsDirectIngressDataPlaneEffectError::MissingIngress(*session_id),
                )?;
                if let Err(error) = validate_ingress_identity(&staged.plan, *session_id, request) {
                    self.staged.insert(*session_id, staged);
                    return Err(error);
                }
                match spawn_windows_direct_ingress(staged.plan, staged.client) {
                    Ok(relay) => {
                        self.request_ids
                            .insert(*session_id, request.request_id.clone());
                        self.relays.insert(*session_id, relay);
                    }
                    Err(error) => {
                        let (native, plan, client) = error.into_parts();
                        self.staged
                            .insert(*session_id, StagedWindowsDirectIngress { plan, client });
                        return Err(native.into());
                    }
                }
            }
            WindowsDataPlaneCommand::ScheduleFirstPayloadDeadline {
                request_id,
                session_id,
                ..
            }
            | WindowsDataPlaneCommand::ScheduleCancellationDeadline {
                request_id,
                session_id,
                ..
            } => {
                self.require_active(*session_id, request_id)?;
            }
            WindowsDataPlaneCommand::MarkFirstPayload {
                request_id,
                session_id,
                ..
            } => {
                self.require_active(*session_id, request_id)?;
                if !self.first_payloads.insert(*session_id) {
                    return Err(
                        WindowsDirectIngressDataPlaneEffectError::DuplicateFirstPayload(
                            *session_id,
                        ),
                    );
                }
            }
            WindowsDataPlaneCommand::CancelSession {
                request_id,
                session_id,
            } => self.require_active(*session_id, request_id)?.cancel(),
            WindowsDataPlaneCommand::CloseSession {
                request_id,
                session_id,
            } => {
                if self.closed.get(session_id).map(String::as_str) == Some(request_id) {
                    return Ok(());
                }
                self.require_active(*session_id, request_id)?;
                let relay = self.relays.remove(session_id).ok_or(
                    WindowsDirectIngressDataPlaneEffectError::UnknownSession(*session_id),
                )?;
                relay.shutdown();
                let _ = relay.finish();
                self.request_ids.remove(session_id);
                retain_bounded_closed_session(
                    &mut self.closed,
                    &mut self.first_payloads,
                    *session_id,
                    request_id,
                    MAX_RETAINED_DIRECT_INGRESS_CLOSED_SESSIONS,
                );
            }
            WindowsDataPlaneCommand::RecordOutcome {
                request_id,
                session_id,
                outcome,
            } => {
                if self.closed.get(session_id).map(String::as_str) != Some(request_id) {
                    return Err(
                        WindowsDirectIngressDataPlaneEffectError::OutcomeBeforeClose(*session_id),
                    );
                }
                if self
                    .outcomes
                    .iter()
                    .any(|(recorded_session_id, _)| recorded_session_id == session_id)
                {
                    return Err(WindowsDirectIngressDataPlaneEffectError::DuplicateOutcome(
                        *session_id,
                    ));
                }
                self.closed.remove(session_id);
                self.first_payloads.remove(session_id);
                self.outcomes.push_back((*session_id, outcome.clone()));
                while self.outcomes.len() > MAX_RETAINED_DIRECT_INGRESS_OUTCOMES {
                    self.outcomes.pop_front();
                }
            }
            WindowsDataPlaneCommand::RejectRequest { request_id, .. } => {
                self.staged
                    .retain(|_, staged| staged.plan.request_id() != request_id);
            }
            WindowsDataPlaneCommand::ReportWorkerStopped if !self.relays.is_empty() => {
                return Err(WindowsDirectIngressDataPlaneEffectError::WorkerStoppedWithResources);
            }
            WindowsDataPlaneCommand::ReportWorkerStartupFailed { .. }
            | WindowsDataPlaneCommand::ReportWorkerStopped => self.staged.clear(),
            WindowsDataPlaneCommand::ReportWorkerReady
            | WindowsDataPlaneCommand::ScheduleShutdownDeadline { .. } => {}
        }
        Ok(())
    }
}

fn validate_ingress_identity(
    plan: &WindowsDirectIngressPlan,
    session_id: u64,
    request: &WindowsDataPlaneRequest,
) -> Result<(), WindowsDirectIngressDataPlaneEffectError> {
    if plan.session_id() != session_id
        || plan.request_id() != request.request_id
        || plan.connector_plan().data_plane_request() != request
    {
        return Err(WindowsDirectIngressDataPlaneEffectError::IngressIdentityMismatch(session_id));
    }
    Ok(())
}

fn run_ingress(
    plan: WindowsDirectIngressPlan,
    mut client: WindowsDirectOwnedClientStream,
    control: Arc<AtomicU8>,
    events: SyncSender<WindowsDirectIngressEvent>,
) -> Result<(), WindowsDirectIngressNativeError> {
    client
        .stream
        .set_nodelay(true)
        .map_err(|_| WindowsDirectIngressNativeError::ClientSocketConfigurationFailed)?;
    client
        .stream
        .set_nonblocking(true)
        .map_err(|_| WindowsDirectIngressNativeError::ClientSocketConfigurationFailed)?;

    let request_id = plan.request_id().to_owned();
    let session_id = plan.session_id();
    let connection_id = plan.connection_id();
    let backpressure_timeout = Duration::from_millis(plan.backpressure_timeout_ms());
    let first_payload_deadline =
        Instant::now() + Duration::from_millis(plan.connector_plan.first_payload_timeout_ms());
    let connector = match spawn_windows_direct_connector(plan.connector_plan) {
        Ok(connector) => connector,
        Err(_) => {
            emit_ingress(
                &events,
                WindowsDirectIngressEvent::ConnectFailed {
                    request_id,
                    session_id,
                    connection_id,
                    reason: "direct connector could not start".to_owned(),
                },
            )?;
            let _ = client.stream.shutdown(Shutdown::Both);
            return Ok(());
        }
    };

    let mut client_read_buffer = vec![0u8; plan.max_client_read_chunk_bytes];
    let mut pending_upstream: Option<(Vec<u8>, Instant)> = None;
    let mut pending_downstream: Option<(Vec<u8>, usize, Instant)> = None;
    let mut first_payload_delivered = false;
    let mut client_closed = false;
    let mut control_forwarded = CONTROL_RUNNING;

    loop {
        let requested_control = control.load(Ordering::Acquire);
        if requested_control > control_forwarded {
            match requested_control {
                CONTROL_SHUTDOWN => connector.shutdown(),
                CONTROL_CANCEL => connector.cancel(),
                _ => {}
            }
            control_forwarded = requested_control;
            pending_upstream = None;
            pending_downstream = None;
            client_closed = true;
            let _ = client.stream.shutdown(Shutdown::Both);
        }

        if control_forwarded == CONTROL_RUNNING
            && !client_closed
            && !first_payload_delivered
            && Instant::now() >= first_payload_deadline
        {
            emit_ingress(
                &events,
                WindowsDirectIngressEvent::FirstPayloadDeadline {
                    request_id,
                    session_id,
                    connection_id,
                },
            )?;
            connector.shutdown();
            let _ = client.stream.shutdown(Shutdown::Both);
            return Ok(());
        }

        if pending_downstream.is_none() {
            match connector.try_recv_event() {
                Ok(Some(WindowsDirectConnectorEvent::Payload { bytes, .. })) => {
                    if !client_closed {
                        pending_downstream = Some((bytes, 0, Instant::now()));
                    }
                }
                Ok(Some(event)) => {
                    let terminal = !matches!(event, WindowsDirectConnectorEvent::Connected { .. });
                    emit_ingress(&events, connector_event_to_ingress(event, connection_id))?;
                    if terminal {
                        let _ = connector.finish();
                        let _ = client.stream.shutdown(Shutdown::Both);
                        return Ok(());
                    }
                }
                Ok(None) => {
                    if connector.is_finished() {
                        let reason = match connector.finish() {
                            Ok(()) if control_forwarded != CONTROL_RUNNING || client_closed => {
                                emit_ingress(
                                    &events,
                                    WindowsDirectIngressEvent::Cancelled {
                                        request_id,
                                        session_id,
                                        connection_id,
                                        reason: if control_forwarded == CONTROL_SHUTDOWN {
                                            WindowsDirectConnectorCancelReason::Shutdown
                                        } else {
                                            WindowsDirectConnectorCancelReason::Caller
                                        },
                                    },
                                )?;
                                let _ = client.stream.shutdown(Shutdown::Both);
                                return Ok(());
                            }
                            Ok(()) => "direct connector stopped without terminal event",
                            Err(_) => "direct connector worker failed",
                        };
                        emit_ingress(
                            &events,
                            WindowsDirectIngressEvent::BackendReset {
                                request_id,
                                session_id,
                                connection_id,
                                reason: reason.to_owned(),
                            },
                        )?;
                        let _ = client.stream.shutdown(Shutdown::Both);
                        return Ok(());
                    }
                }
                Err(_) => {
                    emit_ingress(
                        &events,
                        WindowsDirectIngressEvent::BackendReset {
                            request_id,
                            session_id,
                            connection_id,
                            reason: "direct connector event stream failed".to_owned(),
                        },
                    )?;
                    connector.shutdown();
                    let _ = connector.finish();
                    let _ = client.stream.shutdown(Shutdown::Both);
                    return Ok(());
                }
            }
        }

        if let Some((payload, written, last_progress_at)) = pending_downstream.as_mut() {
            match client.stream.write(&payload[*written..]) {
                Ok(0) => {
                    close_client(
                        &events,
                        &request_id,
                        session_id,
                        connection_id,
                        WindowsDirectIngressClientCloseReason::WriteFailed,
                    )?;
                    client_closed = true;
                    pending_downstream = None;
                    pending_upstream = None;
                    connector.cancel();
                }
                Ok(bytes) => {
                    *written += bytes;
                    *last_progress_at = Instant::now();
                    if *written == payload.len() {
                        if !first_payload_delivered && Instant::now() >= first_payload_deadline {
                            emit_ingress(
                                &events,
                                WindowsDirectIngressEvent::FirstPayloadDeadline {
                                    request_id,
                                    session_id,
                                    connection_id,
                                },
                            )?;
                            connector.shutdown();
                            let _ = client.stream.shutdown(Shutdown::Both);
                            return Ok(());
                        }
                        let delivered = payload.len() as u64;
                        pending_downstream = None;
                        first_payload_delivered = true;
                        emit_ingress(
                            &events,
                            WindowsDirectIngressEvent::PayloadDelivered {
                                request_id: request_id.clone(),
                                session_id,
                                connection_id,
                                bytes: delivered,
                            },
                        )?;
                    }
                }
                Err(error) if is_transient(&error) => {
                    if last_progress_at.elapsed() >= backpressure_timeout {
                        close_client(
                            &events,
                            &request_id,
                            session_id,
                            connection_id,
                            WindowsDirectIngressClientCloseReason::WriteBackpressureDeadline,
                        )?;
                        client_closed = true;
                        pending_downstream = None;
                        pending_upstream = None;
                        connector.cancel();
                    }
                }
                Err(_) => {
                    close_client(
                        &events,
                        &request_id,
                        session_id,
                        connection_id,
                        WindowsDirectIngressClientCloseReason::WriteFailed,
                    )?;
                    client_closed = true;
                    pending_downstream = None;
                    pending_upstream = None;
                    connector.cancel();
                }
            }
        }

        if client_closed {
            thread::sleep(Duration::from_millis(1));
            continue;
        }

        if let Some((payload, stalled_at)) = pending_upstream.as_ref() {
            match connector.send_payload(payload) {
                Ok(()) => pending_upstream = None,
                Err(WindowsDirectConnectorNativeError::OutboundQueueFull) => {
                    if stalled_at.elapsed() >= backpressure_timeout {
                        emit_ingress(
                            &events,
                            WindowsDirectIngressEvent::BackendReset {
                                request_id: request_id.clone(),
                                session_id,
                                connection_id,
                                reason: "backend write backpressure deadline exceeded".to_owned(),
                            },
                        )?;
                        connector.shutdown();
                        let _ = connector.finish();
                        let _ = client.stream.shutdown(Shutdown::Both);
                        return Ok(());
                    }
                }
                Err(_) => {
                    emit_ingress(
                        &events,
                        WindowsDirectIngressEvent::BackendReset {
                            request_id: request_id.clone(),
                            session_id,
                            connection_id,
                            reason: "direct connector stopped while relaying".to_owned(),
                        },
                    )?;
                    connector.shutdown();
                    let _ = connector.finish();
                    let _ = client.stream.shutdown(Shutdown::Both);
                    return Ok(());
                }
            }
        }

        if pending_upstream.is_none() {
            match client.stream.read(&mut client_read_buffer) {
                Ok(0) => {
                    close_client(
                        &events,
                        &request_id,
                        session_id,
                        connection_id,
                        WindowsDirectIngressClientCloseReason::Eof,
                    )?;
                    client_closed = true;
                    pending_downstream = None;
                    connector.cancel();
                }
                Ok(bytes) => {
                    pending_upstream = Some((client_read_buffer[..bytes].to_vec(), Instant::now()));
                }
                Err(error) if is_transient(&error) => {}
                Err(_) => {
                    close_client(
                        &events,
                        &request_id,
                        session_id,
                        connection_id,
                        WindowsDirectIngressClientCloseReason::ReadFailed,
                    )?;
                    client_closed = true;
                    pending_downstream = None;
                    connector.cancel();
                }
            }
        }
        thread::sleep(RELAY_POLL_INTERVAL);
    }
}

fn retain_bounded_closed_session(
    closed: &mut BTreeMap<u64, String>,
    first_payloads: &mut BTreeSet<u64>,
    session_id: u64,
    request_id: &str,
    capacity: usize,
) {
    first_payloads.remove(&session_id);
    while closed.len() >= capacity {
        let Some(oldest_session_id) = closed.first_key_value().map(|(id, _)| *id) else {
            break;
        };
        closed.remove(&oldest_session_id);
    }
    closed.insert(session_id, request_id.to_owned());
}

fn close_client(
    events: &SyncSender<WindowsDirectIngressEvent>,
    request_id: &str,
    session_id: u64,
    connection_id: u64,
    reason: WindowsDirectIngressClientCloseReason,
) -> Result<(), WindowsDirectIngressNativeError> {
    emit_ingress(
        events,
        WindowsDirectIngressEvent::ClientClosed {
            request_id: request_id.to_owned(),
            session_id,
            connection_id,
            reason,
        },
    )
}

fn emit_ingress(
    events: &SyncSender<WindowsDirectIngressEvent>,
    event: WindowsDirectIngressEvent,
) -> Result<(), WindowsDirectIngressNativeError> {
    events.try_send(event).map_err(|error| match error {
        TrySendError::Full(_) => WindowsDirectIngressNativeError::EventQueueFull,
        TrySendError::Disconnected(_) => WindowsDirectIngressNativeError::EventSinkClosed,
    })
}

fn report_worker_failure(
    events: &SyncSender<WindowsDirectIngressEvent>,
    event: WindowsDirectIngressEvent,
) {
    let deadline = Instant::now() + WORKER_FAILURE_REPORT_TIMEOUT;
    let mut pending = event;
    loop {
        match events.try_send(pending) {
            Ok(()) => return,
            Err(TrySendError::Full(event)) if Instant::now() < deadline => {
                pending = event;
                thread::sleep(RELAY_POLL_INTERVAL);
            }
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => return,
        }
    }
}

fn is_transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

#[derive(Debug, Eq, PartialEq)]
pub enum WindowsDirectIngressNativeError {
    InvalidConnectionId,
    ClientIdentityMismatch,
    ClientSocketConfigurationFailed,
    WorkerSpawnFailed,
    WorkerStartChannelClosed,
    WorkerPanicked,
    EventTimeout,
    EventQueueFull,
    EventSinkClosed,
    IngressStopped,
}

impl fmt::Display for WindowsDirectIngressNativeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConnectionId => "direct ingress connection ID is invalid",
            Self::ClientIdentityMismatch => "direct ingress client identity does not match",
            Self::ClientSocketConfigurationFailed => "direct ingress client socket setup failed",
            Self::WorkerSpawnFailed => "direct ingress worker could not start",
            Self::WorkerStartChannelClosed => "direct ingress worker start channel closed",
            Self::WorkerPanicked => "direct ingress worker panicked",
            Self::EventTimeout => "direct ingress event wait timed out",
            Self::EventQueueFull => "direct ingress event queue is full",
            Self::EventSinkClosed => "direct ingress event sink is closed",
            Self::IngressStopped => "direct ingress has stopped",
        })
    }
}

impl std::error::Error for WindowsDirectIngressNativeError {}

#[derive(Debug, Eq, PartialEq)]
pub enum WindowsDirectIngressDataPlaneEffectError {
    MissingIngress(u64),
    DuplicateSession(u64),
    CapacityReached,
    ClientIdentityMismatch(u64),
    IngressIdentityMismatch(u64),
    UnknownSession(u64),
    DuplicateFirstPayload(u64),
    OutcomeBeforeClose(u64),
    DuplicateOutcome(u64),
    WorkerStoppedWithResources,
    Native(WindowsDirectIngressNativeError),
}

impl fmt::Display for WindowsDirectIngressDataPlaneEffectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingIngress(session_id) => {
                write!(formatter, "direct ingress {session_id} is missing")
            }
            Self::DuplicateSession(session_id) => {
                write!(
                    formatter,
                    "direct ingress session {session_id} already exists"
                )
            }
            Self::CapacityReached => formatter.write_str("direct ingress capacity is reached"),
            Self::ClientIdentityMismatch(session_id) => write!(
                formatter,
                "direct ingress client identity for session {session_id} does not match"
            ),
            Self::IngressIdentityMismatch(session_id) => write!(
                formatter,
                "direct ingress plan {session_id} does not match the data-plane session"
            ),
            Self::UnknownSession(session_id) => {
                write!(formatter, "direct ingress session {session_id} is unknown")
            }
            Self::DuplicateFirstPayload(session_id) => write!(
                formatter,
                "direct ingress session {session_id} already marked first payload"
            ),
            Self::OutcomeBeforeClose(session_id) => write!(
                formatter,
                "direct ingress session {session_id} recorded an outcome before close"
            ),
            Self::DuplicateOutcome(session_id) => write!(
                formatter,
                "direct ingress session {session_id} has two outcomes"
            ),
            Self::WorkerStoppedWithResources => {
                formatter.write_str("direct ingress worker stopped with owned resources")
            }
            Self::Native(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for WindowsDirectIngressDataPlaneEffectError {}

impl From<WindowsDirectIngressNativeError> for WindowsDirectIngressDataPlaneEffectError {
    fn from(value: WindowsDirectIngressNativeError) -> Self {
        Self::Native(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_ingress_bookkeeping_is_bounded_and_drops_payload_markers() {
        let mut closed = BTreeMap::new();
        let mut first_payloads = BTreeSet::new();
        for session_id in 1..=4 {
            first_payloads.insert(session_id);
            retain_bounded_closed_session(
                &mut closed,
                &mut first_payloads,
                session_id,
                &format!("request-{session_id}"),
                2,
            );
        }

        assert_eq!(closed.len(), 2);
        assert_eq!(closed.keys().copied().collect::<Vec<_>>(), vec![3, 4]);
        assert!(first_payloads.is_empty());
    }
}
