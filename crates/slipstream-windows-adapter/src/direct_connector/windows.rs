//! Native direct TCP connector for Windows.
//!
//! The standard library maps these operations to Winsock on Windows. The
//! connector accepts only a prepared numeric endpoint and owns its socket and
//! worker thread until a terminal event. It performs no name resolution and
//! has no access to system DNS, proxy, PAC, VPN, or route configuration.

use super::{
    WindowsDirectConnectorCancelReason, WindowsDirectConnectorEvent, WindowsDirectConnectorPlan,
    MAX_DIRECT_CONNECTOR_INITIAL_PAYLOAD_BYTES,
};
use crate::data_plane::{
    WindowsDataPlaneCommand, WindowsDataPlaneEffects, WindowsDataPlaneRequest,
};
use slipstream_core::routing_recovery::ConnectionOutcome;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{
    sync_channel, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError,
};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const STREAM_POLL_INTERVAL: Duration = Duration::from_millis(1);
const OUTBOUND_QUEUE_CAPACITY: usize = 64;
const EVENT_QUEUE_CAPACITY: usize = 128;
const MAX_STAGED_DIRECT_CONNECTOR_PLANS: usize = 1_024;
const MAX_RETAINED_DIRECT_CONNECTOR_OUTCOMES: usize = 1_024;
const CONTROL_RUNNING: u8 = 0;
const CONTROL_CANCEL: u8 = 1;
const CONTROL_SHUTDOWN: u8 = 2;

pub struct WindowsDirectConnectorHandle {
    request_id: String,
    session_id: u64,
    control: Arc<AtomicU8>,
    outbound: SyncSender<Vec<u8>>,
    events: Receiver<WindowsDirectConnectorEvent>,
    worker: Option<JoinHandle<Result<(), WindowsDirectConnectorNativeError>>>,
}

impl WindowsDirectConnectorHandle {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub const fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn send_payload(&self, payload: &[u8]) -> Result<(), WindowsDirectConnectorNativeError> {
        if payload.is_empty() || payload.len() > MAX_DIRECT_CONNECTOR_INITIAL_PAYLOAD_BYTES {
            return Err(WindowsDirectConnectorNativeError::InvalidOutboundPayload);
        }
        if self.control.load(Ordering::Acquire) != CONTROL_RUNNING {
            return Err(WindowsDirectConnectorNativeError::ConnectorStopped);
        }
        self.outbound
            .try_send(payload.to_vec())
            .map_err(|error| match error {
                TrySendError::Full(_) => WindowsDirectConnectorNativeError::OutboundQueueFull,
                TrySendError::Disconnected(_) => {
                    WindowsDirectConnectorNativeError::ConnectorStopped
                }
            })
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
    ) -> Result<WindowsDirectConnectorEvent, WindowsDirectConnectorNativeError> {
        self.events
            .recv_timeout(timeout)
            .map_err(|error| match error {
                RecvTimeoutError::Timeout => WindowsDirectConnectorNativeError::EventTimeout,
                RecvTimeoutError::Disconnected => {
                    WindowsDirectConnectorNativeError::ConnectorStopped
                }
            })
    }

    pub fn try_recv_event(
        &self,
    ) -> Result<Option<WindowsDirectConnectorEvent>, WindowsDirectConnectorNativeError> {
        match self.events.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => Ok(None),
        }
    }

    pub fn is_finished(&self) -> bool {
        self.worker
            .as_ref()
            .map(JoinHandle::is_finished)
            .unwrap_or(true)
    }

    pub fn finish(mut self) -> Result<(), WindowsDirectConnectorNativeError> {
        self.shutdown();
        self.join_worker()
    }

    fn join_worker(&mut self) -> Result<(), WindowsDirectConnectorNativeError> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        worker
            .join()
            .map_err(|_| WindowsDirectConnectorNativeError::WorkerPanicked)?
    }
}

impl Drop for WindowsDirectConnectorHandle {
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

pub fn spawn_windows_direct_connector(
    plan: WindowsDirectConnectorPlan,
) -> Result<WindowsDirectConnectorHandle, WindowsDirectConnectorNativeError> {
    let request_id = plan.request_id.clone();
    let session_id = plan.session_id;
    let control = Arc::new(AtomicU8::new(CONTROL_RUNNING));
    let worker_control = Arc::clone(&control);
    let (outbound, outbound_rx) = sync_channel(OUTBOUND_QUEUE_CAPACITY);
    let (events_tx, events) = sync_channel(EVENT_QUEUE_CAPACITY);
    let worker = thread::Builder::new()
        .name(format!("slipstream-direct-{session_id}"))
        .spawn(move || run_connector(plan, worker_control, outbound_rx, events_tx))
        .map_err(|_| WindowsDirectConnectorNativeError::WorkerSpawnFailed)?;

    Ok(WindowsDirectConnectorHandle {
        request_id,
        session_id,
        control,
        outbound,
        events,
        worker: Some(worker),
    })
}

#[derive(Default)]
pub struct WindowsDirectDataPlaneEffects {
    staged_plans: BTreeMap<u64, WindowsDirectConnectorPlan>,
    connectors: BTreeMap<u64, WindowsDirectConnectorHandle>,
    request_ids: BTreeMap<u64, String>,
    closed: BTreeMap<u64, String>,
    first_payloads: BTreeSet<u64>,
    outcomes: VecDeque<(u64, ConnectionOutcome)>,
}

impl WindowsDirectDataPlaneEffects {
    pub fn stage_plan(
        &mut self,
        plan: WindowsDirectConnectorPlan,
    ) -> Result<(), WindowsDirectDataPlaneEffectError> {
        if self.staged_plans.contains_key(&plan.session_id)
            || self
                .staged_plans
                .values()
                .any(|staged| staged.request_id == plan.request_id)
            || self.connectors.contains_key(&plan.session_id)
            || self.closed.contains_key(&plan.session_id)
            || self
                .outcomes
                .iter()
                .any(|(session_id, _)| *session_id == plan.session_id)
        {
            return Err(WindowsDirectDataPlaneEffectError::DuplicateSession(
                plan.session_id,
            ));
        }
        if self.staged_plans.len() >= MAX_STAGED_DIRECT_CONNECTOR_PLANS {
            return Err(WindowsDirectDataPlaneEffectError::CapacityReached);
        }
        self.staged_plans.insert(plan.session_id, plan);
        Ok(())
    }

    pub fn drain_events(
        &self,
    ) -> Result<Vec<WindowsDirectConnectorEvent>, WindowsDirectDataPlaneEffectError> {
        let mut events = Vec::new();
        for connector in self.connectors.values() {
            while let Some(event) = connector.try_recv_event()? {
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

    pub fn recv_event(
        &self,
        session_id: u64,
        timeout: Duration,
    ) -> Result<WindowsDirectConnectorEvent, WindowsDirectDataPlaneEffectError> {
        self.connectors
            .get(&session_id)
            .ok_or(WindowsDirectDataPlaneEffectError::UnknownSession(
                session_id,
            ))?
            .recv_event(timeout)
            .map_err(Into::into)
    }

    pub fn send_payload(
        &self,
        session_id: u64,
        request_id: &str,
        payload: &[u8],
    ) -> Result<(), WindowsDirectDataPlaneEffectError> {
        self.require_active(session_id, request_id)?
            .send_payload(payload)
            .map_err(Into::into)
    }

    pub fn has_connector(&self, session_id: u64) -> bool {
        self.connectors.contains_key(&session_id)
    }

    pub fn staged_plan_count(&self) -> usize {
        self.staged_plans.len()
    }

    pub fn outcomes(&self) -> impl Iterator<Item = &ConnectionOutcome> {
        self.outcomes.iter().map(|(_, outcome)| outcome)
    }

    fn require_active(
        &self,
        session_id: u64,
        request_id: &str,
    ) -> Result<&WindowsDirectConnectorHandle, WindowsDirectDataPlaneEffectError> {
        if self.request_ids.get(&session_id).map(String::as_str) != Some(request_id) {
            return Err(WindowsDirectDataPlaneEffectError::UnknownSession(
                session_id,
            ));
        }
        self.connectors
            .get(&session_id)
            .ok_or(WindowsDirectDataPlaneEffectError::UnknownSession(
                session_id,
            ))
    }
}

impl WindowsDataPlaneEffects for WindowsDirectDataPlaneEffects {
    type Error = WindowsDirectDataPlaneEffectError;

    fn execute(&mut self, command: &WindowsDataPlaneCommand) -> Result<(), Self::Error> {
        match command {
            WindowsDataPlaneCommand::StartSession {
                session_id,
                request,
            } => {
                let plan = self
                    .staged_plans
                    .get(session_id)
                    .ok_or(WindowsDirectDataPlaneEffectError::MissingPlan(*session_id))?;
                validate_plan_identity(plan, *session_id, request)?;
                let connector = spawn_windows_direct_connector(plan.clone())?;
                self.staged_plans.remove(session_id);
                self.request_ids
                    .insert(*session_id, request.request_id.clone());
                self.connectors.insert(*session_id, connector);
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
                    return Err(WindowsDirectDataPlaneEffectError::DuplicateFirstPayload(
                        *session_id,
                    ));
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
                let connector = self.connectors.remove(session_id).ok_or(
                    WindowsDirectDataPlaneEffectError::UnknownSession(*session_id),
                )?;
                connector.shutdown();
                let _ = connector.finish();
                self.request_ids.remove(session_id);
                self.closed.insert(*session_id, request_id.clone());
            }
            WindowsDataPlaneCommand::RecordOutcome {
                request_id,
                session_id,
                outcome,
            } => {
                if self.closed.get(session_id).map(String::as_str) != Some(request_id) {
                    return Err(WindowsDirectDataPlaneEffectError::OutcomeBeforeClose(
                        *session_id,
                    ));
                }
                if self
                    .outcomes
                    .iter()
                    .any(|(recorded_session_id, _)| recorded_session_id == session_id)
                {
                    return Err(WindowsDirectDataPlaneEffectError::DuplicateOutcome(
                        *session_id,
                    ));
                }
                self.closed.remove(session_id);
                self.first_payloads.remove(session_id);
                self.outcomes.push_back((*session_id, outcome.clone()));
                while self.outcomes.len() > MAX_RETAINED_DIRECT_CONNECTOR_OUTCOMES {
                    self.outcomes.pop_front();
                }
            }
            WindowsDataPlaneCommand::ReportWorkerStopped if !self.connectors.is_empty() => {
                return Err(WindowsDirectDataPlaneEffectError::WorkerStoppedWithResources)
            }
            WindowsDataPlaneCommand::RejectRequest { request_id, .. } => {
                self.staged_plans
                    .retain(|_, plan| plan.request_id != *request_id);
            }
            WindowsDataPlaneCommand::ReportWorkerStartupFailed { .. }
            | WindowsDataPlaneCommand::ReportWorkerStopped => self.staged_plans.clear(),
            WindowsDataPlaneCommand::ReportWorkerReady
            | WindowsDataPlaneCommand::ScheduleShutdownDeadline { .. } => {}
        }
        Ok(())
    }
}

fn validate_plan_identity(
    plan: &WindowsDirectConnectorPlan,
    session_id: u64,
    request: &WindowsDataPlaneRequest,
) -> Result<(), WindowsDirectDataPlaneEffectError> {
    if plan.session_id != session_id
        || plan.request_id != request.request_id
        || plan.data_plane_request != *request
    {
        return Err(WindowsDirectDataPlaneEffectError::PlanIdentityMismatch(
            session_id,
        ));
    }
    Ok(())
}

fn run_connector(
    mut plan: WindowsDirectConnectorPlan,
    control: Arc<AtomicU8>,
    outbound_rx: Receiver<Vec<u8>>,
    events: SyncSender<WindowsDirectConnectorEvent>,
) -> Result<(), WindowsDirectConnectorNativeError> {
    let started = Instant::now();
    let connect_deadline = started + Duration::from_millis(plan.connect_timeout_ms);
    let first_payload_deadline = started + Duration::from_millis(plan.first_payload_timeout_ms);
    let mut stream = match connect_numeric(&plan, &control, connect_deadline, &events)? {
        Some(stream) => stream,
        None => return Ok(()),
    };
    stream
        .set_nodelay(true)
        .map_err(|_| WindowsDirectConnectorNativeError::SocketConfigurationFailed)?;
    stream
        .set_nonblocking(true)
        .map_err(|_| WindowsDirectConnectorNativeError::SocketConfigurationFailed)?;
    if emit_cancel_if_requested(&plan, &control, &events)? {
        return Ok(());
    }
    emit(
        &events,
        WindowsDirectConnectorEvent::Connected {
            request_id: plan.request_id.clone(),
            session_id: plan.session_id,
        },
    )?;

    let mut outbound = VecDeque::new();
    if !plan.initial_payload.is_empty() {
        outbound.push_back((std::mem::take(&mut plan.initial_payload), 0usize));
    }
    let mut first_payload_observed = false;
    let mut read_buffer = vec![0u8; plan.max_read_chunk_bytes];

    loop {
        if emit_cancel_if_requested(&plan, &control, &events)? {
            return Ok(());
        }
        drain_outbound(&outbound_rx, &mut outbound);
        if let Some((payload, written)) = outbound.front_mut() {
            match stream.write(&payload[*written..]) {
                Ok(0) => {
                    emit_reset(&plan, &events, "remote closed while writing")?;
                    return Ok(());
                }
                Ok(bytes) => {
                    *written += bytes;
                    if *written == payload.len() {
                        outbound.pop_front();
                    }
                }
                Err(error) if is_transient(&error) => {}
                Err(_) => {
                    emit_reset(&plan, &events, "stream write failed")?;
                    return Ok(());
                }
            }
        }

        match stream.read(&mut read_buffer) {
            Ok(0) => {
                emit(
                    &events,
                    WindowsDirectConnectorEvent::BackendClosed {
                        request_id: plan.request_id.clone(),
                        session_id: plan.session_id,
                    },
                )?;
                return Ok(());
            }
            Ok(bytes) => {
                if emit_cancel_if_requested(&plan, &control, &events)? {
                    return Ok(());
                }
                first_payload_observed = true;
                if !emit_payload(
                    &events,
                    WindowsDirectConnectorEvent::Payload {
                        request_id: plan.request_id.clone(),
                        session_id: plan.session_id,
                        bytes: read_buffer[..bytes].to_vec(),
                    },
                    &plan,
                    &control,
                )? {
                    return Ok(());
                }
            }
            Err(error) if is_transient(&error) => {}
            Err(_) => {
                emit_reset(&plan, &events, "stream read failed")?;
                return Ok(());
            }
        }

        if !first_payload_observed && Instant::now() >= first_payload_deadline {
            emit(
                &events,
                WindowsDirectConnectorEvent::FirstPayloadDeadline {
                    request_id: plan.request_id.clone(),
                    session_id: plan.session_id,
                },
            )?;
            return Ok(());
        }
        thread::sleep(STREAM_POLL_INTERVAL);
    }
}

fn connect_numeric(
    plan: &WindowsDirectConnectorPlan,
    control: &AtomicU8,
    deadline: Instant,
    events: &SyncSender<WindowsDirectConnectorEvent>,
) -> Result<Option<TcpStream>, WindowsDirectConnectorNativeError> {
    loop {
        if emit_cancel_if_requested(plan, control, events)? {
            return Ok(None);
        }
        let now = Instant::now();
        if now >= deadline {
            emit_connect_failed(plan, events, "connect deadline exceeded")?;
            return Ok(None);
        }
        let timeout = deadline.saturating_duration_since(now);
        match TcpStream::connect_timeout(&plan.endpoint, timeout) {
            Ok(stream) => return Ok(Some(stream)),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                if emit_cancel_if_requested(plan, control, events)? {
                    return Ok(None);
                }
                emit_connect_failed(plan, events, "connect deadline exceeded")?;
                return Ok(None);
            }
            Err(error) => {
                if emit_cancel_if_requested(plan, control, events)? {
                    return Ok(None);
                }
                emit_connect_failed(plan, events, connect_reason(&error))?;
                return Ok(None);
            }
        }
    }
}

fn drain_outbound(receiver: &Receiver<Vec<u8>>, queue: &mut VecDeque<(Vec<u8>, usize)>) {
    while queue.len() < OUTBOUND_QUEUE_CAPACITY {
        match receiver.try_recv() {
            Ok(payload) => queue.push_back((payload, 0)),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => return,
        }
    }
}

fn emit_cancel_if_requested(
    plan: &WindowsDirectConnectorPlan,
    control: &AtomicU8,
    events: &SyncSender<WindowsDirectConnectorEvent>,
) -> Result<bool, WindowsDirectConnectorNativeError> {
    let reason = match control.load(Ordering::Acquire) {
        CONTROL_SHUTDOWN => Some(WindowsDirectConnectorCancelReason::Shutdown),
        CONTROL_CANCEL => Some(WindowsDirectConnectorCancelReason::Caller),
        _ => None,
    };
    let Some(reason) = reason else {
        return Ok(false);
    };
    emit(
        events,
        WindowsDirectConnectorEvent::Cancelled {
            request_id: plan.request_id.clone(),
            session_id: plan.session_id,
            reason,
        },
    )?;
    Ok(true)
}

fn emit_connect_failed(
    plan: &WindowsDirectConnectorPlan,
    events: &SyncSender<WindowsDirectConnectorEvent>,
    reason: &str,
) -> Result<(), WindowsDirectConnectorNativeError> {
    emit(
        events,
        WindowsDirectConnectorEvent::ConnectFailed {
            request_id: plan.request_id.clone(),
            session_id: plan.session_id,
            reason: reason.to_owned(),
        },
    )
}

fn emit_reset(
    plan: &WindowsDirectConnectorPlan,
    events: &SyncSender<WindowsDirectConnectorEvent>,
    reason: &str,
) -> Result<(), WindowsDirectConnectorNativeError> {
    emit(
        events,
        WindowsDirectConnectorEvent::StreamReset {
            request_id: plan.request_id.clone(),
            session_id: plan.session_id,
            reason: reason.to_owned(),
        },
    )
}

fn emit(
    events: &SyncSender<WindowsDirectConnectorEvent>,
    event: WindowsDirectConnectorEvent,
) -> Result<(), WindowsDirectConnectorNativeError> {
    events.try_send(event).map_err(|error| match error {
        TrySendError::Full(_) => WindowsDirectConnectorNativeError::EventQueueFull,
        TrySendError::Disconnected(_) => WindowsDirectConnectorNativeError::EventSinkClosed,
    })
}

fn emit_payload(
    events: &SyncSender<WindowsDirectConnectorEvent>,
    event: WindowsDirectConnectorEvent,
    plan: &WindowsDirectConnectorPlan,
    control: &AtomicU8,
) -> Result<bool, WindowsDirectConnectorNativeError> {
    let mut pending = event;
    loop {
        if control.load(Ordering::Acquire) != CONTROL_RUNNING {
            emit_cancel_if_requested(plan, control, events)?;
            return Ok(false);
        }
        match events.try_send(pending) {
            Ok(()) => return Ok(true),
            Err(TrySendError::Full(event)) => {
                pending = event;
                thread::sleep(STREAM_POLL_INTERVAL);
            }
            Err(TrySendError::Disconnected(_)) => {
                return Err(WindowsDirectConnectorNativeError::EventSinkClosed);
            }
        }
    }
}

fn is_transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

fn connect_reason(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => "connection refused",
        io::ErrorKind::PermissionDenied => "connection denied",
        io::ErrorKind::AddrNotAvailable => "address unavailable",
        _ => "connect failed",
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum WindowsDirectConnectorNativeError {
    WorkerSpawnFailed,
    WorkerPanicked,
    SocketConfigurationFailed,
    InvalidOutboundPayload,
    OutboundQueueFull,
    EventQueueFull,
    EventSinkClosed,
    EventTimeout,
    ConnectorStopped,
}

impl fmt::Display for WindowsDirectConnectorNativeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WorkerSpawnFailed => "direct connector worker could not start",
            Self::WorkerPanicked => "direct connector worker panicked",
            Self::SocketConfigurationFailed => "direct connector socket setup failed",
            Self::InvalidOutboundPayload => "direct connector outbound payload is invalid",
            Self::OutboundQueueFull => "direct connector outbound queue is full",
            Self::EventQueueFull => "direct connector event queue is full",
            Self::EventSinkClosed => "direct connector event sink is closed",
            Self::EventTimeout => "direct connector event wait timed out",
            Self::ConnectorStopped => "direct connector has stopped",
        })
    }
}

impl std::error::Error for WindowsDirectConnectorNativeError {}

#[derive(Debug, Eq, PartialEq)]
pub enum WindowsDirectDataPlaneEffectError {
    MissingPlan(u64),
    DuplicateSession(u64),
    CapacityReached,
    PlanIdentityMismatch(u64),
    UnknownSession(u64),
    DuplicateFirstPayload(u64),
    OutcomeBeforeClose(u64),
    DuplicateOutcome(u64),
    WorkerStoppedWithResources,
    Native(WindowsDirectConnectorNativeError),
}

impl fmt::Display for WindowsDirectDataPlaneEffectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPlan(session_id) => {
                write!(formatter, "direct connector plan {session_id} is missing")
            }
            Self::DuplicateSession(session_id) => {
                write!(
                    formatter,
                    "direct connector session {session_id} already exists"
                )
            }
            Self::CapacityReached => {
                formatter.write_str("direct connector staged-plan capacity is reached")
            }
            Self::PlanIdentityMismatch(session_id) => write!(
                formatter,
                "direct connector plan {session_id} does not match the data-plane session"
            ),
            Self::UnknownSession(session_id) => {
                write!(
                    formatter,
                    "direct connector session {session_id} is unknown"
                )
            }
            Self::DuplicateFirstPayload(session_id) => write!(
                formatter,
                "direct connector session {session_id} already marked first payload"
            ),
            Self::OutcomeBeforeClose(session_id) => write!(
                formatter,
                "direct connector session {session_id} recorded an outcome before close"
            ),
            Self::DuplicateOutcome(session_id) => {
                write!(
                    formatter,
                    "direct connector session {session_id} has two outcomes"
                )
            }
            Self::WorkerStoppedWithResources => {
                formatter.write_str("direct connector worker stopped with owned resources")
            }
            Self::Native(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for WindowsDirectDataPlaneEffectError {}

impl From<WindowsDirectConnectorNativeError> for WindowsDirectDataPlaneEffectError {
    fn from(value: WindowsDirectConnectorNativeError) -> Self {
        Self::Native(value)
    }
}
