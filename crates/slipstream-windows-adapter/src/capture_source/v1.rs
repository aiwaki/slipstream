//! Version 1 contract for a Windows client-stream capture source.
//!
//! This boundary deliberately does not choose a Windows interception API. A
//! native adapter may register one already-accepted stream under an opaque
//! resource ID and report its numeric original destination. This reducer owns
//! the resource until an external policy authority grants a direct admission,
//! the resource is handed to direct ingress, or bounded cleanup closes it.

use crate::direct_connector::{WindowsDirectConnectorEndpoint, WindowsDirectConnectorRequest};
use crate::direct_ingress::{
    prepare_windows_direct_ingress, WindowsDirectIngressEndpointEvidence,
    WindowsDirectIngressEndpointEvidenceSource, WindowsDirectIngressRequest,
    MAX_DIRECT_INGRESS_EVIDENCE_AGE_MS,
};
use serde::{Deserialize, Serialize};
use slipstream_core::routing_policy::RoutingPolicyTables;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

pub const WINDOWS_CAPTURE_SOURCE_CONTRACT_VERSION: u32 = 1;
pub const MAX_CAPTURE_SOURCE_STAGED_CONNECTIONS: usize = 65_535;
pub const MAX_CAPTURE_SOURCE_RETAINED_CONNECTIONS: usize = 65_535;
pub const MAX_CAPTURE_SOURCE_SHUTDOWN_TIMEOUT_MS: u64 = 30_000;
const MAX_REASON_CHARS: usize = 200;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsCaptureSourceConfig {
    pub max_staged_connections: usize,
    pub max_retained_terminal_connections: usize,
    pub admission_timeout_ms: u64,
    pub shutdown_timeout_ms: u64,
}

impl WindowsCaptureSourceConfig {
    pub fn validate(&self) -> Result<(), WindowsCaptureSourceError> {
        if self.max_staged_connections == 0
            || self.max_staged_connections > MAX_CAPTURE_SOURCE_STAGED_CONNECTIONS
        {
            return Err(WindowsCaptureSourceError::InvalidConfig(
                "max_staged_connections",
            ));
        }
        if self.max_retained_terminal_connections == 0
            || self.max_retained_terminal_connections > MAX_CAPTURE_SOURCE_RETAINED_CONNECTIONS
        {
            return Err(WindowsCaptureSourceError::InvalidConfig(
                "max_retained_terminal_connections",
            ));
        }
        if self.admission_timeout_ms == 0
            || self.admission_timeout_ms > MAX_DIRECT_INGRESS_EVIDENCE_AGE_MS
        {
            return Err(WindowsCaptureSourceError::InvalidConfig(
                "admission_timeout_ms",
            ));
        }
        if self.shutdown_timeout_ms == 0
            || self.shutdown_timeout_ms > MAX_CAPTURE_SOURCE_SHUTDOWN_TIMEOUT_MS
        {
            return Err(WindowsCaptureSourceError::InvalidConfig(
                "shutdown_timeout_ms",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsCaptureSourcePhase {
    Stopped,
    Starting,
    Ready,
    Draining,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsCapturedConnectionPhase {
    AwaitingAdmission,
    HandedOff,
    Closed,
}

impl WindowsCapturedConnectionPhase {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::HandedOff | Self::Closed)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsCapturedConnectionState {
    pub connection_id: u64,
    pub resource_id: u64,
    pub original_destination: WindowsDirectConnectorEndpoint,
    pub observed_at_ms: u64,
    pub admission_deadline_at_ms: u64,
    pub phase: WindowsCapturedConnectionPhase,
    pub resource_owned: bool,
    pub terminal_reason: String,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsCaptureSourceState {
    pub phase: WindowsCaptureSourcePhase,
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    pub shutdown_deadline_at_ms: Option<u64>,
    pub startup_failure: String,
    pub next_connection_id: u64,
    pub connections: BTreeMap<u64, WindowsCapturedConnectionState>,
}

impl WindowsCaptureSourceState {
    pub fn new(now_ms: u64) -> Self {
        Self {
            phase: WindowsCaptureSourcePhase::Stopped,
            started_at_ms: now_ms,
            updated_at_ms: now_ms,
            shutdown_deadline_at_ms: None,
            startup_failure: String::new(),
            next_connection_id: 1,
            connections: BTreeMap::new(),
        }
    }

    pub fn staged_connection_count(&self) -> usize {
        self.connections
            .values()
            .filter(|connection| connection.resource_owned)
            .count()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WindowsCaptureSourceEvent {
    StartRequested {
        now_ms: u64,
    },
    SourceReady {
        now_ms: u64,
    },
    SourceStartupFailed {
        now_ms: u64,
        reason: String,
    },
    ConnectionCaptured {
        now_ms: u64,
        resource_id: u64,
        original_destination: WindowsDirectConnectorEndpoint,
    },
    AdmissionGranted {
        now_ms: u64,
        connection_id: u64,
        connector_request: WindowsDirectConnectorRequest,
        max_client_read_chunk_bytes: usize,
        backpressure_timeout_ms: u64,
    },
    AdmissionRejected {
        now_ms: u64,
        connection_id: u64,
        reason: String,
    },
    AdmissionDeadline {
        now_ms: u64,
        connection_id: u64,
    },
    StopRequested {
        now_ms: u64,
    },
    SourceStopped {
        now_ms: u64,
    },
    ShutdownDeadline {
        now_ms: u64,
    },
}

impl WindowsCaptureSourceEvent {
    pub const fn now_ms(&self) -> u64 {
        match self {
            Self::StartRequested { now_ms }
            | Self::SourceReady { now_ms }
            | Self::SourceStartupFailed { now_ms, .. }
            | Self::ConnectionCaptured { now_ms, .. }
            | Self::AdmissionGranted { now_ms, .. }
            | Self::AdmissionRejected { now_ms, .. }
            | Self::AdmissionDeadline { now_ms, .. }
            | Self::StopRequested { now_ms }
            | Self::SourceStopped { now_ms }
            | Self::ShutdownDeadline { now_ms } => *now_ms,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WindowsCaptureSourceCommand {
    StartSource,
    ReportSourceReady,
    OfferConnection {
        connection_id: u64,
        resource_id: u64,
        original_destination: WindowsDirectConnectorEndpoint,
        observed_at_ms: u64,
        valid_until_ms: u64,
    },
    ScheduleAdmissionDeadline {
        connection_id: u64,
        at_ms: u64,
    },
    HandoffIngress {
        connection_id: u64,
        resource_id: u64,
        request: Box<WindowsDirectIngressRequest>,
    },
    CloseCapturedStream {
        connection_id: Option<u64>,
        resource_id: u64,
        reason: String,
    },
    StopAccepting,
    ScheduleShutdownDeadline {
        at_ms: u64,
    },
    ForceStopSource,
    ReportSourceStartupFailed {
        reason: String,
    },
    ReportSourceStopped,
}

impl WindowsCaptureSourceCommand {
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::StartSource => "start_source",
            Self::ReportSourceReady => "report_source_ready",
            Self::OfferConnection { .. } => "offer_connection",
            Self::ScheduleAdmissionDeadline { .. } => "schedule_admission_deadline",
            Self::HandoffIngress { .. } => "handoff_ingress",
            Self::CloseCapturedStream { .. } => "close_captured_stream",
            Self::StopAccepting => "stop_accepting",
            Self::ScheduleShutdownDeadline { .. } => "schedule_shutdown_deadline",
            Self::ForceStopSource => "force_stop_source",
            Self::ReportSourceStartupFailed { .. } => "report_source_startup_failed",
            Self::ReportSourceStopped => "report_source_stopped",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsCaptureSourceTransition {
    pub state: WindowsCaptureSourceState,
    pub commands: Vec<WindowsCaptureSourceCommand>,
}

pub fn reduce_windows_capture_source(
    state: &WindowsCaptureSourceState,
    event: &WindowsCaptureSourceEvent,
    config: &WindowsCaptureSourceConfig,
    policy_tables: &RoutingPolicyTables,
) -> Result<WindowsCaptureSourceTransition, WindowsCaptureSourceError> {
    config.validate()?;
    validate_state(state)?;
    let now_ms = event.now_ms();
    if now_ms < state.updated_at_ms {
        return Err(WindowsCaptureSourceError::NonMonotonicEvent);
    }

    let mut next = state.clone();
    next.updated_at_ms = now_ms;
    let mut commands = Vec::new();

    match event {
        WindowsCaptureSourceEvent::StartRequested { .. } => {
            if matches!(
                next.phase,
                WindowsCaptureSourcePhase::Stopped | WindowsCaptureSourcePhase::Failed
            ) {
                next.phase = WindowsCaptureSourcePhase::Starting;
                next.started_at_ms = now_ms;
                next.shutdown_deadline_at_ms = None;
                next.startup_failure.clear();
                commands.push(WindowsCaptureSourceCommand::StartSource);
            }
        }
        WindowsCaptureSourceEvent::SourceReady { .. } => {
            if next.phase == WindowsCaptureSourcePhase::Starting {
                next.phase = WindowsCaptureSourcePhase::Ready;
                commands.push(WindowsCaptureSourceCommand::ReportSourceReady);
            }
        }
        WindowsCaptureSourceEvent::SourceStartupFailed { reason, .. } => {
            if next.phase == WindowsCaptureSourcePhase::Starting {
                next.phase = WindowsCaptureSourcePhase::Failed;
                next.startup_failure = bounded_reason(reason);
                commands.push(WindowsCaptureSourceCommand::ForceStopSource);
                close_all_owned(&mut next, "source_startup_failed", &mut commands);
                commands.push(WindowsCaptureSourceCommand::ReportSourceStartupFailed {
                    reason: next.startup_failure.clone(),
                });
            }
        }
        WindowsCaptureSourceEvent::ConnectionCaptured {
            resource_id,
            original_destination,
            ..
        } => {
            if next.phase != WindowsCaptureSourcePhase::Ready {
                close_untracked(*resource_id, "source_not_ready", &mut commands);
            } else if !valid_numeric_endpoint(original_destination) {
                close_untracked(*resource_id, "invalid_original_destination", &mut commands);
            } else if *resource_id == 0 {
                close_untracked(*resource_id, "invalid_resource_id", &mut commands);
            } else if next
                .connections
                .values()
                .any(|connection| connection.resource_id == *resource_id)
            {
                return Err(WindowsCaptureSourceError::DuplicateResourceId(*resource_id));
            } else if next.staged_connection_count() >= config.max_staged_connections {
                close_untracked(*resource_id, "capture_limit", &mut commands);
            } else {
                let connection_id = next.next_connection_id;
                next.next_connection_id = connection_id
                    .checked_add(1)
                    .ok_or(WindowsCaptureSourceError::ConnectionIdOverflow)?;
                let deadline = now_ms
                    .checked_add(config.admission_timeout_ms)
                    .ok_or(WindowsCaptureSourceError::TimeOverflow)?;
                next.connections.insert(
                    connection_id,
                    WindowsCapturedConnectionState {
                        connection_id,
                        resource_id: *resource_id,
                        original_destination: original_destination.clone(),
                        observed_at_ms: now_ms,
                        admission_deadline_at_ms: deadline,
                        phase: WindowsCapturedConnectionPhase::AwaitingAdmission,
                        resource_owned: true,
                        terminal_reason: String::new(),
                        updated_at_ms: now_ms,
                    },
                );
                commands.push(WindowsCaptureSourceCommand::OfferConnection {
                    connection_id,
                    resource_id: *resource_id,
                    original_destination: original_destination.clone(),
                    observed_at_ms: now_ms,
                    valid_until_ms: deadline,
                });
                commands.push(WindowsCaptureSourceCommand::ScheduleAdmissionDeadline {
                    connection_id,
                    at_ms: deadline,
                });
            }
        }
        WindowsCaptureSourceEvent::AdmissionGranted {
            connection_id,
            connector_request,
            max_client_read_chunk_bytes,
            backpressure_timeout_ms,
            ..
        } => {
            let Some(connection) = active_connection(&next, *connection_id)? else {
                return Ok(WindowsCaptureSourceTransition {
                    state: next,
                    commands,
                });
            };
            if next.phase != WindowsCaptureSourcePhase::Ready {
                close_connection(&mut next, *connection_id, "source_not_ready", &mut commands)?;
            } else if now_ms > connection.admission_deadline_at_ms {
                close_connection(
                    &mut next,
                    *connection_id,
                    "admission_deadline",
                    &mut commands,
                )?;
            } else if now_ms >= connector_request.connect_deadline_at_ms
                || now_ms
                    >= connector_request
                        .data_plane_request
                        .first_payload_deadline_at_ms
            {
                close_connection(
                    &mut next,
                    *connection_id,
                    "expired_connector_deadline",
                    &mut commands,
                )?;
            } else {
                let request = WindowsDirectIngressRequest {
                    connector_request: connector_request.clone(),
                    endpoint_evidence: WindowsDirectIngressEndpointEvidence {
                        source: WindowsDirectIngressEndpointEvidenceSource::OriginalDestination,
                        connection_id: connection.connection_id,
                        request_id: connector_request.data_plane_request.request_id.clone(),
                        session_id: connector_request.session_id,
                        endpoint: connection.original_destination.clone(),
                        observed_at_ms: connection.observed_at_ms,
                        valid_until_ms: connection.admission_deadline_at_ms.min(
                            connector_request
                                .data_plane_request
                                .first_payload_deadline_at_ms,
                        ),
                    },
                    max_client_read_chunk_bytes: *max_client_read_chunk_bytes,
                    backpressure_timeout_ms: *backpressure_timeout_ms,
                };
                match prepare_windows_direct_ingress(&request, policy_tables) {
                    Ok(_) => {
                        let connection = next
                            .connections
                            .get_mut(connection_id)
                            .expect("active connection was checked");
                        connection.phase = WindowsCapturedConnectionPhase::HandedOff;
                        connection.resource_owned = false;
                        connection.terminal_reason = "handed_off".to_owned();
                        connection.updated_at_ms = now_ms;
                        commands.push(WindowsCaptureSourceCommand::HandoffIngress {
                            connection_id: *connection_id,
                            resource_id: connection.resource_id,
                            request: Box::new(request),
                        });
                    }
                    Err(error) => close_connection(
                        &mut next,
                        *connection_id,
                        &format!("invalid_admission:{}", error.as_str()),
                        &mut commands,
                    )?,
                }
            }
        }
        WindowsCaptureSourceEvent::AdmissionRejected {
            connection_id,
            reason,
            ..
        } => {
            if active_connection(&next, *connection_id)?.is_some() {
                close_connection(
                    &mut next,
                    *connection_id,
                    &format!("admission_rejected:{}", bounded_reason(reason)),
                    &mut commands,
                )?;
            }
        }
        WindowsCaptureSourceEvent::AdmissionDeadline { connection_id, .. } => {
            if let Some(connection) = active_connection(&next, *connection_id)? {
                if now_ms < connection.admission_deadline_at_ms {
                    return Err(WindowsCaptureSourceError::DeadlineBeforeDue);
                }
                close_connection(
                    &mut next,
                    *connection_id,
                    "admission_deadline",
                    &mut commands,
                )?;
            }
        }
        WindowsCaptureSourceEvent::StopRequested { .. } => {
            if matches!(
                next.phase,
                WindowsCaptureSourcePhase::Starting | WindowsCaptureSourcePhase::Ready
            ) {
                next.phase = WindowsCaptureSourcePhase::Draining;
                let deadline = now_ms
                    .checked_add(config.shutdown_timeout_ms)
                    .ok_or(WindowsCaptureSourceError::TimeOverflow)?;
                next.shutdown_deadline_at_ms = Some(deadline);
                commands.push(WindowsCaptureSourceCommand::StopAccepting);
                close_all_owned(&mut next, "source_shutdown", &mut commands);
                commands.push(WindowsCaptureSourceCommand::ScheduleShutdownDeadline {
                    at_ms: deadline,
                });
            }
        }
        WindowsCaptureSourceEvent::SourceStopped { .. } => {
            if matches!(
                next.phase,
                WindowsCaptureSourcePhase::Starting
                    | WindowsCaptureSourcePhase::Ready
                    | WindowsCaptureSourcePhase::Draining
            ) {
                close_all_owned(&mut next, "source_stopped", &mut commands);
                next.phase = WindowsCaptureSourcePhase::Stopped;
                next.shutdown_deadline_at_ms = None;
                commands.push(WindowsCaptureSourceCommand::ReportSourceStopped);
            }
        }
        WindowsCaptureSourceEvent::ShutdownDeadline { .. } => {
            if next.phase == WindowsCaptureSourcePhase::Draining {
                let deadline =
                    next.shutdown_deadline_at_ms
                        .ok_or(WindowsCaptureSourceError::InvalidState(
                            "draining source has no deadline",
                        ))?;
                if now_ms < deadline {
                    return Err(WindowsCaptureSourceError::DeadlineBeforeDue);
                }
                commands.push(WindowsCaptureSourceCommand::ForceStopSource);
                close_all_owned(&mut next, "source_shutdown_deadline", &mut commands);
                next.phase = WindowsCaptureSourcePhase::Stopped;
                next.shutdown_deadline_at_ms = None;
                commands.push(WindowsCaptureSourceCommand::ReportSourceStopped);
            }
        }
    }

    prune_terminal_connections(&mut next, config.max_retained_terminal_connections);
    validate_state(&next)?;
    Ok(WindowsCaptureSourceTransition {
        state: next,
        commands,
    })
}

fn bounded_reason(reason: &str) -> String {
    reason.chars().take(MAX_REASON_CHARS).collect()
}

fn valid_numeric_endpoint(endpoint: &WindowsDirectConnectorEndpoint) -> bool {
    endpoint.port != 0
        && endpoint
            .address
            .parse::<IpAddr>()
            .is_ok_and(|address| address.to_string() == endpoint.address)
}

fn active_connection(
    state: &WindowsCaptureSourceState,
    connection_id: u64,
) -> Result<Option<WindowsCapturedConnectionState>, WindowsCaptureSourceError> {
    match state.connections.get(&connection_id) {
        Some(connection)
            if connection.phase == WindowsCapturedConnectionPhase::AwaitingAdmission =>
        {
            Ok(Some(connection.clone()))
        }
        Some(_) => Ok(None),
        None if connection_id < state.next_connection_id => Ok(None),
        None => Err(WindowsCaptureSourceError::UnknownConnection(connection_id)),
    }
}

fn close_untracked(
    resource_id: u64,
    reason: &str,
    commands: &mut Vec<WindowsCaptureSourceCommand>,
) {
    commands.push(WindowsCaptureSourceCommand::CloseCapturedStream {
        connection_id: None,
        resource_id,
        reason: reason.to_owned(),
    });
}

fn close_connection(
    state: &mut WindowsCaptureSourceState,
    connection_id: u64,
    reason: &str,
    commands: &mut Vec<WindowsCaptureSourceCommand>,
) -> Result<(), WindowsCaptureSourceError> {
    let connection = state
        .connections
        .get_mut(&connection_id)
        .ok_or(WindowsCaptureSourceError::UnknownConnection(connection_id))?;
    if !connection.resource_owned {
        return Ok(());
    }
    connection.phase = WindowsCapturedConnectionPhase::Closed;
    connection.resource_owned = false;
    connection.terminal_reason = bounded_reason(reason);
    connection.updated_at_ms = state.updated_at_ms;
    commands.push(WindowsCaptureSourceCommand::CloseCapturedStream {
        connection_id: Some(connection_id),
        resource_id: connection.resource_id,
        reason: connection.terminal_reason.clone(),
    });
    Ok(())
}

fn close_all_owned(
    state: &mut WindowsCaptureSourceState,
    reason: &str,
    commands: &mut Vec<WindowsCaptureSourceCommand>,
) {
    let connection_ids = state
        .connections
        .iter()
        .filter_map(|(connection_id, connection)| {
            connection.resource_owned.then_some(*connection_id)
        })
        .collect::<Vec<_>>();
    for connection_id in connection_ids {
        close_connection(state, connection_id, reason, commands)
            .expect("collected connection must still exist");
    }
}

fn prune_terminal_connections(state: &mut WindowsCaptureSourceState, retain: usize) {
    let mut terminal = state
        .connections
        .iter()
        .filter_map(|(connection_id, connection)| {
            connection
                .phase
                .is_terminal()
                .then_some((connection.updated_at_ms, *connection_id))
        })
        .collect::<Vec<_>>();
    terminal.sort_unstable();
    let remove_count = terminal.len().saturating_sub(retain);
    for (_, connection_id) in terminal.into_iter().take(remove_count) {
        state.connections.remove(&connection_id);
    }
}

fn validate_state(state: &WindowsCaptureSourceState) -> Result<(), WindowsCaptureSourceError> {
    if state.next_connection_id == 0 {
        return Err(WindowsCaptureSourceError::InvalidState(
            "next connection ID is zero",
        ));
    }
    let has_shutdown_deadline = state.shutdown_deadline_at_ms.is_some();
    if has_shutdown_deadline != (state.phase == WindowsCaptureSourcePhase::Draining) {
        return Err(WindowsCaptureSourceError::InvalidState(
            "shutdown deadline does not match source phase",
        ));
    }
    let mut resource_ids = BTreeSet::new();
    for (connection_id, connection) in &state.connections {
        if *connection_id != connection.connection_id || connection.resource_id == 0 {
            return Err(WindowsCaptureSourceError::InvalidState(
                "connection identity is inconsistent",
            ));
        }
        if !resource_ids.insert(connection.resource_id) {
            return Err(WindowsCaptureSourceError::InvalidState(
                "resource ID was reused",
            ));
        }
        let expected_owned = connection.phase == WindowsCapturedConnectionPhase::AwaitingAdmission;
        if connection.resource_owned != expected_owned {
            return Err(WindowsCaptureSourceError::InvalidState(
                "resource ownership does not match connection phase",
            ));
        }
        if connection.resource_owned && state.phase != WindowsCaptureSourcePhase::Ready {
            return Err(WindowsCaptureSourceError::InvalidState(
                "non-ready source retains a captured stream",
            ));
        }
    }
    Ok(())
}

pub trait WindowsCaptureSourceEffects {
    type Error: fmt::Display;

    /// Executes one command atomically. On `Err`, this command must retain no
    /// partial mutation; a stream handoff must leave the stream capture-owned.
    fn execute(&mut self, command: &WindowsCaptureSourceCommand) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, Default)]
pub struct RecordingWindowsCaptureSourceEffects {
    commands: Vec<WindowsCaptureSourceCommand>,
    source_started: bool,
    accepting: bool,
    open_resources: BTreeSet<u64>,
    handed_off: BTreeMap<u64, WindowsDirectIngressRequest>,
    closed_resources: BTreeMap<u64, String>,
    fail_once: BTreeMap<String, String>,
}

impl RecordingWindowsCaptureSourceEffects {
    pub fn commands(&self) -> &[WindowsCaptureSourceCommand] {
        &self.commands
    }

    pub const fn source_started(&self) -> bool {
        self.source_started
    }

    pub const fn accepting(&self) -> bool {
        self.accepting
    }

    pub fn open_resources(&self) -> &BTreeSet<u64> {
        &self.open_resources
    }

    pub fn handed_off(&self) -> &BTreeMap<u64, WindowsDirectIngressRequest> {
        &self.handed_off
    }

    pub fn closed_resources(&self) -> &BTreeMap<u64, String> {
        &self.closed_resources
    }

    pub fn stage_captured_stream(
        &mut self,
        resource_id: u64,
    ) -> Result<(), WindowsCaptureSourceEffectError> {
        if self.open_resources.contains(&resource_id)
            || self.handed_off.contains_key(&resource_id)
            || self.closed_resources.contains_key(&resource_id)
        {
            return Err(WindowsCaptureSourceEffectError::DuplicateResource(
                resource_id,
            ));
        }
        self.open_resources.insert(resource_id);
        Ok(())
    }

    pub fn fail_once(&mut self, command: &str, message: impl Into<String>) {
        self.fail_once.insert(command.to_owned(), message.into());
    }

    fn require_open(&self, resource_id: u64) -> Result<(), WindowsCaptureSourceEffectError> {
        if self.open_resources.contains(&resource_id) {
            Ok(())
        } else {
            Err(WindowsCaptureSourceEffectError::UnknownResource(
                resource_id,
            ))
        }
    }
}

impl WindowsCaptureSourceEffects for RecordingWindowsCaptureSourceEffects {
    type Error = WindowsCaptureSourceEffectError;

    fn execute(&mut self, command: &WindowsCaptureSourceCommand) -> Result<(), Self::Error> {
        if let Some(message) = self.fail_once.remove(command.kind()) {
            return Err(WindowsCaptureSourceEffectError::InjectedFailure {
                command: command.kind().to_owned(),
                message,
            });
        }
        match command {
            WindowsCaptureSourceCommand::StartSource => {
                if self.source_started {
                    return Err(WindowsCaptureSourceEffectError::SourceAlreadyStarted);
                }
                self.source_started = true;
            }
            WindowsCaptureSourceCommand::ReportSourceReady => {
                if !self.source_started {
                    return Err(WindowsCaptureSourceEffectError::SourceNotStarted);
                }
                self.accepting = true;
            }
            WindowsCaptureSourceCommand::OfferConnection { resource_id, .. } => {
                self.require_open(*resource_id)?;
            }
            WindowsCaptureSourceCommand::ScheduleAdmissionDeadline { .. } => {}
            WindowsCaptureSourceCommand::HandoffIngress {
                connection_id,
                resource_id,
                request,
            } => {
                self.require_open(*resource_id)?;
                if request.endpoint_evidence.connection_id != *connection_id {
                    return Err(WindowsCaptureSourceEffectError::IdentityMismatch(
                        *resource_id,
                    ));
                }
                self.open_resources.remove(resource_id);
                self.handed_off.insert(*resource_id, (**request).clone());
            }
            WindowsCaptureSourceCommand::CloseCapturedStream {
                resource_id,
                reason,
                ..
            } => {
                self.require_open(*resource_id)?;
                self.open_resources.remove(resource_id);
                self.closed_resources.insert(*resource_id, reason.clone());
            }
            WindowsCaptureSourceCommand::StopAccepting => {
                self.accepting = false;
            }
            WindowsCaptureSourceCommand::ScheduleShutdownDeadline { .. } => {}
            WindowsCaptureSourceCommand::ForceStopSource => {
                self.accepting = false;
                self.source_started = false;
            }
            WindowsCaptureSourceCommand::ReportSourceStartupFailed { .. } => {
                if self.source_started || !self.open_resources.is_empty() {
                    return Err(WindowsCaptureSourceEffectError::TerminalWithResources);
                }
            }
            WindowsCaptureSourceCommand::ReportSourceStopped => {
                if !self.open_resources.is_empty() {
                    return Err(WindowsCaptureSourceEffectError::TerminalWithResources);
                }
                self.accepting = false;
                self.source_started = false;
            }
        }

        self.commands.push(command.clone());
        Ok(())
    }
}

pub fn execute_windows_capture_source_transition<E: WindowsCaptureSourceEffects>(
    transition: &WindowsCaptureSourceTransition,
    effects: &mut E,
) -> Result<(), WindowsCaptureSourceEffectExecutionError> {
    execute_windows_capture_source_transition_from(transition, effects, 0)
}

/// Resumes one immutable command batch without replaying its completed prefix.
pub fn execute_windows_capture_source_transition_from<E: WindowsCaptureSourceEffects>(
    transition: &WindowsCaptureSourceTransition,
    effects: &mut E,
    next_command_index: usize,
) -> Result<(), WindowsCaptureSourceEffectExecutionError> {
    if next_command_index > transition.commands.len() {
        return Err(WindowsCaptureSourceEffectExecutionError {
            command: "transition_cursor",
            message: format!(
                "command cursor {next_command_index} exceeds batch length {}",
                transition.commands.len()
            ),
            failed_command_index: next_command_index,
            next_command_index,
            completed_commands: 0,
        });
    }
    for (command_index, command) in transition
        .commands
        .iter()
        .enumerate()
        .skip(next_command_index)
    {
        effects
            .execute(command)
            .map_err(|error| WindowsCaptureSourceEffectExecutionError {
                command: command.kind(),
                message: error.to_string(),
                failed_command_index: command_index,
                next_command_index: command_index,
                completed_commands: command_index,
            })?;
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsCaptureSourceEffectError {
    InjectedFailure { command: String, message: String },
    DuplicateResource(u64),
    UnknownResource(u64),
    IdentityMismatch(u64),
    SourceAlreadyStarted,
    SourceNotStarted,
    TerminalWithResources,
}

impl fmt::Display for WindowsCaptureSourceEffectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InjectedFailure { command, message } => {
                write!(formatter, "{command}: {message}")
            }
            Self::DuplicateResource(resource_id) => {
                write!(formatter, "duplicate resource {resource_id}")
            }
            Self::UnknownResource(resource_id) => {
                write!(formatter, "unknown resource {resource_id}")
            }
            Self::IdentityMismatch(resource_id) => {
                write!(formatter, "resource {resource_id} identity mismatch")
            }
            Self::SourceAlreadyStarted => formatter.write_str("source already started"),
            Self::SourceNotStarted => formatter.write_str("source is not started"),
            Self::TerminalWithResources => {
                formatter.write_str("source became terminal with owned resources")
            }
        }
    }
}

impl std::error::Error for WindowsCaptureSourceEffectError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsCaptureSourceEffectExecutionError {
    pub command: &'static str,
    pub message: String,
    pub failed_command_index: usize,
    pub next_command_index: usize,
    pub completed_commands: usize,
}

impl fmt::Display for WindowsCaptureSourceEffectExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} failed at command {}: {}",
            self.command, self.failed_command_index, self.message
        )
    }
}

impl std::error::Error for WindowsCaptureSourceEffectExecutionError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsCaptureSourceError {
    InvalidConfig(&'static str),
    NonMonotonicEvent,
    ConnectionIdOverflow,
    TimeOverflow,
    DeadlineBeforeDue,
    UnknownConnection(u64),
    DuplicateResourceId(u64),
    InvalidState(&'static str),
}

impl fmt::Display for WindowsCaptureSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(field) => write!(formatter, "invalid capture config: {field}"),
            Self::NonMonotonicEvent => formatter.write_str("non-monotonic capture event"),
            Self::ConnectionIdOverflow => formatter.write_str("capture connection ID overflow"),
            Self::TimeOverflow => formatter.write_str("capture deadline overflow"),
            Self::DeadlineBeforeDue => formatter.write_str("capture deadline fired before due"),
            Self::UnknownConnection(connection_id) => {
                write!(formatter, "unknown capture connection {connection_id}")
            }
            Self::DuplicateResourceId(resource_id) => {
                write!(formatter, "duplicate capture resource {resource_id}")
            }
            Self::InvalidState(message) => write!(formatter, "invalid capture state: {message}"),
        }
    }
}

impl std::error::Error for WindowsCaptureSourceError {}
