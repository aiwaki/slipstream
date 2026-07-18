//! Pure version 1 Windows data-plane worker and session state machine.
//!
//! This module deliberately owns no socket, DNS, proxy, PAC, VPN, process, or
//! packet API. A later native adapter may execute the commands emitted here,
//! but it must feed completion events back through this reducer and retain the
//! same ownership, cancellation, and late-completion rules.

use serde::{Deserialize, Serialize};
use slipstream_core::routing_policy::{normalize_host, RouteClass, RoutePolicyResult, StrategySet};
use slipstream_core::routing_recovery::ConnectionOutcome;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const WINDOWS_DATA_PLANE_CONTRACT_VERSION: u32 = 1;
const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_HOST_BYTES: usize = 253;
const MAX_REASON_CHARS: usize = 200;
const MAX_ACTIVE_SESSIONS: usize = 65_535;
const MAX_RETAINED_TERMINAL_SESSIONS: usize = 65_535;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsDataPlaneConfig {
    pub max_active_sessions: usize,
    pub max_retained_terminal_sessions: usize,
    pub cancel_timeout_ms: u64,
    pub shutdown_timeout_ms: u64,
}

impl WindowsDataPlaneConfig {
    pub fn validate(&self) -> Result<(), WindowsDataPlaneError> {
        if self.max_active_sessions == 0 || self.max_active_sessions > MAX_ACTIVE_SESSIONS {
            return Err(WindowsDataPlaneError::InvalidConfig(
                "max_active_sessions must be within 1..=65535",
            ));
        }
        if self.max_retained_terminal_sessions == 0
            || self.max_retained_terminal_sessions > MAX_RETAINED_TERMINAL_SESSIONS
        {
            return Err(WindowsDataPlaneError::InvalidConfig(
                "max_retained_terminal_sessions must be within 1..=65535",
            ));
        }
        if self.cancel_timeout_ms == 0 {
            return Err(WindowsDataPlaneError::InvalidConfig(
                "cancel_timeout_ms must be positive",
            ));
        }
        if self.shutdown_timeout_ms == 0 {
            return Err(WindowsDataPlaneError::InvalidConfig(
                "shutdown_timeout_ms must be positive",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsDataPlaneBackend {
    Direct,
    LocalEngine,
    SmartDns,
    Geph,
}

impl WindowsDataPlaneBackend {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::LocalEngine => "local_engine",
            Self::SmartDns => "smart_dns",
            Self::Geph => "geph",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsDataPlaneRequest {
    pub request_id: String,
    pub policy: RoutePolicyResult,
    pub backend: WindowsDataPlaneBackend,
    pub started_at_ms: u64,
    pub first_payload_deadline_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsDataPlaneRequestErrorCode {
    InvalidRequestId,
    InvalidHost,
    InvalidDeadline,
    ProtectedRouteMismatch,
    PolicyRouteMismatch,
    BackendRouteMismatch,
}

impl WindowsDataPlaneRequestErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequestId => "invalid_request_id",
            Self::InvalidHost => "invalid_host",
            Self::InvalidDeadline => "invalid_deadline",
            Self::ProtectedRouteMismatch => "protected_route_mismatch",
            Self::PolicyRouteMismatch => "policy_route_mismatch",
            Self::BackendRouteMismatch => "backend_route_mismatch",
        }
    }
}

pub fn validate_windows_data_plane_request(
    request: &WindowsDataPlaneRequest,
) -> Result<(), WindowsDataPlaneRequestErrorCode> {
    if request.request_id.is_empty()
        || request.request_id.len() > MAX_REQUEST_ID_BYTES
        || !request.request_id.is_ascii()
        || request
            .request_id
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(WindowsDataPlaneRequestErrorCode::InvalidRequestId);
    }
    let host = &request.policy.host;
    if !is_normalized_hostname(host) {
        return Err(WindowsDataPlaneRequestErrorCode::InvalidHost);
    }
    if request.first_payload_deadline_at_ms <= request.started_at_ms {
        return Err(WindowsDataPlaneRequestErrorCode::InvalidDeadline);
    }

    if request.policy.service_group.is_protected_local_bypass()
        && (request.policy.route_class != RouteClass::LocalBypass
            || request.backend != WindowsDataPlaneBackend::LocalEngine)
    {
        return Err(WindowsDataPlaneRequestErrorCode::ProtectedRouteMismatch);
    }

    let strategy_matches = matches!(
        (request.policy.route_class, request.policy.strategy_set),
        (RouteClass::DirectPassthrough, StrategySet::Direct)
            | (RouteClass::DirectFirst, StrategySet::DirectFirst)
            | (RouteClass::LocalBypass, StrategySet::FakeOnly)
            | (RouteClass::GeoExit, StrategySet::Geph)
            | (RouteClass::Unknown, StrategySet::General)
    );
    if !strategy_matches {
        return Err(WindowsDataPlaneRequestErrorCode::PolicyRouteMismatch);
    }

    let backend_matches = match request.policy.route_class {
        RouteClass::DirectPassthrough => request.backend == WindowsDataPlaneBackend::Direct,
        RouteClass::DirectFirst => matches!(
            request.backend,
            WindowsDataPlaneBackend::Direct | WindowsDataPlaneBackend::LocalEngine
        ),
        RouteClass::LocalBypass | RouteClass::Unknown => {
            request.backend == WindowsDataPlaneBackend::LocalEngine
        }
        RouteClass::GeoExit => matches!(
            request.backend,
            WindowsDataPlaneBackend::SmartDns | WindowsDataPlaneBackend::Geph
        ),
    };
    if !backend_matches {
        return Err(WindowsDataPlaneRequestErrorCode::BackendRouteMismatch);
    }
    Ok(())
}

fn is_normalized_hostname(host: &str) -> bool {
    if host.is_empty()
        || host.len() > MAX_HOST_BYTES
        || !host.is_ascii()
        || normalize_host(host) != host
    {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsDataPlaneWorkerPhase {
    Starting,
    Ready,
    Draining,
    Stopped,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsDataPlaneSessionPhase {
    Opening,
    AwaitingFirstPayload,
    Relaying,
    Cancelling,
    Succeeded,
    Failed,
    Cancelled,
}

impl WindowsDataPlaneSessionPhase {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsDataPlaneSessionState {
    pub session_id: u64,
    pub request: WindowsDataPlaneRequest,
    pub phase: WindowsDataPlaneSessionPhase,
    pub bytes_received: u64,
    pub first_payload_observed: bool,
    pub cancel_requested: bool,
    pub cancel_deadline_at_ms: Option<u64>,
    pub resource_owned: bool,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsDataPlaneState {
    pub worker_phase: WindowsDataPlaneWorkerPhase,
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    pub shutdown_deadline_at_ms: Option<u64>,
    pub startup_failure: String,
    pub next_session_id: u64,
    pub sessions: BTreeMap<String, WindowsDataPlaneSessionState>,
}

impl WindowsDataPlaneState {
    pub fn new(started_at_ms: u64) -> Self {
        Self {
            worker_phase: WindowsDataPlaneWorkerPhase::Starting,
            started_at_ms,
            updated_at_ms: started_at_ms,
            shutdown_deadline_at_ms: None,
            startup_failure: String::new(),
            next_session_id: 1,
            sessions: BTreeMap::new(),
        }
    }

    pub fn active_session_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|session| !session.phase.is_terminal())
            .count()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WindowsDataPlaneEvent {
    WorkerReady {
        now_ms: u64,
    },
    WorkerStartupFailed {
        now_ms: u64,
        reason: String,
    },
    RequestAccepted {
        now_ms: u64,
        request: WindowsDataPlaneRequest,
    },
    BackendConnected {
        now_ms: u64,
        request_id: String,
        session_id: u64,
    },
    PayloadReceived {
        now_ms: u64,
        request_id: String,
        session_id: u64,
        bytes: u64,
    },
    ConnectFailed {
        now_ms: u64,
        request_id: String,
        session_id: u64,
        reason: String,
    },
    BackendReset {
        now_ms: u64,
        request_id: String,
        session_id: u64,
        reason: String,
    },
    BackendClosed {
        now_ms: u64,
        request_id: String,
        session_id: u64,
    },
    FirstPayloadDeadline {
        now_ms: u64,
        request_id: String,
        session_id: u64,
    },
    CancelRequested {
        now_ms: u64,
        request_id: String,
        session_id: u64,
    },
    SessionCancelled {
        now_ms: u64,
        request_id: String,
        session_id: u64,
    },
    CancellationDeadline {
        now_ms: u64,
        request_id: String,
        session_id: u64,
    },
    ShutdownRequested {
        now_ms: u64,
    },
    ShutdownDeadline {
        now_ms: u64,
    },
}

impl WindowsDataPlaneEvent {
    pub const fn now_ms(&self) -> u64 {
        match self {
            Self::WorkerReady { now_ms }
            | Self::WorkerStartupFailed { now_ms, .. }
            | Self::RequestAccepted { now_ms, .. }
            | Self::BackendConnected { now_ms, .. }
            | Self::PayloadReceived { now_ms, .. }
            | Self::ConnectFailed { now_ms, .. }
            | Self::BackendReset { now_ms, .. }
            | Self::BackendClosed { now_ms, .. }
            | Self::FirstPayloadDeadline { now_ms, .. }
            | Self::CancelRequested { now_ms, .. }
            | Self::SessionCancelled { now_ms, .. }
            | Self::CancellationDeadline { now_ms, .. }
            | Self::ShutdownRequested { now_ms }
            | Self::ShutdownDeadline { now_ms } => *now_ms,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WindowsDataPlaneCommand {
    ReportWorkerReady,
    ReportWorkerStartupFailed {
        reason: String,
    },
    StartSession {
        session_id: u64,
        request: WindowsDataPlaneRequest,
    },
    ScheduleFirstPayloadDeadline {
        request_id: String,
        session_id: u64,
        at_ms: u64,
    },
    MarkFirstPayload {
        request_id: String,
        session_id: u64,
        bytes_received: u64,
    },
    CancelSession {
        request_id: String,
        session_id: u64,
    },
    ScheduleCancellationDeadline {
        request_id: String,
        session_id: u64,
        at_ms: u64,
    },
    CloseSession {
        request_id: String,
        session_id: u64,
    },
    RecordOutcome {
        request_id: String,
        session_id: u64,
        outcome: ConnectionOutcome,
    },
    RejectRequest {
        request_id: String,
        reason: String,
    },
    ScheduleShutdownDeadline {
        at_ms: u64,
    },
    ReportWorkerStopped,
}

impl WindowsDataPlaneCommand {
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::ReportWorkerReady => "report_worker_ready",
            Self::ReportWorkerStartupFailed { .. } => "report_worker_startup_failed",
            Self::StartSession { .. } => "start_session",
            Self::ScheduleFirstPayloadDeadline { .. } => "schedule_first_payload_deadline",
            Self::MarkFirstPayload { .. } => "mark_first_payload",
            Self::CancelSession { .. } => "cancel_session",
            Self::ScheduleCancellationDeadline { .. } => "schedule_cancellation_deadline",
            Self::CloseSession { .. } => "close_session",
            Self::RecordOutcome { .. } => "record_outcome",
            Self::RejectRequest { .. } => "reject_request",
            Self::ScheduleShutdownDeadline { .. } => "schedule_shutdown_deadline",
            Self::ReportWorkerStopped => "report_worker_stopped",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct WindowsDataPlaneTransition {
    pub state: WindowsDataPlaneState,
    pub commands: Vec<WindowsDataPlaneCommand>,
}

fn bounded_reason(reason: &str) -> String {
    reason.chars().take(MAX_REASON_CHARS).collect()
}

fn session_outcome(
    session: &WindowsDataPlaneSessionState,
    now_ms: u64,
    ok: bool,
    failure_phase: &str,
    reason: &str,
) -> ConnectionOutcome {
    ConnectionOutcome {
        host: session.request.policy.host.clone(),
        service_group: session.request.policy.service_group,
        route_class: session.request.policy.route_class,
        backend: session.request.backend.as_str().to_owned(),
        failure_phase: failure_phase.to_owned(),
        bytes_received: session.bytes_received,
        duration: now_ms.saturating_sub(session.request.started_at_ms) as f64 / 1000.0,
        reason: bounded_reason(reason),
        ok,
    }
}

fn close_with_outcome(
    session: &mut WindowsDataPlaneSessionState,
    request_id: &str,
    now_ms: u64,
    phase: WindowsDataPlaneSessionPhase,
    ok: bool,
    failure_phase: &str,
    reason: &str,
) -> Vec<WindowsDataPlaneCommand> {
    session.phase = phase;
    session.resource_owned = false;
    session.updated_at_ms = now_ms;
    vec![
        WindowsDataPlaneCommand::CloseSession {
            request_id: request_id.to_owned(),
            session_id: session.session_id,
        },
        WindowsDataPlaneCommand::RecordOutcome {
            request_id: request_id.to_owned(),
            session_id: session.session_id,
            outcome: session_outcome(session, now_ms, ok, failure_phase, reason),
        },
    ]
}

fn close_cancelled(
    session: &mut WindowsDataPlaneSessionState,
    request_id: &str,
    now_ms: u64,
) -> Vec<WindowsDataPlaneCommand> {
    session.phase = WindowsDataPlaneSessionPhase::Cancelled;
    session.resource_owned = false;
    session.updated_at_ms = now_ms;
    vec![WindowsDataPlaneCommand::CloseSession {
        request_id: request_id.to_owned(),
        session_id: session.session_id,
    }]
}

fn prune_terminal_sessions(state: &mut WindowsDataPlaneState, retained_limit: usize) {
    let terminal_count = state
        .sessions
        .values()
        .filter(|session| session.phase.is_terminal())
        .count();
    let remove_count = terminal_count.saturating_sub(retained_limit);
    if remove_count == 0 {
        return;
    }

    let mut terminal_sessions: Vec<_> = state
        .sessions
        .iter()
        .filter(|(_, session)| session.phase.is_terminal())
        .map(|(request_id, session)| {
            (
                session.updated_at_ms,
                session.session_id,
                request_id.clone(),
            )
        })
        .collect();
    terminal_sessions.sort_unstable();
    for (_, _, request_id) in terminal_sessions.into_iter().take(remove_count) {
        state.sessions.remove(&request_id);
    }
}

fn stop_if_drained(state: &mut WindowsDataPlaneState, commands: &mut Vec<WindowsDataPlaneCommand>) {
    if state.worker_phase == WindowsDataPlaneWorkerPhase::Draining
        && state.active_session_count() == 0
    {
        state.worker_phase = WindowsDataPlaneWorkerPhase::Stopped;
        state.shutdown_deadline_at_ms = None;
        commands.push(WindowsDataPlaneCommand::ReportWorkerStopped);
    }
}

fn reject_request(request_id: &str, reason: &str) -> WindowsDataPlaneCommand {
    WindowsDataPlaneCommand::RejectRequest {
        request_id: request_id.to_owned(),
        reason: reason.to_owned(),
    }
}

pub fn reduce_windows_data_plane(
    state: &WindowsDataPlaneState,
    event: &WindowsDataPlaneEvent,
    config: &WindowsDataPlaneConfig,
) -> Result<WindowsDataPlaneTransition, WindowsDataPlaneError> {
    config.validate()?;
    let now_ms = event.now_ms();
    if now_ms < state.updated_at_ms {
        return Err(WindowsDataPlaneError::NonMonotonicEvent);
    }

    let mut next = state.clone();
    next.updated_at_ms = now_ms;
    let mut commands = Vec::new();

    match event {
        WindowsDataPlaneEvent::WorkerReady { .. } => {
            if next.worker_phase == WindowsDataPlaneWorkerPhase::Starting {
                next.worker_phase = WindowsDataPlaneWorkerPhase::Ready;
                commands.push(WindowsDataPlaneCommand::ReportWorkerReady);
            }
        }
        WindowsDataPlaneEvent::WorkerStartupFailed { reason, .. } => {
            if next.worker_phase == WindowsDataPlaneWorkerPhase::Starting {
                next.worker_phase = WindowsDataPlaneWorkerPhase::Failed;
                next.startup_failure = bounded_reason(reason);
                commands.push(WindowsDataPlaneCommand::ReportWorkerStartupFailed {
                    reason: next.startup_failure.clone(),
                });
            }
        }
        WindowsDataPlaneEvent::RequestAccepted { request, .. } => {
            let request_error = validate_windows_data_plane_request(request)
                .err()
                .or_else(|| {
                    (request.started_at_ms != now_ms)
                        .then_some(WindowsDataPlaneRequestErrorCode::InvalidDeadline)
                });
            if let Some(code) = request_error {
                commands.push(reject_request(
                    &request.request_id,
                    &format!("invalid_request:{}", code.as_str()),
                ));
            } else if next.worker_phase != WindowsDataPlaneWorkerPhase::Ready {
                commands.push(reject_request(&request.request_id, "worker_not_ready"));
            } else if next.sessions.contains_key(&request.request_id) {
                commands.push(reject_request(&request.request_id, "duplicate_request_id"));
            } else if next.active_session_count() >= config.max_active_sessions {
                commands.push(reject_request(&request.request_id, "session_limit"));
            } else {
                let session_id = next.next_session_id;
                next.next_session_id = session_id
                    .checked_add(1)
                    .ok_or(WindowsDataPlaneError::SessionIdOverflow)?;
                next.sessions.insert(
                    request.request_id.clone(),
                    WindowsDataPlaneSessionState {
                        session_id,
                        request: request.clone(),
                        phase: WindowsDataPlaneSessionPhase::Opening,
                        bytes_received: 0,
                        first_payload_observed: false,
                        cancel_requested: false,
                        cancel_deadline_at_ms: None,
                        resource_owned: true,
                        updated_at_ms: now_ms,
                    },
                );
                commands.push(WindowsDataPlaneCommand::StartSession {
                    session_id,
                    request: request.clone(),
                });
                commands.push(WindowsDataPlaneCommand::ScheduleFirstPayloadDeadline {
                    request_id: request.request_id.clone(),
                    session_id,
                    at_ms: request.first_payload_deadline_at_ms,
                });
            }
        }
        WindowsDataPlaneEvent::ShutdownRequested { .. } => {
            if matches!(
                next.worker_phase,
                WindowsDataPlaneWorkerPhase::Stopped | WindowsDataPlaneWorkerPhase::Failed
            ) {
                return Ok(WindowsDataPlaneTransition {
                    state: next,
                    commands,
                });
            }
            if next.worker_phase != WindowsDataPlaneWorkerPhase::Draining {
                next.worker_phase = WindowsDataPlaneWorkerPhase::Draining;
                let deadline = now_ms
                    .checked_add(config.shutdown_timeout_ms)
                    .ok_or(WindowsDataPlaneError::TimeOverflow)?;
                next.shutdown_deadline_at_ms = Some(deadline);
                for (request_id, session) in &mut next.sessions {
                    if !session.phase.is_terminal() && !session.cancel_requested {
                        session.phase = WindowsDataPlaneSessionPhase::Cancelling;
                        session.cancel_requested = true;
                        session.updated_at_ms = now_ms;
                        commands.push(WindowsDataPlaneCommand::CancelSession {
                            request_id: request_id.clone(),
                            session_id: session.session_id,
                        });
                    }
                }
                if next.active_session_count() == 0 {
                    stop_if_drained(&mut next, &mut commands);
                } else {
                    commands.push(WindowsDataPlaneCommand::ScheduleShutdownDeadline {
                        at_ms: deadline,
                    });
                }
            }
        }
        WindowsDataPlaneEvent::ShutdownDeadline { .. } => {
            if next.worker_phase != WindowsDataPlaneWorkerPhase::Draining {
                return Ok(WindowsDataPlaneTransition {
                    state: next,
                    commands,
                });
            }
            let deadline = next
                .shutdown_deadline_at_ms
                .ok_or(WindowsDataPlaneError::InvalidWorkerTransition)?;
            if now_ms < deadline {
                return Err(WindowsDataPlaneError::DeadlineBeforeDue);
            }
            for (request_id, session) in &mut next.sessions {
                if session.phase.is_terminal() {
                    continue;
                }
                if !session.cancel_requested {
                    commands.push(WindowsDataPlaneCommand::CancelSession {
                        request_id: request_id.clone(),
                        session_id: session.session_id,
                    });
                }
                commands.extend(close_cancelled(session, request_id, now_ms));
            }
            stop_if_drained(&mut next, &mut commands);
        }
        _ => {
            let (request_id, session_id) = event
                .session_key()
                .ok_or(WindowsDataPlaneError::InvalidWorkerTransition)?;
            let Some(session) = next.sessions.get_mut(request_id) else {
                return Ok(WindowsDataPlaneTransition {
                    state: next,
                    commands,
                });
            };
            if session.session_id != session_id {
                return Ok(WindowsDataPlaneTransition {
                    state: next,
                    commands,
                });
            }
            if session.phase.is_terminal() {
                return Ok(WindowsDataPlaneTransition {
                    state: next,
                    commands,
                });
            }

            match event {
                WindowsDataPlaneEvent::BackendConnected { .. } => {
                    if session.phase == WindowsDataPlaneSessionPhase::Cancelling {
                        // Cancellation owns the terminal result. A connection
                        // completion already in flight cannot resurrect it.
                    } else if session.phase != WindowsDataPlaneSessionPhase::Opening {
                        return Err(WindowsDataPlaneError::InvalidSessionTransition);
                    } else {
                        session.phase = WindowsDataPlaneSessionPhase::AwaitingFirstPayload;
                        session.updated_at_ms = now_ms;
                    }
                }
                WindowsDataPlaneEvent::PayloadReceived { bytes, .. } => {
                    if session.phase == WindowsDataPlaneSessionPhase::Cancelling {
                        // The native adapter must not forward bytes after
                        // cancellation. The reducer keeps waiting for the
                        // owned cancel acknowledgement or bounded deadline.
                    } else if *bytes == 0 {
                        return Err(WindowsDataPlaneError::ZeroPayload);
                    } else if !matches!(
                        session.phase,
                        WindowsDataPlaneSessionPhase::Opening
                            | WindowsDataPlaneSessionPhase::AwaitingFirstPayload
                            | WindowsDataPlaneSessionPhase::Relaying
                    ) {
                        return Err(WindowsDataPlaneError::InvalidSessionTransition);
                    } else {
                        session.bytes_received = session
                            .bytes_received
                            .checked_add(*bytes)
                            .ok_or(WindowsDataPlaneError::ByteCountOverflow)?;
                        if !session.first_payload_observed {
                            session.first_payload_observed = true;
                            commands.push(WindowsDataPlaneCommand::MarkFirstPayload {
                                request_id: request_id.to_owned(),
                                session_id: session.session_id,
                                bytes_received: session.bytes_received,
                            });
                        }
                        session.phase = WindowsDataPlaneSessionPhase::Relaying;
                        session.updated_at_ms = now_ms;
                    }
                }
                WindowsDataPlaneEvent::ConnectFailed { reason, .. } => {
                    if session.phase == WindowsDataPlaneSessionPhase::Cancelling {
                        commands.extend(close_cancelled(session, request_id, now_ms));
                    } else if session.phase == WindowsDataPlaneSessionPhase::Opening {
                        commands.extend(close_with_outcome(
                            session,
                            request_id,
                            now_ms,
                            WindowsDataPlaneSessionPhase::Failed,
                            false,
                            "connect",
                            reason,
                        ));
                    } else {
                        return Err(WindowsDataPlaneError::InvalidSessionTransition);
                    }
                }
                WindowsDataPlaneEvent::BackendReset { reason, .. } => {
                    if session.phase == WindowsDataPlaneSessionPhase::Cancelling {
                        commands.extend(close_cancelled(session, request_id, now_ms));
                    } else {
                        let failure_phase = match session.phase {
                            WindowsDataPlaneSessionPhase::Opening => "connect",
                            WindowsDataPlaneSessionPhase::AwaitingFirstPayload => "first_payload",
                            WindowsDataPlaneSessionPhase::Relaying => "stream",
                            _ => return Err(WindowsDataPlaneError::InvalidSessionTransition),
                        };
                        commands.extend(close_with_outcome(
                            session,
                            request_id,
                            now_ms,
                            WindowsDataPlaneSessionPhase::Failed,
                            false,
                            failure_phase,
                            reason,
                        ));
                    }
                }
                WindowsDataPlaneEvent::BackendClosed { .. } => {
                    if session.phase == WindowsDataPlaneSessionPhase::Cancelling {
                        commands.extend(close_cancelled(session, request_id, now_ms));
                    } else if matches!(
                        session.phase,
                        WindowsDataPlaneSessionPhase::Opening
                            | WindowsDataPlaneSessionPhase::AwaitingFirstPayload
                    ) {
                        commands.extend(close_with_outcome(
                            session,
                            request_id,
                            now_ms,
                            WindowsDataPlaneSessionPhase::Failed,
                            false,
                            "first_payload",
                            "remote closed without response",
                        ));
                    } else if session.phase == WindowsDataPlaneSessionPhase::Relaying {
                        commands.extend(close_with_outcome(
                            session,
                            request_id,
                            now_ms,
                            WindowsDataPlaneSessionPhase::Succeeded,
                            true,
                            "",
                            "",
                        ));
                    } else {
                        return Err(WindowsDataPlaneError::InvalidSessionTransition);
                    }
                }
                WindowsDataPlaneEvent::FirstPayloadDeadline { .. } => {
                    if now_ms < session.request.first_payload_deadline_at_ms {
                        return Err(WindowsDataPlaneError::DeadlineBeforeDue);
                    }
                    if session.phase != WindowsDataPlaneSessionPhase::Cancelling
                        && matches!(
                            session.phase,
                            WindowsDataPlaneSessionPhase::Opening
                                | WindowsDataPlaneSessionPhase::AwaitingFirstPayload
                        )
                    {
                        commands.push(WindowsDataPlaneCommand::CancelSession {
                            request_id: request_id.to_owned(),
                            session_id: session.session_id,
                        });
                        session.cancel_requested = true;
                        commands.extend(close_with_outcome(
                            session,
                            request_id,
                            now_ms,
                            WindowsDataPlaneSessionPhase::Failed,
                            false,
                            "first_payload",
                            "first payload deadline exceeded",
                        ));
                    }
                }
                WindowsDataPlaneEvent::CancelRequested { .. } => {
                    if session.phase != WindowsDataPlaneSessionPhase::Cancelling {
                        let deadline = now_ms
                            .checked_add(config.cancel_timeout_ms)
                            .ok_or(WindowsDataPlaneError::TimeOverflow)?;
                        session.phase = WindowsDataPlaneSessionPhase::Cancelling;
                        session.cancel_requested = true;
                        session.cancel_deadline_at_ms = Some(deadline);
                        session.updated_at_ms = now_ms;
                        commands.push(WindowsDataPlaneCommand::CancelSession {
                            request_id: request_id.to_owned(),
                            session_id: session.session_id,
                        });
                        commands.push(WindowsDataPlaneCommand::ScheduleCancellationDeadline {
                            request_id: request_id.to_owned(),
                            session_id: session.session_id,
                            at_ms: deadline,
                        });
                    }
                }
                WindowsDataPlaneEvent::SessionCancelled { .. } => {
                    if session.phase != WindowsDataPlaneSessionPhase::Cancelling {
                        return Err(WindowsDataPlaneError::InvalidSessionTransition);
                    }
                    commands.extend(close_cancelled(session, request_id, now_ms));
                }
                WindowsDataPlaneEvent::CancellationDeadline { .. } => {
                    if session.phase != WindowsDataPlaneSessionPhase::Cancelling {
                        return Ok(WindowsDataPlaneTransition {
                            state: next,
                            commands,
                        });
                    }
                    let deadline = session
                        .cancel_deadline_at_ms
                        .ok_or(WindowsDataPlaneError::InvalidSessionTransition)?;
                    if now_ms < deadline {
                        return Err(WindowsDataPlaneError::DeadlineBeforeDue);
                    }
                    commands.extend(close_cancelled(session, request_id, now_ms));
                }
                _ => return Err(WindowsDataPlaneError::InvalidSessionTransition),
            }
            stop_if_drained(&mut next, &mut commands);
        }
    }

    prune_terminal_sessions(&mut next, config.max_retained_terminal_sessions);

    Ok(WindowsDataPlaneTransition {
        state: next,
        commands,
    })
}

impl WindowsDataPlaneEvent {
    fn session_key(&self) -> Option<(&str, u64)> {
        match self {
            Self::BackendConnected {
                request_id,
                session_id,
                ..
            }
            | Self::PayloadReceived {
                request_id,
                session_id,
                ..
            }
            | Self::ConnectFailed {
                request_id,
                session_id,
                ..
            }
            | Self::BackendReset {
                request_id,
                session_id,
                ..
            }
            | Self::BackendClosed {
                request_id,
                session_id,
                ..
            }
            | Self::FirstPayloadDeadline {
                request_id,
                session_id,
                ..
            }
            | Self::CancelRequested {
                request_id,
                session_id,
                ..
            }
            | Self::SessionCancelled {
                request_id,
                session_id,
                ..
            }
            | Self::CancellationDeadline {
                request_id,
                session_id,
                ..
            } => Some((request_id, *session_id)),
            _ => None,
        }
    }
}

pub trait WindowsDataPlaneEffects {
    type Error: fmt::Display;

    fn execute(&mut self, command: &WindowsDataPlaneCommand) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, Default)]
pub struct RecordingWindowsDataPlaneEffects {
    commands: Vec<WindowsDataPlaneCommand>,
    open_resources: BTreeMap<u64, String>,
    closed_resources: BTreeMap<u64, String>,
    first_payloads: BTreeSet<u64>,
    outcome_session_ids: BTreeSet<u64>,
    outcomes: Vec<ConnectionOutcome>,
}

impl RecordingWindowsDataPlaneEffects {
    pub fn commands(&self) -> &[WindowsDataPlaneCommand] {
        &self.commands
    }

    pub fn open_resources(&self) -> &BTreeMap<u64, String> {
        &self.open_resources
    }

    pub fn outcomes(&self) -> &[ConnectionOutcome] {
        &self.outcomes
    }
}

impl WindowsDataPlaneEffects for RecordingWindowsDataPlaneEffects {
    type Error = WindowsDataPlaneEffectError;

    fn execute(&mut self, command: &WindowsDataPlaneCommand) -> Result<(), Self::Error> {
        match command {
            WindowsDataPlaneCommand::StartSession {
                session_id,
                request,
            } => {
                if self.open_resources.contains_key(session_id)
                    || self.closed_resources.contains_key(session_id)
                {
                    return Err(WindowsDataPlaneEffectError::DuplicateResource(format!(
                        "{}#{session_id}",
                        request.request_id
                    )));
                }
                self.open_resources
                    .insert(*session_id, request.request_id.clone());
            }
            WindowsDataPlaneCommand::CancelSession {
                request_id,
                session_id,
            } => {
                self.require_resource(*session_id, request_id)?;
            }
            WindowsDataPlaneCommand::MarkFirstPayload {
                request_id,
                session_id,
                ..
            } => {
                self.require_resource(*session_id, request_id)?;
                if !self.first_payloads.insert(*session_id) {
                    return Err(WindowsDataPlaneEffectError::DuplicateFirstPayload(format!(
                        "{request_id}#{session_id}"
                    )));
                }
            }
            WindowsDataPlaneCommand::CloseSession {
                request_id,
                session_id,
            } => {
                self.require_resource(*session_id, request_id)?;
                let Some(closed_request_id) = self.open_resources.remove(session_id) else {
                    return Err(WindowsDataPlaneEffectError::UnknownResource(format!(
                        "{request_id}#{session_id}"
                    )));
                };
                self.closed_resources.insert(*session_id, closed_request_id);
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
                self.require_resource(*session_id, request_id)?;
            }
            WindowsDataPlaneCommand::RecordOutcome {
                request_id,
                session_id,
                outcome,
            } => {
                if self.open_resources.contains_key(session_id) {
                    return Err(WindowsDataPlaneEffectError::OutcomeBeforeClose(format!(
                        "{request_id}#{session_id}"
                    )));
                }
                if self.closed_resources.get(session_id).map(String::as_str) != Some(request_id) {
                    return Err(WindowsDataPlaneEffectError::OutcomeWithoutClose(format!(
                        "{request_id}#{session_id}"
                    )));
                }
                if !self.outcome_session_ids.insert(*session_id) {
                    return Err(WindowsDataPlaneEffectError::DuplicateOutcome(format!(
                        "{request_id}#{session_id}"
                    )));
                }
                self.outcomes.push(outcome.clone());
            }
            WindowsDataPlaneCommand::ReportWorkerStopped if !self.open_resources.is_empty() => {
                return Err(WindowsDataPlaneEffectError::WorkerStoppedWithResources);
            }
            _ => {}
        }
        self.commands.push(command.clone());
        Ok(())
    }
}

impl RecordingWindowsDataPlaneEffects {
    fn require_resource(
        &self,
        session_id: u64,
        request_id: &str,
    ) -> Result<(), WindowsDataPlaneEffectError> {
        if self.open_resources.get(&session_id).map(String::as_str) == Some(request_id) {
            Ok(())
        } else {
            Err(WindowsDataPlaneEffectError::UnknownResource(format!(
                "{request_id}#{session_id}"
            )))
        }
    }
}

pub fn execute_windows_data_plane_transition<E: WindowsDataPlaneEffects>(
    transition: &WindowsDataPlaneTransition,
    effects: &mut E,
) -> Result<(), WindowsDataPlaneEffectExecutionError> {
    for command in &transition.commands {
        effects
            .execute(command)
            .map_err(|error| WindowsDataPlaneEffectExecutionError {
                command: command.kind(),
                message: error.to_string(),
            })?;
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsDataPlaneEffectError {
    DuplicateResource(String),
    DuplicateFirstPayload(String),
    DuplicateOutcome(String),
    UnknownResource(String),
    OutcomeBeforeClose(String),
    OutcomeWithoutClose(String),
    WorkerStoppedWithResources,
}

impl fmt::Display for WindowsDataPlaneEffectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateResource(request_id) => {
                write!(formatter, "resource {request_id} is already owned")
            }
            Self::DuplicateFirstPayload(request_id) => {
                write!(
                    formatter,
                    "first payload for {request_id} was already recorded"
                )
            }
            Self::DuplicateOutcome(request_id) => {
                write!(formatter, "outcome for {request_id} was already recorded")
            }
            Self::UnknownResource(request_id) => {
                write!(formatter, "resource {request_id} is not owned")
            }
            Self::OutcomeBeforeClose(request_id) => {
                write!(
                    formatter,
                    "outcome for {request_id} preceded resource close"
                )
            }
            Self::OutcomeWithoutClose(request_id) => {
                write!(formatter, "outcome for {request_id} has no closed resource")
            }
            Self::WorkerStoppedWithResources => {
                formatter.write_str("worker stopped while session resources remained owned")
            }
        }
    }
}

impl std::error::Error for WindowsDataPlaneEffectError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsDataPlaneEffectExecutionError {
    pub command: &'static str,
    pub message: String,
}

impl fmt::Display for WindowsDataPlaneEffectExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} effect failed: {}",
            self.command, self.message
        )
    }
}

impl std::error::Error for WindowsDataPlaneEffectExecutionError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsDataPlaneError {
    InvalidConfig(&'static str),
    NonMonotonicEvent,
    InvalidWorkerTransition,
    UnknownSession(String),
    InvalidSessionTransition,
    DeadlineBeforeDue,
    ZeroPayload,
    ByteCountOverflow,
    SessionIdOverflow,
    TimeOverflow,
}

impl fmt::Display for WindowsDataPlaneError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => formatter.write_str(message),
            Self::NonMonotonicEvent => formatter.write_str("data-plane events must be monotonic"),
            Self::InvalidWorkerTransition => formatter.write_str("invalid worker transition"),
            Self::UnknownSession(request_id) => write!(formatter, "unknown session {request_id}"),
            Self::InvalidSessionTransition => formatter.write_str("invalid session transition"),
            Self::DeadlineBeforeDue => formatter.write_str("deadline event arrived before due"),
            Self::ZeroPayload => formatter.write_str("payload bytes must be positive"),
            Self::ByteCountOverflow => formatter.write_str("payload byte count overflow"),
            Self::SessionIdOverflow => formatter.write_str("data-plane session id overflow"),
            Self::TimeOverflow => formatter.write_str("data-plane deadline overflow"),
        }
    }
}

impl std::error::Error for WindowsDataPlaneError {}

#[cfg(test)]
mod tests {
    use super::*;
    use slipstream_core::routing_policy::ServiceGroup;

    fn request(
        request_id: &str,
        service_group: ServiceGroup,
        route_class: RouteClass,
        backend: WindowsDataPlaneBackend,
    ) -> WindowsDataPlaneRequest {
        WindowsDataPlaneRequest {
            request_id: request_id.to_owned(),
            policy: RoutePolicyResult {
                host: "example.com".to_owned(),
                route_class,
                service_group,
                strategy_set: StrategySet::General,
            },
            backend,
            started_at_ms: 1,
            first_payload_deadline_at_ms: 100,
        }
    }

    #[test]
    fn protected_groups_reject_every_geph_edge() {
        for service_group in [ServiceGroup::Discord, ServiceGroup::YoutubeVideo] {
            let request = request(
                "protected",
                service_group,
                RouteClass::GeoExit,
                WindowsDataPlaneBackend::Geph,
            );
            assert_eq!(
                validate_windows_data_plane_request(&request),
                Err(WindowsDataPlaneRequestErrorCode::ProtectedRouteMismatch)
            );
        }
    }

    #[test]
    fn recording_effects_require_close_before_outcome() {
        let mut effects = RecordingWindowsDataPlaneEffects::default();
        let owned_request = request(
            "owned",
            ServiceGroup::Generic,
            RouteClass::Unknown,
            WindowsDataPlaneBackend::LocalEngine,
        );
        effects
            .execute(&WindowsDataPlaneCommand::StartSession {
                session_id: 1,
                request: owned_request.clone(),
            })
            .unwrap();
        let replacement = request(
            "replacement",
            ServiceGroup::Generic,
            RouteClass::Unknown,
            WindowsDataPlaneBackend::LocalEngine,
        );
        assert!(matches!(
            effects.execute(&WindowsDataPlaneCommand::StartSession {
                session_id: 1,
                request: replacement,
            }),
            Err(WindowsDataPlaneEffectError::DuplicateResource(_))
        ));
        assert_eq!(
            effects.open_resources().get(&1).map(String::as_str),
            Some("owned")
        );
        let outcome = ConnectionOutcome {
            host: owned_request.policy.host,
            service_group: owned_request.policy.service_group,
            route_class: owned_request.policy.route_class,
            backend: owned_request.backend.as_str().to_owned(),
            failure_phase: "connect".to_owned(),
            bytes_received: 0,
            duration: 0.001,
            reason: "reset".to_owned(),
            ok: false,
        };
        assert!(matches!(
            effects.execute(&WindowsDataPlaneCommand::RecordOutcome {
                request_id: "owned".to_owned(),
                session_id: 1,
                outcome,
            }),
            Err(WindowsDataPlaneEffectError::OutcomeBeforeClose(_))
        ));
    }
}
