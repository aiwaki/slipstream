//! Version 1 of the pure WFP runtime lifecycle contract.
//!
//! This reducer orders future native effects without invoking WFP, opening a
//! socket, loading a driver, or composing interception into the production
//! service host. The dynamic session is the first stop fail-safe. Kernel
//! callouts remain registered until exact owned-filter absence is proven.

use crate::direct_connector::WindowsDirectConnectorEndpoint;
use crate::wfp_capture::{
    validate_windows_wfp_capture_identity, WindowsWfpCaptureErrorCode, WindowsWfpCaptureIdentity,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const WINDOWS_WFP_RUNTIME_CONTRACT_VERSION: u32 = 1;
pub const MAX_WINDOWS_WFP_RUNTIME_CONNECTIONS: usize = 65_535;
pub const MAX_WINDOWS_WFP_DRAIN_TIMEOUT_MS: u64 = 30_000;
pub const MAX_WINDOWS_WFP_FILTER_RECHECK_MS: u64 = 10_000;
const MAX_REASON_CHARS: usize = 200;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsWfpRuntimeConfig {
    pub max_active_connections: usize,
    pub drain_timeout_ms: u64,
    pub filter_absence_recheck_ms: u64,
}

impl WindowsWfpRuntimeConfig {
    pub fn validate(&self) -> Result<(), WindowsWfpRuntimeError> {
        if self.max_active_connections == 0
            || self.max_active_connections > MAX_WINDOWS_WFP_RUNTIME_CONNECTIONS
        {
            return Err(WindowsWfpRuntimeError::InvalidConfig(
                "max_active_connections",
            ));
        }
        if self.drain_timeout_ms == 0 || self.drain_timeout_ms > MAX_WINDOWS_WFP_DRAIN_TIMEOUT_MS {
            return Err(WindowsWfpRuntimeError::InvalidConfig("drain_timeout_ms"));
        }
        if self.filter_absence_recheck_ms == 0
            || self.filter_absence_recheck_ms > MAX_WINDOWS_WFP_FILTER_RECHECK_MS
        {
            return Err(WindowsWfpRuntimeError::InvalidConfig(
                "filter_absence_recheck_ms",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsWfpRuntimeBinding {
    pub service_generation: u64,
    pub capture_instance_id: String,
    pub runtime_generation: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsWfpRuntimePhase {
    Stopped,
    RegisteringKernelCallouts,
    StartingListeners,
    ActivatingDynamicSession,
    Ready,
    ClosingDynamicSession,
    ProvingFilterAbsence,
    StoppingListeners,
    Draining,
    UnregisteringKernelCallouts,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsWfpShutdownCause {
    Requested,
    StartupFailure,
    RuntimeFailure,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsWfpFilterInspection {
    pub binding: WindowsWfpRuntimeBinding,
    pub session_generation: Option<u64>,
    pub ipv4_present: bool,
    pub ipv6_present: bool,
}

impl WindowsWfpFilterInspection {
    pub const fn filters_absent(&self) -> bool {
        !self.ipv4_present && !self.ipv6_present
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsWfpRuntimeState {
    pub phase: WindowsWfpRuntimePhase,
    pub identity: WindowsWfpCaptureIdentity,
    pub updated_at_ms: u64,
    pub runtime_generation: u64,
    pub next_runtime_generation: u64,
    pub kernel_callouts_registered: bool,
    pub listeners_ready: bool,
    pub active_session_generation: Option<u64>,
    pub last_session_generation: Option<u64>,
    pub next_session_generation: u64,
    pub filters_absent: bool,
    pub filter_inspection_pending: bool,
    pub filter_recheck_at_ms: Option<u64>,
    pub active_connections: BTreeSet<u64>,
    pub drain_deadline_at_ms: Option<u64>,
    pub stop_requested: bool,
    pub shutdown_cause: Option<WindowsWfpShutdownCause>,
    pub terminal_reason: String,
}

impl WindowsWfpRuntimeState {
    pub fn new(
        now_ms: u64,
        identity: WindowsWfpCaptureIdentity,
    ) -> Result<Self, WindowsWfpRuntimeError> {
        validate_windows_wfp_capture_identity(&identity)
            .map_err(WindowsWfpRuntimeError::InvalidCaptureIdentity)?;
        let state = Self {
            phase: WindowsWfpRuntimePhase::Stopped,
            identity,
            updated_at_ms: now_ms,
            runtime_generation: 0,
            next_runtime_generation: 1,
            kernel_callouts_registered: false,
            listeners_ready: false,
            active_session_generation: None,
            last_session_generation: None,
            next_session_generation: 1,
            filters_absent: true,
            filter_inspection_pending: false,
            filter_recheck_at_ms: None,
            active_connections: BTreeSet::new(),
            drain_deadline_at_ms: None,
            stop_requested: false,
            shutdown_cause: None,
            terminal_reason: String::new(),
        };
        validate_state(&state)?;
        Ok(state)
    }

    pub fn binding(&self) -> WindowsWfpRuntimeBinding {
        WindowsWfpRuntimeBinding {
            service_generation: self.identity.service.generation,
            capture_instance_id: self.identity.capture_instance_id.clone(),
            runtime_generation: self.runtime_generation,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WindowsWfpRuntimeEvent {
    StartRequested {
        now_ms: u64,
    },
    KernelCalloutsRegistered {
        now_ms: u64,
        binding: WindowsWfpRuntimeBinding,
    },
    KernelCalloutRegistrationFailed {
        now_ms: u64,
        binding: WindowsWfpRuntimeBinding,
        reason: String,
    },
    OwnedListenersReady {
        now_ms: u64,
        binding: WindowsWfpRuntimeBinding,
        listeners: Vec<WindowsDirectConnectorEndpoint>,
    },
    OwnedListenerStartupFailed {
        now_ms: u64,
        binding: WindowsWfpRuntimeBinding,
        reason: String,
    },
    DynamicSessionActivated {
        now_ms: u64,
        binding: WindowsWfpRuntimeBinding,
        session_generation: u64,
    },
    DynamicSessionActivationFailed {
        now_ms: u64,
        binding: WindowsWfpRuntimeBinding,
        session_generation: u64,
        reason: String,
    },
    ConnectionAccepted {
        now_ms: u64,
        binding: WindowsWfpRuntimeBinding,
        connection_id: u64,
    },
    ConnectionReleased {
        now_ms: u64,
        binding: WindowsWfpRuntimeBinding,
        connection_id: u64,
    },
    StopRequested {
        now_ms: u64,
    },
    RuntimeFault {
        now_ms: u64,
        binding: WindowsWfpRuntimeBinding,
        reason: String,
    },
    DynamicSessionClosed {
        now_ms: u64,
        binding: WindowsWfpRuntimeBinding,
        session_generation: u64,
    },
    OwnedFiltersInspected {
        now_ms: u64,
        inspection: WindowsWfpFilterInspection,
    },
    FilterAbsenceRecheckDue {
        now_ms: u64,
        binding: WindowsWfpRuntimeBinding,
        session_generation: Option<u64>,
    },
    OwnedListenersStopped {
        now_ms: u64,
        binding: WindowsWfpRuntimeBinding,
    },
    DrainDeadline {
        now_ms: u64,
        binding: WindowsWfpRuntimeBinding,
    },
    KernelCalloutsUnregistered {
        now_ms: u64,
        binding: WindowsWfpRuntimeBinding,
    },
}

impl WindowsWfpRuntimeEvent {
    pub const fn now_ms(&self) -> u64 {
        match self {
            Self::StartRequested { now_ms }
            | Self::KernelCalloutsRegistered { now_ms, .. }
            | Self::KernelCalloutRegistrationFailed { now_ms, .. }
            | Self::OwnedListenersReady { now_ms, .. }
            | Self::OwnedListenerStartupFailed { now_ms, .. }
            | Self::DynamicSessionActivated { now_ms, .. }
            | Self::DynamicSessionActivationFailed { now_ms, .. }
            | Self::ConnectionAccepted { now_ms, .. }
            | Self::ConnectionReleased { now_ms, .. }
            | Self::StopRequested { now_ms }
            | Self::RuntimeFault { now_ms, .. }
            | Self::DynamicSessionClosed { now_ms, .. }
            | Self::OwnedFiltersInspected { now_ms, .. }
            | Self::FilterAbsenceRecheckDue { now_ms, .. }
            | Self::OwnedListenersStopped { now_ms, .. }
            | Self::DrainDeadline { now_ms, .. }
            | Self::KernelCalloutsUnregistered { now_ms, .. } => *now_ms,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum WindowsWfpRuntimeCommand {
    RegisterKernelCallouts {
        binding: WindowsWfpRuntimeBinding,
    },
    StartOwnedListeners {
        binding: WindowsWfpRuntimeBinding,
        listeners: Vec<WindowsDirectConnectorEndpoint>,
        target_pid: u32,
    },
    CommitAtomicDynamicSession {
        binding: WindowsWfpRuntimeBinding,
        session_generation: u64,
        target_pid: u32,
    },
    ReportRuntimeReady,
    CloseDynamicSession {
        binding: WindowsWfpRuntimeBinding,
        session_generation: u64,
    },
    InspectOwnedFilters {
        binding: WindowsWfpRuntimeBinding,
        session_generation: Option<u64>,
    },
    ReportFilterRemovalBlocked {
        ipv4_present: bool,
        ipv6_present: bool,
    },
    ScheduleFilterAbsenceRecheck {
        at_ms: u64,
    },
    StopOwnedListeners {
        binding: WindowsWfpRuntimeBinding,
    },
    ScheduleDrainDeadline {
        at_ms: u64,
    },
    RejectAcceptedStream {
        binding: WindowsWfpRuntimeBinding,
        connection_id: u64,
    },
    ForceCloseAcceptedStreams {
        connection_ids: Vec<u64>,
    },
    UnregisterKernelCallouts {
        binding: WindowsWfpRuntimeBinding,
    },
    ReportRuntimeTerminal {
        phase: WindowsWfpRuntimePhase,
        cause: Option<WindowsWfpShutdownCause>,
        reason: String,
    },
}

impl WindowsWfpRuntimeCommand {
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::RegisterKernelCallouts { .. } => "register_kernel_callouts",
            Self::StartOwnedListeners { .. } => "start_owned_listeners",
            Self::CommitAtomicDynamicSession { .. } => "commit_atomic_dynamic_session",
            Self::ReportRuntimeReady => "report_runtime_ready",
            Self::CloseDynamicSession { .. } => "close_dynamic_session",
            Self::InspectOwnedFilters { .. } => "inspect_owned_filters",
            Self::ReportFilterRemovalBlocked { .. } => "report_filter_removal_blocked",
            Self::ScheduleFilterAbsenceRecheck { .. } => "schedule_filter_absence_recheck",
            Self::StopOwnedListeners { .. } => "stop_owned_listeners",
            Self::ScheduleDrainDeadline { .. } => "schedule_drain_deadline",
            Self::RejectAcceptedStream { .. } => "reject_accepted_stream",
            Self::ForceCloseAcceptedStreams { .. } => "force_close_accepted_streams",
            Self::UnregisterKernelCallouts { .. } => "unregister_kernel_callouts",
            Self::ReportRuntimeTerminal { .. } => "report_runtime_terminal",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsWfpRuntimeTransition {
    pub state: WindowsWfpRuntimeState,
    pub commands: Vec<WindowsWfpRuntimeCommand>,
}

pub fn reduce_windows_wfp_runtime(
    state: &WindowsWfpRuntimeState,
    event: &WindowsWfpRuntimeEvent,
    config: &WindowsWfpRuntimeConfig,
) -> Result<WindowsWfpRuntimeTransition, WindowsWfpRuntimeError> {
    config.validate()?;
    validate_state(state)?;
    let now_ms = event.now_ms();
    if now_ms < state.updated_at_ms {
        return Err(WindowsWfpRuntimeError::NonMonotonicEvent);
    }

    let mut next = state.clone();
    next.updated_at_ms = now_ms;
    let mut commands = Vec::new();

    match event {
        WindowsWfpRuntimeEvent::StartRequested { .. } => {
            if matches!(
                next.phase,
                WindowsWfpRuntimePhase::Stopped | WindowsWfpRuntimePhase::Failed
            ) {
                let runtime_generation = next.next_runtime_generation;
                next.next_runtime_generation = runtime_generation
                    .checked_add(1)
                    .ok_or(WindowsWfpRuntimeError::RuntimeGenerationOverflow)?;
                reset_for_start(&mut next);
                next.runtime_generation = runtime_generation;
                next.phase = WindowsWfpRuntimePhase::RegisteringKernelCallouts;
                commands.push(WindowsWfpRuntimeCommand::RegisterKernelCallouts {
                    binding: next.binding(),
                });
            }
        }
        WindowsWfpRuntimeEvent::KernelCalloutsRegistered { binding, .. } => {
            require_phase(&next, WindowsWfpRuntimePhase::RegisteringKernelCallouts)?;
            require_binding(&next, binding)?;
            next.kernel_callouts_registered = true;
            if next.stop_requested {
                begin_filter_inspection(&mut next, &mut commands);
            } else {
                next.phase = WindowsWfpRuntimePhase::StartingListeners;
                commands.push(WindowsWfpRuntimeCommand::StartOwnedListeners {
                    binding: next.binding(),
                    listeners: next.identity.listeners.clone(),
                    target_pid: next.identity.target_pid,
                });
            }
        }
        WindowsWfpRuntimeEvent::KernelCalloutRegistrationFailed {
            binding, reason, ..
        } => {
            require_phase(&next, WindowsWfpRuntimePhase::RegisteringKernelCallouts)?;
            require_binding(&next, binding)?;
            set_failure(&mut next, WindowsWfpShutdownCause::StartupFailure, reason);
            finish_without_resources(&mut next, &mut commands);
        }
        WindowsWfpRuntimeEvent::OwnedListenersReady {
            binding, listeners, ..
        } => {
            require_phase(&next, WindowsWfpRuntimePhase::StartingListeners)?;
            require_binding(&next, binding)?;
            if *listeners != next.identity.listeners {
                return Err(WindowsWfpRuntimeError::ListenerIdentityMismatch);
            }
            next.listeners_ready = true;
            if next.stop_requested {
                begin_filter_inspection(&mut next, &mut commands);
            } else {
                begin_dynamic_session_activation(&mut next, &mut commands)?;
            }
        }
        WindowsWfpRuntimeEvent::OwnedListenerStartupFailed {
            binding, reason, ..
        } => {
            require_phase(&next, WindowsWfpRuntimePhase::StartingListeners)?;
            require_binding(&next, binding)?;
            set_failure(&mut next, WindowsWfpShutdownCause::StartupFailure, reason);
            begin_filter_inspection(&mut next, &mut commands);
        }
        WindowsWfpRuntimeEvent::DynamicSessionActivated {
            binding,
            session_generation,
            ..
        } => {
            require_phase(&next, WindowsWfpRuntimePhase::ActivatingDynamicSession)?;
            require_binding(&next, binding)?;
            require_session(&next, *session_generation)?;
            next.active_session_generation = Some(*session_generation);
            next.filters_absent = false;
            if next.stop_requested {
                begin_dynamic_session_close(&mut next, &mut commands)?;
            } else {
                next.phase = WindowsWfpRuntimePhase::Ready;
                commands.push(WindowsWfpRuntimeCommand::ReportRuntimeReady);
            }
        }
        WindowsWfpRuntimeEvent::DynamicSessionActivationFailed {
            binding,
            session_generation,
            reason,
            ..
        } => {
            require_phase(&next, WindowsWfpRuntimePhase::ActivatingDynamicSession)?;
            require_binding(&next, binding)?;
            require_session(&next, *session_generation)?;
            set_failure(&mut next, WindowsWfpShutdownCause::StartupFailure, reason);
            begin_filter_inspection(&mut next, &mut commands);
        }
        WindowsWfpRuntimeEvent::ConnectionAccepted {
            binding,
            connection_id,
            ..
        } => {
            require_binding(&next, binding)?;
            if *connection_id == 0 {
                return Err(WindowsWfpRuntimeError::InvalidConnectionId);
            }
            if !next.listeners_ready
                || !matches!(
                    next.phase,
                    WindowsWfpRuntimePhase::ActivatingDynamicSession
                        | WindowsWfpRuntimePhase::Ready
                        | WindowsWfpRuntimePhase::ClosingDynamicSession
                        | WindowsWfpRuntimePhase::ProvingFilterAbsence
                        | WindowsWfpRuntimePhase::StoppingListeners
                )
            {
                return Err(WindowsWfpRuntimeError::UnexpectedEvent(
                    "connection accepted while listener is not admissible",
                ));
            }
            if next.active_connections.contains(connection_id) {
                return Err(WindowsWfpRuntimeError::DuplicateConnection(*connection_id));
            }
            if next.active_connections.len() >= config.max_active_connections {
                commands.push(WindowsWfpRuntimeCommand::RejectAcceptedStream {
                    binding: next.binding(),
                    connection_id: *connection_id,
                });
            } else {
                next.active_connections.insert(*connection_id);
            }
        }
        WindowsWfpRuntimeEvent::ConnectionReleased {
            binding,
            connection_id,
            ..
        } => {
            require_binding(&next, binding)?;
            if !next.active_connections.remove(connection_id) {
                if matches!(
                    next.phase,
                    WindowsWfpRuntimePhase::UnregisteringKernelCallouts
                        | WindowsWfpRuntimePhase::Stopped
                        | WindowsWfpRuntimePhase::Failed
                ) {
                    return Ok(WindowsWfpRuntimeTransition {
                        state: next,
                        commands,
                    });
                }
                return Err(WindowsWfpRuntimeError::UnknownConnection(*connection_id));
            }
            if next.phase == WindowsWfpRuntimePhase::Draining && next.active_connections.is_empty()
            {
                next.drain_deadline_at_ms = None;
                begin_kernel_unregister(&mut next, &mut commands)?;
            }
        }
        WindowsWfpRuntimeEvent::StopRequested { .. } => {
            request_shutdown(
                &mut next,
                WindowsWfpShutdownCause::Requested,
                "stop_requested",
                &mut commands,
            )?;
        }
        WindowsWfpRuntimeEvent::RuntimeFault {
            binding, reason, ..
        } => {
            require_binding(&next, binding)?;
            request_shutdown(
                &mut next,
                WindowsWfpShutdownCause::RuntimeFailure,
                reason,
                &mut commands,
            )?;
        }
        WindowsWfpRuntimeEvent::DynamicSessionClosed {
            binding,
            session_generation,
            ..
        } => {
            require_binding(&next, binding)?;
            require_session(&next, *session_generation)?;
            if next.phase == WindowsWfpRuntimePhase::Ready {
                set_failure(
                    &mut next,
                    WindowsWfpShutdownCause::RuntimeFailure,
                    "dynamic_session_closed",
                );
            } else {
                require_phase(&next, WindowsWfpRuntimePhase::ClosingDynamicSession)?;
            }
            next.active_session_generation = None;
            begin_filter_inspection(&mut next, &mut commands);
        }
        WindowsWfpRuntimeEvent::OwnedFiltersInspected { inspection, .. } => {
            require_phase(&next, WindowsWfpRuntimePhase::ProvingFilterAbsence)?;
            require_binding(&next, &inspection.binding)?;
            require_inspection_session(&next, inspection.session_generation)?;
            if !next.filter_inspection_pending {
                return Err(WindowsWfpRuntimeError::UnexpectedEvent(
                    "filter inspection was not requested",
                ));
            }
            next.filter_inspection_pending = false;
            if inspection.filters_absent() {
                next.filters_absent = true;
                next.filter_recheck_at_ms = None;
                if next.listeners_ready {
                    next.phase = WindowsWfpRuntimePhase::StoppingListeners;
                    commands.push(WindowsWfpRuntimeCommand::StopOwnedListeners {
                        binding: next.binding(),
                    });
                } else {
                    begin_kernel_unregister(&mut next, &mut commands)?;
                }
            } else {
                next.filters_absent = false;
                let at_ms = now_ms
                    .checked_add(config.filter_absence_recheck_ms)
                    .ok_or(WindowsWfpRuntimeError::TimeOverflow)?;
                next.filter_recheck_at_ms = Some(at_ms);
                commands.push(WindowsWfpRuntimeCommand::ReportFilterRemovalBlocked {
                    ipv4_present: inspection.ipv4_present,
                    ipv6_present: inspection.ipv6_present,
                });
                commands.push(WindowsWfpRuntimeCommand::ScheduleFilterAbsenceRecheck { at_ms });
            }
        }
        WindowsWfpRuntimeEvent::FilterAbsenceRecheckDue {
            binding,
            session_generation,
            ..
        } => {
            require_phase(&next, WindowsWfpRuntimePhase::ProvingFilterAbsence)?;
            require_binding(&next, binding)?;
            require_inspection_session(&next, *session_generation)?;
            let at_ms =
                next.filter_recheck_at_ms
                    .ok_or(WindowsWfpRuntimeError::UnexpectedEvent(
                        "filter recheck was not scheduled",
                    ))?;
            if now_ms < at_ms {
                return Err(WindowsWfpRuntimeError::DeadlineBeforeDue);
            }
            next.filter_recheck_at_ms = None;
            next.filter_inspection_pending = true;
            commands.push(WindowsWfpRuntimeCommand::InspectOwnedFilters {
                binding: next.binding(),
                session_generation: next.last_session_generation,
            });
        }
        WindowsWfpRuntimeEvent::OwnedListenersStopped { binding, .. } => {
            require_phase(&next, WindowsWfpRuntimePhase::StoppingListeners)?;
            require_binding(&next, binding)?;
            next.listeners_ready = false;
            if next.active_connections.is_empty() {
                begin_kernel_unregister(&mut next, &mut commands)?;
            } else {
                let at_ms = now_ms
                    .checked_add(config.drain_timeout_ms)
                    .ok_or(WindowsWfpRuntimeError::TimeOverflow)?;
                next.phase = WindowsWfpRuntimePhase::Draining;
                next.drain_deadline_at_ms = Some(at_ms);
                commands.push(WindowsWfpRuntimeCommand::ScheduleDrainDeadline { at_ms });
            }
        }
        WindowsWfpRuntimeEvent::DrainDeadline { binding, .. } => {
            require_phase(&next, WindowsWfpRuntimePhase::Draining)?;
            require_binding(&next, binding)?;
            let at_ms =
                next.drain_deadline_at_ms
                    .ok_or(WindowsWfpRuntimeError::UnexpectedEvent(
                        "drain deadline was not scheduled",
                    ))?;
            if now_ms < at_ms {
                return Err(WindowsWfpRuntimeError::DeadlineBeforeDue);
            }
            let connection_ids = next.active_connections.iter().copied().collect();
            next.active_connections.clear();
            next.drain_deadline_at_ms = None;
            commands.push(WindowsWfpRuntimeCommand::ForceCloseAcceptedStreams { connection_ids });
            begin_kernel_unregister(&mut next, &mut commands)?;
        }
        WindowsWfpRuntimeEvent::KernelCalloutsUnregistered { binding, .. } => {
            require_phase(&next, WindowsWfpRuntimePhase::UnregisteringKernelCallouts)?;
            require_binding(&next, binding)?;
            next.kernel_callouts_registered = false;
            next.stop_requested = false;
            next.phase = if matches!(
                next.shutdown_cause,
                Some(
                    WindowsWfpShutdownCause::StartupFailure
                        | WindowsWfpShutdownCause::RuntimeFailure
                )
            ) {
                WindowsWfpRuntimePhase::Failed
            } else {
                WindowsWfpRuntimePhase::Stopped
            };
            commands.push(WindowsWfpRuntimeCommand::ReportRuntimeTerminal {
                phase: next.phase,
                cause: next.shutdown_cause,
                reason: next.terminal_reason.clone(),
            });
        }
    }

    validate_state(&next)?;
    Ok(WindowsWfpRuntimeTransition {
        state: next,
        commands,
    })
}

fn reset_for_start(state: &mut WindowsWfpRuntimeState) {
    state.kernel_callouts_registered = false;
    state.listeners_ready = false;
    state.active_session_generation = None;
    state.last_session_generation = None;
    state.filters_absent = false;
    state.filter_inspection_pending = false;
    state.filter_recheck_at_ms = None;
    state.active_connections.clear();
    state.drain_deadline_at_ms = None;
    state.stop_requested = false;
    state.shutdown_cause = None;
    state.terminal_reason.clear();
}

fn begin_dynamic_session_activation(
    state: &mut WindowsWfpRuntimeState,
    commands: &mut Vec<WindowsWfpRuntimeCommand>,
) -> Result<(), WindowsWfpRuntimeError> {
    let session_generation = state.next_session_generation;
    state.next_session_generation = session_generation
        .checked_add(1)
        .ok_or(WindowsWfpRuntimeError::SessionGenerationOverflow)?;
    state.last_session_generation = Some(session_generation);
    state.phase = WindowsWfpRuntimePhase::ActivatingDynamicSession;
    commands.push(WindowsWfpRuntimeCommand::CommitAtomicDynamicSession {
        binding: state.binding(),
        session_generation,
        target_pid: state.identity.target_pid,
    });
    Ok(())
}

fn begin_dynamic_session_close(
    state: &mut WindowsWfpRuntimeState,
    commands: &mut Vec<WindowsWfpRuntimeCommand>,
) -> Result<(), WindowsWfpRuntimeError> {
    let session_generation =
        state
            .active_session_generation
            .ok_or(WindowsWfpRuntimeError::InvalidState(
                "session close requires an active session",
            ))?;
    state.phase = WindowsWfpRuntimePhase::ClosingDynamicSession;
    commands.push(WindowsWfpRuntimeCommand::CloseDynamicSession {
        binding: state.binding(),
        session_generation,
    });
    Ok(())
}

fn begin_filter_inspection(
    state: &mut WindowsWfpRuntimeState,
    commands: &mut Vec<WindowsWfpRuntimeCommand>,
) {
    state.phase = WindowsWfpRuntimePhase::ProvingFilterAbsence;
    state.filters_absent = false;
    state.filter_recheck_at_ms = None;
    state.filter_inspection_pending = true;
    commands.push(WindowsWfpRuntimeCommand::InspectOwnedFilters {
        binding: state.binding(),
        session_generation: state.last_session_generation,
    });
}

fn begin_kernel_unregister(
    state: &mut WindowsWfpRuntimeState,
    commands: &mut Vec<WindowsWfpRuntimeCommand>,
) -> Result<(), WindowsWfpRuntimeError> {
    if !state.filters_absent
        || state.listeners_ready
        || state.active_session_generation.is_some()
        || !state.active_connections.is_empty()
    {
        return Err(WindowsWfpRuntimeError::InvalidState(
            "kernel unregister requires absent filters and no live resources",
        ));
    }
    state.phase = WindowsWfpRuntimePhase::UnregisteringKernelCallouts;
    commands.push(WindowsWfpRuntimeCommand::UnregisterKernelCallouts {
        binding: state.binding(),
    });
    Ok(())
}

fn request_shutdown(
    state: &mut WindowsWfpRuntimeState,
    cause: WindowsWfpShutdownCause,
    reason: &str,
    commands: &mut Vec<WindowsWfpRuntimeCommand>,
) -> Result<(), WindowsWfpRuntimeError> {
    if matches!(
        state.phase,
        WindowsWfpRuntimePhase::Stopped | WindowsWfpRuntimePhase::Failed
    ) {
        return Ok(());
    }
    state.stop_requested = true;
    if cause != WindowsWfpShutdownCause::Requested || state.shutdown_cause.is_none() {
        state.shutdown_cause = Some(cause);
        state.terminal_reason = bounded_reason(reason);
    }
    if state.phase == WindowsWfpRuntimePhase::Ready {
        begin_dynamic_session_close(state, commands)?;
    }
    Ok(())
}

fn set_failure(state: &mut WindowsWfpRuntimeState, cause: WindowsWfpShutdownCause, reason: &str) {
    state.stop_requested = true;
    state.shutdown_cause = Some(cause);
    state.terminal_reason = bounded_reason(reason);
}

fn finish_without_resources(
    state: &mut WindowsWfpRuntimeState,
    commands: &mut Vec<WindowsWfpRuntimeCommand>,
) {
    state.phase = WindowsWfpRuntimePhase::Failed;
    state.stop_requested = false;
    state.filters_absent = true;
    commands.push(WindowsWfpRuntimeCommand::ReportRuntimeTerminal {
        phase: state.phase,
        cause: state.shutdown_cause,
        reason: state.terminal_reason.clone(),
    });
}

fn require_phase(
    state: &WindowsWfpRuntimeState,
    expected: WindowsWfpRuntimePhase,
) -> Result<(), WindowsWfpRuntimeError> {
    if state.phase == expected {
        Ok(())
    } else {
        Err(WindowsWfpRuntimeError::UnexpectedEvent(
            "event does not match runtime phase",
        ))
    }
}

fn require_binding(
    state: &WindowsWfpRuntimeState,
    binding: &WindowsWfpRuntimeBinding,
) -> Result<(), WindowsWfpRuntimeError> {
    if *binding == state.binding() {
        Ok(())
    } else {
        Err(WindowsWfpRuntimeError::StaleBinding)
    }
}

fn require_session(
    state: &WindowsWfpRuntimeState,
    session_generation: u64,
) -> Result<(), WindowsWfpRuntimeError> {
    if session_generation != 0 && state.last_session_generation == Some(session_generation) {
        Ok(())
    } else {
        Err(WindowsWfpRuntimeError::StaleSessionGeneration)
    }
}

fn require_inspection_session(
    state: &WindowsWfpRuntimeState,
    session_generation: Option<u64>,
) -> Result<(), WindowsWfpRuntimeError> {
    if session_generation == state.last_session_generation {
        Ok(())
    } else {
        Err(WindowsWfpRuntimeError::StaleSessionGeneration)
    }
}

fn bounded_reason(reason: &str) -> String {
    reason.chars().take(MAX_REASON_CHARS).collect()
}

fn validate_state(state: &WindowsWfpRuntimeState) -> Result<(), WindowsWfpRuntimeError> {
    validate_windows_wfp_capture_identity(&state.identity)
        .map_err(WindowsWfpRuntimeError::InvalidCaptureIdentity)?;
    if state.next_session_generation == 0 {
        return Err(WindowsWfpRuntimeError::InvalidState(
            "next session generation is zero",
        ));
    }
    if state.next_runtime_generation == 0 {
        return Err(WindowsWfpRuntimeError::InvalidState(
            "next runtime generation is zero",
        ));
    }
    if state.phase != WindowsWfpRuntimePhase::Stopped && state.runtime_generation == 0 {
        return Err(WindowsWfpRuntimeError::InvalidState(
            "active runtime generation is zero",
        ));
    }
    if state.active_session_generation.is_some()
        && state.active_session_generation != state.last_session_generation
    {
        return Err(WindowsWfpRuntimeError::InvalidState(
            "active session does not match the last session",
        ));
    }
    if state.kernel_callouts_registered
        != matches!(
            state.phase,
            WindowsWfpRuntimePhase::StartingListeners
                | WindowsWfpRuntimePhase::ActivatingDynamicSession
                | WindowsWfpRuntimePhase::Ready
                | WindowsWfpRuntimePhase::ClosingDynamicSession
                | WindowsWfpRuntimePhase::ProvingFilterAbsence
                | WindowsWfpRuntimePhase::StoppingListeners
                | WindowsWfpRuntimePhase::Draining
                | WindowsWfpRuntimePhase::UnregisteringKernelCallouts
        )
    {
        return Err(WindowsWfpRuntimeError::InvalidState(
            "kernel registration does not match runtime phase",
        ));
    }
    if state.listeners_ready
        && !matches!(
            state.phase,
            WindowsWfpRuntimePhase::ActivatingDynamicSession
                | WindowsWfpRuntimePhase::Ready
                | WindowsWfpRuntimePhase::ClosingDynamicSession
                | WindowsWfpRuntimePhase::ProvingFilterAbsence
                | WindowsWfpRuntimePhase::StoppingListeners
        )
    {
        return Err(WindowsWfpRuntimeError::InvalidState(
            "listener readiness does not match runtime phase",
        ));
    }
    if matches!(
        state.phase,
        WindowsWfpRuntimePhase::ActivatingDynamicSession
            | WindowsWfpRuntimePhase::Ready
            | WindowsWfpRuntimePhase::ClosingDynamicSession
            | WindowsWfpRuntimePhase::StoppingListeners
    ) && !state.listeners_ready
    {
        return Err(WindowsWfpRuntimeError::InvalidState(
            "runtime phase requires ready listeners",
        ));
    }
    if state.active_session_generation.is_some()
        != matches!(
            state.phase,
            WindowsWfpRuntimePhase::Ready | WindowsWfpRuntimePhase::ClosingDynamicSession
        )
    {
        return Err(WindowsWfpRuntimeError::InvalidState(
            "active session does not match runtime phase",
        ));
    }
    if state.filter_inspection_pending
        && state.phase != WindowsWfpRuntimePhase::ProvingFilterAbsence
    {
        return Err(WindowsWfpRuntimeError::InvalidState(
            "filter inspection pending outside proof phase",
        ));
    }
    if state.filter_recheck_at_ms.is_some()
        && (state.phase != WindowsWfpRuntimePhase::ProvingFilterAbsence
            || state.filter_inspection_pending)
    {
        return Err(WindowsWfpRuntimeError::InvalidState(
            "filter recheck does not match proof phase",
        ));
    }
    if state.phase == WindowsWfpRuntimePhase::ProvingFilterAbsence
        && state.filter_inspection_pending == state.filter_recheck_at_ms.is_some()
    {
        return Err(WindowsWfpRuntimeError::InvalidState(
            "filter proof must be pending or scheduled",
        ));
    }
    if state.drain_deadline_at_ms.is_some() != (state.phase == WindowsWfpRuntimePhase::Draining) {
        return Err(WindowsWfpRuntimeError::InvalidState(
            "drain deadline does not match drain phase",
        ));
    }
    if !(state.active_connections.is_empty()
        || state.listeners_ready
        || state.phase == WindowsWfpRuntimePhase::Draining)
    {
        return Err(WindowsWfpRuntimeError::InvalidState(
            "connections remain without a listener or drain",
        ));
    }
    if matches!(
        state.phase,
        WindowsWfpRuntimePhase::StoppingListeners
            | WindowsWfpRuntimePhase::Draining
            | WindowsWfpRuntimePhase::UnregisteringKernelCallouts
            | WindowsWfpRuntimePhase::Stopped
            | WindowsWfpRuntimePhase::Failed
    ) && !state.filters_absent
    {
        return Err(WindowsWfpRuntimeError::InvalidState(
            "teardown advanced before filter absence",
        ));
    }
    if matches!(
        state.phase,
        WindowsWfpRuntimePhase::Stopped | WindowsWfpRuntimePhase::Failed
    ) && (state.kernel_callouts_registered
        || state.listeners_ready
        || state.active_session_generation.is_some()
        || !state.active_connections.is_empty()
        || state.filter_inspection_pending
        || state.filter_recheck_at_ms.is_some()
        || state.drain_deadline_at_ms.is_some())
    {
        return Err(WindowsWfpRuntimeError::InvalidState(
            "terminal runtime retains resources",
        ));
    }
    Ok(())
}

pub trait WindowsWfpRuntimeEffects {
    type Error: fmt::Display;

    /// Executes one command atomically. In particular, dynamic-session commit
    /// either retains the one owned session with all runtime objects or leaves
    /// no session/provider/sublayer/callout/context/filter mutation behind.
    fn execute(&mut self, command: &WindowsWfpRuntimeCommand) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, Default)]
pub struct RecordingWindowsWfpRuntimeEffects {
    commands: Vec<WindowsWfpRuntimeCommand>,
    kernel_registration_pending: bool,
    kernel_registered: bool,
    listener_start_pending: bool,
    listeners_ready: bool,
    session_activation_pending: Option<u64>,
    active_session: Option<u64>,
    session_close_pending: Option<u64>,
    filters_present: bool,
    filter_inspection_pending: bool,
    listener_stop_pending: bool,
    unregister_pending: bool,
    active_connections: BTreeSet<u64>,
    fail_once: BTreeMap<String, String>,
}

impl RecordingWindowsWfpRuntimeEffects {
    pub fn commands(&self) -> &[WindowsWfpRuntimeCommand] {
        &self.commands
    }

    pub const fn kernel_registered(&self) -> bool {
        self.kernel_registered
    }

    pub const fn listeners_ready(&self) -> bool {
        self.listeners_ready
    }

    pub const fn active_session(&self) -> Option<u64> {
        self.active_session
    }

    pub const fn filters_present(&self) -> bool {
        self.filters_present
    }

    pub fn active_connections(&self) -> &BTreeSet<u64> {
        &self.active_connections
    }

    pub fn fail_once(&mut self, command: &str, message: impl Into<String>) {
        self.fail_once.insert(command.to_owned(), message.into());
    }

    pub fn stage_event(
        &mut self,
        event: &WindowsWfpRuntimeEvent,
    ) -> Result<(), WindowsWfpRuntimeEffectError> {
        match event {
            WindowsWfpRuntimeEvent::KernelCalloutsRegistered { .. } => {
                if !self.kernel_registration_pending {
                    return Err(WindowsWfpRuntimeEffectError::UnexpectedCompletion(
                        "kernel registration",
                    ));
                }
                self.kernel_registration_pending = false;
                self.kernel_registered = true;
            }
            WindowsWfpRuntimeEvent::KernelCalloutRegistrationFailed { .. } => {
                if !self.kernel_registration_pending {
                    return Err(WindowsWfpRuntimeEffectError::UnexpectedCompletion(
                        "kernel registration failure",
                    ));
                }
                self.kernel_registration_pending = false;
            }
            WindowsWfpRuntimeEvent::OwnedListenersReady { .. } => {
                if !self.listener_start_pending {
                    return Err(WindowsWfpRuntimeEffectError::UnexpectedCompletion(
                        "listener start",
                    ));
                }
                self.listener_start_pending = false;
                self.listeners_ready = true;
            }
            WindowsWfpRuntimeEvent::OwnedListenerStartupFailed { .. } => {
                if !self.listener_start_pending {
                    return Err(WindowsWfpRuntimeEffectError::UnexpectedCompletion(
                        "listener start failure",
                    ));
                }
                self.listener_start_pending = false;
            }
            WindowsWfpRuntimeEvent::DynamicSessionActivated {
                session_generation, ..
            } => {
                if self.session_activation_pending != Some(*session_generation) {
                    return Err(WindowsWfpRuntimeEffectError::UnexpectedCompletion(
                        "dynamic session activation",
                    ));
                }
                self.session_activation_pending = None;
                self.active_session = Some(*session_generation);
                self.filters_present = true;
            }
            WindowsWfpRuntimeEvent::DynamicSessionActivationFailed {
                session_generation, ..
            } => {
                if self.session_activation_pending != Some(*session_generation) {
                    return Err(WindowsWfpRuntimeEffectError::UnexpectedCompletion(
                        "dynamic session activation failure",
                    ));
                }
                self.session_activation_pending = None;
                self.filters_present = false;
            }
            WindowsWfpRuntimeEvent::ConnectionAccepted { connection_id, .. } => {
                if !self.active_connections.insert(*connection_id) {
                    return Err(WindowsWfpRuntimeEffectError::DuplicateConnection(
                        *connection_id,
                    ));
                }
            }
            WindowsWfpRuntimeEvent::ConnectionReleased { connection_id, .. } => {
                if !self.active_connections.remove(connection_id)
                    && (self.kernel_registered || self.listeners_ready)
                {
                    return Err(WindowsWfpRuntimeEffectError::UnknownConnection(
                        *connection_id,
                    ));
                }
            }
            WindowsWfpRuntimeEvent::DynamicSessionClosed {
                session_generation, ..
            } => {
                if self.session_close_pending != Some(*session_generation)
                    && self.active_session != Some(*session_generation)
                {
                    return Err(WindowsWfpRuntimeEffectError::UnexpectedCompletion(
                        "dynamic session close",
                    ));
                }
                self.session_close_pending = None;
                self.active_session = None;
                self.filters_present = false;
            }
            WindowsWfpRuntimeEvent::OwnedFiltersInspected { inspection, .. } => {
                if !self.filter_inspection_pending {
                    return Err(WindowsWfpRuntimeEffectError::UnexpectedCompletion(
                        "filter inspection",
                    ));
                }
                self.filter_inspection_pending = false;
                self.filters_present = !inspection.filters_absent();
            }
            WindowsWfpRuntimeEvent::OwnedListenersStopped { .. } => {
                if !self.listener_stop_pending {
                    return Err(WindowsWfpRuntimeEffectError::UnexpectedCompletion(
                        "listener stop",
                    ));
                }
                self.listener_stop_pending = false;
                self.listeners_ready = false;
            }
            WindowsWfpRuntimeEvent::KernelCalloutsUnregistered { .. } => {
                if !self.unregister_pending {
                    return Err(WindowsWfpRuntimeEffectError::UnexpectedCompletion(
                        "kernel unregister",
                    ));
                }
                self.unregister_pending = false;
                self.kernel_registered = false;
            }
            WindowsWfpRuntimeEvent::StartRequested { .. }
            | WindowsWfpRuntimeEvent::StopRequested { .. }
            | WindowsWfpRuntimeEvent::RuntimeFault { .. }
            | WindowsWfpRuntimeEvent::FilterAbsenceRecheckDue { .. }
            | WindowsWfpRuntimeEvent::DrainDeadline { .. } => {}
        }
        Ok(())
    }
}

impl WindowsWfpRuntimeEffects for RecordingWindowsWfpRuntimeEffects {
    type Error = WindowsWfpRuntimeEffectError;

    fn execute(&mut self, command: &WindowsWfpRuntimeCommand) -> Result<(), Self::Error> {
        if let Some(message) = self.fail_once.remove(command.kind()) {
            return Err(WindowsWfpRuntimeEffectError::InjectedFailure {
                command: command.kind().to_owned(),
                message,
            });
        }
        match command {
            WindowsWfpRuntimeCommand::RegisterKernelCallouts { .. } => {
                if self.kernel_registered || self.kernel_registration_pending {
                    return Err(WindowsWfpRuntimeEffectError::ResourceAlreadyActive(
                        "kernel callouts",
                    ));
                }
                self.kernel_registration_pending = true;
            }
            WindowsWfpRuntimeCommand::StartOwnedListeners { .. } => {
                if !self.kernel_registered || self.listeners_ready || self.listener_start_pending {
                    return Err(WindowsWfpRuntimeEffectError::InvalidEffectOrder(
                        "listeners require registered kernel callouts",
                    ));
                }
                self.listener_start_pending = true;
            }
            WindowsWfpRuntimeCommand::CommitAtomicDynamicSession {
                session_generation, ..
            } => {
                if !self.kernel_registered
                    || !self.listeners_ready
                    || self.active_session.is_some()
                    || self.session_activation_pending.is_some()
                {
                    return Err(WindowsWfpRuntimeEffectError::InvalidEffectOrder(
                        "dynamic session requires ready callouts and listeners",
                    ));
                }
                self.session_activation_pending = Some(*session_generation);
            }
            WindowsWfpRuntimeCommand::ReportRuntimeReady => {
                if self.active_session.is_none() || !self.filters_present {
                    return Err(WindowsWfpRuntimeEffectError::InvalidEffectOrder(
                        "ready requires an active dynamic session",
                    ));
                }
            }
            WindowsWfpRuntimeCommand::CloseDynamicSession {
                session_generation, ..
            } => {
                if self.active_session != Some(*session_generation)
                    || self.session_close_pending.is_some()
                {
                    return Err(WindowsWfpRuntimeEffectError::InvalidEffectOrder(
                        "session close requires the exact active session",
                    ));
                }
                self.session_close_pending = Some(*session_generation);
            }
            WindowsWfpRuntimeCommand::InspectOwnedFilters { .. } => {
                if self.active_session.is_some()
                    || self.session_close_pending.is_some()
                    || self.filter_inspection_pending
                {
                    return Err(WindowsWfpRuntimeEffectError::InvalidEffectOrder(
                        "filter inspection requires a closed session",
                    ));
                }
                self.filter_inspection_pending = true;
            }
            WindowsWfpRuntimeCommand::ReportFilterRemovalBlocked {
                ipv4_present,
                ipv6_present,
            } => {
                if !self.filters_present || (!ipv4_present && !ipv6_present) {
                    return Err(WindowsWfpRuntimeEffectError::InvalidEffectOrder(
                        "blocked report requires observed filters",
                    ));
                }
            }
            WindowsWfpRuntimeCommand::ScheduleFilterAbsenceRecheck { .. } => {}
            WindowsWfpRuntimeCommand::StopOwnedListeners { .. } => {
                if self.filters_present
                    || !self.listeners_ready
                    || self.listener_stop_pending
                    || self.active_session.is_some()
                {
                    return Err(WindowsWfpRuntimeEffectError::InvalidEffectOrder(
                        "listeners stop only after filter absence",
                    ));
                }
                self.listener_stop_pending = true;
            }
            WindowsWfpRuntimeCommand::ScheduleDrainDeadline { .. } => {
                if self.listeners_ready || self.active_connections.is_empty() {
                    return Err(WindowsWfpRuntimeEffectError::InvalidEffectOrder(
                        "drain requires stopped listeners and active streams",
                    ));
                }
            }
            WindowsWfpRuntimeCommand::RejectAcceptedStream { connection_id, .. } => {
                if !self.listeners_ready || !self.active_connections.contains(connection_id) {
                    return Err(WindowsWfpRuntimeEffectError::InvalidEffectOrder(
                        "rejected stream must be owned by a ready listener",
                    ));
                }
                self.active_connections.remove(connection_id);
            }
            WindowsWfpRuntimeCommand::ForceCloseAcceptedStreams { connection_ids } => {
                if self.listeners_ready
                    || self.filters_present
                    || connection_ids.iter().copied().collect::<BTreeSet<_>>()
                        != self.active_connections
                {
                    return Err(WindowsWfpRuntimeEffectError::InvalidEffectOrder(
                        "forced close must consume the exact drained stream set",
                    ));
                }
                self.active_connections.clear();
            }
            WindowsWfpRuntimeCommand::UnregisterKernelCallouts { .. } => {
                if !self.kernel_registered
                    || self.unregister_pending
                    || self.listeners_ready
                    || self.active_session.is_some()
                    || self.filters_present
                    || !self.active_connections.is_empty()
                {
                    return Err(WindowsWfpRuntimeEffectError::InvalidEffectOrder(
                        "kernel unregister requires exact filter absence and no resources",
                    ));
                }
                self.unregister_pending = true;
            }
            WindowsWfpRuntimeCommand::ReportRuntimeTerminal { .. } => {
                if self.kernel_registered
                    || self.kernel_registration_pending
                    || self.listeners_ready
                    || self.listener_start_pending
                    || self.active_session.is_some()
                    || self.session_activation_pending.is_some()
                    || self.session_close_pending.is_some()
                    || self.filter_inspection_pending
                    || self.listener_stop_pending
                    || self.unregister_pending
                    || !self.active_connections.is_empty()
                {
                    return Err(WindowsWfpRuntimeEffectError::TerminalWithResources);
                }
            }
        }
        self.commands.push(command.clone());
        Ok(())
    }
}

pub fn execute_windows_wfp_runtime_transition<E: WindowsWfpRuntimeEffects>(
    transition: &WindowsWfpRuntimeTransition,
    effects: &mut E,
) -> Result<(), WindowsWfpRuntimeEffectExecutionError> {
    execute_windows_wfp_runtime_transition_from(transition, effects, 0)
}

/// Resumes one immutable command batch without replaying its completed prefix.
pub fn execute_windows_wfp_runtime_transition_from<E: WindowsWfpRuntimeEffects>(
    transition: &WindowsWfpRuntimeTransition,
    effects: &mut E,
    next_command_index: usize,
) -> Result<(), WindowsWfpRuntimeEffectExecutionError> {
    if next_command_index > transition.commands.len() {
        return Err(WindowsWfpRuntimeEffectExecutionError {
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
            .map_err(|error| WindowsWfpRuntimeEffectExecutionError {
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
pub enum WindowsWfpRuntimeEffectError {
    InjectedFailure { command: String, message: String },
    UnexpectedCompletion(&'static str),
    ResourceAlreadyActive(&'static str),
    InvalidEffectOrder(&'static str),
    DuplicateConnection(u64),
    UnknownConnection(u64),
    TerminalWithResources,
}

impl fmt::Display for WindowsWfpRuntimeEffectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InjectedFailure { command, message } => write!(formatter, "{command}: {message}"),
            Self::UnexpectedCompletion(resource) => {
                write!(formatter, "unexpected completion: {resource}")
            }
            Self::ResourceAlreadyActive(resource) => {
                write!(formatter, "already active: {resource}")
            }
            Self::InvalidEffectOrder(message) => {
                write!(formatter, "invalid effect order: {message}")
            }
            Self::DuplicateConnection(connection_id) => {
                write!(formatter, "duplicate connection {connection_id}")
            }
            Self::UnknownConnection(connection_id) => {
                write!(formatter, "unknown connection {connection_id}")
            }
            Self::TerminalWithResources => {
                formatter.write_str("runtime became terminal with resources")
            }
        }
    }
}

impl std::error::Error for WindowsWfpRuntimeEffectError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsWfpRuntimeEffectExecutionError {
    pub command: &'static str,
    pub message: String,
    pub failed_command_index: usize,
    pub next_command_index: usize,
    pub completed_commands: usize,
}

impl fmt::Display for WindowsWfpRuntimeEffectExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} failed at command {}: {}",
            self.command, self.failed_command_index, self.message
        )
    }
}

impl std::error::Error for WindowsWfpRuntimeEffectExecutionError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsWfpRuntimeError {
    InvalidConfig(&'static str),
    InvalidCaptureIdentity(WindowsWfpCaptureErrorCode),
    NonMonotonicEvent,
    UnexpectedEvent(&'static str),
    StaleBinding,
    StaleSessionGeneration,
    ListenerIdentityMismatch,
    InvalidConnectionId,
    DuplicateConnection(u64),
    UnknownConnection(u64),
    RuntimeGenerationOverflow,
    SessionGenerationOverflow,
    TimeOverflow,
    DeadlineBeforeDue,
    InvalidState(&'static str),
}

impl fmt::Display for WindowsWfpRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(field) => write!(formatter, "invalid WFP runtime config: {field}"),
            Self::InvalidCaptureIdentity(code) => {
                write!(formatter, "invalid WFP capture identity: {code}")
            }
            Self::NonMonotonicEvent => formatter.write_str("non-monotonic WFP runtime event"),
            Self::UnexpectedEvent(message) => {
                write!(formatter, "unexpected WFP runtime event: {message}")
            }
            Self::StaleBinding => formatter.write_str("stale WFP runtime binding"),
            Self::StaleSessionGeneration => formatter.write_str("stale WFP session generation"),
            Self::ListenerIdentityMismatch => formatter.write_str("WFP listener identity mismatch"),
            Self::InvalidConnectionId => formatter.write_str("invalid WFP connection ID"),
            Self::DuplicateConnection(connection_id) => {
                write!(formatter, "duplicate WFP connection {connection_id}")
            }
            Self::UnknownConnection(connection_id) => {
                write!(formatter, "unknown WFP connection {connection_id}")
            }
            Self::RuntimeGenerationOverflow => {
                formatter.write_str("WFP runtime generation overflow")
            }
            Self::SessionGenerationOverflow => {
                formatter.write_str("WFP session generation overflow")
            }
            Self::TimeOverflow => formatter.write_str("WFP runtime deadline overflow"),
            Self::DeadlineBeforeDue => formatter.write_str("WFP runtime deadline fired before due"),
            Self::InvalidState(message) => {
                write!(formatter, "invalid WFP runtime state: {message}")
            }
        }
    }
}

impl std::error::Error for WindowsWfpRuntimeError {}
