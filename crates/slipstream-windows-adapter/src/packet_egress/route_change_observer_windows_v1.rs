//! Bounded, read-only Windows route-change observation.
//!
//! Version 1 subscribes to kernel route-table notifications and retains only a
//! small in-memory event window. It cannot create, update, or delete routes and
//! is not composed into the production service host.

use super::WindowsPacketInterfaceIdentity;
use std::collections::VecDeque;
use std::error::Error;
use std::ffi::c_void;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr::null_mut;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, MibAddInstance as MIB_ADD_INSTANCE,
    MibDeleteInstance as MIB_DELETE_INSTANCE, MibInitialNotification as MIB_INITIAL_NOTIFICATION,
    MibParameterNotification as MIB_PARAMETER_NOTIFICATION, NotifyRouteChange2, MIB_IPFORWARD_ROW2,
    MIB_NOTIFICATION_TYPE,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};

pub const WINDOWS_ROUTE_CHANGE_OBSERVER_VERSION: u32 = 1;
const MAX_RETAINED_EVENTS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsRouteChangeKindV1 {
    ParameterChanged,
    Added,
    Deleted,
    Initial,
    Unknown(i32),
}

impl WindowsRouteChangeKindV1 {
    const fn from_native(value: MIB_NOTIFICATION_TYPE) -> Self {
        match value {
            MIB_PARAMETER_NOTIFICATION => Self::ParameterChanged,
            MIB_ADD_INSTANCE => Self::Added,
            MIB_DELETE_INSTANCE => Self::Deleted,
            MIB_INITIAL_NOTIFICATION => Self::Initial,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsRouteChangeRouteV1 {
    interface: WindowsPacketInterfaceIdentity,
    network: IpAddr,
    prefix_length: u8,
}

impl WindowsRouteChangeRouteV1 {
    pub const fn interface(&self) -> WindowsPacketInterfaceIdentity {
        self.interface
    }

    pub const fn network(&self) -> IpAddr {
        self.network
    }

    pub const fn prefix_length(&self) -> u8 {
        self.prefix_length
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsRouteChangeEventV1 {
    sequence: u64,
    kind: WindowsRouteChangeKindV1,
    route: Option<WindowsRouteChangeRouteV1>,
}

impl WindowsRouteChangeEventV1 {
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn kind(&self) -> WindowsRouteChangeKindV1 {
        self.kind
    }

    pub const fn route(&self) -> Option<WindowsRouteChangeRouteV1> {
        self.route
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsRouteChangeObserverErrorCode {
    SubscribeFailed,
    InvalidSubscriptionHandle,
    ObserverClosed,
    StatePoisoned,
    SequenceExhausted,
    EventHistoryOverflow,
    WaitTimedOut,
    CancelFailed,
}

impl WindowsRouteChangeObserverErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SubscribeFailed => "subscribe_failed",
            Self::InvalidSubscriptionHandle => "invalid_subscription_handle",
            Self::ObserverClosed => "observer_closed",
            Self::StatePoisoned => "state_poisoned",
            Self::SequenceExhausted => "sequence_exhausted",
            Self::EventHistoryOverflow => "event_history_overflow",
            Self::WaitTimedOut => "wait_timed_out",
            Self::CancelFailed => "cancel_failed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsRouteChangeObserverError {
    code: WindowsRouteChangeObserverErrorCode,
    win32_code: Option<u32>,
}

impl WindowsRouteChangeObserverError {
    const fn new(code: WindowsRouteChangeObserverErrorCode) -> Self {
        Self {
            code,
            win32_code: None,
        }
    }

    const fn win32(code: WindowsRouteChangeObserverErrorCode, win32_code: u32) -> Self {
        Self {
            code,
            win32_code: Some(win32_code),
        }
    }

    pub const fn code(&self) -> WindowsRouteChangeObserverErrorCode {
        self.code
    }

    pub const fn win32_code(&self) -> Option<u32> {
        self.win32_code
    }
}

impl fmt::Display for WindowsRouteChangeObserverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.win32_code {
            Some(win32_code) => write!(
                formatter,
                "{} (Win32 error {win32_code})",
                self.code.as_str()
            ),
            None => formatter.write_str(self.code.as_str()),
        }
    }
}

impl Error for WindowsRouteChangeObserverError {}

#[derive(Debug)]
struct ObserverState {
    next_sequence: u64,
    dropped_through_sequence: u64,
    sequence_exhausted: bool,
    events: VecDeque<WindowsRouteChangeEventV1>,
}

impl ObserverState {
    fn new() -> Self {
        Self {
            next_sequence: 1,
            dropped_through_sequence: 0,
            sequence_exhausted: false,
            events: VecDeque::with_capacity(MAX_RETAINED_EVENTS),
        }
    }

    fn push(&mut self, kind: WindowsRouteChangeKindV1, route: Option<WindowsRouteChangeRouteV1>) {
        let sequence = self.next_sequence;
        let Some(next_sequence) = sequence.checked_add(1) else {
            self.sequence_exhausted = true;
            return;
        };
        self.next_sequence = next_sequence;
        if self.events.len() == MAX_RETAINED_EVENTS {
            if let Some(dropped) = self.events.pop_front() {
                self.dropped_through_sequence = dropped.sequence;
            }
        }
        self.events.push_back(WindowsRouteChangeEventV1 {
            sequence,
            kind,
            route,
        });
    }

    const fn checkpoint(&self) -> u64 {
        self.next_sequence - 1
    }
}

struct ObserverContext {
    state: Mutex<ObserverState>,
    changed: Condvar,
}

impl ObserverContext {
    fn new() -> Self {
        Self {
            state: Mutex::new(ObserverState::new()),
            changed: Condvar::new(),
        }
    }
}

/// One exact kernel route-change subscription.
///
/// Cancellation never holds the callback mutex. If Windows rejects
/// cancellation, the callback context is intentionally retained for process
/// lifetime rather than freed while the kernel may still reference it.
pub struct WindowsRouteChangeObserverV1 {
    handle: HANDLE,
    context: *mut ObserverContext,
}

impl WindowsRouteChangeObserverV1 {
    pub fn subscribe() -> Result<Self, WindowsRouteChangeObserverError> {
        use WindowsRouteChangeObserverErrorCode as Code;

        let context = Box::into_raw(Box::new(ObserverContext::new()));
        let mut handle: HANDLE = null_mut();
        let result = unsafe {
            NotifyRouteChange2(
                AF_UNSPEC,
                Some(route_change_callback),
                context.cast::<c_void>(),
                false,
                &mut handle,
            )
        };
        if result != 0 {
            unsafe {
                drop(Box::from_raw(context));
            }
            return Err(WindowsRouteChangeObserverError::win32(
                Code::SubscribeFailed,
                result,
            ));
        }
        if handle.is_null() {
            // Windows reported a successful registration but did not return a
            // handle that can cancel it. Retain the callback context for
            // process lifetime because the kernel may still reference it.
            return Err(WindowsRouteChangeObserverError::new(
                Code::InvalidSubscriptionHandle,
            ));
        }
        Ok(Self { handle, context })
    }

    pub fn checkpoint(&self) -> Result<u64, WindowsRouteChangeObserverError> {
        let state = self.lock_state()?;
        require_sequence_available(&state)?;
        Ok(state.checkpoint())
    }

    pub fn wait_for_route_after(
        &self,
        after_sequence: u64,
        kind: WindowsRouteChangeKindV1,
        interface: WindowsPacketInterfaceIdentity,
        network: IpAddr,
        prefix_length: u8,
        timeout: Duration,
    ) -> Result<WindowsRouteChangeEventV1, WindowsRouteChangeObserverError> {
        use WindowsRouteChangeObserverErrorCode as Code;

        let deadline = Instant::now() + timeout;
        let mut state = self.lock_state()?;
        loop {
            require_sequence_available(&state)?;
            if after_sequence < state.dropped_through_sequence {
                return Err(WindowsRouteChangeObserverError::new(
                    Code::EventHistoryOverflow,
                ));
            }
            if let Some(event) = state.events.iter().copied().find(|event| {
                event.sequence > after_sequence
                    && event.kind == kind
                    && event.route
                        == Some(WindowsRouteChangeRouteV1 {
                            interface,
                            network,
                            prefix_length,
                        })
            }) {
                return Ok(event);
            }

            let now = Instant::now();
            if now >= deadline {
                return Err(WindowsRouteChangeObserverError::new(Code::WaitTimedOut));
            }
            let wait = deadline.saturating_duration_since(now);
            let (next_state, timeout_result) = self
                .context_ref()?
                .changed
                .wait_timeout(state, wait)
                .map_err(|_| WindowsRouteChangeObserverError::new(Code::StatePoisoned))?;
            state = next_state;
            if timeout_result.timed_out() {
                return Err(WindowsRouteChangeObserverError::new(Code::WaitTimedOut));
            }
        }
    }

    pub fn close(&mut self) -> Result<(), WindowsRouteChangeObserverError> {
        use WindowsRouteChangeObserverErrorCode as Code;

        if self.handle.is_null() {
            return Ok(());
        }
        let handle = self.handle;
        let context = self.context;
        let result = unsafe { CancelMibChangeNotify2(handle) };
        self.handle = null_mut();
        self.context = null_mut();
        if result != 0 {
            // The kernel may still call this context. Retain it rather than
            // risking a callback use-after-free.
            return Err(WindowsRouteChangeObserverError::win32(
                Code::CancelFailed,
                result,
            ));
        }
        unsafe {
            drop(Box::from_raw(context));
        }
        Ok(())
    }

    fn context_ref(&self) -> Result<&ObserverContext, WindowsRouteChangeObserverError> {
        use WindowsRouteChangeObserverErrorCode as Code;

        if self.context.is_null() || self.handle.is_null() {
            return Err(WindowsRouteChangeObserverError::new(Code::ObserverClosed));
        }
        Ok(unsafe { &*self.context })
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, ObserverState>, WindowsRouteChangeObserverError> {
        use WindowsRouteChangeObserverErrorCode as Code;

        self.context_ref()?
            .state
            .lock()
            .map_err(|_| WindowsRouteChangeObserverError::new(Code::StatePoisoned))
    }
}

impl Drop for WindowsRouteChangeObserverV1 {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn require_sequence_available(
    state: &ObserverState,
) -> Result<(), WindowsRouteChangeObserverError> {
    if state.sequence_exhausted {
        return Err(WindowsRouteChangeObserverError::new(
            WindowsRouteChangeObserverErrorCode::SequenceExhausted,
        ));
    }
    Ok(())
}

unsafe extern "system" fn route_change_callback(
    caller_context: *const c_void,
    row: *const MIB_IPFORWARD_ROW2,
    notification_type: MIB_NOTIFICATION_TYPE,
) {
    if caller_context.is_null() {
        return;
    }
    let context = unsafe { &*caller_context.cast::<ObserverContext>() };
    let route = if row.is_null() {
        None
    } else {
        route_from_native_row(unsafe { &*row })
    };
    let mut state = match context.state.lock() {
        Ok(state) => state,
        Err(poisoned) => poisoned.into_inner(),
    };
    state.push(
        WindowsRouteChangeKindV1::from_native(notification_type),
        route,
    );
    drop(state);
    context.changed.notify_all();
}

fn route_from_native_row(row: &MIB_IPFORWARD_ROW2) -> Option<WindowsRouteChangeRouteV1> {
    let network = ip_from_native_prefix(row)?;
    let interface = WindowsPacketInterfaceIdentity {
        luid: unsafe { row.InterfaceLuid.Value },
        index: row.InterfaceIndex,
    };
    if interface.luid == 0 || interface.index == 0 {
        return None;
    }
    Some(WindowsRouteChangeRouteV1 {
        interface,
        network,
        prefix_length: row.DestinationPrefix.PrefixLength,
    })
}

fn ip_from_native_prefix(row: &MIB_IPFORWARD_ROW2) -> Option<IpAddr> {
    let address = &row.DestinationPrefix.Prefix;
    let family = unsafe { address.si_family };
    match family {
        AF_INET => {
            let octets = unsafe { address.Ipv4.sin_addr.S_un.S_un_b };
            Some(IpAddr::V4(Ipv4Addr::new(
                octets.s_b1,
                octets.s_b2,
                octets.s_b3,
                octets.s_b4,
            )))
        }
        AF_INET6 => {
            let octets = unsafe { address.Ipv6.sin6_addr.u.Byte };
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}
