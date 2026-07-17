//! Read-only Win32 Service Control Manager observer.

use super::v1::{
    WindowsScmState, WindowsServiceObservation, WindowsServiceObserver,
    WindowsServiceObserverError, WindowsServiceSnapshot,
};
use crate::service_lifecycle::WINDOWS_SERVICE_NAME;
use std::mem::{size_of, MaybeUninit};
use std::ptr::{null, null_mut};
use std::slice;
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_SERVICE_DOES_NOT_EXIST,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceConfigW, QueryServiceStatusEx,
    QUERY_SERVICE_CONFIGW, SC_HANDLE, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO,
    SERVICE_CONTINUE_PENDING, SERVICE_PAUSED, SERVICE_PAUSE_PENDING, SERVICE_QUERY_CONFIG,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS_PROCESS,
    SERVICE_STOPPED, SERVICE_STOP_PENDING,
};

const MAX_SERVICE_CONFIG_BYTES: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsScmObserver;

impl WindowsScmObserver {
    pub const fn new() -> Self {
        Self
    }
}

impl WindowsServiceObserver for WindowsScmObserver {
    fn observe(&self) -> Result<WindowsServiceObservation, WindowsServiceObserverError> {
        let manager_handle = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
        let manager = OwnedScHandle::open(manager_handle, "OpenSCManagerW")?;
        let service_name = wide_null(WINDOWS_SERVICE_NAME);
        let service_handle = unsafe {
            OpenServiceW(
                manager.raw(),
                service_name.as_ptr(),
                SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
            )
        };
        if service_handle.is_null() {
            let code = unsafe { GetLastError() };
            if code == ERROR_SERVICE_DOES_NOT_EXIST {
                return Ok(WindowsServiceObservation::absent());
            }
            return Err(WindowsServiceObserverError::Win32 {
                operation: "OpenServiceW",
                code,
            });
        }
        let service = OwnedScHandle(service_handle);

        observe_open_service_handle(service.raw())
    }
}

pub(crate) fn observe_open_service_handle(
    service: SC_HANDLE,
) -> Result<WindowsServiceObservation, WindowsServiceObserverError> {
    if service.is_null() {
        return Err(WindowsServiceObserverError::InvalidData {
            field: "service_handle",
            detail: "handle is null",
        });
    }
    let (scm_state, process_id) = query_status(service)?;
    let binary_path = query_binary_path(service)?;
    Ok(WindowsServiceObservation::Present {
        snapshot: WindowsServiceSnapshot::from_scm(binary_path, scm_state, process_id),
    })
}

struct OwnedScHandle(SC_HANDLE);

impl OwnedScHandle {
    fn open(
        handle: SC_HANDLE,
        operation: &'static str,
    ) -> Result<Self, WindowsServiceObserverError> {
        if handle.is_null() {
            return Err(WindowsServiceObserverError::Win32 {
                operation,
                code: unsafe { GetLastError() },
            });
        }
        Ok(Self(handle))
    }

    const fn raw(&self) -> SC_HANDLE {
        self.0
    }
}

impl Drop for OwnedScHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseServiceHandle(self.0);
            }
        }
    }
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn query_status(service: SC_HANDLE) -> Result<(WindowsScmState, u32), WindowsServiceObserverError> {
    let mut status = MaybeUninit::<SERVICE_STATUS_PROCESS>::zeroed();
    let mut bytes_needed = 0;
    let ok = unsafe {
        QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            status.as_mut_ptr().cast::<u8>(),
            size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut bytes_needed,
        )
    };
    if ok == 0 {
        return Err(last_error("QueryServiceStatusEx"));
    }
    let status = unsafe { status.assume_init() };
    Ok((map_scm_state(status.dwCurrentState), status.dwProcessId))
}

fn query_binary_path(service: SC_HANDLE) -> Result<String, WindowsServiceObserverError> {
    let mut bytes_needed = 0;
    let first = unsafe { QueryServiceConfigW(service, null_mut(), 0, &mut bytes_needed) };
    if first != 0 {
        return Err(WindowsServiceObserverError::InvalidData {
            field: "configuration",
            detail: "size probe unexpectedly succeeded",
        });
    }
    let code = unsafe { GetLastError() };
    if code != ERROR_INSUFFICIENT_BUFFER {
        return Err(WindowsServiceObserverError::Win32 {
            operation: "QueryServiceConfigW(size)",
            code,
        });
    }
    let required = bytes_needed as usize;
    if required == 0 || required > MAX_SERVICE_CONFIG_BYTES {
        return Err(WindowsServiceObserverError::InvalidData {
            field: "configuration",
            detail: "reported size is outside the SCM limit",
        });
    }

    let word_size = size_of::<usize>();
    let word_count = required.div_ceil(word_size);
    let mut buffer = vec![0usize; word_count];
    let buffer_bytes = buffer.len() * word_size;
    let config = buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    let ok =
        unsafe { QueryServiceConfigW(service, config, buffer_bytes as u32, &mut bytes_needed) };
    if ok == 0 {
        return Err(last_error("QueryServiceConfigW"));
    }

    let binary_path = unsafe { (*config).lpBinaryPathName };
    unsafe { bounded_wide_string(binary_path, buffer.as_ptr().cast::<u8>(), buffer_bytes) }
}

unsafe fn bounded_wide_string(
    value: *const u16,
    buffer: *const u8,
    buffer_bytes: usize,
) -> Result<String, WindowsServiceObserverError> {
    if value.is_null() {
        return Err(WindowsServiceObserverError::InvalidData {
            field: "binary_path",
            detail: "pointer is null",
        });
    }
    let start = buffer as usize;
    let end = start + buffer_bytes;
    let value_start = value as usize;
    if value_start < start || value_start >= end || (value_start - start) % 2 != 0 {
        return Err(WindowsServiceObserverError::InvalidData {
            field: "binary_path",
            detail: "pointer is outside the query buffer",
        });
    }
    let remaining_units = (end - value_start) / size_of::<u16>();
    let units = unsafe { slice::from_raw_parts(value, remaining_units) };
    let terminator = units.iter().position(|unit| *unit == 0).ok_or(
        WindowsServiceObserverError::InvalidData {
            field: "binary_path",
            detail: "value is not null-terminated",
        },
    )?;
    String::from_utf16(&units[..terminator]).map_err(|_| WindowsServiceObserverError::InvalidData {
        field: "binary_path",
        detail: "value is not valid UTF-16",
    })
}

fn map_scm_state(state: u32) -> WindowsScmState {
    match state {
        SERVICE_STOPPED => WindowsScmState::Stopped,
        SERVICE_START_PENDING => WindowsScmState::StartPending,
        SERVICE_STOP_PENDING => WindowsScmState::StopPending,
        SERVICE_RUNNING => WindowsScmState::Running,
        SERVICE_CONTINUE_PENDING => WindowsScmState::ContinuePending,
        SERVICE_PAUSE_PENDING => WindowsScmState::PausePending,
        SERVICE_PAUSED => WindowsScmState::Paused,
        other => WindowsScmState::Unknown(other),
    }
}

fn last_error(operation: &'static str) -> WindowsServiceObserverError {
    WindowsServiceObserverError::Win32 {
        operation,
        code: unsafe { GetLastError() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_scm_constants_map_conservatively() {
        assert_eq!(map_scm_state(SERVICE_STOPPED), WindowsScmState::Stopped);
        assert_eq!(
            map_scm_state(SERVICE_START_PENDING),
            WindowsScmState::StartPending
        );
        assert_eq!(
            map_scm_state(SERVICE_STOP_PENDING),
            WindowsScmState::StopPending
        );
        assert_eq!(map_scm_state(SERVICE_RUNNING), WindowsScmState::Running);
        assert_eq!(
            map_scm_state(SERVICE_CONTINUE_PENDING),
            WindowsScmState::ContinuePending
        );
        assert_eq!(
            map_scm_state(SERVICE_PAUSE_PENDING),
            WindowsScmState::PausePending
        );
        assert_eq!(map_scm_state(SERVICE_PAUSED), WindowsScmState::Paused);
        assert_eq!(map_scm_state(99), WindowsScmState::Unknown(99));
    }
}
