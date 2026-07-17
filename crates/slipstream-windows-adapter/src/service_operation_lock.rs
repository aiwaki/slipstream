//! Machine-wide serialization for privileged Windows service lifecycle effects.

use std::ffi::c_void;
use std::fmt;
use std::mem::size_of;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, HLOCAL, WAIT_ABANDONED, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};

const OPERATION_MUTEX_NAME: &str = r"Global\SlipstreamServiceLifecycleV1";
const OWNER_ONLY_SDDL: &str = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";
const OPERATION_LOCK_TIMEOUT_MS: u32 = 30_000;

pub(crate) fn acquire_service_operation_lock(
) -> Result<WindowsServiceOperationGuard, WindowsServiceOperationLockError> {
    acquire_service_operation_lock_with_timeout(OPERATION_LOCK_TIMEOUT_MS)
}

fn acquire_service_operation_lock_with_timeout(
    timeout_ms: u32,
) -> Result<WindowsServiceOperationGuard, WindowsServiceOperationLockError> {
    let descriptor = owner_only_security_descriptor()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0.cast::<c_void>(),
        bInheritHandle: 0,
    };
    let name = wide_null(OPERATION_MUTEX_NAME);
    let handle = unsafe { CreateMutexW(&attributes, 0, name.as_ptr()) };
    if handle.is_null() {
        return Err(last_error("CreateMutexW"));
    }

    match unsafe { WaitForSingleObject(handle, timeout_ms) } {
        WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(WindowsServiceOperationGuard(handle)),
        WAIT_TIMEOUT => {
            unsafe {
                CloseHandle(handle);
            }
            Err(WindowsServiceOperationLockError::TimedOut)
        }
        WAIT_FAILED => {
            let error = last_error("WaitForSingleObject");
            unsafe {
                CloseHandle(handle);
            }
            Err(error)
        }
        value => {
            unsafe {
                CloseHandle(handle);
            }
            Err(WindowsServiceOperationLockError::UnexpectedWait(value))
        }
    }
}

pub(crate) struct WindowsServiceOperationGuard(HANDLE);

impl Drop for WindowsServiceOperationGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                ReleaseMutex(self.0);
                CloseHandle(self.0);
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WindowsServiceOperationLockError {
    TimedOut,
    Win32 { operation: &'static str, code: u32 },
    UnexpectedWait(u32),
    Verification(&'static str),
}

impl fmt::Display for WindowsServiceOperationLockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimedOut => {
                formatter.write_str("timed out waiting for the service operation lock")
            }
            Self::Win32 { operation, code } => {
                write!(formatter, "{operation} failed with Win32 error {code}")
            }
            Self::UnexpectedWait(value) => {
                write!(
                    formatter,
                    "service operation lock returned wait status {value}"
                )
            }
            Self::Verification(detail) => {
                write!(
                    formatter,
                    "service operation lock verification failed: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for WindowsServiceOperationLockError {}

fn owner_only_security_descriptor(
) -> Result<OwnedLocalSecurityDescriptor, WindowsServiceOperationLockError> {
    let sddl = wide_null(OWNER_ONLY_SDDL);
    let mut descriptor = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(last_error("create service operation lock descriptor"));
    }
    if descriptor.is_null() {
        return Err(WindowsServiceOperationLockError::Verification(
            "owner-only descriptor is null",
        ));
    }
    Ok(OwnedLocalSecurityDescriptor(descriptor))
}

struct OwnedLocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for OwnedLocalSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                windows_sys::Win32::Foundation::LocalFree(self.0 as HLOCAL);
            }
        }
    }
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn last_error(operation: &'static str) -> WindowsServiceOperationLockError {
    WindowsServiceOperationLockError::Win32 {
        operation,
        code: unsafe { GetLastError() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn machine_wide_lock_serializes_concurrent_effects() {
        let first = acquire_service_operation_lock().expect("acquire first operation lock");
        let timed_out = thread::spawn(|| {
            matches!(
                acquire_service_operation_lock_with_timeout(25),
                Err(WindowsServiceOperationLockError::TimedOut)
            )
        })
        .join()
        .expect("join lock contender");
        assert!(timed_out, "concurrent service effect must not enter");
        drop(first);
        let _next = acquire_service_operation_lock_with_timeout(1_000)
            .expect("lock must be reusable after release");
    }
}
