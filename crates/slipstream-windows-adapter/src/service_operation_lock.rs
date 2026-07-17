//! Machine-wide serialization for privileged Windows service lifecycle effects.

use std::ffi::c_void;
use std::fmt;
use std::mem::{size_of, MaybeUninit};
use std::ptr::{addr_of, null_mut};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_SUCCESS, HANDLE, HLOCAL, WAIT_ABANDONED, WAIT_FAILED,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, GetAce, GetAclInformation, IsValidAcl, IsValidSid, IsWellKnownSid,
    WinBuiltinAdministratorsSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
    ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE};
use windows_sys::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};

const OPERATION_MUTEX_NAME: &str = r"Global\SlipstreamServiceLifecycleV1";
const TRUSTED_KERNEL_OBJECT_SDDL: &str = "O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)";
const OPERATION_LOCK_TIMEOUT_MS: u32 = 30_000;

pub(crate) fn acquire_service_operation_lock(
) -> Result<WindowsServiceOperationGuard, WindowsServiceOperationLockError> {
    acquire_service_operation_lock_with_timeout(OPERATION_LOCK_TIMEOUT_MS)
}

fn acquire_service_operation_lock_with_timeout(
    timeout_ms: u32,
) -> Result<WindowsServiceOperationGuard, WindowsServiceOperationLockError> {
    acquire_named_service_operation_lock_with_timeout(OPERATION_MUTEX_NAME, timeout_ms)
}

fn acquire_named_service_operation_lock_with_timeout(
    mutex_name: &str,
    timeout_ms: u32,
) -> Result<WindowsServiceOperationGuard, WindowsServiceOperationLockError> {
    let descriptor = trusted_kernel_object_security_descriptor()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0.cast::<c_void>(),
        bInheritHandle: 0,
    };
    let name = wide_null(mutex_name);
    let handle = unsafe { CreateMutexW(&attributes, 0, name.as_ptr()) };
    if handle.is_null() {
        return Err(last_error("CreateMutexW"));
    }
    match has_trusted_kernel_object_security(handle) {
        Ok(true) => {}
        Ok(false) => {
            unsafe {
                CloseHandle(handle);
            }
            return Err(WindowsServiceOperationLockError::Verification(
                "kernel object owner or DACL is untrusted",
            ));
        }
        Err(error) => {
            unsafe {
                CloseHandle(handle);
            }
            return Err(error);
        }
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

fn trusted_kernel_object_security_descriptor(
) -> Result<OwnedLocalSecurityDescriptor, WindowsServiceOperationLockError> {
    security_descriptor_from_sddl(
        TRUSTED_KERNEL_OBJECT_SDDL,
        "create service operation lock descriptor",
    )
}

fn security_descriptor_from_sddl(
    value: &str,
    operation: &'static str,
) -> Result<OwnedLocalSecurityDescriptor, WindowsServiceOperationLockError> {
    let sddl = wide_null(value);
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
        return Err(last_error(operation));
    }
    if descriptor.is_null() {
        return Err(WindowsServiceOperationLockError::Verification(
            "trusted kernel-object descriptor is null",
        ));
    }
    Ok(OwnedLocalSecurityDescriptor(descriptor))
}

fn has_trusted_kernel_object_security(
    handle: HANDLE,
) -> Result<bool, WindowsServiceOperationLockError> {
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let result = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    let owned_descriptor = OwnedLocalSecurityDescriptor(descriptor);
    if result != ERROR_SUCCESS {
        return Err(WindowsServiceOperationLockError::Win32 {
            operation: "GetSecurityInfo(service operation lock)",
            code: result,
        });
    }
    if owned_descriptor.0.is_null() || owner.is_null() || dacl.is_null() {
        return Ok(false);
    }
    if !is_trusted_machine_sid(owner) || unsafe { IsValidAcl(dacl) } == 0 {
        return Ok(false);
    }

    let mut size_information = MaybeUninit::<ACL_SIZE_INFORMATION>::zeroed();
    if unsafe {
        GetAclInformation(
            dacl,
            size_information.as_mut_ptr().cast::<c_void>(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(last_error("GetAclInformation(service operation lock)"));
    }
    let size_information = unsafe { size_information.assume_init() };
    let mut trusted_allow = false;
    for index in 0..size_information.AceCount {
        let mut raw_ace = null_mut();
        if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(last_error("GetAce(service operation lock)"));
        }
        let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
        if u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        match u32::from(header.AceType) {
            ACCESS_ALLOWED_ACE_TYPE => {
                if usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>() {
                    return Ok(false);
                }
                let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
                let sid = addr_of!(ace.SidStart).cast_mut().cast::<c_void>();
                if unsafe { IsValidSid(sid) } == 0 || !is_trusted_machine_sid(sid) {
                    return Ok(false);
                }
                trusted_allow = true;
            }
            ACCESS_DENIED_ACE_TYPE => {}
            _ => return Ok(false),
        }
    }
    Ok(trusted_allow)
}

fn is_trusted_machine_sid(sid: PSID) -> bool {
    unsafe {
        IsWellKnownSid(sid, WinLocalSystemSid) != 0
            || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
    }
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

    #[test]
    fn precreated_untrusted_mutex_is_rejected() {
        let name = format!(
            r"Global\SlipstreamServiceLifecycleV1-Untrusted-{}",
            std::process::id()
        );
        let wide = wide_null(&name);
        let descriptor =
            security_descriptor_from_sddl("D:P(A;;GA;;;WD)", "create untrusted mutex descriptor")
                .expect("create untrusted mutex descriptor");
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0.cast::<c_void>(),
            bInheritHandle: 0,
        };
        let squatted = unsafe { CreateMutexW(&attributes, 0, wide.as_ptr()) };
        assert!(!squatted.is_null(), "create disposable untrusted mutex");

        let result = acquire_named_service_operation_lock_with_timeout(&name, 25);
        unsafe {
            CloseHandle(squatted);
        }
        assert!(matches!(
            result,
            Err(WindowsServiceOperationLockError::Verification(
                "kernel object owner or DACL is untrusted"
            ))
        ));
    }
}
