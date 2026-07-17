//! Handle-bound, read-only Windows service ownership evidence.

use super::{
    assess_windows_service_ownership, parse_windows_owner_record_v1, WindowsExecutableEvidence,
    WindowsOwnerRecordEvidence, WindowsScmEvidence, WindowsServiceOwnershipAssessment,
    WindowsServiceOwnershipInput, WindowsServiceOwnershipRecord, MAX_WINDOWS_OWNER_RECORD_BYTES,
    WINDOWS_OWNER_RECORD_DIRECTORY, WINDOWS_OWNER_RECORD_FILE_NAME,
};
use crate::service_observer::{
    WindowsScmObserver, WindowsServiceObservation, WindowsServiceObserver,
    WindowsServiceObserverError,
};
use sha2::{Digest, Sha256};
use std::ffi::{c_void, OsString};
use std::fs::File;
use std::io::Read;
use std::mem::{size_of, MaybeUninit};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};
use std::ptr::{addr_of, null, null_mut};
use std::slice;
use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
    GENERIC_ALL, GENERIC_READ, GENERIC_WRITE, HANDLE, HLOCAL, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Globalization::{CompareStringOrdinal, CSTR_EQUAL};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    AclSizeInformation, GetAce, GetAclInformation, IsValidAcl, IsValidSid, IsWellKnownSid,
    WinBuiltinAdministratorsSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
    ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFileInformationByHandle, GetFinalPathNameByHandleW, BY_HANDLE_FILE_INFORMATION,
    DELETE, FILE_APPEND_DATA, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
    WRITE_OWNER,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE};
use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath};

const MAX_WINDOWS_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_FINAL_PATH_UTF16_UNITS: usize = 32_768;
const MUTATING_FILE_ACCESS: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | FILE_DELETE_CHILD
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_WRITE
    | GENERIC_ALL;

#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsServiceOwnershipCollector;

impl WindowsServiceOwnershipCollector {
    pub const fn new() -> Self {
        Self
    }

    pub fn collect_input(&self) -> WindowsServiceOwnershipInput {
        let scm = scm_evidence();
        let record = match machine_owner_record_path() {
            Ok(path) => read_owner_record(&path),
            Err(_) => WindowsOwnerRecordEvidence::Inaccessible,
        };
        let executable = match (&record, &scm) {
            (
                WindowsOwnerRecordEvidence::OwnerOnly { record },
                WindowsScmEvidence::Observed {
                    observation: WindowsServiceObservation::Present { .. },
                },
            ) => verify_executable(record),
            _ => WindowsExecutableEvidence::NotChecked,
        };
        WindowsServiceOwnershipInput {
            record,
            scm,
            executable,
        }
    }

    pub fn assess(&self) -> WindowsServiceOwnershipAssessment {
        assess_windows_service_ownership(&self.collect_input())
    }
}

fn scm_evidence() -> WindowsScmEvidence {
    match WindowsScmObserver::new().observe() {
        Ok(observation) => WindowsScmEvidence::Observed { observation },
        Err(WindowsServiceObserverError::Win32 { .. }) => WindowsScmEvidence::Inaccessible,
        Err(WindowsServiceObserverError::InvalidData { .. }) => WindowsScmEvidence::Invalid,
    }
}

fn machine_owner_record_path() -> Result<PathBuf, NativeEvidenceError> {
    let mut raw_path = null_mut();
    let result =
        unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, null_mut(), &mut raw_path) };
    let owned = OwnedCoTaskMemWide(raw_path);
    if result < 0 || owned.0.is_null() {
        return Err(NativeEvidenceError::Inaccessible);
    }
    let units = unsafe { bounded_wide_pointer(owned.0)? };
    let mut path = PathBuf::from(OsString::from_wide(units));
    path.push(WINDOWS_OWNER_RECORD_DIRECTORY);
    path.push(WINDOWS_OWNER_RECORD_FILE_NAME);
    Ok(path)
}

fn read_owner_record(path: &Path) -> WindowsOwnerRecordEvidence {
    match read_owner_record_inner(path) {
        Ok(record) => WindowsOwnerRecordEvidence::OwnerOnly { record },
        Err(NativeEvidenceError::Missing) => WindowsOwnerRecordEvidence::Missing,
        Err(NativeEvidenceError::Inaccessible) => WindowsOwnerRecordEvidence::Inaccessible,
        Err(NativeEvidenceError::Invalid) => WindowsOwnerRecordEvidence::Invalid,
        Err(NativeEvidenceError::UntrustedPermissions) => {
            WindowsOwnerRecordEvidence::UntrustedPermissions
        }
    }
}

fn read_owner_record_inner(
    path: &Path,
) -> Result<WindowsServiceOwnershipRecord, NativeEvidenceError> {
    let mut file = open_readonly(path, GENERIC_READ | READ_CONTROL)?;
    let size = validate_regular_file(&file, MAX_WINDOWS_OWNER_RECORD_BYTES as u64)?;
    if !final_path_matches(&file, path)? {
        return Err(NativeEvidenceError::Invalid);
    }
    if !has_trusted_machine_write_permissions(&file)? {
        return Err(NativeEvidenceError::UntrustedPermissions);
    }

    let mut bytes = Vec::with_capacity(size as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| NativeEvidenceError::Inaccessible)?;
    if bytes.len() as u64 != size {
        return Err(NativeEvidenceError::Invalid);
    }
    parse_windows_owner_record_v1(&bytes).map_err(|_| NativeEvidenceError::Invalid)
}

fn verify_executable(record: &WindowsServiceOwnershipRecord) -> WindowsExecutableEvidence {
    match verify_executable_inner(record) {
        Ok(executable_sha256) => WindowsExecutableEvidence::Verified {
            executable_path: record.executable_path.clone(),
            executable_sha256,
        },
        Err(NativeEvidenceError::Missing) => WindowsExecutableEvidence::Missing,
        Err(NativeEvidenceError::Inaccessible) => WindowsExecutableEvidence::Inaccessible,
        Err(NativeEvidenceError::Invalid | NativeEvidenceError::UntrustedPermissions) => {
            WindowsExecutableEvidence::Invalid
        }
    }
}

fn verify_executable_inner(
    record: &WindowsServiceOwnershipRecord,
) -> Result<String, NativeEvidenceError> {
    let path = Path::new(&record.executable_path);
    let mut file = open_readonly(path, GENERIC_READ)?;
    let size = validate_regular_file(&file, MAX_WINDOWS_EXECUTABLE_BYTES)?;
    if !final_path_matches(&file, path)? {
        return Err(NativeEvidenceError::Invalid);
    }

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| NativeEvidenceError::Inaccessible)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(NativeEvidenceError::Invalid)?;
        if total > MAX_WINDOWS_EXECUTABLE_BYTES {
            return Err(NativeEvidenceError::Invalid);
        }
        hasher.update(&buffer[..read]);
    }
    if total != size {
        return Err(NativeEvidenceError::Invalid);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn open_readonly(path: &Path, desired_access: u32) -> Result<File, NativeEvidenceError> {
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            desired_access,
            FILE_SHARE_READ,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let code = unsafe { GetLastError() };
        return Err(
            if code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND {
                NativeEvidenceError::Missing
            } else {
                NativeEvidenceError::Inaccessible
            },
        );
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn validate_regular_file(file: &File, maximum_size: u64) -> Result<u64, NativeEvidenceError> {
    let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
    let ok = unsafe { GetFileInformationByHandle(raw_handle(file), information.as_mut_ptr()) };
    if ok == 0 {
        return Err(NativeEvidenceError::Inaccessible);
    }
    let information = unsafe { information.assume_init() };
    if information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
    {
        return Err(NativeEvidenceError::Invalid);
    }
    let size = (u64::from(information.nFileSizeHigh) << 32) | u64::from(information.nFileSizeLow);
    if size == 0 || size > maximum_size {
        return Err(NativeEvidenceError::Invalid);
    }
    Ok(size)
}

fn final_path_matches(file: &File, expected: &Path) -> Result<bool, NativeEvidenceError> {
    let mut actual = vec![0u16; MAX_FINAL_PATH_UTF16_UNITS];
    let length = unsafe {
        GetFinalPathNameByHandleW(
            raw_handle(file),
            actual.as_mut_ptr(),
            actual.len() as u32,
            0,
        )
    };
    if length == 0 || length as usize >= actual.len() {
        return Err(NativeEvidenceError::Invalid);
    }
    actual.truncate(length as usize);
    let actual = strip_extended_dos_prefix(&actual);
    let expected: Vec<u16> = expected.as_os_str().encode_wide().collect();
    let expected = strip_extended_dos_prefix(&expected);
    if actual.len() > i32::MAX as usize || expected.len() > i32::MAX as usize {
        return Err(NativeEvidenceError::Invalid);
    }
    let comparison = unsafe {
        CompareStringOrdinal(
            actual.as_ptr(),
            actual.len() as i32,
            expected.as_ptr(),
            expected.len() as i32,
            1,
        )
    };
    if comparison == 0 {
        return Err(NativeEvidenceError::Invalid);
    }
    Ok(comparison == CSTR_EQUAL)
}

fn strip_extended_dos_prefix(path: &[u16]) -> &[u16] {
    const PREFIX: &[u16] = &[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
    path.strip_prefix(PREFIX).unwrap_or(path)
}

fn has_trusted_machine_write_permissions(file: &File) -> Result<bool, NativeEvidenceError> {
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let result = unsafe {
        GetSecurityInfo(
            raw_handle(file),
            SE_FILE_OBJECT,
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
        return Err(NativeEvidenceError::Inaccessible);
    }
    if owned_descriptor.0.is_null() || owner.is_null() || dacl.is_null() {
        return Ok(false);
    }
    if !is_trusted_machine_sid(owner) || unsafe { IsValidAcl(dacl) } == 0 {
        return Ok(false);
    }

    let mut size_information = MaybeUninit::<ACL_SIZE_INFORMATION>::zeroed();
    let ok = unsafe {
        GetAclInformation(
            dacl,
            size_information.as_mut_ptr().cast::<c_void>(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    };
    if ok == 0 {
        return Err(NativeEvidenceError::Invalid);
    }
    let size_information = unsafe { size_information.assume_init() };
    let mut trusted_writer = false;
    for index in 0..size_information.AceCount {
        let mut raw_ace = null_mut();
        if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(NativeEvidenceError::Invalid);
        }
        let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
        if u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        match u32::from(header.AceType) {
            ACCESS_ALLOWED_ACE_TYPE => {
                if usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>() {
                    return Err(NativeEvidenceError::Invalid);
                }
                let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
                let sid = addr_of!(ace.SidStart).cast_mut().cast::<c_void>();
                if unsafe { IsValidSid(sid) } == 0 {
                    return Err(NativeEvidenceError::Invalid);
                }
                if ace.Mask & MUTATING_FILE_ACCESS != 0 {
                    if !is_trusted_machine_sid(sid) {
                        return Ok(false);
                    }
                    trusted_writer = true;
                }
            }
            ACCESS_DENIED_ACE_TYPE => {}
            _ => return Ok(false),
        }
    }
    Ok(trusted_writer)
}

fn is_trusted_machine_sid(sid: PSID) -> bool {
    unsafe {
        IsWellKnownSid(sid, WinLocalSystemSid) != 0
            || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
    }
}

fn raw_handle(file: &File) -> HANDLE {
    file.as_raw_handle()
}

unsafe fn bounded_wide_pointer<'a>(value: *const u16) -> Result<&'a [u16], NativeEvidenceError> {
    if value.is_null() {
        return Err(NativeEvidenceError::Invalid);
    }
    for length in 0..MAX_FINAL_PATH_UTF16_UNITS {
        if unsafe { *value.add(length) } == 0 {
            return Ok(unsafe { slice::from_raw_parts(value, length) });
        }
    }
    Err(NativeEvidenceError::Invalid)
}

struct OwnedCoTaskMemWide(*mut u16);

impl Drop for OwnedCoTaskMemWide {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CoTaskMemFree(self.0.cast::<c_void>()) }
        }
    }
}

struct OwnedLocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for OwnedLocalSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0 as HLOCAL);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeEvidenceError {
    Missing,
    Inaccessible,
    Invalid,
    UntrustedPermissions,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_lifecycle::WindowsServiceOwnership;
    use crate::service_observer::{WindowsScmState, WindowsServiceSnapshot};
    use std::fs;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::SetFileSecurityW;

    fn temporary_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "slipstream-windows-evidence-{}-{name}",
            std::process::id()
        ))
    }

    #[test]
    fn exact_handle_hashes_the_opened_regular_file() {
        let path = temporary_path("executable.bin");
        fs::write(&path, b"slipstream-windows-evidence").expect("write executable fixture");
        let record = WindowsServiceOwnershipRecord {
            schema_version: 1,
            service_name: "dev.slipstream.service".into(),
            scm_binary_path: format!("\"{}\" --service", path.display()),
            executable_path: path.to_string_lossy().into_owned(),
            executable_sha256: "0".repeat(64),
            generation: 1,
        };
        let digest = verify_executable_inner(&record).expect("hash exact opened handle");
        assert_eq!(
            digest,
            "96c45d5cb404c8500d3a2f49e8aecc6b5ff98a147f0d0e6f69e325daa60850ab"
        );
        fs::remove_file(path).expect("remove executable fixture");
    }

    #[test]
    fn missing_record_is_not_inferred_from_other_machine_state() {
        let path = temporary_path("missing-owner-record.json");
        let _ = fs::remove_file(&path);
        assert_eq!(
            read_owner_record(&path),
            WindowsOwnerRecordEvidence::Missing
        );
    }

    #[test]
    fn disposable_machine_acl_and_exact_hash_produce_owned_evidence() {
        if std::env::var_os("SLIPSTREAM_WINDOWS_DISPOSABLE_CI").is_none() {
            return;
        }

        let directory = temporary_path("owner-only");
        let executable_path = directory.join("slipstream-service.exe");
        let record_path = directory.join(WINDOWS_OWNER_RECORD_FILE_NAME);
        fs::create_dir_all(&directory).expect("create evidence fixture directory");
        fs::write(&executable_path, b"slipstream-windows-evidence")
            .expect("write executable fixture");
        let executable_path = executable_path.to_string_lossy().into_owned();
        let record = WindowsServiceOwnershipRecord {
            schema_version: 1,
            service_name: "dev.slipstream.service".into(),
            scm_binary_path: format!("\"{executable_path}\" --service"),
            executable_path,
            executable_sha256: "96c45d5cb404c8500d3a2f49e8aecc6b5ff98a147f0d0e6f69e325daa60850ab"
                .into(),
            generation: 1,
        };
        fs::write(
            &record_path,
            serde_json::to_vec(&record).expect("serialize owner record"),
        )
        .expect("write owner record");
        apply_disposable_machine_acl(&record_path);

        let proven_record = match read_owner_record(&record_path) {
            WindowsOwnerRecordEvidence::OwnerOnly { record } => record,
            other => panic!("expected owner-only record evidence, got {other:?}"),
        };
        let input = WindowsServiceOwnershipInput {
            record: WindowsOwnerRecordEvidence::OwnerOnly {
                record: proven_record.clone(),
            },
            scm: WindowsScmEvidence::Observed {
                observation: WindowsServiceObservation::Present {
                    snapshot: WindowsServiceSnapshot::from_scm(
                        proven_record.scm_binary_path.clone(),
                        WindowsScmState::Stopped,
                        0,
                    ),
                },
            },
            executable: verify_executable(&proven_record),
        };
        let assessment = assess_windows_service_ownership(&input);
        assert_eq!(assessment.ownership, WindowsServiceOwnership::Owned);

        fs::remove_dir_all(directory).expect("remove evidence fixture directory");
    }

    fn apply_disposable_machine_acl(path: &Path) {
        let sddl: Vec<u16> = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut descriptor = null_mut();
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        assert_ne!(converted, 0, "convert disposable SDDL");
        let descriptor = OwnedLocalSecurityDescriptor(descriptor);
        let wide_path: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let applied = unsafe {
            SetFileSecurityW(
                wide_path.as_ptr(),
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                descriptor.0,
            )
        };
        assert_ne!(applied, 0, "apply disposable owner-only ACL");
    }
}
