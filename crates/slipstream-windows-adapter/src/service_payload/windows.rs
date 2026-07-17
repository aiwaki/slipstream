//! Windows-only, handle-bound payload staging for lifecycle v1.

use crate::service_lifecycle::{
    WindowsServiceAction, WindowsServiceActionKind, WindowsServiceEffects, WindowsServiceIdentity,
};
use crate::service_operation_lock::{
    acquire_service_operation_lock, WindowsServiceOperationLockError,
};
use crate::service_ownership::windows::{
    final_path_matches, has_trusted_machine_write_permissions, machine_owner_record_path,
    raw_handle, staged_payload_evidence_at, validate_regular_file, NativeEvidenceError,
};
use crate::service_ownership::{
    canonical_scm_binary_path, parse_windows_owner_record_v1, WindowsExecutableEvidence,
    WindowsOwnerRecordEvidence, WindowsServiceOwnershipRecord, WindowsStagedPayloadEvidence,
    MAX_WINDOWS_OWNER_RECORD_BYTES, WINDOWS_SERVICE_OWNERSHIP_RECORD_SCHEMA_VERSION,
};
use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::{size_of, MaybeUninit};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND,
    GENERIC_READ, GENERIC_WRITE, HLOCAL, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FileDispositionInfo, FlushFileBuffers,
    GetFileInformationByHandle, MoveFileExW, SetFileInformationByHandle,
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, DELETE, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, MOVEFILE_WRITE_THROUGH, OPEN_EXISTING, READ_CONTROL,
};

#[cfg(test)]
use crate::service_ownership::WINDOWS_OWNER_RECORD_FILE_NAME;

const WINDOWS_PAYLOAD_DIRECTORY: &str = "payloads";
const WINDOWS_PAYLOAD_FILE_PREFIX: &str = "slipstream-service-";
const WINDOWS_PAYLOAD_PENDING_SUFFIX: &str = ".pending-v1";
const WINDOWS_OWNER_RECORD_PENDING_FILE_NAME: &str = ".service-owner-v1.json.pending-v1";
const MAX_WINDOWS_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const OWNER_ONLY_SDDL: &str = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";

pub struct WindowsServicePayloadEffects {
    source_path: PathBuf,
    #[cfg(test)]
    destination_directory_override: Option<PathBuf>,
    #[cfg(test)]
    fail_after_record_commit: bool,
    #[cfg(test)]
    fail_after_executable_create: bool,
    #[cfg(test)]
    fail_after_record_create: bool,
}

impl WindowsServicePayloadEffects {
    pub fn new(source_path: impl Into<PathBuf>) -> Self {
        Self {
            source_path: source_path.into(),
            #[cfg(test)]
            destination_directory_override: None,
            #[cfg(test)]
            fail_after_record_commit: false,
            #[cfg(test)]
            fail_after_executable_create: false,
            #[cfg(test)]
            fail_after_record_create: false,
        }
    }

    pub fn stage_payload(
        &self,
        identity: &WindowsServiceIdentity,
    ) -> Result<(), WindowsServicePayloadError> {
        let _operation_guard = acquire_service_operation_lock()?;
        self.stage_payload_locked(identity)
    }

    fn stage_payload_locked(
        &self,
        identity: &WindowsServiceIdentity,
    ) -> Result<(), WindowsServicePayloadError> {
        identity
            .validate()
            .map_err(|_| WindowsServicePayloadError::InvalidIdentity)?;
        let paths = self.destination_paths(identity)?;
        let mut transaction = StageTransaction::default();
        let result = self.stage_payload_inner(identity, &paths, &mut transaction);
        match result {
            Ok(()) => {
                transaction.disarm();
                Ok(())
            }
            Err(primary) => match transaction.compensate() {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(WindowsServicePayloadError::CompensationFailed {
                    primary: primary.to_string(),
                    cleanup: cleanup.to_string(),
                }),
            },
        }
    }

    pub fn remove_owned_payload(
        &self,
        identity: &WindowsServiceIdentity,
    ) -> Result<(), WindowsServicePayloadError> {
        let _operation_guard = acquire_service_operation_lock()?;
        self.remove_owned_payload_locked(identity)
    }

    fn remove_owned_payload_locked(
        &self,
        identity: &WindowsServiceIdentity,
    ) -> Result<(), WindowsServicePayloadError> {
        identity
            .validate()
            .map_err(|_| WindowsServicePayloadError::InvalidIdentity)?;
        let paths = self.destination_paths(identity)?;
        let evidence = staged_payload_evidence_at(&paths.record);
        let record = exact_staged_record(&evidence, identity, &paths.executable)?;

        let mut record_file = open_existing_file(
            &paths.record,
            GENERIC_READ | READ_CONTROL | DELETE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
        )?
        .ok_or(WindowsServicePayloadError::ExistingState(
            "owner record disappeared before removal",
        ))?;
        let reopened_record = read_exact_record_handle(&mut record_file, &paths.record)?;
        if reopened_record != record {
            return Err(WindowsServicePayloadError::ExistingState(
                "owner record changed before removal",
            ));
        }

        let mut executable_file = open_existing_file(
            &paths.executable,
            GENERIC_READ | READ_CONTROL | DELETE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
        )?
        .ok_or(WindowsServicePayloadError::ExistingState(
            "owned executable disappeared before removal",
        ))?;
        verify_executable_handle(
            &mut executable_file,
            &paths.executable,
            &identity.executable_sha256,
        )?;

        mark_delete_on_close(&record_file, "delete owner record")?;
        drop(record_file);
        mark_delete_on_close(&executable_file, "delete owned executable")?;
        drop(executable_file);
        Ok(())
    }

    pub(crate) fn verify_payload_absent_locked(
        &self,
        identity: &WindowsServiceIdentity,
    ) -> Result<(), WindowsServicePayloadError> {
        if self.payload_is_absent_locked(identity)? {
            return Ok(());
        }
        Err(WindowsServicePayloadError::ExistingState(
            "owned or pending payload state remains",
        ))
    }

    pub(crate) fn payload_is_absent_locked(
        &self,
        identity: &WindowsServiceIdentity,
    ) -> Result<bool, WindowsServicePayloadError> {
        identity
            .validate()
            .map_err(|_| WindowsServicePayloadError::InvalidIdentity)?;
        let paths = self.destination_paths(identity)?;
        for path in [
            &paths.record,
            &paths.record_pending,
            &paths.executable,
            &paths.executable_pending,
        ] {
            if open_existing_file(
                path,
                GENERIC_READ | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            )?
            .is_some()
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn stage_payload_inner(
        &self,
        identity: &WindowsServiceIdentity,
        paths: &DestinationPaths,
        transaction: &mut StageTransaction,
    ) -> Result<(), WindowsServicePayloadError> {
        let mut source = open_existing_file(&self.source_path, GENERIC_READ, FILE_SHARE_READ)?
            .ok_or(WindowsServicePayloadError::InvalidSource(
                "payload source is missing",
            ))?;
        let source_size = validate_regular_file(&source, MAX_WINDOWS_EXECUTABLE_BYTES)
            .map_err(map_source_evidence_error)?;
        if !final_path_matches(&source, &self.source_path).map_err(map_source_evidence_error)? {
            return Err(WindowsServicePayloadError::InvalidSource(
                "payload source path is not exact",
            ));
        }
        let source_digest = hash_open_file(&mut source, source_size, "hash payload source")?;
        if source_digest != identity.executable_sha256 {
            return Err(WindowsServicePayloadError::HashMismatch);
        }
        source
            .seek(SeekFrom::Start(0))
            .map_err(|_| WindowsServicePayloadError::Io("rewind payload source"))?;

        match staged_payload_evidence_at(&paths.record) {
            WindowsStagedPayloadEvidence {
                record: WindowsOwnerRecordEvidence::Missing,
                executable: WindowsExecutableEvidence::NotChecked,
            } => {}
            evidence => {
                exact_staged_record(&evidence, identity, &paths.executable)?;
                verify_existing_executable(&paths.executable, &identity.executable_sha256)?;
                return Ok(());
            }
        }

        ensure_secure_directory(&paths.destination_directory)?;
        ensure_secure_directory(&paths.payload_directory)?;

        if !verify_optional_existing_executable(&paths.executable, &identity.executable_sha256)? {
            transaction.executable = Some(create_new_secure_file(&paths.executable_pending)?);
            #[cfg(test)]
            if self.fail_after_executable_create {
                return Err(WindowsServicePayloadError::Verification(
                    "injected failure after pending executable creation",
                ));
            }
            let pending =
                transaction
                    .executable
                    .as_mut()
                    .ok_or(WindowsServicePayloadError::Verification(
                        "payload transaction lost its executable handle",
                    ))?;
            copy_exact_payload(
                &mut source,
                pending,
                source_size,
                &identity.executable_sha256,
            )?;
            verify_created_file(
                pending,
                &paths.executable_pending,
                &identity.executable_sha256,
            )?;
            move_file_exact(
                &paths.executable_pending,
                &paths.executable,
                "commit payload executable",
            )?;
            let pending =
                transaction
                    .executable
                    .as_mut()
                    .ok_or(WindowsServicePayloadError::Verification(
                        "payload transaction lost its executable handle",
                    ))?;
            verify_executable_handle(pending, &paths.executable, &identity.executable_sha256)?;
        }

        let record = WindowsServiceOwnershipRecord {
            schema_version: WINDOWS_SERVICE_OWNERSHIP_RECORD_SCHEMA_VERSION,
            service_name: identity.service_name.clone(),
            scm_binary_path: canonical_scm_binary_path(&path_text(&paths.executable)?),
            executable_path: path_text(&paths.executable)?,
            executable_sha256: identity.executable_sha256.clone(),
            generation: identity.generation,
        };
        record
            .validate()
            .map_err(|_| WindowsServicePayloadError::Verification("invalid owner record"))?;
        let record_bytes = serde_json::to_vec(&record)
            .map_err(|_| WindowsServicePayloadError::Verification("serialize owner record"))?;
        if record_bytes.is_empty() || record_bytes.len() > MAX_WINDOWS_OWNER_RECORD_BYTES {
            return Err(WindowsServicePayloadError::Verification(
                "serialized owner record is out of bounds",
            ));
        }

        transaction.record = Some(create_new_secure_file(&paths.record_pending)?);
        #[cfg(test)]
        if self.fail_after_record_create {
            return Err(WindowsServicePayloadError::Verification(
                "injected failure after pending owner record creation",
            ));
        }
        let pending_record =
            transaction
                .record
                .as_mut()
                .ok_or(WindowsServicePayloadError::Verification(
                    "payload transaction lost its owner record handle",
                ))?;
        pending_record
            .write_all(&record_bytes)
            .map_err(|_| WindowsServicePayloadError::Io("write owner record"))?;
        flush_file(pending_record, "flush owner record")?;
        verify_record_handle(pending_record, &paths.record_pending, &record)?;
        move_file_exact(&paths.record_pending, &paths.record, "commit owner record")?;
        let pending_record =
            transaction
                .record
                .as_mut()
                .ok_or(WindowsServicePayloadError::Verification(
                    "payload transaction lost its owner record handle",
                ))?;
        verify_record_handle(pending_record, &paths.record, &record)?;

        #[cfg(test)]
        if self.fail_after_record_commit {
            return Err(WindowsServicePayloadError::Verification(
                "injected failure after owner record commit",
            ));
        }

        let evidence = staged_payload_evidence_at(&paths.record);
        exact_staged_record(&evidence, identity, &paths.executable)?;
        Ok(())
    }

    fn destination_paths(
        &self,
        identity: &WindowsServiceIdentity,
    ) -> Result<DestinationPaths, WindowsServicePayloadError> {
        #[cfg(test)]
        let record = match &self.destination_directory_override {
            Some(directory) => directory.join(WINDOWS_OWNER_RECORD_FILE_NAME),
            None => machine_owner_record_path().map_err(map_destination_evidence_error)?,
        };
        #[cfg(not(test))]
        let record = machine_owner_record_path().map_err(map_destination_evidence_error)?;

        let destination_directory = record.parent().map(Path::to_path_buf).ok_or(
            WindowsServicePayloadError::Verification("owner record has no parent directory"),
        )?;
        let payload_directory = destination_directory.join(WINDOWS_PAYLOAD_DIRECTORY);
        let executable_name = format!(
            "{WINDOWS_PAYLOAD_FILE_PREFIX}{}.exe",
            identity.executable_sha256
        );
        let executable = payload_directory.join(&executable_name);
        let executable_pending = payload_directory.join(format!(
            ".{executable_name}{WINDOWS_PAYLOAD_PENDING_SUFFIX}"
        ));
        let record_pending = destination_directory.join(WINDOWS_OWNER_RECORD_PENDING_FILE_NAME);
        Ok(DestinationPaths {
            destination_directory,
            payload_directory,
            executable,
            executable_pending,
            record,
            record_pending,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_disposable_test(
        source_path: PathBuf,
        destination_directory: PathBuf,
    ) -> Self {
        Self {
            source_path,
            destination_directory_override: Some(destination_directory),
            fail_after_record_commit: false,
            fail_after_executable_create: false,
            fail_after_record_create: false,
        }
    }

    pub(crate) fn apply_locked(
        &mut self,
        action: &WindowsServiceAction,
    ) -> Result<(), WindowsServicePayloadError> {
        match action {
            WindowsServiceAction::StagePayload { identity } => self.stage_payload_locked(identity),
            WindowsServiceAction::RemoveOwnedPayload { identity } => {
                self.remove_owned_payload_locked(identity)
            }
            _ => Err(WindowsServicePayloadError::UnsupportedAction(action.kind())),
        }
    }
}

impl WindowsServiceEffects for WindowsServicePayloadEffects {
    type Error = WindowsServicePayloadError;

    fn apply(&mut self, action: &WindowsServiceAction) -> Result<(), Self::Error> {
        let _operation_guard = acquire_service_operation_lock()?;
        self.apply_locked(action)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsServicePayloadError {
    UnsupportedAction(WindowsServiceActionKind),
    InvalidIdentity,
    InvalidSource(&'static str),
    HashMismatch,
    ExistingState(&'static str),
    Verification(&'static str),
    Io(&'static str),
    Win32 { operation: &'static str, code: u32 },
    CompensationFailed { primary: String, cleanup: String },
    OperationLock(String),
}

impl fmt::Display for WindowsServicePayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAction(action) => {
                write!(formatter, "unsupported Windows payload action: {action:?}")
            }
            Self::InvalidIdentity => formatter.write_str("invalid Windows service identity"),
            Self::InvalidSource(reason) => write!(formatter, "invalid payload source: {reason}"),
            Self::HashMismatch => formatter.write_str("payload source SHA-256 does not match identity"),
            Self::ExistingState(reason) => write!(formatter, "refusing existing payload state: {reason}"),
            Self::Verification(reason) => write!(formatter, "payload verification failed: {reason}"),
            Self::Io(operation) => write!(formatter, "payload I/O failed: {operation}"),
            Self::Win32 { operation, code } => {
                write!(formatter, "Windows payload operation {operation} failed with {code}")
            }
            Self::CompensationFailed { primary, cleanup } => write!(
                formatter,
                "Windows payload transaction failed ({primary}); exact cleanup also failed ({cleanup})"
            ),
            Self::OperationLock(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for WindowsServicePayloadError {}

impl From<WindowsServiceOperationLockError> for WindowsServicePayloadError {
    fn from(value: WindowsServiceOperationLockError) -> Self {
        Self::OperationLock(value.to_string())
    }
}

#[derive(Debug)]
struct DestinationPaths {
    destination_directory: PathBuf,
    payload_directory: PathBuf,
    executable: PathBuf,
    executable_pending: PathBuf,
    record: PathBuf,
    record_pending: PathBuf,
}

#[derive(Default)]
struct StageTransaction {
    executable: Option<File>,
    record: Option<File>,
}

impl StageTransaction {
    fn disarm(&mut self) {
        self.record = None;
        self.executable = None;
    }

    fn compensate(&mut self) -> Result<(), WindowsServicePayloadError> {
        let mut first_error = None;
        if let Some(record) = self.record.take() {
            if let Err(error) = mark_delete_on_close(&record, "compensate owner record") {
                first_error = Some(error);
            }
            drop(record);
        }
        if let Some(executable) = self.executable.take() {
            if let Err(error) = mark_delete_on_close(&executable, "compensate payload executable") {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
            drop(executable);
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

fn exact_staged_record(
    evidence: &WindowsStagedPayloadEvidence,
    identity: &WindowsServiceIdentity,
    executable_path: &Path,
) -> Result<WindowsServiceOwnershipRecord, WindowsServicePayloadError> {
    let expected_path = path_text(executable_path)?;
    let record = match &evidence.record {
        WindowsOwnerRecordEvidence::OwnerOnly { record } => record,
        WindowsOwnerRecordEvidence::Missing => {
            return Err(WindowsServicePayloadError::ExistingState(
                "owner record is missing",
            ))
        }
        WindowsOwnerRecordEvidence::Inaccessible => {
            return Err(WindowsServicePayloadError::ExistingState(
                "owner record is inaccessible",
            ))
        }
        WindowsOwnerRecordEvidence::Invalid => {
            return Err(WindowsServicePayloadError::ExistingState(
                "owner record is invalid",
            ))
        }
        WindowsOwnerRecordEvidence::UntrustedPermissions => {
            return Err(WindowsServicePayloadError::ExistingState(
                "owner record permissions are untrusted",
            ))
        }
    };
    if record.identity() != *identity || record.executable_path != expected_path {
        return Err(WindowsServicePayloadError::ExistingState(
            "owner record belongs to a different identity",
        ));
    }
    match &evidence.executable {
        WindowsExecutableEvidence::Verified {
            executable_path,
            executable_sha256,
        } if executable_path.as_str() == expected_path.as_str()
            && executable_sha256.as_str() == identity.executable_sha256.as_str() => {}
        _ => {
            return Err(WindowsServicePayloadError::ExistingState(
                "owned executable evidence is incomplete",
            ))
        }
    }
    Ok(record.clone())
}

fn ensure_secure_directory(path: &Path) -> Result<(), WindowsServicePayloadError> {
    let descriptor = owner_only_security_descriptor()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0.cast::<c_void>(),
        bInheritHandle: 0,
    };
    let wide = wide_path(path);
    let created = unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } != 0;
    if !created {
        let code = unsafe { GetLastError() };
        if code != ERROR_ALREADY_EXISTS {
            return Err(WindowsServicePayloadError::Win32 {
                operation: "create secure directory",
                code,
            });
        }
    }

    let directory = open_existing_raw(
        path,
        READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    )?
    .ok_or(WindowsServicePayloadError::ExistingState(
        "destination directory disappeared",
    ))?;
    let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
    if unsafe { GetFileInformationByHandle(raw_handle(&directory), information.as_mut_ptr()) } == 0
    {
        return Err(last_win32("inspect destination directory"));
    }
    let information = unsafe { information.assume_init() };
    if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(WindowsServicePayloadError::ExistingState(
            "destination is not a regular non-reparse directory",
        ));
    }
    if !final_path_matches(&directory, path).map_err(map_destination_evidence_error)? {
        return Err(WindowsServicePayloadError::ExistingState(
            "destination directory path is not exact",
        ));
    }
    if !has_trusted_machine_write_permissions(&directory).map_err(map_destination_evidence_error)? {
        return Err(WindowsServicePayloadError::ExistingState(
            "destination directory permissions are untrusted",
        ));
    }
    Ok(())
}

fn owner_only_security_descriptor(
) -> Result<OwnedLocalSecurityDescriptor, WindowsServicePayloadError> {
    let sddl: Vec<u16> = OWNER_ONLY_SDDL
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
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
        return Err(last_win32("create owner-only security descriptor"));
    }
    if descriptor.is_null() {
        return Err(WindowsServicePayloadError::Verification(
            "owner-only security descriptor is null",
        ));
    }
    Ok(OwnedLocalSecurityDescriptor(descriptor))
}

fn create_new_secure_file(path: &Path) -> Result<File, WindowsServicePayloadError> {
    let descriptor = owner_only_security_descriptor()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0.cast::<c_void>(),
        bInheritHandle: 0,
    };
    let wide = wide_path(path);
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL | DELETE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(last_win32("create secure pending file"));
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn open_existing_file(
    path: &Path,
    desired_access: u32,
    share_mode: u32,
) -> Result<Option<File>, WindowsServicePayloadError> {
    open_existing_raw(
        path,
        desired_access,
        share_mode,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
    )
}

fn open_existing_raw(
    path: &Path,
    desired_access: u32,
    share_mode: u32,
    flags: u32,
) -> Result<Option<File>, WindowsServicePayloadError> {
    let wide = wide_path(path);
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            desired_access,
            share_mode,
            null(),
            OPEN_EXISTING,
            flags,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let code = unsafe { GetLastError() };
        if code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND {
            return Ok(None);
        }
        return Err(WindowsServicePayloadError::Win32 {
            operation: "open exact Windows payload path",
            code,
        });
    }
    Ok(Some(unsafe { File::from_raw_handle(handle) }))
}

fn verify_optional_existing_executable(
    path: &Path,
    expected_sha256: &str,
) -> Result<bool, WindowsServicePayloadError> {
    let Some(mut file) = open_existing_file(
        path,
        GENERIC_READ | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
    )?
    else {
        return Ok(false);
    };
    verify_executable_handle(&mut file, path, expected_sha256)?;
    Ok(true)
}

fn verify_existing_executable(
    path: &Path,
    expected_sha256: &str,
) -> Result<(), WindowsServicePayloadError> {
    if verify_optional_existing_executable(path, expected_sha256)? {
        Ok(())
    } else {
        Err(WindowsServicePayloadError::ExistingState(
            "owned executable is missing",
        ))
    }
}

fn verify_created_file(
    file: &mut File,
    path: &Path,
    expected_sha256: &str,
) -> Result<(), WindowsServicePayloadError> {
    verify_executable_handle(file, path, expected_sha256)
}

fn verify_executable_handle(
    file: &mut File,
    path: &Path,
    expected_sha256: &str,
) -> Result<(), WindowsServicePayloadError> {
    let size = validate_regular_file(file, MAX_WINDOWS_EXECUTABLE_BYTES)
        .map_err(map_destination_evidence_error)?;
    if !final_path_matches(file, path).map_err(map_destination_evidence_error)? {
        return Err(WindowsServicePayloadError::Verification(
            "executable path is not exact",
        ));
    }
    if !has_trusted_machine_write_permissions(file).map_err(map_destination_evidence_error)? {
        return Err(WindowsServicePayloadError::ExistingState(
            "executable permissions are untrusted",
        ));
    }
    let digest = hash_open_file(file, size, "hash staged executable")?;
    if digest != expected_sha256 {
        return Err(WindowsServicePayloadError::ExistingState(
            "content-addressed executable hash does not match",
        ));
    }
    Ok(())
}

fn read_exact_record_handle(
    file: &mut File,
    path: &Path,
) -> Result<WindowsServiceOwnershipRecord, WindowsServicePayloadError> {
    let size = validate_regular_file(file, MAX_WINDOWS_OWNER_RECORD_BYTES as u64)
        .map_err(map_destination_evidence_error)?;
    if !final_path_matches(file, path).map_err(map_destination_evidence_error)? {
        return Err(WindowsServicePayloadError::Verification(
            "owner record path is not exact",
        ));
    }
    if !has_trusted_machine_write_permissions(file).map_err(map_destination_evidence_error)? {
        return Err(WindowsServicePayloadError::ExistingState(
            "owner record permissions are untrusted",
        ));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| WindowsServicePayloadError::Io("rewind owner record"))?;
    let mut bytes = Vec::with_capacity(size as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| WindowsServicePayloadError::Io("read owner record"))?;
    if bytes.len() as u64 != size {
        return Err(WindowsServicePayloadError::Verification(
            "owner record size changed while open",
        ));
    }
    parse_windows_owner_record_v1(&bytes)
        .map_err(|_| WindowsServicePayloadError::Verification("parse owner record"))
}

fn verify_record_handle(
    file: &mut File,
    path: &Path,
    expected: &WindowsServiceOwnershipRecord,
) -> Result<(), WindowsServicePayloadError> {
    let actual = read_exact_record_handle(file, path)?;
    if &actual != expected {
        return Err(WindowsServicePayloadError::Verification(
            "owner record changed during staging",
        ));
    }
    Ok(())
}

fn copy_exact_payload(
    source: &mut File,
    destination: &mut File,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<(), WindowsServicePayloadError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|_| WindowsServicePayloadError::Io("read payload source"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(WindowsServicePayloadError::Verification(
                "payload size overflow",
            ))?;
        if total > MAX_WINDOWS_EXECUTABLE_BYTES {
            return Err(WindowsServicePayloadError::InvalidSource(
                "payload exceeds the size limit",
            ));
        }
        destination
            .write_all(&buffer[..read])
            .map_err(|_| WindowsServicePayloadError::Io("write pending payload"))?;
        hasher.update(&buffer[..read]);
    }
    if total != expected_size || format!("{:x}", hasher.finalize()) != expected_sha256 {
        return Err(WindowsServicePayloadError::HashMismatch);
    }
    flush_file(destination, "flush pending payload")
}

fn hash_open_file(
    file: &mut File,
    expected_size: u64,
    operation: &'static str,
) -> Result<String, WindowsServicePayloadError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| WindowsServicePayloadError::Io(operation))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| WindowsServicePayloadError::Io(operation))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(WindowsServicePayloadError::Verification(
                "payload size overflow",
            ))?;
        if total > MAX_WINDOWS_EXECUTABLE_BYTES {
            return Err(WindowsServicePayloadError::Verification(
                "payload exceeds the size limit",
            ));
        }
        hasher.update(&buffer[..read]);
    }
    if total != expected_size {
        return Err(WindowsServicePayloadError::Verification(
            "payload size changed while open",
        ));
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn flush_file(file: &File, operation: &'static str) -> Result<(), WindowsServicePayloadError> {
    if unsafe { FlushFileBuffers(raw_handle(file)) } == 0 {
        Err(last_win32(operation))
    } else {
        Ok(())
    }
}

fn move_file_exact(
    source: &Path,
    destination: &Path,
    operation: &'static str,
) -> Result<(), WindowsServicePayloadError> {
    let source = wide_path(source);
    let destination = wide_path(destination);
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(last_win32(operation))
    } else {
        Ok(())
    }
}

fn mark_delete_on_close(
    file: &File,
    operation: &'static str,
) -> Result<(), WindowsServicePayloadError> {
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    if unsafe {
        SetFileInformationByHandle(
            raw_handle(file),
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast::<c_void>(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        Err(last_win32(operation))
    } else {
        Ok(())
    }
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn path_text(path: &Path) -> Result<String, WindowsServicePayloadError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or(WindowsServicePayloadError::Verification(
            "Windows payload path is not valid Unicode",
        ))
}

fn last_win32(operation: &'static str) -> WindowsServicePayloadError {
    WindowsServicePayloadError::Win32 {
        operation,
        code: unsafe { GetLastError() },
    }
}

fn map_source_evidence_error(error: NativeEvidenceError) -> WindowsServicePayloadError {
    match error {
        NativeEvidenceError::Missing => {
            WindowsServicePayloadError::InvalidSource("payload source is missing")
        }
        NativeEvidenceError::Inaccessible => {
            WindowsServicePayloadError::InvalidSource("payload source is inaccessible")
        }
        NativeEvidenceError::Invalid | NativeEvidenceError::UntrustedPermissions => {
            WindowsServicePayloadError::InvalidSource("payload source is not a regular exact file")
        }
    }
}

fn map_destination_evidence_error(error: NativeEvidenceError) -> WindowsServicePayloadError {
    match error {
        NativeEvidenceError::Missing => {
            WindowsServicePayloadError::ExistingState("destination evidence is missing")
        }
        NativeEvidenceError::Inaccessible => {
            WindowsServicePayloadError::ExistingState("destination evidence is inaccessible")
        }
        NativeEvidenceError::Invalid => {
            WindowsServicePayloadError::ExistingState("destination evidence is invalid")
        }
        NativeEvidenceError::UntrustedPermissions => WindowsServicePayloadError::ExistingState(
            "destination evidence permissions are untrusted",
        ),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const PAYLOAD: &[u8] = b"slipstream-windows-evidence";
    const PAYLOAD_SHA256: &str = "96c45d5cb404c8500d3a2f49e8aecc6b5ff98a147f0d0e6f69e325daa60850ab";

    fn disposable_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "slipstream-payload-stage-{}-{name}",
            std::process::id()
        ))
    }

    fn identity(generation: u64) -> WindowsServiceIdentity {
        WindowsServiceIdentity {
            service_name: "dev.slipstream.service".into(),
            executable_sha256: PAYLOAD_SHA256.into(),
            generation,
        }
    }

    fn disposable_effects(name: &str) -> (WindowsServicePayloadEffects, PathBuf, PathBuf) {
        let root = disposable_path(name);
        let source = disposable_path(&format!("{name}-source.exe"));
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_file(&source);
        fs::create_dir(&root).expect("create disposable payload root");
        fs::write(&source, PAYLOAD).expect("write disposable payload source");
        let destination = root.join("Slipstream");
        (
            WindowsServicePayloadEffects::for_disposable_test(source.clone(), destination),
            root,
            source,
        )
    }

    #[test]
    fn stage_and_remove_use_exact_owner_only_evidence() {
        if std::env::var_os("SLIPSTREAM_WINDOWS_DISPOSABLE_CI").is_none() {
            return;
        }
        let (mut effects, root, source) = disposable_effects("round-trip");
        let identity = identity(1);
        effects
            .apply(&WindowsServiceAction::StagePayload {
                identity: identity.clone(),
            })
            .expect("stage exact payload");
        effects
            .apply(&WindowsServiceAction::StagePayload {
                identity: identity.clone(),
            })
            .expect("exact staging is idempotent");
        effects
            .apply(&WindowsServiceAction::RemoveOwnedPayload { identity })
            .expect("remove exact owned payload");

        assert!(!root
            .join("Slipstream")
            .join(WINDOWS_OWNER_RECORD_FILE_NAME)
            .exists());
        fs::remove_dir_all(root).expect("remove disposable payload root");
        fs::remove_file(source).expect("remove disposable payload source");
    }

    #[test]
    fn hash_mismatch_leaves_no_commit_marker_or_payload() {
        if std::env::var_os("SLIPSTREAM_WINDOWS_DISPOSABLE_CI").is_none() {
            return;
        }
        let (effects, root, source) = disposable_effects("hash-mismatch");
        let mut wrong = identity(1);
        wrong.executable_sha256 = "0".repeat(64);
        assert_eq!(
            effects.stage_payload(&wrong),
            Err(WindowsServicePayloadError::HashMismatch)
        );
        assert!(!root
            .join("Slipstream")
            .join(WINDOWS_OWNER_RECORD_FILE_NAME)
            .exists());
        assert!(!root
            .join("Slipstream")
            .join(WINDOWS_PAYLOAD_DIRECTORY)
            .join(format!(
                "{WINDOWS_PAYLOAD_FILE_PREFIX}{}.exe",
                wrong.executable_sha256
            ))
            .exists());
        let _ = fs::remove_dir_all(root);
        fs::remove_file(source).expect("remove disposable payload source");
    }

    #[test]
    fn post_commit_failure_compensates_exact_created_handles() {
        if std::env::var_os("SLIPSTREAM_WINDOWS_DISPOSABLE_CI").is_none() {
            return;
        }
        let (mut effects, root, source) = disposable_effects("compensation");
        effects.fail_after_record_commit = true;
        assert!(matches!(
            effects.stage_payload(&identity(1)),
            Err(WindowsServicePayloadError::Verification(
                "injected failure after owner record commit"
            ))
        ));
        assert!(!root
            .join("Slipstream")
            .join(WINDOWS_OWNER_RECORD_FILE_NAME)
            .exists());
        assert!(!root
            .join("Slipstream")
            .join(WINDOWS_PAYLOAD_DIRECTORY)
            .join(format!("{WINDOWS_PAYLOAD_FILE_PREFIX}{PAYLOAD_SHA256}.exe"))
            .exists());
        fs::remove_dir_all(root).expect("remove disposable payload root");
        fs::remove_file(source).expect("remove disposable payload source");
    }

    #[test]
    fn pending_executable_failure_compensates_the_registered_handle() {
        if std::env::var_os("SLIPSTREAM_WINDOWS_DISPOSABLE_CI").is_none() {
            return;
        }
        let (mut effects, root, source) = disposable_effects("pending-executable");
        effects.fail_after_executable_create = true;
        assert!(matches!(
            effects.stage_payload(&identity(1)),
            Err(WindowsServicePayloadError::Verification(
                "injected failure after pending executable creation"
            ))
        ));
        assert!(!root
            .join("Slipstream")
            .join(WINDOWS_PAYLOAD_DIRECTORY)
            .join(format!(
                ".{WINDOWS_PAYLOAD_FILE_PREFIX}{PAYLOAD_SHA256}.exe{WINDOWS_PAYLOAD_PENDING_SUFFIX}"
            ))
            .exists());
        fs::remove_dir_all(root).expect("remove disposable payload root");
        fs::remove_file(source).expect("remove disposable payload source");
    }

    #[test]
    fn pending_record_failure_compensates_both_registered_handles() {
        if std::env::var_os("SLIPSTREAM_WINDOWS_DISPOSABLE_CI").is_none() {
            return;
        }
        let (mut effects, root, source) = disposable_effects("pending-record");
        effects.fail_after_record_create = true;
        assert!(matches!(
            effects.stage_payload(&identity(1)),
            Err(WindowsServicePayloadError::Verification(
                "injected failure after pending owner record creation"
            ))
        ));
        assert!(!root
            .join("Slipstream")
            .join(WINDOWS_OWNER_RECORD_PENDING_FILE_NAME)
            .exists());
        assert!(!root
            .join("Slipstream")
            .join(WINDOWS_PAYLOAD_DIRECTORY)
            .join(format!("{WINDOWS_PAYLOAD_FILE_PREFIX}{PAYLOAD_SHA256}.exe"))
            .exists());
        fs::remove_dir_all(root).expect("remove disposable payload root");
        fs::remove_file(source).expect("remove disposable payload source");
    }

    #[test]
    fn a_different_generation_cannot_replace_the_commit_marker() {
        if std::env::var_os("SLIPSTREAM_WINDOWS_DISPOSABLE_CI").is_none() {
            return;
        }
        let (effects, root, source) = disposable_effects("generation-collision");
        effects
            .stage_payload(&identity(1))
            .expect("stage first identity");
        assert!(matches!(
            effects.stage_payload(&identity(2)),
            Err(WindowsServicePayloadError::ExistingState(
                "owner record belongs to a different identity"
            ))
        ));
        effects
            .remove_owned_payload(&identity(1))
            .expect("remove original identity");
        fs::remove_dir_all(root).expect("remove disposable payload root");
        fs::remove_file(source).expect("remove disposable payload source");
    }
}
