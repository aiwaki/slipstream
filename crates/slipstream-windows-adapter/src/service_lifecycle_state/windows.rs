//! Windows-only, handle-bound durable service lifecycle state.

use super::{
    parse_windows_service_active_install_record_v1, parse_windows_service_intent_record_v1,
    WindowsDurableRecordEvidence, WindowsServiceActiveInstallRecordV1,
    WindowsServiceIntentRecordV1, WindowsServiceLifecycleStateAssessment,
    WindowsServiceLifecycleStateEvidence, MAX_WINDOWS_SERVICE_STATE_RECORD_BYTES,
    WINDOWS_SERVICE_ACTIVE_INSTALL_FILE_NAME, WINDOWS_SERVICE_ACTIVE_INSTALL_PENDING_FILE_NAME,
    WINDOWS_SERVICE_INTENT_FILE_NAME, WINDOWS_SERVICE_INTENT_PENDING_FILE_NAME,
};
use crate::service_lifecycle::{
    WindowsServiceAction, WindowsServiceActionKind, WindowsServiceDesiredState,
    WindowsServiceEffects, WindowsServiceIdentity,
};
use crate::service_operation_lock::{
    acquire_service_operation_lock, WindowsServiceOperationLockError,
};
use crate::service_ownership::windows::{
    final_path_matches, has_trusted_machine_write_permissions, machine_owner_record_path,
    raw_handle, staged_payload_evidence_at, validate_regular_file, NativeEvidenceError,
};
use crate::service_ownership::{WindowsExecutableEvidence, WindowsOwnerRecordEvidence};
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
    FILE_SHARE_WRITE, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, OPEN_EXISTING,
    READ_CONTROL,
};

const OWNER_ONLY_SDDL: &str = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";

pub struct WindowsServiceLifecycleStateEffects {
    #[cfg(test)]
    destination_directory_override: Option<PathBuf>,
    #[cfg(test)]
    fail_after_intent_pending_create: bool,
    #[cfg(test)]
    fail_after_active_pending_create: bool,
}

impl WindowsServiceLifecycleStateEffects {
    pub const fn new() -> Self {
        Self {
            #[cfg(test)]
            destination_directory_override: None,
            #[cfg(test)]
            fail_after_intent_pending_create: false,
            #[cfg(test)]
            fail_after_active_pending_create: false,
        }
    }

    pub fn collect(&self) -> WindowsServiceLifecycleStateEvidence {
        match self.state_paths() {
            Ok(paths) => collect_at(&paths),
            Err(_) => WindowsServiceLifecycleStateEvidence {
                intent: WindowsDurableRecordEvidence::Inaccessible,
                active_install: WindowsDurableRecordEvidence::Inaccessible,
            },
        }
    }

    pub fn persist_intent(
        &self,
        desired: WindowsServiceDesiredState,
        identity: Option<WindowsServiceIdentity>,
        crash_restart_attempts: u32,
    ) -> Result<(), WindowsServiceLifecycleStateError> {
        let _operation_guard = acquire_service_operation_lock()?;
        let record = WindowsServiceIntentRecordV1::new(desired, identity, crash_restart_attempts)
            .map_err(|_| WindowsServiceLifecycleStateError::InvalidRecord("intent"))?;
        let paths = self.state_paths()?;
        ensure_secure_directory(&paths.root)?;
        let evidence = collect_at(&paths);
        let (current_intent, active_install) = stable_records(&evidence)?;
        validate_intent_transition(current_intent.as_ref(), active_install.as_ref(), &record)?;
        if current_intent.as_ref() == Some(&record) {
            return Ok(());
        }
        let bytes = record
            .canonical_bytes()
            .map_err(|_| WindowsServiceLifecycleStateError::InvalidRecord("intent"))?;
        write_record_atomic(
            AtomicRecordWrite {
                pending_path: &paths.intent_pending,
                committed_path: &paths.intent,
                bytes: &bytes,
                replace_existing: true,
                operation: "commit durable intent",
                fail_after_pending_create: self.inject_fail_after_intent_pending_create(),
            },
            |actual| actual == record,
            parse_windows_service_intent_record_v1,
        )
    }

    pub fn commit_install(
        &self,
        identity: &WindowsServiceIdentity,
    ) -> Result<(), WindowsServiceLifecycleStateError> {
        let _operation_guard = acquire_service_operation_lock()?;
        identity
            .validate()
            .map_err(|_| WindowsServiceLifecycleStateError::InvalidIdentity)?;
        let paths = self.state_paths()?;
        ensure_secure_directory(&paths.root)?;
        let evidence = collect_at(&paths);
        let (intent, active_install) = stable_records(&evidence)?;
        let intent = intent.ok_or(WindowsServiceLifecycleStateError::ExistingState(
            "commit requires a durable running intent",
        ))?;
        if intent.desired != WindowsServiceDesiredState::Running
            || intent.identity.as_ref() != Some(identity)
            || intent.crash_restart_attempts != 0
        {
            return Err(WindowsServiceLifecycleStateError::ExistingState(
                "commit does not match the durable running intent",
            ));
        }
        verify_staged_payload(&paths, identity)?;

        let record = WindowsServiceActiveInstallRecordV1::new(identity.clone())
            .map_err(|_| WindowsServiceLifecycleStateError::InvalidIdentity)?;
        if let Some(active_install) = active_install {
            return if active_install == record {
                Ok(())
            } else {
                Err(WindowsServiceLifecycleStateError::ExistingState(
                    "a different active install is already committed",
                ))
            };
        }

        let bytes = record
            .canonical_bytes()
            .map_err(|_| WindowsServiceLifecycleStateError::InvalidRecord("active install"))?;
        write_record_atomic(
            AtomicRecordWrite {
                pending_path: &paths.active_pending,
                committed_path: &paths.active,
                bytes: &bytes,
                replace_existing: false,
                operation: "commit active install",
                fail_after_pending_create: self.inject_fail_after_active_pending_create(),
            },
            |actual| actual == record,
            parse_windows_service_active_install_record_v1,
        )
    }

    pub fn clear_active_install_record(
        &self,
        identity: &WindowsServiceIdentity,
    ) -> Result<(), WindowsServiceLifecycleStateError> {
        let _operation_guard = acquire_service_operation_lock()?;
        identity
            .validate()
            .map_err(|_| WindowsServiceLifecycleStateError::InvalidIdentity)?;
        let paths = self.state_paths()?;
        let evidence = collect_at(&paths);
        let (intent, active_install) = stable_records(&evidence)?;
        let intent = intent.ok_or(WindowsServiceLifecycleStateError::ExistingState(
            "clear requires a durable absent intent",
        ))?;
        if intent.desired != WindowsServiceDesiredState::Absent
            || intent
                .identity
                .as_ref()
                .is_some_and(|persisted| persisted != identity)
        {
            return Err(WindowsServiceLifecycleStateError::ExistingState(
                "clear would weaken a non-absent or different durable intent",
            ));
        }
        let Some(active_install) = active_install else {
            return Ok(());
        };
        if active_install.identity != *identity {
            return Err(WindowsServiceLifecycleStateError::ExistingState(
                "active install belongs to a different identity",
            ));
        }

        let mut file = open_existing_file(
            &paths.active,
            GENERIC_READ | READ_CONTROL | DELETE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
        )?
        .ok_or(WindowsServiceLifecycleStateError::ExistingState(
            "active install disappeared before clearing",
        ))?;
        let reopened = read_record_handle(
            &mut file,
            &paths.active,
            parse_windows_service_active_install_record_v1,
        )?;
        if reopened != active_install {
            return Err(WindowsServiceLifecycleStateError::ExistingState(
                "active install changed before clearing",
            ));
        }
        mark_delete_on_close(&file, "clear active install")?;
        drop(file);
        match read_record_at(
            &paths.active,
            parse_windows_service_active_install_record_v1,
        ) {
            Ok(None) => Ok(()),
            Ok(Some(_)) => Err(WindowsServiceLifecycleStateError::Verification(
                "active install remained after clearing",
            )),
            Err(error) => Err(map_native_evidence_error(error)),
        }
    }

    fn state_paths(&self) -> Result<StatePaths, WindowsServiceLifecycleStateError> {
        #[cfg(test)]
        let root = match &self.destination_directory_override {
            Some(root) => root.clone(),
            None => machine_state_root()?,
        };
        #[cfg(not(test))]
        let root = machine_state_root()?;

        Ok(StatePaths {
            intent: root.join(WINDOWS_SERVICE_INTENT_FILE_NAME),
            intent_pending: root.join(WINDOWS_SERVICE_INTENT_PENDING_FILE_NAME),
            active: root.join(WINDOWS_SERVICE_ACTIVE_INSTALL_FILE_NAME),
            active_pending: root.join(WINDOWS_SERVICE_ACTIVE_INSTALL_PENDING_FILE_NAME),
            owner_record: machine_owner_record_for_root(&root),
            root,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_disposable_test(destination_directory: PathBuf) -> Self {
        Self {
            destination_directory_override: Some(destination_directory),
            fail_after_intent_pending_create: false,
            fail_after_active_pending_create: false,
        }
    }

    fn inject_fail_after_intent_pending_create(&self) -> bool {
        #[cfg(test)]
        {
            self.fail_after_intent_pending_create
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    fn inject_fail_after_active_pending_create(&self) -> bool {
        #[cfg(test)]
        {
            self.fail_after_active_pending_create
        }
        #[cfg(not(test))]
        {
            false
        }
    }
}

impl Default for WindowsServiceLifecycleStateEffects {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsServiceEffects for WindowsServiceLifecycleStateEffects {
    type Error = WindowsServiceLifecycleStateError;

    fn apply(&mut self, action: &WindowsServiceAction) -> Result<(), Self::Error> {
        match action {
            WindowsServiceAction::PersistIntent {
                desired,
                identity,
                crash_restart_attempts,
            } => self.persist_intent(*desired, identity.clone(), *crash_restart_attempts),
            WindowsServiceAction::CommitInstall { identity } => self.commit_install(identity),
            WindowsServiceAction::ClearActiveInstallRecord { identity } => {
                self.clear_active_install_record(identity)
            }
            _ => Err(WindowsServiceLifecycleStateError::UnsupportedAction(
                action.kind(),
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsServiceLifecycleStateError {
    UnsupportedAction(WindowsServiceActionKind),
    InvalidIdentity,
    InvalidRecord(&'static str),
    InterruptedWrite(&'static str),
    ExistingState(&'static str),
    Verification(&'static str),
    Io(&'static str),
    Win32 { operation: &'static str, code: u32 },
    CompensationFailed { primary: String, cleanup: String },
    OperationLock(String),
}

impl fmt::Display for WindowsServiceLifecycleStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAction(action) => {
                write!(formatter, "unsupported Windows lifecycle-state action: {action:?}")
            }
            Self::InvalidIdentity => formatter.write_str("invalid Windows service identity"),
            Self::InvalidRecord(record) => write!(formatter, "invalid {record} record"),
            Self::InterruptedWrite(record) => {
                write!(formatter, "interrupted {record} write requires recovery")
            }
            Self::ExistingState(reason) => {
                write!(formatter, "refusing lifecycle state: {reason}")
            }
            Self::Verification(reason) => {
                write!(formatter, "lifecycle state verification failed: {reason}")
            }
            Self::Io(operation) => write!(formatter, "lifecycle state I/O failed: {operation}"),
            Self::Win32 { operation, code } => {
                write!(formatter, "Windows lifecycle state operation {operation} failed with {code}")
            }
            Self::CompensationFailed { primary, cleanup } => write!(
                formatter,
                "Windows lifecycle state transaction failed ({primary}); pending-file cleanup also failed ({cleanup})"
            ),
            Self::OperationLock(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for WindowsServiceLifecycleStateError {}

impl From<WindowsServiceOperationLockError> for WindowsServiceLifecycleStateError {
    fn from(value: WindowsServiceOperationLockError) -> Self {
        Self::OperationLock(value.to_string())
    }
}

#[derive(Debug)]
struct StatePaths {
    root: PathBuf,
    intent: PathBuf,
    intent_pending: PathBuf,
    active: PathBuf,
    active_pending: PathBuf,
    owner_record: PathBuf,
}

fn collect_at(paths: &StatePaths) -> WindowsServiceLifecycleStateEvidence {
    WindowsServiceLifecycleStateEvidence {
        intent: collect_record_evidence(
            &paths.intent,
            &paths.intent_pending,
            parse_windows_service_intent_record_v1,
        ),
        active_install: collect_record_evidence(
            &paths.active,
            &paths.active_pending,
            parse_windows_service_active_install_record_v1,
        ),
    }
}

fn stable_records(
    evidence: &WindowsServiceLifecycleStateEvidence,
) -> Result<
    (
        Option<WindowsServiceIntentRecordV1>,
        Option<WindowsServiceActiveInstallRecordV1>,
    ),
    WindowsServiceLifecycleStateError,
> {
    match evidence.assess() {
        WindowsServiceLifecycleStateAssessment::Stable {
            intent,
            active_install,
        } => Ok((intent, active_install)),
        WindowsServiceLifecycleStateAssessment::InterruptedWrite => Err(
            WindowsServiceLifecycleStateError::InterruptedWrite("lifecycle state"),
        ),
        WindowsServiceLifecycleStateAssessment::Unknown => {
            Err(WindowsServiceLifecycleStateError::ExistingState(
                "lifecycle state evidence is inaccessible, invalid, or untrusted",
            ))
        }
        WindowsServiceLifecycleStateAssessment::Inconsistent => {
            Err(WindowsServiceLifecycleStateError::ExistingState(
                "intent and active install records are inconsistent",
            ))
        }
    }
}

fn validate_intent_transition(
    current: Option<&WindowsServiceIntentRecordV1>,
    active: Option<&WindowsServiceActiveInstallRecordV1>,
    next: &WindowsServiceIntentRecordV1,
) -> Result<(), WindowsServiceLifecycleStateError> {
    if let Some(active) = active {
        if next.identity.as_ref() != Some(&active.identity) {
            return Err(WindowsServiceLifecycleStateError::ExistingState(
                "intent cannot detach from the active install identity",
            ));
        }
    }
    if let Some(current) = current {
        let restores_absent_without_committed_install = active.is_none()
            && next.desired == WindowsServiceDesiredState::Absent
            && next.identity.is_none();
        if current.desired != WindowsServiceDesiredState::Absent
            && current.identity != next.identity
            && !restores_absent_without_committed_install
        {
            return Err(WindowsServiceLifecycleStateError::ExistingState(
                "intent cannot replace a live identity",
            ));
        }
    }
    Ok(())
}

fn verify_staged_payload(
    paths: &StatePaths,
    identity: &WindowsServiceIdentity,
) -> Result<(), WindowsServiceLifecycleStateError> {
    let evidence = staged_payload_evidence_at(&paths.owner_record);
    let record = match evidence.record {
        WindowsOwnerRecordEvidence::OwnerOnly { record } => record,
        _ => {
            return Err(WindowsServiceLifecycleStateError::ExistingState(
                "active install requires exact staged payload ownership",
            ))
        }
    };
    if record.identity() != *identity {
        return Err(WindowsServiceLifecycleStateError::ExistingState(
            "staged payload belongs to a different identity",
        ));
    }
    match evidence.executable {
        WindowsExecutableEvidence::Verified {
            executable_path,
            executable_sha256,
        } if executable_path == record.executable_path
            && executable_sha256 == identity.executable_sha256 =>
        {
            Ok(())
        }
        _ => Err(WindowsServiceLifecycleStateError::ExistingState(
            "staged payload executable evidence is incomplete",
        )),
    }
}

fn collect_record_evidence<T>(
    committed_path: &Path,
    pending_path: &Path,
    parser: fn(&[u8]) -> Result<T, super::WindowsServiceLifecycleStateContractError>,
) -> WindowsDurableRecordEvidence<T> {
    let committed = match read_record_at(committed_path, parser) {
        Ok(Some(record)) => WindowsDurableRecordEvidence::Committed { record },
        Ok(None) => WindowsDurableRecordEvidence::Missing,
        Err(NativeEvidenceError::Missing) => WindowsDurableRecordEvidence::Missing,
        Err(NativeEvidenceError::Inaccessible) => WindowsDurableRecordEvidence::Inaccessible,
        Err(NativeEvidenceError::Invalid) => WindowsDurableRecordEvidence::Invalid,
        Err(NativeEvidenceError::UntrustedPermissions) => {
            WindowsDurableRecordEvidence::UntrustedPermissions
        }
    };
    match inspect_pending_at(pending_path) {
        Ok(false) => committed,
        Ok(true) => match committed {
            WindowsDurableRecordEvidence::Missing => {
                WindowsDurableRecordEvidence::InterruptedWrite { committed: None }
            }
            WindowsDurableRecordEvidence::Committed { record } => {
                WindowsDurableRecordEvidence::InterruptedWrite {
                    committed: Some(record),
                }
            }
            other => other,
        },
        Err(NativeEvidenceError::Missing) => committed,
        Err(NativeEvidenceError::Inaccessible) => WindowsDurableRecordEvidence::Inaccessible,
        Err(NativeEvidenceError::Invalid) => WindowsDurableRecordEvidence::Invalid,
        Err(NativeEvidenceError::UntrustedPermissions) => {
            WindowsDurableRecordEvidence::UntrustedPermissions
        }
    }
}

fn read_record_at<T>(
    path: &Path,
    parser: fn(&[u8]) -> Result<T, super::WindowsServiceLifecycleStateContractError>,
) -> Result<Option<T>, NativeEvidenceError> {
    let mut file = match open_existing_file(
        path,
        GENERIC_READ | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
    ) {
        Ok(Some(file)) => file,
        Ok(None) => return Ok(None),
        Err(_) => return Err(NativeEvidenceError::Inaccessible),
    };
    read_record_handle_native(&mut file, path, parser).map(Some)
}

fn read_record_handle_native<T>(
    file: &mut File,
    path: &Path,
    parser: fn(&[u8]) -> Result<T, super::WindowsServiceLifecycleStateContractError>,
) -> Result<T, NativeEvidenceError> {
    let size = validate_regular_file(file, MAX_WINDOWS_SERVICE_STATE_RECORD_BYTES as u64)?;
    if !final_path_matches(file, path)? {
        return Err(NativeEvidenceError::Invalid);
    }
    if !has_trusted_machine_write_permissions(file)? {
        return Err(NativeEvidenceError::UntrustedPermissions);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| NativeEvidenceError::Inaccessible)?;
    let mut bytes = Vec::with_capacity(size as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| NativeEvidenceError::Inaccessible)?;
    if bytes.len() as u64 != size {
        return Err(NativeEvidenceError::Invalid);
    }
    parser(&bytes).map_err(|_| NativeEvidenceError::Invalid)
}

fn inspect_pending_at(path: &Path) -> Result<bool, NativeEvidenceError> {
    let file = match open_existing_file(
        path,
        GENERIC_READ | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
    ) {
        Ok(Some(file)) => file,
        Ok(None) => return Ok(false),
        Err(_) => return Err(NativeEvidenceError::Inaccessible),
    };
    validate_pending_file(&file)?;
    if !final_path_matches(&file, path)? {
        return Err(NativeEvidenceError::Invalid);
    }
    if !has_trusted_machine_write_permissions(&file)? {
        return Err(NativeEvidenceError::UntrustedPermissions);
    }
    Ok(true)
}

fn validate_pending_file(file: &File) -> Result<(), NativeEvidenceError> {
    let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
    if unsafe { GetFileInformationByHandle(raw_handle(file), information.as_mut_ptr()) } == 0 {
        return Err(NativeEvidenceError::Inaccessible);
    }
    let information = unsafe { information.assume_init() };
    if information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
    {
        return Err(NativeEvidenceError::Invalid);
    }
    let size = (u64::from(information.nFileSizeHigh) << 32) | u64::from(information.nFileSizeLow);
    if size > MAX_WINDOWS_SERVICE_STATE_RECORD_BYTES as u64 {
        return Err(NativeEvidenceError::Invalid);
    }
    Ok(())
}

struct AtomicRecordWrite<'a> {
    pending_path: &'a Path,
    committed_path: &'a Path,
    bytes: &'a [u8],
    replace_existing: bool,
    operation: &'static str,
    fail_after_pending_create: bool,
}

fn write_record_atomic<T: Eq>(
    request: AtomicRecordWrite<'_>,
    matches_expected: impl FnOnce(T) -> bool,
    parser: fn(&[u8]) -> Result<T, super::WindowsServiceLifecycleStateContractError>,
) -> Result<(), WindowsServiceLifecycleStateError> {
    let mut pending = create_new_secure_file(request.pending_path)?;
    let result = (|| {
        if request.fail_after_pending_create {
            return Err(WindowsServiceLifecycleStateError::Verification(
                "injected failure after pending state creation",
            ));
        }
        pending
            .write_all(request.bytes)
            .map_err(|_| WindowsServiceLifecycleStateError::Io("write pending state"))?;
        flush_file(&pending, "flush pending state")?;
        let actual = read_record_handle(&mut pending, request.pending_path, parser)?;
        if !matches_expected(actual) {
            return Err(WindowsServiceLifecycleStateError::Verification(
                "pending state content changed",
            ));
        }
        move_file_exact(
            request.pending_path,
            request.committed_path,
            request.replace_existing,
            request.operation,
        )
    })();

    if let Err(primary) = result {
        return match mark_delete_on_close(&pending, "compensate pending lifecycle state") {
            Ok(()) => {
                drop(pending);
                Err(primary)
            }
            Err(cleanup) => Err(WindowsServiceLifecycleStateError::CompensationFailed {
                primary: primary.to_string(),
                cleanup: cleanup.to_string(),
            }),
        };
    }
    drop(pending);
    Ok(())
}

fn read_record_handle<T>(
    file: &mut File,
    path: &Path,
    parser: fn(&[u8]) -> Result<T, super::WindowsServiceLifecycleStateContractError>,
) -> Result<T, WindowsServiceLifecycleStateError> {
    read_record_handle_native(file, path, parser).map_err(map_native_evidence_error)
}

fn machine_state_root() -> Result<PathBuf, WindowsServiceLifecycleStateError> {
    let record = machine_owner_record_path().map_err(map_native_evidence_error)?;
    record
        .parent()
        .map(Path::to_path_buf)
        .ok_or(WindowsServiceLifecycleStateError::Verification(
            "machine owner record has no parent directory",
        ))
}

fn machine_owner_record_for_root(root: &Path) -> PathBuf {
    root.join(crate::service_ownership::WINDOWS_OWNER_RECORD_FILE_NAME)
}

fn ensure_secure_directory(path: &Path) -> Result<(), WindowsServiceLifecycleStateError> {
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
            return Err(WindowsServiceLifecycleStateError::Win32 {
                operation: "create secure lifecycle state directory",
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
    .ok_or(WindowsServiceLifecycleStateError::ExistingState(
        "lifecycle state directory disappeared",
    ))?;
    let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
    if unsafe { GetFileInformationByHandle(raw_handle(&directory), information.as_mut_ptr()) } == 0
    {
        return Err(last_win32("inspect lifecycle state directory"));
    }
    let information = unsafe { information.assume_init() };
    if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(WindowsServiceLifecycleStateError::ExistingState(
            "lifecycle state destination is not a regular non-reparse directory",
        ));
    }
    if !final_path_matches(&directory, path).map_err(map_native_evidence_error)? {
        return Err(WindowsServiceLifecycleStateError::ExistingState(
            "lifecycle state directory path is not exact",
        ));
    }
    if !has_trusted_machine_write_permissions(&directory).map_err(map_native_evidence_error)? {
        return Err(WindowsServiceLifecycleStateError::ExistingState(
            "lifecycle state directory permissions are untrusted",
        ));
    }
    Ok(())
}

fn owner_only_security_descriptor(
) -> Result<OwnedLocalSecurityDescriptor, WindowsServiceLifecycleStateError> {
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
        return Err(last_win32("create owner-only lifecycle state descriptor"));
    }
    if descriptor.is_null() {
        return Err(WindowsServiceLifecycleStateError::Verification(
            "owner-only lifecycle state descriptor is null",
        ));
    }
    Ok(OwnedLocalSecurityDescriptor(descriptor))
}

fn create_new_secure_file(path: &Path) -> Result<File, WindowsServiceLifecycleStateError> {
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
        let code = unsafe { GetLastError() };
        if code == ERROR_ALREADY_EXISTS {
            return Err(WindowsServiceLifecycleStateError::InterruptedWrite(
                "pending lifecycle state",
            ));
        }
        return Err(WindowsServiceLifecycleStateError::Win32 {
            operation: "create secure pending lifecycle state",
            code,
        });
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn open_existing_file(
    path: &Path,
    desired_access: u32,
    share_mode: u32,
) -> Result<Option<File>, WindowsServiceLifecycleStateError> {
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
) -> Result<Option<File>, WindowsServiceLifecycleStateError> {
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
        return Err(WindowsServiceLifecycleStateError::Win32 {
            operation: "open exact Windows lifecycle state path",
            code,
        });
    }
    Ok(Some(unsafe { File::from_raw_handle(handle) }))
}

fn flush_file(
    file: &File,
    operation: &'static str,
) -> Result<(), WindowsServiceLifecycleStateError> {
    if unsafe { FlushFileBuffers(raw_handle(file)) } == 0 {
        Err(last_win32(operation))
    } else {
        Ok(())
    }
}

fn move_file_exact(
    source: &Path,
    destination: &Path,
    replace_existing: bool,
    operation: &'static str,
) -> Result<(), WindowsServiceLifecycleStateError> {
    let source = wide_path(source);
    let destination = wide_path(destination);
    let flags = MOVEFILE_WRITE_THROUGH
        | if replace_existing {
            MOVEFILE_REPLACE_EXISTING
        } else {
            0
        };
    if unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), flags) } == 0 {
        Err(last_win32(operation))
    } else {
        Ok(())
    }
}

fn mark_delete_on_close(
    file: &File,
    operation: &'static str,
) -> Result<(), WindowsServiceLifecycleStateError> {
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

fn last_win32(operation: &'static str) -> WindowsServiceLifecycleStateError {
    WindowsServiceLifecycleStateError::Win32 {
        operation,
        code: unsafe { GetLastError() },
    }
}

fn map_native_evidence_error(error: NativeEvidenceError) -> WindowsServiceLifecycleStateError {
    match error {
        NativeEvidenceError::Missing => {
            WindowsServiceLifecycleStateError::ExistingState("lifecycle state evidence is missing")
        }
        NativeEvidenceError::Inaccessible => WindowsServiceLifecycleStateError::ExistingState(
            "lifecycle state evidence is inaccessible",
        ),
        NativeEvidenceError::Invalid => {
            WindowsServiceLifecycleStateError::ExistingState("lifecycle state evidence is invalid")
        }
        NativeEvidenceError::UntrustedPermissions => {
            WindowsServiceLifecycleStateError::ExistingState(
                "lifecycle state evidence permissions are untrusted",
            )
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_payload::WindowsServicePayloadEffects;
    use sha2::{Digest, Sha256};
    use std::fs;

    const PAYLOAD: &[u8] = b"slipstream-lifecycle-state-fixture";

    fn disposable_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "slipstream-lifecycle-state-{}-{name}",
            std::process::id()
        ))
    }

    fn identity(generation: u64) -> WindowsServiceIdentity {
        WindowsServiceIdentity {
            service_name: "dev.slipstream.service".to_owned(),
            executable_sha256: format!("{:x}", Sha256::digest(PAYLOAD)),
            generation,
        }
    }

    fn disposable_effects(
        name: &str,
    ) -> (
        WindowsServiceLifecycleStateEffects,
        WindowsServicePayloadEffects,
        PathBuf,
        PathBuf,
    ) {
        let root = disposable_path(name);
        let source = disposable_path(&format!("{name}-source.exe"));
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_file(&source);
        fs::create_dir(&root).expect("create disposable lifecycle state root");
        fs::write(&source, PAYLOAD).expect("write disposable payload source");
        let destination = root.join("Slipstream");
        (
            WindowsServiceLifecycleStateEffects::for_disposable_test(destination.clone()),
            WindowsServicePayloadEffects::for_disposable_test(source.clone(), destination),
            root,
            source,
        )
    }

    #[test]
    fn intent_commit_and_clear_round_trip_is_owner_only() {
        if std::env::var_os("SLIPSTREAM_WINDOWS_DISPOSABLE_CI").is_none() {
            return;
        }
        let (state, payload, root, source) = disposable_effects("round-trip");
        let identity = identity(1);
        state
            .persist_intent(
                WindowsServiceDesiredState::Running,
                Some(identity.clone()),
                0,
            )
            .expect("persist running intent");
        payload
            .stage_payload(&identity)
            .expect("stage payload before active commit");
        state
            .commit_install(&identity)
            .expect("commit active install");
        assert!(state.collect().is_stable_for_scm_evaluation());

        state
            .persist_intent(
                WindowsServiceDesiredState::Absent,
                Some(identity.clone()),
                0,
            )
            .expect("persist uninstall tombstone");
        state
            .clear_active_install_record(&identity)
            .expect("clear exact active install");
        let evidence = state.collect();
        assert!(matches!(
            evidence.intent,
            WindowsDurableRecordEvidence::Committed {
                record: WindowsServiceIntentRecordV1 {
                    desired: WindowsServiceDesiredState::Absent,
                    identity: Some(_),
                    ..
                }
            }
        ));
        assert_eq!(
            evidence.active_install,
            WindowsDurableRecordEvidence::Missing
        );

        payload
            .remove_owned_payload(&identity)
            .expect("remove disposable payload");
        fs::remove_dir_all(root).expect("remove disposable lifecycle state root");
        fs::remove_file(source).expect("remove disposable payload source");
    }

    #[test]
    fn pending_intent_is_reported_and_blocks_further_effects() {
        if std::env::var_os("SLIPSTREAM_WINDOWS_DISPOSABLE_CI").is_none() {
            return;
        }
        let (state, _payload, root, source) = disposable_effects("interrupted-intent");
        let identity = identity(1);
        state
            .persist_intent(
                WindowsServiceDesiredState::Running,
                Some(identity.clone()),
                0,
            )
            .expect("persist baseline intent");
        let paths = state.state_paths().expect("state paths");
        let mut pending = create_new_secure_file(&paths.intent_pending).expect("create pending");
        pending
            .write_all(b"partial")
            .expect("write partial pending");
        flush_file(&pending, "flush interrupted pending").expect("flush partial pending");
        drop(pending);

        assert_eq!(
            state.collect().assess(),
            WindowsServiceLifecycleStateAssessment::InterruptedWrite
        );
        assert!(matches!(
            state.persist_intent(WindowsServiceDesiredState::Stopped, Some(identity), 0,),
            Err(WindowsServiceLifecycleStateError::InterruptedWrite(_))
        ));

        let pending = open_existing_file(
            &paths.intent_pending,
            GENERIC_READ | READ_CONTROL | DELETE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
        )
        .expect("open pending for cleanup")
        .expect("pending exists");
        mark_delete_on_close(&pending, "remove interrupted test pending").expect("delete pending");
        drop(pending);
        fs::remove_dir_all(root).expect("remove disposable lifecycle state root");
        fs::remove_file(source).expect("remove disposable payload source");
    }

    #[test]
    fn empty_registered_pending_intent_is_an_interrupted_write() {
        if std::env::var_os("SLIPSTREAM_WINDOWS_DISPOSABLE_CI").is_none() {
            return;
        }
        let (state, _payload, root, source) = disposable_effects("empty-pending");
        let paths = state.state_paths().expect("state paths");
        ensure_secure_directory(&paths.root).expect("secure state root");
        let pending = create_new_secure_file(&paths.intent_pending).expect("register pending");
        drop(pending);

        assert_eq!(
            state.collect().assess(),
            WindowsServiceLifecycleStateAssessment::InterruptedWrite
        );

        let pending = open_existing_file(
            &paths.intent_pending,
            GENERIC_READ | READ_CONTROL | DELETE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
        )
        .expect("open empty pending for cleanup")
        .expect("empty pending exists");
        mark_delete_on_close(&pending, "remove empty pending test file").expect("delete pending");
        drop(pending);
        fs::remove_dir_all(root).expect("remove disposable lifecycle state root");
        fs::remove_file(source).expect("remove disposable payload source");
    }

    #[test]
    fn uncommitted_install_intent_can_roll_back_to_absent_without_identity() {
        if std::env::var_os("SLIPSTREAM_WINDOWS_DISPOSABLE_CI").is_none() {
            return;
        }
        let (state, _payload, root, source) = disposable_effects("rollback-intent");
        state
            .persist_intent(WindowsServiceDesiredState::Running, Some(identity(1)), 0)
            .expect("persist uncommitted install intent");
        state
            .persist_intent(WindowsServiceDesiredState::Absent, None, 0)
            .expect("restore prior absent intent");

        assert!(matches!(
            state.collect().intent,
            WindowsDurableRecordEvidence::Committed {
                record: WindowsServiceIntentRecordV1 {
                    desired: WindowsServiceDesiredState::Absent,
                    identity: None,
                    ..
                }
            }
        ));

        fs::remove_dir_all(root).expect("remove disposable lifecycle state root");
        fs::remove_file(source).expect("remove disposable payload source");
    }

    #[test]
    fn pending_create_failure_compensates_exact_handle() {
        if std::env::var_os("SLIPSTREAM_WINDOWS_DISPOSABLE_CI").is_none() {
            return;
        }
        let (mut state, _payload, root, source) = disposable_effects("pending-compensation");
        state.fail_after_intent_pending_create = true;
        assert!(matches!(
            state.persist_intent(WindowsServiceDesiredState::Running, Some(identity(1)), 0,),
            Err(WindowsServiceLifecycleStateError::Verification(
                "injected failure after pending state creation"
            ))
        ));
        let paths = state.state_paths().expect("state paths");
        assert!(!paths.intent.exists());
        assert!(!paths.intent_pending.exists());
        fs::remove_dir_all(root).expect("remove disposable lifecycle state root");
        fs::remove_file(source).expect("remove disposable payload source");
    }

    #[test]
    fn active_commit_rejects_identity_collision_and_non_absent_clear() {
        if std::env::var_os("SLIPSTREAM_WINDOWS_DISPOSABLE_CI").is_none() {
            return;
        }
        let (state, payload, root, source) = disposable_effects("identity-collision");
        let first = identity(1);
        state
            .persist_intent(WindowsServiceDesiredState::Running, Some(first.clone()), 0)
            .expect("persist first intent");
        payload.stage_payload(&first).expect("stage first payload");
        state.commit_install(&first).expect("commit first install");
        assert!(matches!(
            state.clear_active_install_record(&first),
            Err(WindowsServiceLifecycleStateError::ExistingState(
                "clear would weaken a non-absent or different durable intent"
            ))
        ));
        assert!(matches!(
            state.persist_intent(WindowsServiceDesiredState::Running, Some(identity(2)), 0,),
            Err(WindowsServiceLifecycleStateError::ExistingState(_))
        ));

        state
            .persist_intent(WindowsServiceDesiredState::Absent, Some(first.clone()), 0)
            .expect("persist absent intent");
        state
            .clear_active_install_record(&first)
            .expect("clear first active install");
        payload
            .remove_owned_payload(&first)
            .expect("remove first payload");
        fs::remove_dir_all(root).expect("remove disposable lifecycle state root");
        fs::remove_file(source).expect("remove disposable payload source");
    }
}
