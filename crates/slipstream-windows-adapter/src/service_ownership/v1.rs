//! Pure version 1 ownership assessment for the Windows service.

use crate::service_lifecycle::{
    WindowsServiceDesiredState, WindowsServiceIdentity, WindowsServiceObservedState,
    WindowsServiceOwnership, WindowsServiceState, WINDOWS_SERVICE_NAME,
};
use crate::service_observer::{WindowsScmState, WindowsServiceObservation};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const WINDOWS_SERVICE_OWNERSHIP_CONTRACT_VERSION: u32 = 1;
pub const WINDOWS_SERVICE_OWNERSHIP_RECORD_SCHEMA_VERSION: u32 = 1;
pub const WINDOWS_SERVICE_ARGUMENT: &str = "--service";
const MAX_WINDOWS_RECORD_STRING_UTF16_UNITS: usize = 32_767;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsServiceOwnershipRecord {
    pub schema_version: u32,
    pub service_name: String,
    pub scm_binary_path: String,
    pub executable_path: String,
    pub executable_sha256: String,
    pub generation: u64,
}

impl WindowsServiceOwnershipRecord {
    pub fn validate(&self) -> Result<(), WindowsServiceOwnershipContractError> {
        if self.schema_version != WINDOWS_SERVICE_OWNERSHIP_RECORD_SCHEMA_VERSION {
            return Err(WindowsServiceOwnershipContractError::InvalidRecord(
                "schema_version",
            ));
        }
        if self.service_name != WINDOWS_SERVICE_NAME {
            return Err(WindowsServiceOwnershipContractError::InvalidRecord(
                "service_name",
            ));
        }
        validate_executable_path(&self.executable_path)?;
        validate_bounded_text("scm_binary_path", &self.scm_binary_path)?;
        if self.scm_binary_path != canonical_scm_binary_path(&self.executable_path) {
            return Err(WindowsServiceOwnershipContractError::InvalidRecord(
                "scm_binary_path",
            ));
        }
        self.identity()
            .validate()
            .map_err(|_| WindowsServiceOwnershipContractError::InvalidRecord("identity"))
    }

    pub fn identity(&self) -> WindowsServiceIdentity {
        WindowsServiceIdentity {
            service_name: self.service_name.clone(),
            executable_sha256: self.executable_sha256.clone(),
            generation: self.generation,
        }
    }
}

pub fn canonical_scm_binary_path(executable_path: &str) -> String {
    format!("\"{executable_path}\" {WINDOWS_SERVICE_ARGUMENT}")
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum WindowsOwnerRecordEvidence {
    Missing,
    OwnerOnly {
        record: WindowsServiceOwnershipRecord,
    },
    Inaccessible,
    Invalid,
    UntrustedPermissions,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum WindowsScmEvidence {
    Observed {
        observation: WindowsServiceObservation,
    },
    Inaccessible,
    Invalid,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum WindowsExecutableEvidence {
    NotChecked,
    Verified {
        executable_path: String,
        executable_sha256: String,
    },
    Missing,
    Inaccessible,
    Invalid,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsServiceOwnershipInput {
    pub record: WindowsOwnerRecordEvidence,
    pub scm: WindowsScmEvidence,
    pub executable: WindowsExecutableEvidence,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsServiceOwnershipReason {
    Absent,
    Owned,
    ServiceWithoutRecord,
    RecordWithoutService,
    RecordInaccessible,
    RecordInvalid,
    RecordPermissionsUntrusted,
    ScmInaccessible,
    ScmInvalid,
    TransitionalServiceState,
    ServiceNameMismatch,
    ScmBinaryPathMismatch,
    ExecutableNotChecked,
    ExecutableMissing,
    ExecutableInaccessible,
    ExecutableInvalid,
    ExecutablePathMismatch,
    ExecutableHashMismatch,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsServiceOwnershipAssessment {
    pub ownership: WindowsServiceOwnership,
    pub observed: WindowsServiceObservedState,
    pub identity: Option<WindowsServiceIdentity>,
    pub reason: WindowsServiceOwnershipReason,
}

impl WindowsServiceOwnershipAssessment {
    pub fn lifecycle_state(
        &self,
        desired: WindowsServiceDesiredState,
        crash_restart_attempts: u32,
    ) -> WindowsServiceState {
        WindowsServiceState {
            desired,
            observed: self.observed,
            ownership: self.ownership,
            active: self.identity.clone(),
            crash_restart_attempts,
        }
    }
}

pub fn assess_windows_service_ownership(
    input: &WindowsServiceOwnershipInput,
) -> WindowsServiceOwnershipAssessment {
    let observation = match &input.scm {
        WindowsScmEvidence::Observed { observation } => observation,
        WindowsScmEvidence::Inaccessible => {
            return assessment(
                WindowsServiceOwnership::Unknown,
                WindowsServiceObservedState::Unknown,
                None,
                WindowsServiceOwnershipReason::ScmInaccessible,
            );
        }
        WindowsScmEvidence::Invalid => {
            return assessment(
                WindowsServiceOwnership::Unknown,
                WindowsServiceObservedState::Unknown,
                None,
                WindowsServiceOwnershipReason::ScmInvalid,
            );
        }
    };

    match observation {
        WindowsServiceObservation::Absent { service_name } => {
            if service_name != WINDOWS_SERVICE_NAME {
                return assessment(
                    WindowsServiceOwnership::Unknown,
                    WindowsServiceObservedState::Unknown,
                    None,
                    WindowsServiceOwnershipReason::ServiceNameMismatch,
                );
            }
            match &input.record {
                WindowsOwnerRecordEvidence::Missing => assessment(
                    WindowsServiceOwnership::Absent,
                    WindowsServiceObservedState::Absent,
                    None,
                    WindowsServiceOwnershipReason::Absent,
                ),
                WindowsOwnerRecordEvidence::OwnerOnly { .. } => assessment(
                    WindowsServiceOwnership::Unknown,
                    WindowsServiceObservedState::Absent,
                    None,
                    WindowsServiceOwnershipReason::RecordWithoutService,
                ),
                WindowsOwnerRecordEvidence::Inaccessible => assessment(
                    WindowsServiceOwnership::Unknown,
                    WindowsServiceObservedState::Absent,
                    None,
                    WindowsServiceOwnershipReason::RecordInaccessible,
                ),
                WindowsOwnerRecordEvidence::Invalid => assessment(
                    WindowsServiceOwnership::Unknown,
                    WindowsServiceObservedState::Absent,
                    None,
                    WindowsServiceOwnershipReason::RecordInvalid,
                ),
                WindowsOwnerRecordEvidence::UntrustedPermissions => assessment(
                    WindowsServiceOwnership::Unknown,
                    WindowsServiceObservedState::Absent,
                    None,
                    WindowsServiceOwnershipReason::RecordPermissionsUntrusted,
                ),
            }
        }
        WindowsServiceObservation::Present { snapshot } => {
            let observed = snapshot.scm_state.observed();
            if snapshot.observed != observed
                || (matches!(snapshot.scm_state, WindowsScmState::Running)
                    && snapshot.process_id.is_none())
                || (!matches!(snapshot.scm_state, WindowsScmState::Running)
                    && snapshot.process_id.is_some())
            {
                return assessment(
                    WindowsServiceOwnership::Unknown,
                    WindowsServiceObservedState::Unknown,
                    None,
                    WindowsServiceOwnershipReason::ScmInvalid,
                );
            }
            if observed == WindowsServiceObservedState::Unknown {
                return assessment(
                    WindowsServiceOwnership::Unknown,
                    WindowsServiceObservedState::Unknown,
                    None,
                    WindowsServiceOwnershipReason::TransitionalServiceState,
                );
            }
            if snapshot.service_name != WINDOWS_SERVICE_NAME {
                return assessment(
                    WindowsServiceOwnership::Foreign,
                    observed,
                    None,
                    WindowsServiceOwnershipReason::ServiceNameMismatch,
                );
            }

            let record = match &input.record {
                WindowsOwnerRecordEvidence::Missing => {
                    return assessment(
                        WindowsServiceOwnership::Foreign,
                        observed,
                        None,
                        WindowsServiceOwnershipReason::ServiceWithoutRecord,
                    );
                }
                WindowsOwnerRecordEvidence::OwnerOnly { record } => record,
                WindowsOwnerRecordEvidence::Inaccessible => {
                    return assessment(
                        WindowsServiceOwnership::Unknown,
                        observed,
                        None,
                        WindowsServiceOwnershipReason::RecordInaccessible,
                    );
                }
                WindowsOwnerRecordEvidence::Invalid => {
                    return assessment(
                        WindowsServiceOwnership::Unknown,
                        observed,
                        None,
                        WindowsServiceOwnershipReason::RecordInvalid,
                    );
                }
                WindowsOwnerRecordEvidence::UntrustedPermissions => {
                    return assessment(
                        WindowsServiceOwnership::Unknown,
                        observed,
                        None,
                        WindowsServiceOwnershipReason::RecordPermissionsUntrusted,
                    );
                }
            };
            if record.validate().is_err() {
                return assessment(
                    WindowsServiceOwnership::Unknown,
                    observed,
                    None,
                    WindowsServiceOwnershipReason::RecordInvalid,
                );
            }
            if snapshot.binary_path != record.scm_binary_path {
                return assessment(
                    WindowsServiceOwnership::Foreign,
                    observed,
                    None,
                    WindowsServiceOwnershipReason::ScmBinaryPathMismatch,
                );
            }

            match &input.executable {
                WindowsExecutableEvidence::NotChecked => assessment(
                    WindowsServiceOwnership::Unknown,
                    observed,
                    None,
                    WindowsServiceOwnershipReason::ExecutableNotChecked,
                ),
                WindowsExecutableEvidence::Missing => assessment(
                    WindowsServiceOwnership::Unknown,
                    observed,
                    None,
                    WindowsServiceOwnershipReason::ExecutableMissing,
                ),
                WindowsExecutableEvidence::Inaccessible => assessment(
                    WindowsServiceOwnership::Unknown,
                    observed,
                    None,
                    WindowsServiceOwnershipReason::ExecutableInaccessible,
                ),
                WindowsExecutableEvidence::Invalid => assessment(
                    WindowsServiceOwnership::Unknown,
                    observed,
                    None,
                    WindowsServiceOwnershipReason::ExecutableInvalid,
                ),
                WindowsExecutableEvidence::Verified {
                    executable_path,
                    executable_sha256,
                } => {
                    if executable_path != &record.executable_path {
                        return assessment(
                            WindowsServiceOwnership::Foreign,
                            observed,
                            None,
                            WindowsServiceOwnershipReason::ExecutablePathMismatch,
                        );
                    }
                    if executable_sha256 != &record.executable_sha256 {
                        return assessment(
                            WindowsServiceOwnership::Foreign,
                            observed,
                            None,
                            WindowsServiceOwnershipReason::ExecutableHashMismatch,
                        );
                    }
                    assessment(
                        WindowsServiceOwnership::Owned,
                        observed,
                        Some(record.identity()),
                        WindowsServiceOwnershipReason::Owned,
                    )
                }
            }
        }
    }
}

fn assessment(
    ownership: WindowsServiceOwnership,
    observed: WindowsServiceObservedState,
    identity: Option<WindowsServiceIdentity>,
    reason: WindowsServiceOwnershipReason,
) -> WindowsServiceOwnershipAssessment {
    WindowsServiceOwnershipAssessment {
        ownership,
        observed,
        identity,
        reason,
    }
}

fn validate_bounded_text(
    field: &'static str,
    value: &str,
) -> Result<(), WindowsServiceOwnershipContractError> {
    if value.is_empty()
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value.encode_utf16().count() > MAX_WINDOWS_RECORD_STRING_UTF16_UNITS
    {
        return Err(WindowsServiceOwnershipContractError::InvalidRecord(field));
    }
    Ok(())
}

fn validate_executable_path(path: &str) -> Result<(), WindowsServiceOwnershipContractError> {
    validate_bounded_text("executable_path", path)?;
    let bytes = path.as_bytes();
    let tail = path.get(3..).unwrap_or_default();
    if bytes.len() < 4
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || bytes[2] != b'\\'
        || path.contains('/')
        || path.contains('"')
        || tail.contains(':')
        || tail
            .split('\\')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(WindowsServiceOwnershipContractError::InvalidRecord(
            "executable_path",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsServiceOwnershipContractError {
    InvalidRecord(&'static str),
}

impl fmt::Display for WindowsServiceOwnershipContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRecord(field) => write!(formatter, "invalid owner record field {field}"),
        }
    }
}

impl std::error::Error for WindowsServiceOwnershipContractError {}
