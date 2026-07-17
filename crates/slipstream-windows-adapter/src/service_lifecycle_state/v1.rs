//! Frozen v1 records and evidence classification for durable service lifecycle state.

use crate::service_lifecycle::{
    WindowsServiceDesiredState, WindowsServiceIdentity, DEFAULT_MAX_CRASH_RESTARTS,
};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const WINDOWS_SERVICE_LIFECYCLE_STATE_CONTRACT_VERSION: u32 = 1;
pub const WINDOWS_SERVICE_LIFECYCLE_STATE_SCHEMA_VERSION: u32 = 1;
pub const WINDOWS_SERVICE_INTENT_RECORD_KIND: &str = "slipstream.windows_service_intent";
pub const WINDOWS_SERVICE_ACTIVE_INSTALL_RECORD_KIND: &str = "slipstream.windows_active_install";
pub const WINDOWS_SERVICE_INTENT_FILE_NAME: &str = "service-intent-v1.json";
pub const WINDOWS_SERVICE_INTENT_PENDING_FILE_NAME: &str = ".service-intent-v1.json.pending-v1";
pub const WINDOWS_SERVICE_ACTIVE_INSTALL_FILE_NAME: &str = "service-active-v1.json";
pub const WINDOWS_SERVICE_ACTIVE_INSTALL_PENDING_FILE_NAME: &str =
    ".service-active-v1.json.pending-v1";
pub const MAX_WINDOWS_SERVICE_STATE_RECORD_BYTES: usize = 4 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsServiceIntentRecordV1 {
    pub schema_version: u32,
    pub record_kind: String,
    pub desired: WindowsServiceDesiredState,
    pub identity: Option<WindowsServiceIdentity>,
    pub crash_restart_attempts: u32,
}

impl WindowsServiceIntentRecordV1 {
    pub fn new(
        desired: WindowsServiceDesiredState,
        identity: Option<WindowsServiceIdentity>,
        crash_restart_attempts: u32,
    ) -> Result<Self, WindowsServiceLifecycleStateContractError> {
        let record = Self {
            schema_version: WINDOWS_SERVICE_LIFECYCLE_STATE_SCHEMA_VERSION,
            record_kind: WINDOWS_SERVICE_INTENT_RECORD_KIND.to_owned(),
            desired,
            identity,
            crash_restart_attempts,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), WindowsServiceLifecycleStateContractError> {
        if self.schema_version != WINDOWS_SERVICE_LIFECYCLE_STATE_SCHEMA_VERSION {
            return Err(WindowsServiceLifecycleStateContractError::Invalid(
                "intent schema version is not v1",
            ));
        }
        if self.record_kind != WINDOWS_SERVICE_INTENT_RECORD_KIND {
            return Err(WindowsServiceLifecycleStateContractError::Invalid(
                "intent record kind is not canonical",
            ));
        }
        if self.desired == WindowsServiceDesiredState::Unknown {
            return Err(WindowsServiceLifecycleStateContractError::Invalid(
                "unknown durable intent is not actionable",
            ));
        }
        if self.crash_restart_attempts > DEFAULT_MAX_CRASH_RESTARTS {
            return Err(WindowsServiceLifecycleStateContractError::Invalid(
                "crash restart attempts exceed the v1 bound",
            ));
        }
        if self.desired != WindowsServiceDesiredState::Running && self.crash_restart_attempts != 0 {
            return Err(WindowsServiceLifecycleStateContractError::Invalid(
                "non-running intent cannot retain a crash restart budget",
            ));
        }
        match (&self.desired, &self.identity) {
            (WindowsServiceDesiredState::Running | WindowsServiceDesiredState::Stopped, None) => {
                return Err(WindowsServiceLifecycleStateContractError::Invalid(
                    "running or stopped intent requires an exact identity",
                ));
            }
            (_, Some(identity)) => identity.validate().map_err(|_| {
                WindowsServiceLifecycleStateContractError::Invalid(
                    "intent contains an invalid service identity",
                )
            })?,
            _ => {}
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WindowsServiceLifecycleStateContractError> {
        self.validate()?;
        bounded_json(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsServiceActiveInstallRecordV1 {
    pub schema_version: u32,
    pub record_kind: String,
    pub identity: WindowsServiceIdentity,
}

impl WindowsServiceActiveInstallRecordV1 {
    pub fn new(
        identity: WindowsServiceIdentity,
    ) -> Result<Self, WindowsServiceLifecycleStateContractError> {
        let record = Self {
            schema_version: WINDOWS_SERVICE_LIFECYCLE_STATE_SCHEMA_VERSION,
            record_kind: WINDOWS_SERVICE_ACTIVE_INSTALL_RECORD_KIND.to_owned(),
            identity,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), WindowsServiceLifecycleStateContractError> {
        if self.schema_version != WINDOWS_SERVICE_LIFECYCLE_STATE_SCHEMA_VERSION {
            return Err(WindowsServiceLifecycleStateContractError::Invalid(
                "active install schema version is not v1",
            ));
        }
        if self.record_kind != WINDOWS_SERVICE_ACTIVE_INSTALL_RECORD_KIND {
            return Err(WindowsServiceLifecycleStateContractError::Invalid(
                "active install record kind is not canonical",
            ));
        }
        self.identity.validate().map_err(|_| {
            WindowsServiceLifecycleStateContractError::Invalid(
                "active install contains an invalid service identity",
            )
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WindowsServiceLifecycleStateContractError> {
        self.validate()?;
        bounded_json(self)
    }
}

pub fn parse_windows_service_intent_record_v1(
    bytes: &[u8],
) -> Result<WindowsServiceIntentRecordV1, WindowsServiceLifecycleStateContractError> {
    bounded_input(bytes)?;
    let wire: StrictIntentRecordV1 = serde_json::from_slice(bytes).map_err(|_| {
        WindowsServiceLifecycleStateContractError::Invalid("intent record is not strict v1 JSON")
    })?;
    let record = WindowsServiceIntentRecordV1 {
        schema_version: wire.schema_version,
        record_kind: wire.record_kind,
        desired: wire.desired,
        identity: wire.identity.map(Into::into),
        crash_restart_attempts: wire.crash_restart_attempts,
    };
    record.validate()?;
    Ok(record)
}

pub fn parse_windows_service_active_install_record_v1(
    bytes: &[u8],
) -> Result<WindowsServiceActiveInstallRecordV1, WindowsServiceLifecycleStateContractError> {
    bounded_input(bytes)?;
    let wire: StrictActiveInstallRecordV1 = serde_json::from_slice(bytes).map_err(|_| {
        WindowsServiceLifecycleStateContractError::Invalid(
            "active install record is not strict v1 JSON",
        )
    })?;
    let record = WindowsServiceActiveInstallRecordV1 {
        schema_version: wire.schema_version,
        record_kind: wire.record_kind,
        identity: wire.identity.into(),
    };
    record.validate()?;
    Ok(record)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsDurableRecordEvidence<T> {
    Missing,
    Committed { record: T },
    InterruptedWrite { committed: Option<T> },
    Inaccessible,
    Invalid,
    UntrustedPermissions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsServiceLifecycleStateEvidence {
    pub intent: WindowsDurableRecordEvidence<WindowsServiceIntentRecordV1>,
    pub active_install: WindowsDurableRecordEvidence<WindowsServiceActiveInstallRecordV1>,
}

impl WindowsServiceLifecycleStateEvidence {
    pub fn assess(&self) -> WindowsServiceLifecycleStateAssessment {
        let intent = match committed_record(&self.intent) {
            Ok(record) => record,
            Err(WindowsEvidenceBarrier::Interrupted) => {
                return WindowsServiceLifecycleStateAssessment::InterruptedWrite
            }
            Err(WindowsEvidenceBarrier::Unknown) => {
                return WindowsServiceLifecycleStateAssessment::Unknown
            }
        };
        let active_install = match committed_record(&self.active_install) {
            Ok(record) => record,
            Err(WindowsEvidenceBarrier::Interrupted) => {
                return WindowsServiceLifecycleStateAssessment::InterruptedWrite
            }
            Err(WindowsEvidenceBarrier::Unknown) => {
                return WindowsServiceLifecycleStateAssessment::Unknown
            }
        };

        if let Some(active) = active_install {
            let Some(intent) = intent else {
                return WindowsServiceLifecycleStateAssessment::Inconsistent;
            };
            if intent.identity.as_ref() != Some(&active.identity) {
                return WindowsServiceLifecycleStateAssessment::Inconsistent;
            }
        }

        WindowsServiceLifecycleStateAssessment::Stable {
            intent: intent.cloned(),
            active_install: active_install.cloned(),
        }
    }

    /// Returns whether state evidence is stable enough to evaluate a separate,
    /// action-specific SCM ownership gate. This is not mutation authorization.
    pub fn is_stable_for_scm_evaluation(&self) -> bool {
        matches!(
            self.assess(),
            WindowsServiceLifecycleStateAssessment::Stable { .. }
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsServiceLifecycleStateAssessment {
    Stable {
        intent: Option<WindowsServiceIntentRecordV1>,
        active_install: Option<WindowsServiceActiveInstallRecordV1>,
    },
    InterruptedWrite,
    Unknown,
    Inconsistent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsServiceLifecycleStateContractError {
    Invalid(&'static str),
    TooLarge,
}

impl fmt::Display for WindowsServiceLifecycleStateContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(formatter, "invalid lifecycle state record: {reason}"),
            Self::TooLarge => formatter.write_str("lifecycle state record exceeds the v1 bound"),
        }
    }
}

impl std::error::Error for WindowsServiceLifecycleStateContractError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictIntentRecordV1 {
    schema_version: u32,
    record_kind: String,
    desired: WindowsServiceDesiredState,
    identity: Option<StrictIdentityV1>,
    crash_restart_attempts: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictActiveInstallRecordV1 {
    schema_version: u32,
    record_kind: String,
    identity: StrictIdentityV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictIdentityV1 {
    service_name: String,
    executable_sha256: String,
    generation: u64,
}

impl From<StrictIdentityV1> for WindowsServiceIdentity {
    fn from(value: StrictIdentityV1) -> Self {
        Self {
            service_name: value.service_name,
            executable_sha256: value.executable_sha256,
            generation: value.generation,
        }
    }
}

enum WindowsEvidenceBarrier {
    Interrupted,
    Unknown,
}

fn committed_record<T>(
    evidence: &WindowsDurableRecordEvidence<T>,
) -> Result<Option<&T>, WindowsEvidenceBarrier> {
    match evidence {
        WindowsDurableRecordEvidence::Missing => Ok(None),
        WindowsDurableRecordEvidence::Committed { record } => Ok(Some(record)),
        WindowsDurableRecordEvidence::InterruptedWrite { .. } => {
            Err(WindowsEvidenceBarrier::Interrupted)
        }
        WindowsDurableRecordEvidence::Inaccessible
        | WindowsDurableRecordEvidence::Invalid
        | WindowsDurableRecordEvidence::UntrustedPermissions => {
            Err(WindowsEvidenceBarrier::Unknown)
        }
    }
}

fn bounded_input(bytes: &[u8]) -> Result<(), WindowsServiceLifecycleStateContractError> {
    if bytes.is_empty() {
        return Err(WindowsServiceLifecycleStateContractError::Invalid(
            "record is empty",
        ));
    }
    if bytes.len() > MAX_WINDOWS_SERVICE_STATE_RECORD_BYTES {
        return Err(WindowsServiceLifecycleStateContractError::TooLarge);
    }
    Ok(())
}

fn bounded_json<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, WindowsServiceLifecycleStateContractError> {
    let bytes = serde_json::to_vec(value).map_err(|_| {
        WindowsServiceLifecycleStateContractError::Invalid("record cannot be serialized")
    })?;
    bounded_input(&bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn identity(generation: u64) -> WindowsServiceIdentity {
        WindowsServiceIdentity {
            service_name: "dev.slipstream.service".to_owned(),
            executable_sha256: SHA256.to_owned(),
            generation,
        }
    }

    fn intent(desired: WindowsServiceDesiredState) -> WindowsServiceIntentRecordV1 {
        WindowsServiceIntentRecordV1::new(desired, Some(identity(1)), 0).expect("valid intent")
    }

    #[test]
    fn strict_records_round_trip_canonically() {
        let intent = intent(WindowsServiceDesiredState::Running);
        assert_eq!(
            parse_windows_service_intent_record_v1(&intent.canonical_bytes().unwrap()).unwrap(),
            intent
        );
        let active = WindowsServiceActiveInstallRecordV1::new(identity(1)).unwrap();
        assert_eq!(
            parse_windows_service_active_install_record_v1(&active.canonical_bytes().unwrap())
                .unwrap(),
            active
        );
    }

    #[test]
    fn strict_records_reject_unknown_fields_and_unbounded_budgets() {
        let extra = format!(
            r#"{{"schema_version":1,"record_kind":"{WINDOWS_SERVICE_INTENT_RECORD_KIND}","desired":"running","identity":{{"service_name":"dev.slipstream.service","executable_sha256":"{SHA256}","generation":1,"extra":true}},"crash_restart_attempts":0}}"#
        );
        assert!(parse_windows_service_intent_record_v1(extra.as_bytes()).is_err());
        assert!(WindowsServiceIntentRecordV1::new(
            WindowsServiceDesiredState::Running,
            Some(identity(1)),
            DEFAULT_MAX_CRASH_RESTARTS + 1,
        )
        .is_err());
    }

    #[test]
    fn interrupted_or_untrusted_evidence_blocks_scm_mutation() {
        let evidence = WindowsServiceLifecycleStateEvidence {
            intent: WindowsDurableRecordEvidence::InterruptedWrite {
                committed: Some(intent(WindowsServiceDesiredState::Running)),
            },
            active_install: WindowsDurableRecordEvidence::Missing,
        };
        assert_eq!(
            evidence.assess(),
            WindowsServiceLifecycleStateAssessment::InterruptedWrite
        );
        assert!(!evidence.is_stable_for_scm_evaluation());

        let unknown = WindowsServiceLifecycleStateEvidence {
            intent: WindowsDurableRecordEvidence::UntrustedPermissions,
            active_install: WindowsDurableRecordEvidence::Missing,
        };
        assert_eq!(
            unknown.assess(),
            WindowsServiceLifecycleStateAssessment::Unknown
        );
        assert!(!unknown.is_stable_for_scm_evaluation());
    }

    #[test]
    fn committed_intent_and_matching_active_record_are_stable() {
        let intent = intent(WindowsServiceDesiredState::Running);
        let active = WindowsServiceActiveInstallRecordV1::new(identity(1)).unwrap();
        let evidence = WindowsServiceLifecycleStateEvidence {
            intent: WindowsDurableRecordEvidence::Committed {
                record: intent.clone(),
            },
            active_install: WindowsDurableRecordEvidence::Committed {
                record: active.clone(),
            },
        };
        assert_eq!(
            evidence.assess(),
            WindowsServiceLifecycleStateAssessment::Stable {
                intent: Some(intent),
                active_install: Some(active),
            }
        );
        assert!(evidence.is_stable_for_scm_evaluation());
    }

    #[test]
    fn mismatched_active_record_is_inconsistent() {
        let evidence = WindowsServiceLifecycleStateEvidence {
            intent: WindowsDurableRecordEvidence::Committed {
                record: intent(WindowsServiceDesiredState::Running),
            },
            active_install: WindowsDurableRecordEvidence::Committed {
                record: WindowsServiceActiveInstallRecordV1::new(identity(2)).unwrap(),
            },
        };
        assert_eq!(
            evidence.assess(),
            WindowsServiceLifecycleStateAssessment::Inconsistent
        );
        assert!(!evidence.is_stable_for_scm_evaluation());
    }
}
