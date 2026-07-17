//! Strict, platform-neutral parsing for the machine ownership record.

use super::{WindowsServiceOwnershipRecord, WINDOWS_SERVICE_OWNERSHIP_RECORD_SCHEMA_VERSION};
use crate::service_lifecycle::WINDOWS_SERVICE_NAME;
use serde::Deserialize;
use std::fmt;

pub const WINDOWS_OWNER_RECORD_DIRECTORY: &str = "Slipstream";
pub const WINDOWS_OWNER_RECORD_FILE_NAME: &str = "service-owner-v1.json";
pub const MAX_WINDOWS_OWNER_RECORD_BYTES: usize = 8 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictWindowsServiceOwnershipRecordV1 {
    schema_version: u32,
    service_name: String,
    scm_binary_path: String,
    executable_path: String,
    executable_sha256: String,
    generation: u64,
}

pub fn parse_windows_owner_record_v1(
    bytes: &[u8],
) -> Result<WindowsServiceOwnershipRecord, WindowsOwnerRecordParseError> {
    if bytes.is_empty() {
        return Err(WindowsOwnerRecordParseError::Empty);
    }
    if bytes.len() > MAX_WINDOWS_OWNER_RECORD_BYTES {
        return Err(WindowsOwnerRecordParseError::TooLarge);
    }

    let strict: StrictWindowsServiceOwnershipRecordV1 =
        serde_json::from_slice(bytes).map_err(|_| WindowsOwnerRecordParseError::InvalidJson)?;
    let record = WindowsServiceOwnershipRecord {
        schema_version: strict.schema_version,
        service_name: strict.service_name,
        scm_binary_path: strict.scm_binary_path,
        executable_path: strict.executable_path,
        executable_sha256: strict.executable_sha256,
        generation: strict.generation,
    };
    record
        .validate()
        .map_err(|_| WindowsOwnerRecordParseError::InvalidContract)?;
    validate_canonical_record_path(&record.executable_path)?;
    if record.schema_version != WINDOWS_SERVICE_OWNERSHIP_RECORD_SCHEMA_VERSION
        || record.service_name != WINDOWS_SERVICE_NAME
    {
        return Err(WindowsOwnerRecordParseError::InvalidContract);
    }
    Ok(record)
}

fn validate_canonical_record_path(path: &str) -> Result<(), WindowsOwnerRecordParseError> {
    let mut components = path[3..].split('\\');
    if components.any(|component| {
        component.is_empty()
            || component.ends_with('.')
            || component.ends_with(' ')
            || component.chars().any(char::is_control)
    }) {
        return Err(WindowsOwnerRecordParseError::InvalidContract);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsOwnerRecordParseError {
    Empty,
    TooLarge,
    InvalidJson,
    InvalidContract,
}

impl fmt::Display for WindowsOwnerRecordParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "Windows owner record is empty",
            Self::TooLarge => "Windows owner record exceeds the v1 size limit",
            Self::InvalidJson => "Windows owner record is not strict v1 JSON",
            Self::InvalidContract => "Windows owner record violates the v1 contract",
        })
    }
}

impl std::error::Error for WindowsOwnerRecordParseError {}
