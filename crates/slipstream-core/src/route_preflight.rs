//! Strict, privacy-bounded exact-host route preflight contract.
//!
//! A preflight result is evidence only. Route policy remains responsible for
//! comparing independent candidates and authorizing an exact-host transition.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

pub const ROUTE_PREFLIGHT_VERSION: u8 = 1;
pub const MAX_ROUTE_PREFLIGHT_BYTES: usize = 2048;
pub const MAX_ROUTE_PREFLIGHT_DEADLINE_MS: u64 = 8_000;
pub const MAX_ROUTE_PREFLIGHT_CANDIDATES: usize = 4;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutePreflightCandidate {
    System,
    AppDoh,
    LocalStrategy,
    OwnedGeph,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutePreflightOutcome {
    NavigationPending,
    RegionalAccessDenied,
    EdgeAccessDenied,
    ChallengeOrAuth,
    Usable,
    TerminalError,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RoutePreflightJobV1 {
    pub schema_version: u8,
    pub capability: String,
    pub host: String,
    pub candidate_routes: Vec<RoutePreflightCandidate>,
    pub issued_at_unix_ms: u64,
    pub deadline_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RoutePreflightResultV1 {
    pub schema_version: u8,
    pub capability: String,
    pub host: String,
    pub candidate_route: RoutePreflightCandidate,
    pub outcome: RoutePreflightOutcome,
    pub observed_at_unix_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutePreflightErrorCode {
    EmptyInput,
    PayloadTooLarge,
    InvalidJson,
    InvalidShape,
    UnsupportedVersion,
    InvalidCapability,
    InvalidHost,
    InvalidCandidateRoutes,
    InvalidCandidateRoute,
    InvalidOutcome,
    InvalidIssuedAt,
    InvalidDeadline,
    InvalidObservedAt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutePreflightError {
    pub code: RoutePreflightErrorCode,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutePreflightDecisionReason {
    Accepted,
    BindingMismatch,
    CandidateNotAllowed,
    ObservationOutsideDeadline,
    Expired,
    Replay,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RoutePreflightDecision {
    pub accepted: bool,
    pub reason: RoutePreflightDecisionReason,
    pub host: String,
    pub candidate_route: RoutePreflightCandidate,
    pub outcome: RoutePreflightOutcome,
}

fn error(code: RoutePreflightErrorCode) -> RoutePreflightError {
    RoutePreflightError { code }
}

fn parse_object(
    payload: &[u8],
    required_fields: &[&str],
) -> Result<Map<String, Value>, RoutePreflightError> {
    if payload.is_empty() {
        return Err(error(RoutePreflightErrorCode::EmptyInput));
    }
    if payload.len() > MAX_ROUTE_PREFLIGHT_BYTES {
        return Err(error(RoutePreflightErrorCode::PayloadTooLarge));
    }
    let value: Value =
        serde_json::from_slice(payload).map_err(|_| error(RoutePreflightErrorCode::InvalidJson))?;
    let object = value
        .as_object()
        .ok_or_else(|| error(RoutePreflightErrorCode::InvalidShape))?;
    if object.len() != required_fields.len()
        || !required_fields
            .iter()
            .all(|field| object.contains_key(*field))
    {
        return Err(error(RoutePreflightErrorCode::InvalidShape));
    }
    Ok(object.clone())
}

fn parse_version(object: &Map<String, Value>) -> Result<u8, RoutePreflightError> {
    let version = object["schema_version"]
        .as_u64()
        .and_then(|value| u8::try_from(value).ok())
        .ok_or_else(|| error(RoutePreflightErrorCode::UnsupportedVersion))?;
    if version != ROUTE_PREFLIGHT_VERSION {
        return Err(error(RoutePreflightErrorCode::UnsupportedVersion));
    }
    Ok(version)
}

fn parse_capability(object: &Map<String, Value>) -> Result<String, RoutePreflightError> {
    let capability = object["capability"]
        .as_str()
        .ok_or_else(|| error(RoutePreflightErrorCode::InvalidCapability))?;
    if capability.len() != 32
        || !capability
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(error(RoutePreflightErrorCode::InvalidCapability));
    }
    Ok(capability.to_owned())
}

fn normalize_hostname(value: &str) -> Option<String> {
    if value.trim() != value {
        return None;
    }
    let mut host = value.to_ascii_lowercase();
    if host.ends_with('.') {
        host.pop();
    }
    if host.is_empty() || host.len() > 253 || !host.contains('.') {
        return None;
    }
    if IpAddr::from_str(&host).is_ok() {
        return None;
    }
    let valid = host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    });
    valid.then_some(host)
}

fn parse_host(object: &Map<String, Value>) -> Result<String, RoutePreflightError> {
    object["host"]
        .as_str()
        .and_then(normalize_hostname)
        .ok_or_else(|| error(RoutePreflightErrorCode::InvalidHost))
}

pub fn parse_route_preflight_job_v1(
    payload: &[u8],
) -> Result<RoutePreflightJobV1, RoutePreflightError> {
    const FIELDS: [&str; 6] = [
        "schema_version",
        "capability",
        "host",
        "candidate_routes",
        "issued_at_unix_ms",
        "deadline_unix_ms",
    ];
    let object = parse_object(payload, &FIELDS)?;
    let schema_version = parse_version(&object)?;
    let capability = parse_capability(&object)?;
    let host = parse_host(&object)?;
    let candidate_routes: Vec<RoutePreflightCandidate> =
        serde_json::from_value(object["candidate_routes"].clone())
            .map_err(|_| error(RoutePreflightErrorCode::InvalidCandidateRoutes))?;
    let unique: HashSet<_> = candidate_routes.iter().copied().collect();
    if candidate_routes.is_empty()
        || candidate_routes.len() > MAX_ROUTE_PREFLIGHT_CANDIDATES
        || unique.len() != candidate_routes.len()
    {
        return Err(error(RoutePreflightErrorCode::InvalidCandidateRoutes));
    }
    let issued_at_unix_ms = object["issued_at_unix_ms"]
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or_else(|| error(RoutePreflightErrorCode::InvalidIssuedAt))?;
    let deadline_unix_ms = object["deadline_unix_ms"]
        .as_u64()
        .filter(|value| {
            *value > issued_at_unix_ms
                && value.saturating_sub(issued_at_unix_ms) <= MAX_ROUTE_PREFLIGHT_DEADLINE_MS
        })
        .ok_or_else(|| error(RoutePreflightErrorCode::InvalidDeadline))?;
    Ok(RoutePreflightJobV1 {
        schema_version,
        capability,
        host,
        candidate_routes,
        issued_at_unix_ms,
        deadline_unix_ms,
    })
}

pub fn parse_route_preflight_result_v1(
    payload: &[u8],
) -> Result<RoutePreflightResultV1, RoutePreflightError> {
    const FIELDS: [&str; 6] = [
        "schema_version",
        "capability",
        "host",
        "candidate_route",
        "outcome",
        "observed_at_unix_ms",
    ];
    let object = parse_object(payload, &FIELDS)?;
    let schema_version = parse_version(&object)?;
    let capability = parse_capability(&object)?;
    let host = parse_host(&object)?;
    let candidate_route = serde_json::from_value(object["candidate_route"].clone())
        .map_err(|_| error(RoutePreflightErrorCode::InvalidCandidateRoute))?;
    let outcome = serde_json::from_value(object["outcome"].clone())
        .map_err(|_| error(RoutePreflightErrorCode::InvalidOutcome))?;
    let observed_at_unix_ms = object["observed_at_unix_ms"]
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or_else(|| error(RoutePreflightErrorCode::InvalidObservedAt))?;
    Ok(RoutePreflightResultV1 {
        schema_version,
        capability,
        host,
        candidate_route,
        outcome,
        observed_at_unix_ms,
    })
}

pub fn validate_route_preflight_result_v1(
    job: &RoutePreflightJobV1,
    result: &RoutePreflightResultV1,
    now_unix_ms: u64,
    capability_seen: bool,
) -> RoutePreflightDecision {
    let reason = if capability_seen {
        RoutePreflightDecisionReason::Replay
    } else if job.schema_version != result.schema_version
        || job.capability != result.capability
        || job.host != result.host
    {
        RoutePreflightDecisionReason::BindingMismatch
    } else if !job.candidate_routes.contains(&result.candidate_route) {
        RoutePreflightDecisionReason::CandidateNotAllowed
    } else if result.observed_at_unix_ms < job.issued_at_unix_ms
        || result.observed_at_unix_ms > job.deadline_unix_ms
    {
        RoutePreflightDecisionReason::ObservationOutsideDeadline
    } else if now_unix_ms > job.deadline_unix_ms {
        RoutePreflightDecisionReason::Expired
    } else {
        RoutePreflightDecisionReason::Accepted
    };
    RoutePreflightDecision {
        accepted: reason == RoutePreflightDecisionReason::Accepted,
        reason,
        host: result.host.clone(),
        candidate_route: result.candidate_route,
        outcome: result.outcome,
    }
}
