//! Strict privacy-bounded browser semantic-signal contract.

use crate::routing_policy::RouteClass;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::net::IpAddr;
use std::str::FromStr;

pub const SEMANTIC_ROUTE_SIGNAL_VERSION: u8 = 1;
pub const SEMANTIC_ROUTE_SIGNAL_V2_VERSION: u8 = 2;
pub const MAX_SEMANTIC_SIGNAL_BYTES: usize = 2048;
pub const MAX_SEMANTIC_SIGNAL_AGE_MS: u64 = 120_000;
pub const MAX_SEMANTIC_SIGNAL_FUTURE_SKEW_MS: u64 = 5_000;
pub const SEMANTIC_SIGNAL_COOLDOWN_MS: u64 = 300_000;
pub const MIN_SEMANTIC_SIGNAL_CONFIDENCE_BPS: u16 = 9_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SemanticRouteSignalV1 {
    pub schema_version: u8,
    pub signal_id: String,
    pub source: String,
    pub host: String,
    pub category: String,
    pub confidence_bps: u16,
    pub observed_at_unix_ms: u64,
    pub top_level: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SemanticRouteSignalV2 {
    pub schema_version: u8,
    pub signal_id: String,
    pub source: String,
    pub host: String,
    pub category: String,
    pub confidence_bps: u16,
    pub observed_at_unix_ms: u64,
    pub top_level: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticSignalErrorCode {
    EmptyInput,
    PayloadTooLarge,
    InvalidJson,
    InvalidShape,
    UnsupportedVersion,
    InvalidSignalId,
    InvalidSource,
    InvalidHost,
    InvalidCategory,
    InvalidConfidence,
    InvalidObservedAt,
    InvalidTopLevel,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticSignalError {
    pub code: SemanticSignalErrorCode,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SemanticRouteSignalContext {
    pub now_unix_ms: u64,
    pub route_class: RouteClass,
    pub owned_geph_payload_ready: bool,
    pub last_accepted_at_unix_ms: Option<u64>,
    pub signal_id_seen: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticRouteSignalAction {
    None,
    ConfirmExactHostGeoExit,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticRouteSignalReason {
    Accepted,
    NotTopLevel,
    LowConfidence,
    Stale,
    Future,
    Replay,
    ProtectedRoute,
    AlreadyGeoExit,
    BackendUnavailable,
    RateLimited,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SemanticRouteSignalDecision {
    pub accepted: bool,
    pub action: SemanticRouteSignalAction,
    pub reason: SemanticRouteSignalReason,
    pub host: String,
}

fn error(code: SemanticSignalErrorCode) -> SemanticSignalError {
    SemanticSignalError { code }
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

fn exact_signal_object(value: Value) -> Result<Map<String, Value>, SemanticSignalError> {
    const REQUIRED_FIELDS: [&str; 8] = [
        "schema_version",
        "signal_id",
        "source",
        "host",
        "category",
        "confidence_bps",
        "observed_at_unix_ms",
        "top_level",
    ];

    let object = value
        .as_object()
        .ok_or_else(|| error(SemanticSignalErrorCode::InvalidShape))?;
    if object.len() != REQUIRED_FIELDS.len()
        || !REQUIRED_FIELDS
            .iter()
            .all(|field| object.contains_key(*field))
    {
        return Err(error(SemanticSignalErrorCode::InvalidShape));
    }
    Ok(object.clone())
}

pub fn parse_semantic_route_signal_v1(
    payload: &[u8],
) -> Result<SemanticRouteSignalV1, SemanticSignalError> {
    if payload.is_empty() {
        return Err(error(SemanticSignalErrorCode::EmptyInput));
    }
    if payload.len() > MAX_SEMANTIC_SIGNAL_BYTES {
        return Err(error(SemanticSignalErrorCode::PayloadTooLarge));
    }
    let value: Value =
        serde_json::from_slice(payload).map_err(|_| error(SemanticSignalErrorCode::InvalidJson))?;
    let wire = exact_signal_object(value)?;
    let schema_version = wire["schema_version"]
        .as_u64()
        .and_then(|version| u8::try_from(version).ok())
        .ok_or_else(|| error(SemanticSignalErrorCode::UnsupportedVersion))?;
    if schema_version != SEMANTIC_ROUTE_SIGNAL_VERSION {
        return Err(error(SemanticSignalErrorCode::UnsupportedVersion));
    }
    let signal_id = wire["signal_id"]
        .as_str()
        .ok_or_else(|| error(SemanticSignalErrorCode::InvalidSignalId))?;
    if signal_id.len() != 32
        || !signal_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(error(SemanticSignalErrorCode::InvalidSignalId));
    }
    let source = wire["source"]
        .as_str()
        .ok_or_else(|| error(SemanticSignalErrorCode::InvalidSource))?;
    if source != "browser_extension" {
        return Err(error(SemanticSignalErrorCode::InvalidSource));
    }
    let host = wire["host"]
        .as_str()
        .and_then(normalize_hostname)
        .ok_or_else(|| error(SemanticSignalErrorCode::InvalidHost))?;
    let category = wire["category"]
        .as_str()
        .ok_or_else(|| error(SemanticSignalErrorCode::InvalidCategory))?;
    if category != "regional_access_denied" {
        return Err(error(SemanticSignalErrorCode::InvalidCategory));
    }
    let confidence_bps = wire["confidence_bps"]
        .as_u64()
        .and_then(|confidence| u16::try_from(confidence).ok())
        .filter(|confidence| *confidence <= 10_000)
        .ok_or_else(|| error(SemanticSignalErrorCode::InvalidConfidence))?;
    let observed_at_unix_ms = wire["observed_at_unix_ms"]
        .as_u64()
        .filter(|observed_at| *observed_at > 0)
        .ok_or_else(|| error(SemanticSignalErrorCode::InvalidObservedAt))?;
    let top_level = wire["top_level"]
        .as_bool()
        .ok_or_else(|| error(SemanticSignalErrorCode::InvalidTopLevel))?;
    Ok(SemanticRouteSignalV1 {
        schema_version,
        signal_id: signal_id.to_owned(),
        source: source.to_owned(),
        host,
        category: category.to_owned(),
        confidence_bps,
        observed_at_unix_ms,
        top_level,
    })
}

pub fn parse_semantic_route_signal_v2(
    payload: &[u8],
) -> Result<SemanticRouteSignalV2, SemanticSignalError> {
    if payload.is_empty() {
        return Err(error(SemanticSignalErrorCode::EmptyInput));
    }
    if payload.len() > MAX_SEMANTIC_SIGNAL_BYTES {
        return Err(error(SemanticSignalErrorCode::PayloadTooLarge));
    }
    let value: Value =
        serde_json::from_slice(payload).map_err(|_| error(SemanticSignalErrorCode::InvalidJson))?;
    let wire = exact_signal_object(value)?;
    let schema_version = wire["schema_version"]
        .as_u64()
        .and_then(|version| u8::try_from(version).ok())
        .ok_or_else(|| error(SemanticSignalErrorCode::UnsupportedVersion))?;
    if schema_version != SEMANTIC_ROUTE_SIGNAL_V2_VERSION {
        return Err(error(SemanticSignalErrorCode::UnsupportedVersion));
    }
    let signal_id = wire["signal_id"]
        .as_str()
        .ok_or_else(|| error(SemanticSignalErrorCode::InvalidSignalId))?;
    if signal_id.len() != 32
        || !signal_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(error(SemanticSignalErrorCode::InvalidSignalId));
    }
    let source = wire["source"]
        .as_str()
        .ok_or_else(|| error(SemanticSignalErrorCode::InvalidSource))?;
    if source != "browser_extension" {
        return Err(error(SemanticSignalErrorCode::InvalidSource));
    }
    let host = wire["host"]
        .as_str()
        .and_then(normalize_hostname)
        .ok_or_else(|| error(SemanticSignalErrorCode::InvalidHost))?;
    let category = wire["category"]
        .as_str()
        .ok_or_else(|| error(SemanticSignalErrorCode::InvalidCategory))?;
    if category != "incomplete_response" {
        return Err(error(SemanticSignalErrorCode::InvalidCategory));
    }
    let confidence_bps = wire["confidence_bps"]
        .as_u64()
        .and_then(|confidence| u16::try_from(confidence).ok())
        .filter(|confidence| *confidence <= 10_000)
        .ok_or_else(|| error(SemanticSignalErrorCode::InvalidConfidence))?;
    let observed_at_unix_ms = wire["observed_at_unix_ms"]
        .as_u64()
        .filter(|observed_at| *observed_at > 0)
        .ok_or_else(|| error(SemanticSignalErrorCode::InvalidObservedAt))?;
    let top_level = wire["top_level"]
        .as_bool()
        .ok_or_else(|| error(SemanticSignalErrorCode::InvalidTopLevel))?;
    Ok(SemanticRouteSignalV2 {
        schema_version,
        signal_id: signal_id.to_owned(),
        source: source.to_owned(),
        host,
        category: category.to_owned(),
        confidence_bps,
        observed_at_unix_ms,
        top_level,
    })
}

pub fn validate_semantic_route_signal(payload: &[u8]) -> Result<(), SemanticSignalError> {
    if payload.is_empty() {
        return Err(error(SemanticSignalErrorCode::EmptyInput));
    }
    if payload.len() > MAX_SEMANTIC_SIGNAL_BYTES {
        return Err(error(SemanticSignalErrorCode::PayloadTooLarge));
    }
    let value: Value =
        serde_json::from_slice(payload).map_err(|_| error(SemanticSignalErrorCode::InvalidJson))?;
    let wire = exact_signal_object(value)?;
    match wire["schema_version"].as_u64() {
        Some(version) if version == u64::from(SEMANTIC_ROUTE_SIGNAL_VERSION) => {
            parse_semantic_route_signal_v1(payload).map(|_| ())
        }
        Some(version) if version == u64::from(SEMANTIC_ROUTE_SIGNAL_V2_VERSION) => {
            parse_semantic_route_signal_v2(payload).map(|_| ())
        }
        _ => Err(error(SemanticSignalErrorCode::UnsupportedVersion)),
    }
}

fn decision_for_host(
    host: &str,
    accepted: bool,
    action: SemanticRouteSignalAction,
    reason: SemanticRouteSignalReason,
) -> SemanticRouteSignalDecision {
    SemanticRouteSignalDecision {
        accepted,
        action,
        reason,
        host: host.to_owned(),
    }
}

fn reduce_semantic_route_signal_fields(
    host: &str,
    top_level: bool,
    confidence_bps: u16,
    observed_at_unix_ms: u64,
    context: &SemanticRouteSignalContext,
) -> SemanticRouteSignalDecision {
    use SemanticRouteSignalAction::{ConfirmExactHostGeoExit, None};
    use SemanticRouteSignalReason::{
        Accepted, AlreadyGeoExit, BackendUnavailable, Future, LowConfidence, NotTopLevel,
        ProtectedRoute, RateLimited, Replay, Stale,
    };

    if !top_level {
        return decision_for_host(host, false, None, NotTopLevel);
    }
    if confidence_bps < MIN_SEMANTIC_SIGNAL_CONFIDENCE_BPS {
        return decision_for_host(host, false, None, LowConfidence);
    }
    if observed_at_unix_ms
        > context
            .now_unix_ms
            .saturating_add(MAX_SEMANTIC_SIGNAL_FUTURE_SKEW_MS)
    {
        return decision_for_host(host, false, None, Future);
    }
    if context.now_unix_ms.saturating_sub(observed_at_unix_ms) > MAX_SEMANTIC_SIGNAL_AGE_MS {
        return decision_for_host(host, false, None, Stale);
    }
    if context.signal_id_seen {
        return decision_for_host(host, false, None, Replay);
    }
    if matches!(
        context.route_class,
        RouteClass::DirectPassthrough | RouteClass::DirectFirst | RouteClass::LocalBypass
    ) {
        return decision_for_host(host, false, None, ProtectedRoute);
    }
    if context.route_class == RouteClass::GeoExit {
        return decision_for_host(host, false, None, AlreadyGeoExit);
    }
    if context.route_class != RouteClass::Unknown {
        return decision_for_host(host, false, None, ProtectedRoute);
    }
    if !context.owned_geph_payload_ready {
        return decision_for_host(host, false, None, BackendUnavailable);
    }
    if context
        .last_accepted_at_unix_ms
        .is_some_and(|last| context.now_unix_ms.saturating_sub(last) < SEMANTIC_SIGNAL_COOLDOWN_MS)
    {
        return decision_for_host(host, false, None, RateLimited);
    }
    decision_for_host(host, true, ConfirmExactHostGeoExit, Accepted)
}

pub fn reduce_semantic_route_signal(
    signal: &SemanticRouteSignalV1,
    context: &SemanticRouteSignalContext,
) -> SemanticRouteSignalDecision {
    reduce_semantic_route_signal_fields(
        &signal.host,
        signal.top_level,
        signal.confidence_bps,
        signal.observed_at_unix_ms,
        context,
    )
}

pub fn reduce_semantic_route_signal_v2(
    signal: &SemanticRouteSignalV2,
    context: &SemanticRouteSignalContext,
) -> SemanticRouteSignalDecision {
    reduce_semantic_route_signal_fields(
        &signal.host,
        signal.top_level,
        signal.confidence_bps,
        signal.observed_at_unix_ms,
        context,
    )
}
