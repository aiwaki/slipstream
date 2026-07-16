use crate::routing_policy::{
    bundled_policy_v1, classify_route_policy, GeoExitRoutePolicy, RouteClass, RoutingPolicyTables,
    ServiceGroup, StaticRoutePolicy, StrategySet,
};
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

pub const ROUTE_POLICY_MANIFEST_CONTRACT_VERSION: u32 = 1;

const MAX_POLICY_VERSION: u64 = 1_000_000;
const MAX_SOURCE_BYTES: usize = 128;
const MAX_ROUTES_PER_TABLE: usize = 128;
const MAX_DOMAINS_PER_ROUTE: usize = 256;
const MAX_TOTAL_DOMAINS: usize = 4_096;
const MAX_HOST_BYTES: usize = 253;
const MAX_LABEL_BYTES: usize = 63;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ManifestRoutePolicy {
    pub domains: Vec<String>,
    pub route_class: RouteClass,
    pub service_group: ServiceGroup,
    pub strategy_set: StrategySet,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RoutePolicyManifest {
    pub version: u32,
    pub source: String,
    pub static_routes: Vec<ManifestRoutePolicy>,
    pub geo_exit_routes: Vec<ManifestRoutePolicy>,
    pub attempt_limits: BTreeMap<String, u8>,
}

impl RoutePolicyManifest {
    pub fn routing_tables(&self) -> RoutingPolicyTables {
        RoutingPolicyTables {
            static_routes: self
                .static_routes
                .iter()
                .map(|policy| StaticRoutePolicy {
                    domains: policy.domains.clone(),
                    route_class: policy.route_class,
                    service_group: policy.service_group,
                    strategy_set: policy.strategy_set,
                })
                .collect(),
            geo_exit_routes: self
                .geo_exit_routes
                .iter()
                .map(|policy| GeoExitRoutePolicy {
                    domains: policy.domains.clone(),
                    service_group: policy.service_group,
                })
                .collect(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutePolicyManifestErrorCode {
    InvalidJson,
    InvalidType,
    MissingField,
    EmptyValue,
    OutOfRange,
    LimitExceeded,
    InvalidHostname,
    UnsupportedServiceGroup,
    UnsupportedRouteClass,
    StrategyMismatch,
    GeoExitRouteMismatch,
    StaticGeoExitForbidden,
    ProtectedLocalBypass,
    ProtectedRouteMismatch,
    ProtectedDirectFirst,
    ProtectedGeoExitOverlap,
    UnsupportedAttemptRoute,
}

impl RoutePolicyManifestErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidJson => "invalid_json",
            Self::InvalidType => "invalid_type",
            Self::MissingField => "missing_field",
            Self::EmptyValue => "empty_value",
            Self::OutOfRange => "out_of_range",
            Self::LimitExceeded => "limit_exceeded",
            Self::InvalidHostname => "invalid_hostname",
            Self::UnsupportedServiceGroup => "unsupported_service_group",
            Self::UnsupportedRouteClass => "unsupported_route_class",
            Self::StrategyMismatch => "strategy_mismatch",
            Self::GeoExitRouteMismatch => "geo_exit_route_mismatch",
            Self::StaticGeoExitForbidden => "static_geo_exit_forbidden",
            Self::ProtectedLocalBypass => "protected_local_bypass",
            Self::ProtectedRouteMismatch => "protected_route_mismatch",
            Self::ProtectedDirectFirst => "protected_direct_first",
            Self::ProtectedGeoExitOverlap => "protected_geo_exit_overlap",
            Self::UnsupportedAttemptRoute => "unsupported_attempt_route",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RoutePolicyManifestError {
    pub code: RoutePolicyManifestErrorCode,
    pub path: String,
    pub message: String,
}

impl RoutePolicyManifestError {
    fn new(
        code: RoutePolicyManifestErrorCode,
        path: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            path: path.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for RoutePolicyManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} at {}", self.message, self.path)
    }
}

impl std::error::Error for RoutePolicyManifestError {}

pub fn parse_route_policy_manifest_json(
    raw: &str,
) -> Result<RoutePolicyManifest, RoutePolicyManifestError> {
    let value: Value = serde_json::from_str(raw).map_err(|error| {
        RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::InvalidJson,
            "$",
            format!("policy manifest is not valid JSON: {error}"),
        )
    })?;
    parse_route_policy_manifest(&value)
}

pub fn parse_route_policy_manifest(
    value: &Value,
) -> Result<RoutePolicyManifest, RoutePolicyManifestError> {
    let root = value.as_object().ok_or_else(|| {
        RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::InvalidType,
            "$",
            "policy manifest must be an object",
        )
    })?;

    let version = require_integer(root.get("version"), "$.version", 1, MAX_POLICY_VERSION)?;
    let source = require_string(root, "source", "$.source")?;
    if source.trim().is_empty() {
        return Err(RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::EmptyValue,
            "$.source",
            "source must be a non-empty string",
        ));
    }
    if source.len() > MAX_SOURCE_BYTES {
        return Err(RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::LimitExceeded,
            "$.source",
            format!("source exceeds {MAX_SOURCE_BYTES} bytes"),
        ));
    }

    let static_values = require_array(root, "static_routes", "$.static_routes")?;
    if static_values.is_empty() {
        return Err(RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::EmptyValue,
            "$.static_routes",
            "static_routes must be a non-empty list",
        ));
    }
    enforce_route_limit(static_values, "$.static_routes")?;

    let geo_values = require_array(root, "geo_exit_routes", "$.geo_exit_routes")?;
    enforce_route_limit(geo_values, "$.geo_exit_routes")?;

    let mut static_routes = Vec::with_capacity(static_values.len());
    let mut total_domains = 0usize;
    for (index, entry) in static_values.iter().enumerate() {
        let policy = parse_route_entry(entry, &format!("$.static_routes[{index}]"), true)?;
        total_domains += policy.domains.len();
        enforce_total_domain_limit(total_domains)?;
        static_routes.push(policy);
    }

    let mut geo_exit_routes = Vec::with_capacity(geo_values.len());
    for (index, entry) in geo_values.iter().enumerate() {
        let policy = parse_route_entry(entry, &format!("$.geo_exit_routes[{index}]"), false)?;
        total_domains += policy.domains.len();
        enforce_total_domain_limit(total_domains)?;
        geo_exit_routes.push(policy);
    }

    let attempt_limits = parse_attempt_limits(root)?;
    let manifest = RoutePolicyManifest {
        version: version as u32,
        source: source.to_owned(),
        static_routes,
        geo_exit_routes,
        attempt_limits,
    };
    validate_protected_routes(&manifest)?;
    Ok(manifest)
}

fn require_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    path: &str,
) -> Result<&'a str, RoutePolicyManifestError> {
    let value = object.get(field).ok_or_else(|| {
        RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::MissingField,
            path,
            format!("{field} is required"),
        )
    })?;
    value.as_str().ok_or_else(|| {
        RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::InvalidType,
            path,
            format!("{field} must be a string"),
        )
    })
}

fn require_integer(
    value: Option<&Value>,
    path: &str,
    minimum: u64,
    maximum: u64,
) -> Result<u64, RoutePolicyManifestError> {
    let value = value.ok_or_else(|| {
        RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::MissingField,
            path,
            format!("{} is required", path.rsplit('.').next().unwrap_or(path)),
        )
    })?;
    let integer = value.as_u64().ok_or_else(|| {
        RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::InvalidType,
            path,
            format!(
                "{} must be an integer",
                path.rsplit('.').next().unwrap_or(path)
            ),
        )
    })?;
    if !(minimum..=maximum).contains(&integer) {
        return Err(RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::OutOfRange,
            path,
            format!("{} out of range", path.rsplit('.').next().unwrap_or(path)),
        ));
    }
    Ok(integer)
}

fn require_array<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    path: &str,
) -> Result<&'a Vec<Value>, RoutePolicyManifestError> {
    let value = object.get(field).ok_or_else(|| {
        RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::MissingField,
            path,
            format!("{field} is required"),
        )
    })?;
    value.as_array().ok_or_else(|| {
        RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::InvalidType,
            path,
            format!("{field} must be a list"),
        )
    })
}

fn enforce_route_limit(routes: &[Value], path: &str) -> Result<(), RoutePolicyManifestError> {
    if routes.len() > MAX_ROUTES_PER_TABLE {
        return Err(RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::LimitExceeded,
            path,
            format!("route table exceeds {MAX_ROUTES_PER_TABLE} entries"),
        ));
    }
    Ok(())
}

fn enforce_total_domain_limit(total: usize) -> Result<(), RoutePolicyManifestError> {
    if total > MAX_TOTAL_DOMAINS {
        return Err(RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::LimitExceeded,
            "$",
            format!("policy manifest exceeds {MAX_TOTAL_DOMAINS} domains"),
        ));
    }
    Ok(())
}

fn parse_route_entry(
    value: &Value,
    path: &str,
    is_static: bool,
) -> Result<ManifestRoutePolicy, RoutePolicyManifestError> {
    let entry = value.as_object().ok_or_else(|| {
        RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::InvalidType,
            path,
            format!("{} must be an object", short_path(path)),
        )
    })?;

    let service_path = format!("{path}.service_group");
    let service_group = parse_service_group(
        require_string(entry, "service_group", &service_path)?,
        &service_path,
    )?;

    let route_path = format!("{path}.route_class");
    let route_class = match entry.get("route_class") {
        Some(raw) => parse_route_class_value(raw, &route_path)?,
        None if !is_static => RouteClass::GeoExit,
        None => {
            return Err(RoutePolicyManifestError::new(
                RoutePolicyManifestErrorCode::MissingField,
                route_path,
                "route_class is required",
            ));
        }
    };
    if !is_static && route_class != RouteClass::GeoExit {
        return Err(RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::GeoExitRouteMismatch,
            route_path,
            format!("{} must be geo_exit", short_path(path)),
        ));
    }

    let strategy_path = format!("{path}.strategy_set");
    let strategy_set = match entry.get("strategy_set") {
        Some(raw) => parse_strategy_set_value(raw, &strategy_path)?,
        None if !is_static => StrategySet::Geph,
        None => {
            return Err(RoutePolicyManifestError::new(
                RoutePolicyManifestErrorCode::MissingField,
                strategy_path,
                "strategy_set is required",
            ));
        }
    };
    if !strategy_matches(route_class, strategy_set) {
        return Err(RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::StrategyMismatch,
            strategy_path,
            format!(
                "{}.strategy_set does not match route_class",
                short_path(path)
            ),
        ));
    }
    if service_group.is_protected_local_bypass()
        && (route_class != RouteClass::LocalBypass || strategy_set != StrategySet::FakeOnly)
    {
        return Err(RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::ProtectedLocalBypass,
            path,
            format!("{service_group} must stay local_bypass/fake_only"),
        ));
    }
    if is_static && route_class == RouteClass::GeoExit {
        return Err(RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::StaticGeoExitForbidden,
            route_path,
            "geo_exit routes belong in geo_exit_routes, not static_routes",
        ));
    }

    Ok(ManifestRoutePolicy {
        domains: parse_domains(entry.get("domains"), path)?,
        route_class,
        service_group,
        strategy_set,
    })
}

fn parse_domains(
    value: Option<&Value>,
    route_path: &str,
) -> Result<Vec<String>, RoutePolicyManifestError> {
    let path = format!("{route_path}.domains");
    let value = value.ok_or_else(|| {
        RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::MissingField,
            &path,
            format!("{}.domains is required", short_path(route_path)),
        )
    })?;
    let domains = value.as_array().ok_or_else(|| {
        RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::InvalidType,
            &path,
            format!(
                "{}.domains must be a non-empty list",
                short_path(route_path)
            ),
        )
    })?;
    if domains.is_empty() {
        return Err(RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::EmptyValue,
            &path,
            format!(
                "{}.domains must be a non-empty list",
                short_path(route_path)
            ),
        ));
    }
    if domains.len() > MAX_DOMAINS_PER_ROUTE {
        return Err(RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::LimitExceeded,
            &path,
            format!("route exceeds {MAX_DOMAINS_PER_ROUTE} domains"),
        ));
    }

    let mut normalized = Vec::with_capacity(domains.len());
    let mut seen = HashSet::with_capacity(domains.len());
    for (index, value) in domains.iter().enumerate() {
        let entry_path = format!("{path}[{index}]");
        let raw = value.as_str().ok_or_else(|| {
            RoutePolicyManifestError::new(
                RoutePolicyManifestErrorCode::InvalidType,
                &entry_path,
                format!("{}.domains entries must be strings", short_path(route_path)),
            )
        })?;
        let host = normalize_manifest_hostname(raw).map_err(|message| {
            RoutePolicyManifestError::new(
                RoutePolicyManifestErrorCode::InvalidHostname,
                &entry_path,
                format!(
                    "{}.domains contains invalid host {raw:?}: {message}",
                    short_path(route_path)
                ),
            )
        })?;
        if seen.insert(host.clone()) {
            normalized.push(host);
        }
    }
    Ok(normalized)
}

fn normalize_manifest_hostname(raw: &str) -> Result<String, &'static str> {
    if raw != raw.trim() {
        return Err("surrounding whitespace is not allowed");
    }
    if !raw.is_ascii() {
        return Err("host must be ASCII");
    }
    let without_root_dot = raw.strip_suffix('.').unwrap_or(raw);
    if without_root_dot.ends_with('.') {
        return Err("only one trailing root dot is allowed");
    }
    let host = without_root_dot.to_ascii_lowercase();
    if host.is_empty() || host.len() > MAX_HOST_BYTES {
        return Err("host length is invalid");
    }
    if IpAddr::from_str(&host).is_ok() {
        return Err("IP literals are not policy hostnames");
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return Err("host must contain at least two labels");
    }
    for label in labels {
        if label.is_empty() || label.len() > MAX_LABEL_BYTES {
            return Err("DNS label length is invalid");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("DNS labels cannot start or end with a hyphen");
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err("DNS labels may contain only ASCII letters, digits, and hyphens");
        }
    }
    Ok(host)
}

fn parse_service_group(raw: &str, path: &str) -> Result<ServiceGroup, RoutePolicyManifestError> {
    match raw {
        "discord" => Ok(ServiceGroup::Discord),
        "youtube_video" => Ok(ServiceGroup::YoutubeVideo),
        "openai" => Ok(ServiceGroup::Openai),
        "anthropic" => Ok(ServiceGroup::Anthropic),
        "telegram" => Ok(ServiceGroup::Telegram),
        "steam_store" => Ok(ServiceGroup::SteamStore),
        "github" => Ok(ServiceGroup::Github),
        "google" => Ok(ServiceGroup::Google),
        "spotify" => Ok(ServiceGroup::Spotify),
        "generic" => Ok(ServiceGroup::Generic),
        _ => Err(RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::UnsupportedServiceGroup,
            path,
            format!("{path} is not supported"),
        )),
    }
}

fn parse_route_class_value(
    value: &Value,
    path: &str,
) -> Result<RouteClass, RoutePolicyManifestError> {
    let raw = value.as_str().ok_or_else(|| {
        RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::InvalidType,
            path,
            format!("{path} must be a string"),
        )
    })?;
    match raw {
        "direct_passthrough" => Ok(RouteClass::DirectPassthrough),
        "direct_first" => Ok(RouteClass::DirectFirst),
        "local_bypass" => Ok(RouteClass::LocalBypass),
        "geo_exit" => Ok(RouteClass::GeoExit),
        _ => Err(RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::UnsupportedRouteClass,
            path,
            format!("{path} is not supported"),
        )),
    }
}

fn parse_strategy_set_value(
    value: &Value,
    path: &str,
) -> Result<StrategySet, RoutePolicyManifestError> {
    let raw = value.as_str().ok_or_else(|| {
        RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::InvalidType,
            path,
            format!("{path} must be a string"),
        )
    })?;
    match raw {
        "direct" => Ok(StrategySet::Direct),
        "direct_first" => Ok(StrategySet::DirectFirst),
        "fake_only" => Ok(StrategySet::FakeOnly),
        "geph" => Ok(StrategySet::Geph),
        _ => Err(RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::StrategyMismatch,
            path,
            format!("{path} is not supported"),
        )),
    }
}

fn strategy_matches(route_class: RouteClass, strategy_set: StrategySet) -> bool {
    matches!(
        (route_class, strategy_set),
        (RouteClass::DirectPassthrough, StrategySet::Direct)
            | (RouteClass::DirectFirst, StrategySet::DirectFirst)
            | (RouteClass::LocalBypass, StrategySet::FakeOnly)
            | (RouteClass::GeoExit, StrategySet::Geph)
    )
}

fn parse_attempt_limits(
    root: &Map<String, Value>,
) -> Result<BTreeMap<String, u8>, RoutePolicyManifestError> {
    let path = "$.attempt_limits";
    let value = root.get("attempt_limits").ok_or_else(|| {
        RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::MissingField,
            path,
            "attempt_limits is required",
        )
    })?;
    let values = value.as_object().ok_or_else(|| {
        RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::InvalidType,
            path,
            "attempt_limits must be an object",
        )
    })?;

    let mut limits = BTreeMap::new();
    for (route, value) in values {
        let route_path = format!("{path}.{route}");
        if route != "default"
            && !matches!(
                route.as_str(),
                "direct_passthrough" | "direct_first" | "local_bypass" | "geo_exit"
            )
        {
            return Err(RoutePolicyManifestError::new(
                RoutePolicyManifestErrorCode::UnsupportedAttemptRoute,
                &route_path,
                format!("attempt_limits has unsupported route {route:?}"),
            ));
        }
        let limit = require_integer(Some(value), &route_path, 1, 8)?;
        limits.insert(route.clone(), limit as u8);
    }
    if !limits.contains_key("default") {
        return Err(RoutePolicyManifestError::new(
            RoutePolicyManifestErrorCode::MissingField,
            "$.attempt_limits.default",
            "attempt_limits.default is required",
        ));
    }
    Ok(limits)
}

#[derive(Clone)]
struct ProtectedExpectation {
    domain: String,
    route_class: RouteClass,
    service_group: ServiceGroup,
    strategy_set: StrategySet,
}

fn protected_expectations() -> Vec<ProtectedExpectation> {
    bundled_policy_v1()
        .static_routes
        .into_iter()
        .filter(|policy| {
            policy.service_group.is_protected_local_bypass()
                || policy.route_class == RouteClass::DirectFirst
        })
        .flat_map(|policy| {
            policy
                .domains
                .into_iter()
                .map(move |domain| ProtectedExpectation {
                    domain,
                    route_class: policy.route_class,
                    service_group: policy.service_group,
                    strategy_set: policy.strategy_set,
                })
        })
        .collect()
}

fn validate_protected_routes(
    manifest: &RoutePolicyManifest,
) -> Result<(), RoutePolicyManifestError> {
    let expectations = protected_expectations();
    for (route_index, policy) in manifest.geo_exit_routes.iter().enumerate() {
        for (domain_index, domain) in policy.domains.iter().enumerate() {
            if let Some(protected) = expectations
                .iter()
                .find(|expected| domain_patterns_overlap(domain, &expected.domain))
            {
                return Err(RoutePolicyManifestError::new(
                    RoutePolicyManifestErrorCode::ProtectedGeoExitOverlap,
                    format!("$.geo_exit_routes[{route_index}].domains[{domain_index}]"),
                    format!(
                        "geo_exit domain {domain:?} overlaps protected domain {:?}",
                        protected.domain
                    ),
                ));
            }
        }
    }

    let tables = manifest.routing_tables();
    for expected in &expectations {
        let mut candidates = vec![expected.domain.as_str()];
        let mut seen = HashSet::from([expected.domain.as_str()]);
        for candidate in manifest
            .static_routes
            .iter()
            .flat_map(|policy| policy.domains.iter().map(String::as_str))
            .filter(|candidate| host_is_or_subdomain(candidate, &expected.domain))
        {
            if seen.insert(candidate) {
                candidates.push(candidate);
            }
        }

        for candidate in candidates {
            let actual = classify_route_policy(candidate, &tables);
            if actual.route_class == expected.route_class
                && actual.service_group == expected.service_group
                && actual.strategy_set == expected.strategy_set
            {
                continue;
            }
            let protected_suffix = if candidate == expected.domain {
                String::new()
            } else {
                format!(" under protected suffix {}", expected.domain)
            };
            if expected.route_class == RouteClass::DirectFirst {
                return Err(RoutePolicyManifestError::new(
                    RoutePolicyManifestErrorCode::ProtectedDirectFirst,
                    "$.static_routes",
                    format!(
                        "protected direct-first domains missing or shadowed: {candidate}{protected_suffix}"
                    ),
                ));
            }
            return Err(RoutePolicyManifestError::new(
                RoutePolicyManifestErrorCode::ProtectedRouteMismatch,
                "$.static_routes",
                format!(
                    "protected local-bypass domain missing or shadowed: {candidate}{protected_suffix} must stay local_bypass/fake_only as {}",
                    expected.service_group
                ),
            ));
        }
    }
    Ok(())
}

fn domain_patterns_overlap(left: &str, right: &str) -> bool {
    host_is_or_subdomain(left, right) || host_is_or_subdomain(right, left)
}

fn host_is_or_subdomain(host: &str, suffix: &str) -> bool {
    host == suffix
        || host
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn short_path(path: &str) -> &str {
    path.strip_prefix("$.").unwrap_or(path)
}
