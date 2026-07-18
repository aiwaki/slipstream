//! Version 1 Windows packet-adapter boundary.
//!
//! This module admits a pinned, already-verified Wintun DLL and prepares only
//! fresh policy-bound exact-destination route plans. A separate pure gate can
//! reject a candidate when the same address is bound to incompatible routing
//! policy. Neither result authorizes a native effect. This module does not load
//! a DLL, create an adapter, install a route, resolve a name, or touch system
//! DNS, proxy, PAC, VPN, or the production service host.

use serde::{Deserialize, Serialize};
use slipstream_core::routing_policy::{
    classify_route_policy, normalize_host, RouteClass, RoutePolicyResult, RoutingPolicyTables,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const WINDOWS_PACKET_ADAPTER_CONTRACT_VERSION: u32 = 1;
pub const WINTUN_VERSION: &str = "0.14.1";
pub const WINTUN_ARCHIVE_SHA256: &str =
    "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51";
pub const WINTUN_ARCHIVE_LENGTH: u64 = 750_540;
pub const WINTUN_LICENSE_SHA256: &str =
    "183adac21e7d96c508c8fd34d394b7b6708bc81564ad1bad61ab66143a008cd2";
pub const WINTUN_PUBLISHER: &str = "WireGuard LLC";
pub const WINTUN_SIGNER_SHA256: &str =
    "c9e1b3127c2f1312056d49a93ac4bd700393fd323d2bf3b2235aff52bea8d136";
pub const WINTUN_AMD64_DLL_PATH: &str = "wintun/bin/amd64/wintun.dll";
pub const WINTUN_AMD64_DLL_SHA256: &str =
    "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";
pub const WINTUN_AMD64_DLL_LENGTH: u64 = 427_552;
pub const WINTUN_AMD64_PE_MACHINE: u16 = 0x8664;
pub const WINTUN_ARM64_DLL_PATH: &str = "wintun/bin/arm64/wintun.dll";
pub const WINTUN_ARM64_DLL_SHA256: &str =
    "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80";
pub const WINTUN_ARM64_DLL_LENGTH: u64 = 222_488;
pub const WINTUN_ARM64_PE_MACHINE: u16 = 0xaa64;
pub const MAX_PACKET_ROUTE_EVIDENCE_LIFETIME_MS: u64 = 5 * 60 * 1000;
pub const MAX_PACKET_ROUTE_CONFLICT_EVIDENCE_LIFETIME_MS: u64 = 30 * 1000;
pub const MAX_PACKET_ROUTE_CONFLICT_HOSTS: usize = 256;
pub const MAX_PACKET_ROUTE_CONFLICT_HOST_BYTES: usize = 253;
const MAX_PACKET_ROUTE_CONFLICT_LABEL_BYTES: usize = 63;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsPacketAdapterArchitecture {
    Amd64,
    Arm64,
}

impl WindowsPacketAdapterArchitecture {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Amd64 => "x86_64",
            Self::Arm64 => "aarch64",
        }
    }

    const fn expected(self) -> WindowsPacketAdapterArtifactExpectation {
        match self {
            Self::Amd64 => WindowsPacketAdapterArtifactExpectation {
                dll_path: WINTUN_AMD64_DLL_PATH,
                dll_sha256: WINTUN_AMD64_DLL_SHA256,
                dll_length: WINTUN_AMD64_DLL_LENGTH,
                pe_machine: WINTUN_AMD64_PE_MACHINE,
            },
            Self::Arm64 => WindowsPacketAdapterArtifactExpectation {
                dll_path: WINTUN_ARM64_DLL_PATH,
                dll_sha256: WINTUN_ARM64_DLL_SHA256,
                dll_length: WINTUN_ARM64_DLL_LENGTH,
                pe_machine: WINTUN_ARM64_PE_MACHINE,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WindowsPacketAdapterArtifactExpectation {
    dll_path: &'static str,
    dll_sha256: &'static str,
    dll_length: u64,
    pe_machine: u16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsPacketAdapterSignatureStatus {
    Valid,
    Invalid,
    Untrusted,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsPacketAdapterArtifactEvidence {
    pub version: String,
    pub archive_sha256: String,
    pub archive_length: u64,
    pub license_sha256: String,
    pub dll_path: String,
    pub dll_sha256: String,
    pub dll_length: u64,
    pub pe_machine: u16,
    pub signature_status: WindowsPacketAdapterSignatureStatus,
    pub publisher: String,
    pub signer_sha256: String,
    pub timestamped: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPacketAdapterArtifactAdmission {
    architecture: WindowsPacketAdapterArchitecture,
    dll_path: &'static str,
    dll_sha256: &'static str,
}

impl WindowsPacketAdapterArtifactAdmission {
    pub const fn architecture(&self) -> WindowsPacketAdapterArchitecture {
        self.architecture
    }

    pub const fn dll_path(&self) -> &'static str {
        self.dll_path
    }

    pub const fn dll_sha256(&self) -> &'static str {
        self.dll_sha256
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsPacketAdapterErrorCode {
    UnsupportedArchitecture,
    VersionMismatch,
    ArchiveHashMismatch,
    ArchiveLengthMismatch,
    LicenseHashMismatch,
    DllPathMismatch,
    DllHashMismatch,
    DllLengthMismatch,
    PeMachineMismatch,
    SignatureNotValid,
    PublisherMismatch,
    SignerMismatch,
    TimestampMissing,
    PolicyMismatch,
    RouteClassNotCaptured,
    EvidenceHostNotCanonical,
    EvidenceHostMismatch,
    DestinationNotObserved,
    DestinationNotCanonical,
    UnsafeDestination,
    RouteNotExact,
    InvalidEvidenceWindow,
    EvidenceExpired,
}

impl WindowsPacketAdapterErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedArchitecture => "unsupported_architecture",
            Self::VersionMismatch => "version_mismatch",
            Self::ArchiveHashMismatch => "archive_hash_mismatch",
            Self::ArchiveLengthMismatch => "archive_length_mismatch",
            Self::LicenseHashMismatch => "license_hash_mismatch",
            Self::DllPathMismatch => "dll_path_mismatch",
            Self::DllHashMismatch => "dll_hash_mismatch",
            Self::DllLengthMismatch => "dll_length_mismatch",
            Self::PeMachineMismatch => "pe_machine_mismatch",
            Self::SignatureNotValid => "signature_not_valid",
            Self::PublisherMismatch => "publisher_mismatch",
            Self::SignerMismatch => "signer_mismatch",
            Self::TimestampMissing => "timestamp_missing",
            Self::PolicyMismatch => "policy_mismatch",
            Self::RouteClassNotCaptured => "route_class_not_captured",
            Self::EvidenceHostNotCanonical => "evidence_host_not_canonical",
            Self::EvidenceHostMismatch => "evidence_host_mismatch",
            Self::DestinationNotObserved => "destination_not_observed",
            Self::DestinationNotCanonical => "destination_not_canonical",
            Self::UnsafeDestination => "unsafe_destination",
            Self::RouteNotExact => "route_not_exact",
            Self::InvalidEvidenceWindow => "invalid_evidence_window",
            Self::EvidenceExpired => "evidence_expired",
        }
    }
}

pub fn admit_windows_packet_adapter_artifact(
    architecture: &str,
    evidence: &WindowsPacketAdapterArtifactEvidence,
) -> Result<WindowsPacketAdapterArtifactAdmission, WindowsPacketAdapterErrorCode> {
    let architecture = match architecture {
        "x86_64" => WindowsPacketAdapterArchitecture::Amd64,
        "aarch64" => WindowsPacketAdapterArchitecture::Arm64,
        _ => return Err(WindowsPacketAdapterErrorCode::UnsupportedArchitecture),
    };
    let expected = architecture.expected();
    if evidence.version != WINTUN_VERSION {
        return Err(WindowsPacketAdapterErrorCode::VersionMismatch);
    }
    if evidence.archive_sha256 != WINTUN_ARCHIVE_SHA256 {
        return Err(WindowsPacketAdapterErrorCode::ArchiveHashMismatch);
    }
    if evidence.archive_length != WINTUN_ARCHIVE_LENGTH {
        return Err(WindowsPacketAdapterErrorCode::ArchiveLengthMismatch);
    }
    if evidence.license_sha256 != WINTUN_LICENSE_SHA256 {
        return Err(WindowsPacketAdapterErrorCode::LicenseHashMismatch);
    }
    if evidence.dll_path != expected.dll_path {
        return Err(WindowsPacketAdapterErrorCode::DllPathMismatch);
    }
    if evidence.dll_sha256 != expected.dll_sha256 {
        return Err(WindowsPacketAdapterErrorCode::DllHashMismatch);
    }
    if evidence.dll_length != expected.dll_length {
        return Err(WindowsPacketAdapterErrorCode::DllLengthMismatch);
    }
    if evidence.pe_machine != expected.pe_machine {
        return Err(WindowsPacketAdapterErrorCode::PeMachineMismatch);
    }
    if evidence.signature_status != WindowsPacketAdapterSignatureStatus::Valid {
        return Err(WindowsPacketAdapterErrorCode::SignatureNotValid);
    }
    if evidence.publisher != WINTUN_PUBLISHER {
        return Err(WindowsPacketAdapterErrorCode::PublisherMismatch);
    }
    if evidence.signer_sha256 != WINTUN_SIGNER_SHA256 {
        return Err(WindowsPacketAdapterErrorCode::SignerMismatch);
    }
    if !evidence.timestamped {
        return Err(WindowsPacketAdapterErrorCode::TimestampMissing);
    }

    Ok(WindowsPacketAdapterArtifactAdmission {
        architecture,
        dll_path: expected.dll_path,
        dll_sha256: expected.dll_sha256,
    })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsPacketRouteEvidenceSource {
    SystemDnsObservation,
    OwnedResolverQuery,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsPacketResolverEvidence {
    source: WindowsPacketRouteEvidenceSource,
    host: String,
    addresses: Vec<String>,
    observed_at_ms: u64,
    expires_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsPacketRouteRequest {
    pub policy: RoutePolicyResult,
    pub destination: String,
    pub prefix_length: u8,
    resolver_evidence: WindowsPacketResolverEvidence,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsPacketRoutePurpose {
    LocalBypass,
    GeoExit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPacketRoutePlan {
    policy: RoutePolicyResult,
    destination: IpAddr,
    prefix_length: u8,
    evidence_source: WindowsPacketRouteEvidenceSource,
    expires_at_ms: u64,
    purpose: WindowsPacketRoutePurpose,
}

impl WindowsPacketRoutePlan {
    pub fn policy(&self) -> &RoutePolicyResult {
        &self.policy
    }

    pub const fn destination(&self) -> IpAddr {
        self.destination
    }

    pub const fn prefix_length(&self) -> u8 {
        self.prefix_length
    }

    pub const fn evidence_source(&self) -> WindowsPacketRouteEvidenceSource {
        self.evidence_source
    }

    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    pub const fn purpose(&self) -> WindowsPacketRoutePurpose {
        self.purpose
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsPacketRouteConflictCoverage {
    CompleteOwnedResolutionBoundary,
    PartialObservation,
}

/// Opaque evidence issued by a future owner of the complete resolution boundary.
///
/// A partial DNS cache cannot construct this value. The future native issuer
/// must advance `collector_generation` whenever the address bindings change and
/// retain a lease on that generation for the entire lifetime of any route.
#[derive(Debug, Eq, PartialEq)]
pub struct WindowsPacketRouteConflictEvidence {
    coverage: WindowsPacketRouteConflictCoverage,
    collector_generation: u64,
    destination: IpAddr,
    binding_hosts: Vec<String>,
    snapshot_started_at_ms: u64,
    snapshot_completed_at_ms: u64,
    expires_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsPacketRouteConflictErrorCode {
    RouteEvidenceExpired,
    RoutePolicyChanged,
    EvidenceDestinationMismatch,
    EvidenceCoverageIncomplete,
    EvidenceGenerationInvalid,
    EvidenceWindowInvalid,
    EvidenceExpired,
    EvidenceBindingLimitExceeded,
    EvidenceHostNotCanonical,
    EvidenceHostsNotSortedUnique,
    EvidenceCandidateHostMissing,
    SharedDestinationConflict,
}

impl WindowsPacketRouteConflictErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RouteEvidenceExpired => "route_evidence_expired",
            Self::RoutePolicyChanged => "route_policy_changed",
            Self::EvidenceDestinationMismatch => "evidence_destination_mismatch",
            Self::EvidenceCoverageIncomplete => "evidence_coverage_incomplete",
            Self::EvidenceGenerationInvalid => "evidence_generation_invalid",
            Self::EvidenceWindowInvalid => "evidence_window_invalid",
            Self::EvidenceExpired => "evidence_expired",
            Self::EvidenceBindingLimitExceeded => "evidence_binding_limit_exceeded",
            Self::EvidenceHostNotCanonical => "evidence_host_not_canonical",
            Self::EvidenceHostsNotSortedUnique => "evidence_hosts_not_sorted_unique",
            Self::EvidenceCandidateHostMissing => "evidence_candidate_host_missing",
            Self::SharedDestinationConflict => "shared_destination_conflict",
        }
    }
}

/// A short-lived pure admission, not permission to mutate the Windows route table.
#[derive(Debug)]
pub struct WindowsPacketRouteConflictAdmission {
    route: WindowsPacketRoutePlan,
    collector_generation: u64,
    expires_at_ms: u64,
}

impl WindowsPacketRouteConflictAdmission {
    pub fn route(&self) -> &WindowsPacketRoutePlan {
        &self.route
    }

    pub const fn collector_generation(&self) -> u64 {
        self.collector_generation
    }

    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

pub fn prepare_windows_packet_route(
    request: &WindowsPacketRouteRequest,
    now_ms: u64,
    policy_tables: &RoutingPolicyTables,
) -> Result<WindowsPacketRoutePlan, WindowsPacketAdapterErrorCode> {
    let classified = classify_route_policy(&request.policy.host, policy_tables);
    if request.policy != classified {
        return Err(WindowsPacketAdapterErrorCode::PolicyMismatch);
    }
    let purpose = match classified.route_class {
        RouteClass::LocalBypass => WindowsPacketRoutePurpose::LocalBypass,
        RouteClass::GeoExit => WindowsPacketRoutePurpose::GeoExit,
        RouteClass::DirectPassthrough | RouteClass::DirectFirst | RouteClass::Unknown => {
            return Err(WindowsPacketAdapterErrorCode::RouteClassNotCaptured)
        }
    };
    let evidence = &request.resolver_evidence;
    let evidence_host = normalize_host(&evidence.host);
    if evidence_host != evidence.host {
        return Err(WindowsPacketAdapterErrorCode::EvidenceHostNotCanonical);
    }
    if evidence_host != classified.host {
        return Err(WindowsPacketAdapterErrorCode::EvidenceHostMismatch);
    }
    if !evidence
        .addresses
        .iter()
        .any(|address| address == &request.destination)
    {
        return Err(WindowsPacketAdapterErrorCode::DestinationNotObserved);
    }
    let destination: IpAddr = request
        .destination
        .parse()
        .map_err(|_| WindowsPacketAdapterErrorCode::DestinationNotCanonical)?;
    if destination.to_string() != request.destination {
        return Err(WindowsPacketAdapterErrorCode::DestinationNotCanonical);
    }
    if !is_safe_public_destination(destination) {
        return Err(WindowsPacketAdapterErrorCode::UnsafeDestination);
    }
    let required_prefix = if destination.is_ipv4() { 32 } else { 128 };
    if request.prefix_length != required_prefix {
        return Err(WindowsPacketAdapterErrorCode::RouteNotExact);
    }
    if evidence.observed_at_ms >= evidence.expires_at_ms
        || evidence
            .expires_at_ms
            .saturating_sub(evidence.observed_at_ms)
            > MAX_PACKET_ROUTE_EVIDENCE_LIFETIME_MS
        || now_ms < evidence.observed_at_ms
    {
        return Err(WindowsPacketAdapterErrorCode::InvalidEvidenceWindow);
    }
    if now_ms >= evidence.expires_at_ms {
        return Err(WindowsPacketAdapterErrorCode::EvidenceExpired);
    }

    Ok(WindowsPacketRoutePlan {
        policy: classified,
        destination,
        prefix_length: required_prefix,
        evidence_source: evidence.source,
        expires_at_ms: evidence.expires_at_ms,
        purpose,
    })
}

/// Rejects an exact-route candidate unless every host in a complete, fresh
/// destination binding snapshot selects the same route class and strategy.
///
/// A future native caller must additionally retain the collector-generation
/// lease for the entire native route lifetime and remove the route before that
/// lease is released. This pure function performs neither operation.
pub fn admit_windows_packet_route_conflicts(
    route: WindowsPacketRoutePlan,
    evidence: WindowsPacketRouteConflictEvidence,
    now_ms: u64,
    policy_tables: &RoutingPolicyTables,
) -> Result<WindowsPacketRouteConflictAdmission, WindowsPacketRouteConflictErrorCode> {
    if now_ms >= route.expires_at_ms() {
        return Err(WindowsPacketRouteConflictErrorCode::RouteEvidenceExpired);
    }

    let active_policy = classify_route_policy(&route.policy().host, policy_tables);
    if active_policy != *route.policy() {
        return Err(WindowsPacketRouteConflictErrorCode::RoutePolicyChanged);
    }
    if evidence.destination != route.destination() {
        return Err(WindowsPacketRouteConflictErrorCode::EvidenceDestinationMismatch);
    }
    if evidence.coverage != WindowsPacketRouteConflictCoverage::CompleteOwnedResolutionBoundary {
        return Err(WindowsPacketRouteConflictErrorCode::EvidenceCoverageIncomplete);
    }
    if evidence.collector_generation == 0 {
        return Err(WindowsPacketRouteConflictErrorCode::EvidenceGenerationInvalid);
    }
    if evidence.snapshot_started_at_ms > evidence.snapshot_completed_at_ms
        || evidence.snapshot_completed_at_ms > now_ms
        || evidence.snapshot_completed_at_ms >= evidence.expires_at_ms
        || evidence
            .expires_at_ms
            .saturating_sub(evidence.snapshot_started_at_ms)
            > MAX_PACKET_ROUTE_CONFLICT_EVIDENCE_LIFETIME_MS
    {
        return Err(WindowsPacketRouteConflictErrorCode::EvidenceWindowInvalid);
    }
    if now_ms >= evidence.expires_at_ms {
        return Err(WindowsPacketRouteConflictErrorCode::EvidenceExpired);
    }
    if evidence.binding_hosts.is_empty()
        || evidence.binding_hosts.len() > MAX_PACKET_ROUTE_CONFLICT_HOSTS
    {
        return Err(WindowsPacketRouteConflictErrorCode::EvidenceBindingLimitExceeded);
    }
    if evidence
        .binding_hosts
        .iter()
        .any(|host| !is_canonical_policy_host(host))
    {
        return Err(WindowsPacketRouteConflictErrorCode::EvidenceHostNotCanonical);
    }
    if evidence
        .binding_hosts
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(WindowsPacketRouteConflictErrorCode::EvidenceHostsNotSortedUnique);
    }
    if evidence
        .binding_hosts
        .binary_search(&route.policy().host)
        .is_err()
    {
        return Err(WindowsPacketRouteConflictErrorCode::EvidenceCandidateHostMissing);
    }
    if evidence.binding_hosts.iter().any(|host| {
        let binding_policy = classify_route_policy(host, policy_tables);
        binding_policy.route_class != route.policy().route_class
            || binding_policy.strategy_set != route.policy().strategy_set
    }) {
        return Err(WindowsPacketRouteConflictErrorCode::SharedDestinationConflict);
    }

    Ok(WindowsPacketRouteConflictAdmission {
        expires_at_ms: route.expires_at_ms().min(evidence.expires_at_ms),
        collector_generation: evidence.collector_generation,
        route,
    })
}

fn is_canonical_policy_host(host: &str) -> bool {
    if host.is_empty()
        || host.len() > MAX_PACKET_ROUTE_CONFLICT_HOST_BYTES
        || !host.is_ascii()
        || normalize_host(host) != host
        || host.parse::<IpAddr>().is_ok()
    {
        return false;
    }

    let mut labels = host.split('.');
    let mut label_count = 0;
    for label in &mut labels {
        label_count += 1;
        if label.is_empty()
            || label.len() > MAX_PACKET_ROUTE_CONFLICT_LABEL_BYTES
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return false;
        }
    }
    label_count >= 2
}

fn is_safe_public_destination(destination: IpAddr) -> bool {
    match destination {
        IpAddr::V4(address) => is_safe_public_ipv4(address),
        IpAddr::V6(address) => is_safe_public_ipv6(address),
    }
}

fn is_safe_public_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_private()
        && !address.is_link_local()
        && !address.is_multicast()
        && !address.is_broadcast()
        && !address.is_documentation()
        && octets[0] != 0
        && !(octets[0] == 100 && (64..=127).contains(&octets[1]))
        && !(octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        && !(octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
        && !(octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        && octets[0] < 224
}

fn is_safe_public_ipv6(address: Ipv6Addr) -> bool {
    if ipv6_in_prefix(address, Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32) {
        return false;
    }

    // Frozen from the IANA IPv6 Global Unicast Address Space registry dated
    // 2025-10-10. Unlisted space inside 2000::/3 is reserved and must fail
    // closed until a new contract version reviews a later registry snapshot.
    [
        (Ipv6Addr::new(0x2001, 0x0001, 0, 0, 0, 0, 0, 1), 128),
        (Ipv6Addr::new(0x2001, 0x0001, 0, 0, 0, 0, 0, 2), 128),
        (Ipv6Addr::new(0x2001, 0x0001, 0, 0, 0, 0, 0, 3), 128),
        (Ipv6Addr::new(0x2001, 0x0003, 0, 0, 0, 0, 0, 0), 32),
        (Ipv6Addr::new(0x2001, 0x0004, 0x0112, 0, 0, 0, 0, 0), 48),
        (Ipv6Addr::new(0x2001, 0x0020, 0, 0, 0, 0, 0, 0), 28),
        (Ipv6Addr::new(0x2001, 0x0030, 0, 0, 0, 0, 0, 0), 28),
        (Ipv6Addr::new(0x2001, 0x0200, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x0400, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x0600, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x0800, 0, 0, 0, 0, 0, 0), 22),
        (Ipv6Addr::new(0x2001, 0x0c00, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x0e00, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x1200, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x1400, 0, 0, 0, 0, 0, 0), 22),
        (Ipv6Addr::new(0x2001, 0x1800, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x1a00, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x1c00, 0, 0, 0, 0, 0, 0), 22),
        (Ipv6Addr::new(0x2001, 0x2000, 0, 0, 0, 0, 0, 0), 19),
        (Ipv6Addr::new(0x2001, 0x4000, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x4200, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x4400, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x4600, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x4800, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x4a00, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x4c00, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x5000, 0, 0, 0, 0, 0, 0), 20),
        (Ipv6Addr::new(0x2001, 0x8000, 0, 0, 0, 0, 0, 0), 19),
        (Ipv6Addr::new(0x2001, 0xa000, 0, 0, 0, 0, 0, 0), 20),
        (Ipv6Addr::new(0x2001, 0xb000, 0, 0, 0, 0, 0, 0), 20),
        (Ipv6Addr::new(0x2003, 0, 0, 0, 0, 0, 0, 0), 18),
        (Ipv6Addr::new(0x2400, 0, 0, 0, 0, 0, 0, 0), 12),
        (Ipv6Addr::new(0x2410, 0, 0, 0, 0, 0, 0, 0), 12),
        (Ipv6Addr::new(0x2600, 0, 0, 0, 0, 0, 0, 0), 12),
        (Ipv6Addr::new(0x2610, 0, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2620, 0, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2630, 0, 0, 0, 0, 0, 0, 0), 12),
        (Ipv6Addr::new(0x2800, 0, 0, 0, 0, 0, 0, 0), 12),
        (Ipv6Addr::new(0x2a00, 0, 0, 0, 0, 0, 0, 0), 12),
        (Ipv6Addr::new(0x2a10, 0, 0, 0, 0, 0, 0, 0), 12),
        (Ipv6Addr::new(0x2c00, 0, 0, 0, 0, 0, 0, 0), 12),
    ]
    .into_iter()
    .any(|(network, prefix_length)| ipv6_in_prefix(address, network, prefix_length))
}

fn ipv6_in_prefix(address: Ipv6Addr, network: Ipv6Addr, prefix_length: u32) -> bool {
    let mask = u128::MAX << (128 - prefix_length);
    (u128::from(address) & mask) == (u128::from(network) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use slipstream_core::routing_policy::bundled_policy_v1;

    const CONTRACT: &str = include_str!("../../../../contracts/windows-packet-adapter-v1.json");

    #[derive(Debug, Deserialize)]
    struct ContractFixture {
        route_vectors: Vec<RouteVector>,
        conflict_vectors: Vec<RouteConflictVector>,
    }

    #[derive(Debug, Deserialize)]
    struct RouteVector {
        name: String,
        now_ms: u64,
        request: RouteRequestFixture,
        expected: String,
    }

    #[derive(Debug, Deserialize)]
    struct RouteRequestFixture {
        policy: RoutePolicyResult,
        destination: String,
        prefix_length: u8,
        resolver_evidence: ResolverEvidenceFixture,
    }

    #[derive(Debug, Deserialize)]
    struct ResolverEvidenceFixture {
        source: WindowsPacketRouteEvidenceSource,
        host: String,
        addresses: Vec<String>,
        observed_at_ms: u64,
        expires_at_ms: u64,
    }

    #[derive(Debug, Deserialize)]
    struct RouteConflictVector {
        name: String,
        now_ms: u64,
        route_host: String,
        destination: String,
        route_evidence_expires_at_ms: u64,
        evidence: RouteConflictEvidenceFixture,
        expected: String,
    }

    #[derive(Debug, Deserialize)]
    struct RouteConflictEvidenceFixture {
        coverage: WindowsPacketRouteConflictCoverage,
        collector_generation: u64,
        destination: String,
        binding_hosts: Vec<String>,
        snapshot_started_at_ms: u64,
        snapshot_completed_at_ms: u64,
        expires_at_ms: u64,
    }

    impl RouteRequestFixture {
        fn into_request(self) -> WindowsPacketRouteRequest {
            WindowsPacketRouteRequest {
                policy: self.policy,
                destination: self.destination,
                prefix_length: self.prefix_length,
                resolver_evidence: WindowsPacketResolverEvidence {
                    source: self.resolver_evidence.source,
                    host: self.resolver_evidence.host,
                    addresses: self.resolver_evidence.addresses,
                    observed_at_ms: self.resolver_evidence.observed_at_ms,
                    expires_at_ms: self.resolver_evidence.expires_at_ms,
                },
            }
        }
    }

    impl RouteConflictVector {
        fn prepare_route(&self, policy: &RoutingPolicyTables) -> WindowsPacketRoutePlan {
            let request = WindowsPacketRouteRequest {
                policy: classify_route_policy(&self.route_host, policy),
                destination: self.destination.clone(),
                prefix_length: if self
                    .destination
                    .parse::<IpAddr>()
                    .expect("conflict fixture destination must parse")
                    .is_ipv4()
                {
                    32
                } else {
                    128
                },
                resolver_evidence: WindowsPacketResolverEvidence {
                    source: WindowsPacketRouteEvidenceSource::OwnedResolverQuery,
                    host: self.route_host.clone(),
                    addresses: vec![self.destination.clone()],
                    observed_at_ms: self.now_ms.saturating_sub(100),
                    expires_at_ms: self.route_evidence_expires_at_ms,
                },
            };
            prepare_windows_packet_route(&request, self.now_ms, policy)
                .expect("conflict fixture route must prepare")
        }

        fn into_evidence(self) -> WindowsPacketRouteConflictEvidence {
            WindowsPacketRouteConflictEvidence {
                coverage: self.evidence.coverage,
                collector_generation: self.evidence.collector_generation,
                destination: self
                    .evidence
                    .destination
                    .parse()
                    .expect("conflict fixture evidence destination must parse"),
                binding_hosts: self.evidence.binding_hosts,
                snapshot_started_at_ms: self.evidence.snapshot_started_at_ms,
                snapshot_completed_at_ms: self.evidence.snapshot_completed_at_ms,
                expires_at_ms: self.evidence.expires_at_ms,
            }
        }
    }

    fn conflict_vector() -> RouteConflictVector {
        RouteConflictVector {
            name: "unit-fixture".to_owned(),
            now_ms: 2_000,
            route_host: "updates.discord.com".to_owned(),
            destination: "104.16.58.5".to_owned(),
            route_evidence_expires_at_ms: 20_000,
            evidence: RouteConflictEvidenceFixture {
                coverage: WindowsPacketRouteConflictCoverage::CompleteOwnedResolutionBoundary,
                collector_generation: 1,
                destination: "104.16.58.5".to_owned(),
                binding_hosts: vec!["updates.discord.com".to_owned()],
                snapshot_started_at_ms: 1_900,
                snapshot_completed_at_ms: 1_950,
                expires_at_ms: 10_000,
            },
            expected: "admitted".to_owned(),
        }
    }

    #[test]
    fn packet_routes_are_resolver_bound_public_exact_and_fresh() {
        let fixture: ContractFixture =
            serde_json::from_str(CONTRACT).expect("Windows packet-adapter contract must parse");
        let policy = bundled_policy_v1();

        for vector in fixture.route_vectors {
            let request = vector.request.into_request();
            let result = prepare_windows_packet_route(&request, vector.now_ms, &policy);
            let actual = match &result {
                Ok(plan) => match plan.purpose() {
                    WindowsPacketRoutePurpose::LocalBypass => "local_bypass",
                    WindowsPacketRoutePurpose::GeoExit => "geo_exit",
                },
                Err(error) => error.as_str(),
            };
            assert_eq!(actual, vector.expected, "{}", vector.name);
            if let Ok(plan) = result {
                assert_eq!(plan.policy(), &request.policy);
                assert_eq!(plan.destination().to_string(), request.destination);
                assert_eq!(plan.prefix_length(), request.prefix_length);
                assert_eq!(plan.evidence_source(), request.resolver_evidence.source);
                assert_eq!(
                    plan.expires_at_ms(),
                    request.resolver_evidence.expires_at_ms
                );
            }
        }
    }

    #[test]
    fn packet_route_conflicts_require_complete_fresh_compatible_bindings() {
        let fixture: ContractFixture =
            serde_json::from_str(CONTRACT).expect("Windows packet-adapter contract must parse");
        let policy = bundled_policy_v1();

        for vector in fixture.conflict_vectors {
            let route = vector.prepare_route(&policy);
            let destination = route.destination();
            let route_expires_at_ms = route.expires_at_ms();
            let collector_generation = vector.evidence.collector_generation;
            let evidence_expires_at_ms = vector.evidence.expires_at_ms;
            let name = vector.name.clone();
            let expected = vector.expected.clone();
            let now_ms = vector.now_ms;
            let evidence = vector.into_evidence();
            let result = admit_windows_packet_route_conflicts(route, evidence, now_ms, &policy);
            let actual = match &result {
                Ok(_) => "admitted",
                Err(error) => error.as_str(),
            };
            assert_eq!(actual, expected.as_str(), "{name}");
            if let Ok(admission) = result {
                assert_eq!(admission.route().destination(), destination, "{name}");
                assert_eq!(
                    admission.collector_generation(),
                    collector_generation,
                    "{name}"
                );
                assert_eq!(
                    admission.expires_at_ms(),
                    route_expires_at_ms.min(evidence_expires_at_ms),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn packet_route_conflicts_reject_policy_change_and_unbounded_bindings() {
        let policy = bundled_policy_v1();
        let vector = conflict_vector();
        let route = vector.prepare_route(&policy);
        let mut changed_policy = policy.clone();
        changed_policy
            .static_routes
            .retain(|entry| entry.service_group.as_str() != "discord");
        assert!(matches!(
            admit_windows_packet_route_conflicts(
                route,
                vector.into_evidence(),
                2_000,
                &changed_policy,
            ),
            Err(WindowsPacketRouteConflictErrorCode::RoutePolicyChanged)
        ));

        let vector = conflict_vector();
        let route = vector.prepare_route(&policy);
        assert!(matches!(
            admit_windows_packet_route_conflicts(route, vector.into_evidence(), 20_000, &policy),
            Err(WindowsPacketRouteConflictErrorCode::RouteEvidenceExpired)
        ));

        let mut vector = conflict_vector();
        vector.evidence.collector_generation = 2;
        vector.evidence.binding_hosts = (0..=MAX_PACKET_ROUTE_CONFLICT_HOSTS)
            .map(|index| format!("{index:03}.updates.discord.com"))
            .collect();
        let route = vector.prepare_route(&policy);
        assert!(matches!(
            admit_windows_packet_route_conflicts(route, vector.into_evidence(), 2_000, &policy),
            Err(WindowsPacketRouteConflictErrorCode::EvidenceBindingLimitExceeded)
        ));

        let mut vector = conflict_vector();
        vector.evidence.binding_hosts = vec![format!(
            "{}.example",
            "a".repeat(MAX_PACKET_ROUTE_CONFLICT_HOST_BYTES)
        )];
        let route = vector.prepare_route(&policy);
        assert!(matches!(
            admit_windows_packet_route_conflicts(route, vector.into_evidence(), 2_000, &policy),
            Err(WindowsPacketRouteConflictErrorCode::EvidenceHostNotCanonical)
        ));
    }
}
