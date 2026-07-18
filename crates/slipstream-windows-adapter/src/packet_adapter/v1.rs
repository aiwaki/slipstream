//! Version 1 Windows packet-adapter boundary.
//!
//! This module admits a pinned, already-verified Wintun DLL and prepares only
//! fresh policy-bound exact-destination route plans. It does not load a DLL,
//! create an adapter, install a route, resolve a name, or touch system DNS,
//! proxy, PAC, VPN, or the production service host.

use serde::{Deserialize, Serialize};
use slipstream_core::routing_policy::{
    classify_route_policy, RouteClass, RoutePolicyResult, RoutingPolicyTables,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsPacketRouteRequest {
    pub policy: RoutePolicyResult,
    pub destination: String,
    pub prefix_length: u8,
    pub evidence_source: WindowsPacketRouteEvidenceSource,
    pub observed_at_ms: u64,
    pub expires_at_ms: u64,
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
    if request.observed_at_ms >= request.expires_at_ms
        || request.expires_at_ms.saturating_sub(request.observed_at_ms)
            > MAX_PACKET_ROUTE_EVIDENCE_LIFETIME_MS
        || now_ms < request.observed_at_ms
    {
        return Err(WindowsPacketAdapterErrorCode::InvalidEvidenceWindow);
    }
    if now_ms >= request.expires_at_ms {
        return Err(WindowsPacketAdapterErrorCode::EvidenceExpired);
    }

    Ok(WindowsPacketRoutePlan {
        policy: classified,
        destination,
        prefix_length: required_prefix,
        evidence_source: request.evidence_source,
        expires_at_ms: request.expires_at_ms,
        purpose,
    })
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
    let segments = address.segments();
    let prohibited = address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || address.to_ipv4_mapped().is_some();
    !prohibited
}
