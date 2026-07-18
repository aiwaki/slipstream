use serde::Deserialize;
use serde_json::Value;
use slipstream_core::routing_policy::bundled_policy_v1;
use slipstream_windows_adapter::packet_adapter::{
    admit_windows_packet_adapter_artifact, prepare_windows_packet_route,
    WindowsPacketAdapterArtifactEvidence, WindowsPacketAdapterErrorCode,
    WindowsPacketAdapterSignatureStatus, WindowsPacketRoutePurpose, WindowsPacketRouteRequest,
    WINDOWS_PACKET_ADAPTER_CONTRACT_VERSION, WINTUN_AMD64_DLL_LENGTH, WINTUN_AMD64_DLL_PATH,
    WINTUN_AMD64_DLL_SHA256, WINTUN_AMD64_PE_MACHINE, WINTUN_ARCHIVE_LENGTH, WINTUN_ARCHIVE_SHA256,
    WINTUN_ARM64_DLL_LENGTH, WINTUN_ARM64_DLL_PATH, WINTUN_ARM64_DLL_SHA256,
    WINTUN_ARM64_PE_MACHINE, WINTUN_LICENSE_SHA256, WINTUN_PUBLISHER, WINTUN_SIGNER_SHA256,
    WINTUN_VERSION,
};
use std::collections::BTreeMap;

const CONTRACT: &str = include_str!("../../../contracts/windows-packet-adapter-v1.json");
const SOURCE: &str = include_str!("../../../vendor/wintun/SOURCE.json");
const VERSION: &str = include_str!("../../../vendor/wintun/VERSION");

#[derive(Debug, Deserialize)]
struct ContractFixture {
    schema_version: u32,
    contract: String,
    contract_version: u32,
    invariants: Value,
    upstream: UpstreamFixture,
    architectures: BTreeMap<String, ArchitectureFixture>,
    artifact_vectors: Vec<ArtifactVector>,
    route_vectors: Vec<RouteVector>,
}

#[derive(Debug, Deserialize)]
struct UpstreamFixture {
    name: String,
    version: String,
    source_url: String,
    archive_sha256: String,
    archive_length: u64,
    license_sha256: String,
    publisher: String,
    signer_sha256: String,
}

#[derive(Debug, Deserialize)]
struct ArchitectureFixture {
    dll_path: String,
    dll_sha256: String,
    dll_length: u64,
    pe_machine: u16,
}

#[derive(Debug, Deserialize)]
struct ArtifactVector {
    name: String,
    architecture: String,
    evidence: WindowsPacketAdapterArtifactEvidence,
    expected: String,
}

#[derive(Debug, Deserialize)]
struct RouteVector {
    name: String,
    now_ms: u64,
    request: WindowsPacketRouteRequest,
    expected: String,
}

fn contract() -> ContractFixture {
    serde_json::from_str(CONTRACT).expect("Windows packet-adapter v1 must be valid JSON")
}

#[test]
fn source_record_and_contract_freeze_the_same_official_artifacts() {
    let fixture = contract();
    let source: Value = serde_json::from_str(SOURCE).expect("Wintun source record must be JSON");
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.contract, "slipstream.windows_packet_adapter");
    assert_eq!(
        fixture.contract_version,
        WINDOWS_PACKET_ADAPTER_CONTRACT_VERSION
    );
    assert_eq!(fixture.upstream.name, "Wintun");
    assert_eq!(fixture.upstream.version, WINTUN_VERSION);
    assert_eq!(VERSION.trim(), WINTUN_VERSION);
    assert_eq!(fixture.upstream.source_url, source["source_url"]);
    assert_eq!(fixture.upstream.archive_sha256, WINTUN_ARCHIVE_SHA256);
    assert_eq!(fixture.upstream.archive_length, WINTUN_ARCHIVE_LENGTH);
    assert_eq!(fixture.upstream.license_sha256, WINTUN_LICENSE_SHA256);
    assert_eq!(fixture.upstream.publisher, WINTUN_PUBLISHER);
    assert_eq!(fixture.upstream.signer_sha256, WINTUN_SIGNER_SHA256);
    assert_eq!(source["version"], WINTUN_VERSION);
    assert_eq!(source["archive_sha256"], WINTUN_ARCHIVE_SHA256);
    assert_eq!(source["archive_length"], WINTUN_ARCHIVE_LENGTH);
    assert_eq!(source["license"]["sha256"], WINTUN_LICENSE_SHA256);
    assert_eq!(source["signature"]["publisher"], WINTUN_PUBLISHER);
    assert_eq!(
        source["signature"]["leaf_certificate_sha256"],
        WINTUN_SIGNER_SHA256
    );

    let amd64 = &fixture.architectures["x86_64"];
    assert_eq!(amd64.dll_path, WINTUN_AMD64_DLL_PATH);
    assert_eq!(amd64.dll_sha256, WINTUN_AMD64_DLL_SHA256);
    assert_eq!(amd64.dll_length, WINTUN_AMD64_DLL_LENGTH);
    assert_eq!(amd64.pe_machine, WINTUN_AMD64_PE_MACHINE);
    assert_eq!(source["architectures"]["x86_64"]["path"], amd64.dll_path);
    assert_eq!(
        source["architectures"]["x86_64"]["sha256"],
        amd64.dll_sha256
    );
    assert_eq!(
        source["architectures"]["x86_64"]["length"],
        amd64.dll_length
    );
    assert_eq!(
        source["architectures"]["x86_64"]["pe_machine"],
        amd64.pe_machine
    );

    let arm64 = &fixture.architectures["aarch64"];
    assert_eq!(arm64.dll_path, WINTUN_ARM64_DLL_PATH);
    assert_eq!(arm64.dll_sha256, WINTUN_ARM64_DLL_SHA256);
    assert_eq!(arm64.dll_length, WINTUN_ARM64_DLL_LENGTH);
    assert_eq!(arm64.pe_machine, WINTUN_ARM64_PE_MACHINE);
    assert_eq!(source["architectures"]["aarch64"]["path"], arm64.dll_path);
    assert_eq!(
        source["architectures"]["aarch64"]["sha256"],
        arm64.dll_sha256
    );
    assert_eq!(
        source["architectures"]["aarch64"]["length"],
        arm64.dll_length
    );
    assert_eq!(
        source["architectures"]["aarch64"]["pe_machine"],
        arm64.pe_machine
    );

    assert_eq!(fixture.invariants["slipstream_owned_kernel_driver"], false);
    assert_eq!(fixture.invariants["default_route_mutation"], false);
    assert_eq!(
        fixture.invariants["route_plan_is_native_authorization"],
        false
    );
    assert_eq!(
        fixture.invariants["shared_destination_conflict_check_required"],
        true
    );
    assert_eq!(fixture.invariants["native_route_installation"], false);
    assert_eq!(fixture.invariants["system_dns_mutation"], false);
    assert_eq!(fixture.invariants["proxy_pac_vpn_mutation"], false);
    assert_eq!(
        fixture.invariants["production_service_host_composition"],
        false
    );
}

#[test]
fn exact_artifact_evidence_is_required_for_every_supported_architecture() {
    for vector in contract().artifact_vectors {
        let result = admit_windows_packet_adapter_artifact(&vector.architecture, &vector.evidence);
        let actual = match result {
            Ok(admission) => {
                assert_eq!(admission.architecture().as_str(), vector.architecture);
                assert_eq!(admission.dll_path(), vector.evidence.dll_path);
                assert_eq!(admission.dll_sha256(), vector.evidence.dll_sha256);
                "admitted"
            }
            Err(error) => error.as_str(),
        };
        assert_eq!(actual, vector.expected, "{}", vector.name);
    }
}

#[test]
fn packet_routes_are_policy_bound_public_exact_and_fresh() {
    let policy = bundled_policy_v1();
    for vector in contract().route_vectors {
        let result = prepare_windows_packet_route(&vector.request, vector.now_ms, &policy);
        let actual = match &result {
            Ok(plan) => match plan.purpose() {
                WindowsPacketRoutePurpose::LocalBypass => "local_bypass",
                WindowsPacketRoutePurpose::GeoExit => "geo_exit",
            },
            Err(error) => error.as_str(),
        };
        assert_eq!(actual, vector.expected, "{}", vector.name);
        if let Ok(plan) = result {
            assert_eq!(plan.policy(), &vector.request.policy);
            assert_eq!(plan.destination().to_string(), vector.request.destination);
            assert_eq!(plan.prefix_length(), vector.request.prefix_length);
            assert_eq!(plan.evidence_source(), vector.request.evidence_source);
            assert_eq!(plan.expires_at_ms(), vector.request.expires_at_ms);
        }
    }
}

#[test]
fn every_artifact_failure_has_a_stable_machine_code() {
    let codes = [
        WindowsPacketAdapterErrorCode::UnsupportedArchitecture,
        WindowsPacketAdapterErrorCode::VersionMismatch,
        WindowsPacketAdapterErrorCode::ArchiveHashMismatch,
        WindowsPacketAdapterErrorCode::ArchiveLengthMismatch,
        WindowsPacketAdapterErrorCode::LicenseHashMismatch,
        WindowsPacketAdapterErrorCode::DllPathMismatch,
        WindowsPacketAdapterErrorCode::DllHashMismatch,
        WindowsPacketAdapterErrorCode::DllLengthMismatch,
        WindowsPacketAdapterErrorCode::PeMachineMismatch,
        WindowsPacketAdapterErrorCode::SignatureNotValid,
        WindowsPacketAdapterErrorCode::PublisherMismatch,
        WindowsPacketAdapterErrorCode::SignerMismatch,
        WindowsPacketAdapterErrorCode::TimestampMissing,
    ];
    assert!(codes.iter().all(|code| !code.as_str().is_empty()));
}

#[test]
fn every_pinned_artifact_field_is_enforced() {
    let fixture = contract();
    let valid = fixture.artifact_vectors[0].evidence.clone();
    let cases: Vec<(
        WindowsPacketAdapterArtifactEvidence,
        WindowsPacketAdapterErrorCode,
    )> = vec![
        (
            WindowsPacketAdapterArtifactEvidence {
                version: "0.14.2".to_owned(),
                ..valid.clone()
            },
            WindowsPacketAdapterErrorCode::VersionMismatch,
        ),
        (
            WindowsPacketAdapterArtifactEvidence {
                archive_sha256: "00".repeat(32),
                ..valid.clone()
            },
            WindowsPacketAdapterErrorCode::ArchiveHashMismatch,
        ),
        (
            WindowsPacketAdapterArtifactEvidence {
                archive_length: valid.archive_length + 1,
                ..valid.clone()
            },
            WindowsPacketAdapterErrorCode::ArchiveLengthMismatch,
        ),
        (
            WindowsPacketAdapterArtifactEvidence {
                license_sha256: "00".repeat(32),
                ..valid.clone()
            },
            WindowsPacketAdapterErrorCode::LicenseHashMismatch,
        ),
        (
            WindowsPacketAdapterArtifactEvidence {
                dll_path: WINTUN_ARM64_DLL_PATH.to_owned(),
                ..valid.clone()
            },
            WindowsPacketAdapterErrorCode::DllPathMismatch,
        ),
        (
            WindowsPacketAdapterArtifactEvidence {
                dll_sha256: "00".repeat(32),
                ..valid.clone()
            },
            WindowsPacketAdapterErrorCode::DllHashMismatch,
        ),
        (
            WindowsPacketAdapterArtifactEvidence {
                dll_length: valid.dll_length + 1,
                ..valid.clone()
            },
            WindowsPacketAdapterErrorCode::DllLengthMismatch,
        ),
        (
            WindowsPacketAdapterArtifactEvidence {
                pe_machine: WINTUN_ARM64_PE_MACHINE,
                ..valid.clone()
            },
            WindowsPacketAdapterErrorCode::PeMachineMismatch,
        ),
        (
            WindowsPacketAdapterArtifactEvidence {
                signature_status: WindowsPacketAdapterSignatureStatus::Invalid,
                ..valid.clone()
            },
            WindowsPacketAdapterErrorCode::SignatureNotValid,
        ),
        (
            WindowsPacketAdapterArtifactEvidence {
                publisher: "Unknown".to_owned(),
                ..valid.clone()
            },
            WindowsPacketAdapterErrorCode::PublisherMismatch,
        ),
        (
            WindowsPacketAdapterArtifactEvidence {
                signer_sha256: "00".repeat(32),
                ..valid.clone()
            },
            WindowsPacketAdapterErrorCode::SignerMismatch,
        ),
        (
            WindowsPacketAdapterArtifactEvidence {
                timestamped: false,
                ..valid.clone()
            },
            WindowsPacketAdapterErrorCode::TimestampMissing,
        ),
    ];

    for (evidence, expected) in cases {
        assert_eq!(
            admit_windows_packet_adapter_artifact("x86_64", &evidence),
            Err(expected)
        );
    }
}
