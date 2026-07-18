use serde::Deserialize;
use serde_json::Value;
use slipstream_core::routing_policy::bundled_policy_v1;
use slipstream_windows_adapter::direct_connector::WindowsDirectConnectorEndpoint;
use slipstream_windows_adapter::direct_ingress::WindowsDirectIngressRequest;
use slipstream_windows_adapter::wfp_capture::{
    decode_windows_wfp_redirect_context_v1, encode_windows_wfp_redirect_context_v1,
    prepare_windows_wfp_outbound_socket, validate_windows_wfp_capture,
    WindowsWfpAcceptedSocketInput, WindowsWfpCaptureIdentity,
    MAX_WINDOWS_WFP_REDIRECT_RECORDS_BYTES, WINDOWS_WFP_CAPTURE_CONTRACT_VERSION,
    WINDOWS_WFP_REDIRECT_CONTEXT_LENGTH,
};
use std::net::{IpAddr, SocketAddr};

const CONTRACT: &str = include_str!("../../../contracts/windows-wfp-capture-v1.json");

#[derive(Debug, Deserialize)]
struct ContractFixture {
    schema_version: u32,
    contract: String,
    contract_version: u32,
    invariants: Value,
    wire_format: WireFormat,
    identity: WindowsWfpCaptureIdentity,
    valid_contexts: Vec<ValidContext>,
    context_rejections: Vec<ContextRejection>,
    capture_rejections: Vec<CaptureRejection>,
    handoff_vectors: Vec<HandoffVector>,
}

#[derive(Debug, Deserialize)]
struct WireFormat {
    magic_hex: String,
    fields: Vec<WireField>,
}

#[derive(Debug, Deserialize)]
struct WireField {
    name: String,
    offset: usize,
    length: usize,
}

#[derive(Debug, Deserialize)]
struct ValidContext {
    name: String,
    context_hex: String,
    original_destination: WindowsDirectConnectorEndpoint,
    original_local_endpoint: WindowsDirectConnectorEndpoint,
    accepted_local_endpoint: WindowsDirectConnectorEndpoint,
    redirect_records_hex: String,
}

#[derive(Debug, Deserialize)]
struct Mutation {
    offset: usize,
    bytes_hex: String,
}

#[derive(Debug, Deserialize)]
struct ContextRejection {
    name: String,
    base: String,
    truncate_to: Option<usize>,
    #[serde(default)]
    append_hex: String,
    mutations: Vec<Mutation>,
    expected_error: String,
}

#[derive(Debug, Deserialize)]
struct CaptureRejection {
    name: String,
    base: String,
    connection_id: Option<u64>,
    #[serde(default)]
    empty_context: bool,
    #[serde(default)]
    context_mutations: Vec<Mutation>,
    redirect_records_size: usize,
    accepted_local_endpoint: Option<WindowsDirectConnectorEndpoint>,
    expected_error: String,
}

#[derive(Debug, Deserialize)]
struct HandoffVector {
    name: String,
    base: String,
    capture_connection_id: u64,
    ingress_request: WindowsDirectIngressRequest,
    expected_accepted: bool,
    expected_error: String,
}

fn contract() -> ContractFixture {
    serde_json::from_str(CONTRACT).expect("Windows WFP capture v1 must be valid JSON")
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex must contain complete bytes");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("fixture hex must be ASCII");
            u8::from_str_radix(text, 16).expect("fixture hex must be valid")
        })
        .collect()
}

fn mutate(mut bytes: Vec<u8>, mutations: &[Mutation]) -> Vec<u8> {
    for mutation in mutations {
        let replacement = decode_hex(&mutation.bytes_hex);
        let end = mutation.offset + replacement.len();
        assert!(end <= bytes.len(), "mutation must remain in the context");
        bytes[mutation.offset..end].copy_from_slice(&replacement);
    }
    bytes
}

fn endpoint(value: &WindowsDirectConnectorEndpoint) -> SocketAddr {
    SocketAddr::new(
        value
            .address
            .parse::<IpAddr>()
            .expect("fixture endpoint must be numeric"),
        value.port,
    )
}

fn find_context<'a>(fixture: &'a ContractFixture, name: &str) -> &'a ValidContext {
    fixture
        .valid_contexts
        .iter()
        .find(|context| context.name == name)
        .unwrap_or_else(|| panic!("missing context {name:?}"))
}

fn input_from(
    connection_id: u64,
    redirect_context: Vec<u8>,
    redirect_records: Vec<u8>,
    accepted_local_endpoint: WindowsDirectConnectorEndpoint,
) -> WindowsWfpAcceptedSocketInput {
    WindowsWfpAcceptedSocketInput {
        connection_id,
        redirect_context,
        redirect_records,
        accepted_local_endpoint,
    }
}

#[test]
fn rust_executes_frozen_windows_wfp_wire_vectors() {
    let fixture = contract();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.contract, "slipstream.windows_wfp_capture");
    assert_eq!(
        fixture.contract_version,
        WINDOWS_WFP_CAPTURE_CONTRACT_VERSION
    );
    assert_eq!(
        fixture.invariants["wire_context_bytes"],
        WINDOWS_WFP_REDIRECT_CONTEXT_LENGTH
    );
    assert_eq!(
        fixture.invariants["redirect_records_max_bytes"],
        MAX_WINDOWS_WFP_REDIRECT_RECORDS_BYTES
    );
    assert_eq!(fixture.invariants["dns_proxy_pac_vpn_mutation"], false);
    assert_eq!(
        fixture.invariants["production_service_host_network_effects"],
        false
    );
    assert_eq!(
        fixture.invariants["exact_ingress_admission_identity_required"],
        true
    );
    assert_eq!(fixture.wire_format.magic_hex, "534c495057465000");
    let fields: Vec<_> = fixture
        .wire_format
        .fields
        .iter()
        .map(|field| (field.name.as_str(), field.offset, field.length))
        .collect();
    assert_eq!(
        fields,
        vec![
            ("magic", 0, 8),
            ("version", 8, 2),
            ("header_length", 10, 2),
            ("total_length", 12, 4),
            ("service_generation", 16, 8),
            ("target_pid", 24, 4),
            ("protocol", 28, 1),
            ("address_family", 29, 1),
            ("flags", 30, 2),
            ("original_port", 32, 2),
            ("original_local_port", 34, 2),
            ("original_address", 36, 16),
            ("original_local_address", 52, 16),
            ("capture_instance_id", 68, 16),
            ("service_executable_sha256", 84, 32),
            ("reserved_zero", 116, 12),
        ]
    );

    for vector in &fixture.valid_contexts {
        let expected_context = decode_hex(&vector.context_hex);
        assert_eq!(expected_context.len(), WINDOWS_WFP_REDIRECT_CONTEXT_LENGTH);
        let decoded = decode_windows_wfp_redirect_context_v1(&expected_context)
            .unwrap_or_else(|error| panic!("{} decode: {error}", vector.name));
        assert_eq!(
            decoded.original_destination(),
            endpoint(&vector.original_destination),
            "{} destination",
            vector.name
        );
        assert_eq!(
            decoded.original_local_endpoint(),
            endpoint(&vector.original_local_endpoint),
            "{} local endpoint",
            vector.name
        );
        assert_eq!(decoded.encode().as_slice(), expected_context.as_slice());
        assert_eq!(
            encode_windows_wfp_redirect_context_v1(
                &fixture.identity,
                &vector.original_destination,
                &vector.original_local_endpoint,
            )
            .unwrap_or_else(|error| panic!("{} encode: {error}", vector.name))
            .as_slice(),
            expected_context.as_slice(),
            "{} reference encoder",
            vector.name
        );

        let records = decode_hex(&vector.redirect_records_hex);
        let capture = validate_windows_wfp_capture(
            input_from(
                1,
                expected_context,
                records.clone(),
                vector.accepted_local_endpoint.clone(),
            ),
            &fixture.identity,
        )
        .unwrap_or_else(|error| panic!("{} capture: {error}", vector.name));
        assert_eq!(
            capture.original_destination(),
            endpoint(&vector.original_destination)
        );
        assert_eq!(
            capture.original_local_endpoint(),
            endpoint(&vector.original_local_endpoint)
        );
        assert_eq!(
            capture.accepted_local_endpoint(),
            endpoint(&vector.accepted_local_endpoint)
        );
        assert_eq!(capture.redirect_records_len(), records.len());
    }
}

#[test]
fn malformed_wfp_contexts_fail_with_stable_error_codes() {
    let fixture = contract();
    for vector in &fixture.context_rejections {
        let base = find_context(&fixture, &vector.base);
        let mut context = mutate(decode_hex(&base.context_hex), &vector.mutations);
        if let Some(length) = vector.truncate_to {
            context.truncate(length);
        }
        context.extend(decode_hex(&vector.append_hex));
        let error = decode_windows_wfp_redirect_context_v1(&context).unwrap_err();
        assert_eq!(error.as_str(), vector.expected_error, "{}", vector.name);
    }
}

#[test]
fn accepted_sockets_require_exact_owned_identity_and_bounded_records() {
    let fixture = contract();
    for vector in &fixture.capture_rejections {
        let base = find_context(&fixture, &vector.base);
        let redirect_context = if vector.empty_context {
            Vec::new()
        } else {
            mutate(decode_hex(&base.context_hex), &vector.context_mutations)
        };
        let accepted_local_endpoint = vector
            .accepted_local_endpoint
            .clone()
            .unwrap_or_else(|| base.accepted_local_endpoint.clone());
        let error = validate_windows_wfp_capture(
            input_from(
                vector.connection_id.unwrap_or(1),
                redirect_context,
                vec![0xa5; vector.redirect_records_size],
                accepted_local_endpoint,
            ),
            &fixture.identity,
        )
        .unwrap_err();
        assert_eq!(error.as_str(), vector.expected_error, "{}", vector.name);
    }

    let base = find_context(&fixture, "ipv4");
    let capture = validate_windows_wfp_capture(
        input_from(
            1,
            decode_hex(&base.context_hex),
            vec![0x5a; MAX_WINDOWS_WFP_REDIRECT_RECORDS_BYTES],
            base.accepted_local_endpoint.clone(),
        ),
        &fixture.identity,
    )
    .expect("the exact redirect-record ceiling must remain accepted");
    assert_eq!(
        capture.redirect_records_len(),
        MAX_WINDOWS_WFP_REDIRECT_RECORDS_BYTES
    );
}

#[test]
fn capture_identity_rejects_ambiguous_or_unowned_listener_sets() {
    let fixture = contract();
    let base = find_context(&fixture, "ipv4");
    let mut cases = Vec::new();

    let mut zero_pid = fixture.identity.clone();
    zero_pid.target_pid = 0;
    cases.push(("zero pid", zero_pid, "invalid_target_pid"));

    let mut uppercase_instance = fixture.identity.clone();
    uppercase_instance.capture_instance_id = uppercase_instance.capture_instance_id.to_uppercase();
    cases.push((
        "uppercase instance",
        uppercase_instance,
        "invalid_capture_instance",
    ));

    let mut uppercase_hash = fixture.identity.clone();
    uppercase_hash.service.executable_sha256 =
        uppercase_hash.service.executable_sha256.to_uppercase();
    cases.push((
        "uppercase executable hash",
        uppercase_hash,
        "invalid_service_identity",
    ));

    let mut zero_hash = fixture.identity.clone();
    zero_hash.service.executable_sha256 = "0".repeat(64);
    cases.push(("zero executable hash", zero_hash, "invalid_executable_hash"));

    let mut missing_listener = fixture.identity.clone();
    missing_listener.listeners.clear();
    cases.push(("missing listener", missing_listener, "invalid_listener_set"));

    let mut duplicate_family = fixture.identity.clone();
    duplicate_family.listeners = vec![
        WindowsDirectConnectorEndpoint {
            address: "127.0.0.1".to_owned(),
            port: 1443,
        },
        WindowsDirectConnectorEndpoint {
            address: "127.0.0.1".to_owned(),
            port: 2443,
        },
    ];
    cases.push((
        "duplicate listener family",
        duplicate_family,
        "invalid_listener_set",
    ));

    for (name, identity, expected_error) in cases {
        let error = validate_windows_wfp_capture(
            input_from(
                1,
                decode_hex(&base.context_hex),
                decode_hex(&base.redirect_records_hex),
                base.accepted_local_endpoint.clone(),
            ),
            &identity,
        )
        .unwrap_err();
        assert_eq!(error.as_str(), expected_error, "{name}");
    }
}

#[test]
fn redirect_records_are_one_shot_and_precede_the_connect_endpoint() {
    let fixture = contract();
    let policy_tables = bundled_policy_v1();
    let recovery_request = fixture
        .handoff_vectors
        .iter()
        .find(|vector| vector.expected_accepted)
        .expect("one accepted handoff vector")
        .ingress_request
        .clone();
    for vector in &fixture.handoff_vectors {
        let base = find_context(&fixture, &vector.base);
        let records = decode_hex(&base.redirect_records_hex);
        let capture = validate_windows_wfp_capture(
            input_from(
                vector.capture_connection_id,
                decode_hex(&base.context_hex),
                records.clone(),
                base.accepted_local_endpoint.clone(),
            ),
            &fixture.identity,
        )
        .expect("handoff fixture must validate");
        let result =
            prepare_windows_wfp_outbound_socket(capture, &vector.ingress_request, &policy_tables);
        if vector.expected_accepted {
            let record_plan = result.unwrap_or_else(|error| panic!("{}: {error}", vector.name));
            assert_eq!(record_plan.redirect_records(), records.as_slice());
            let connect_plan = record_plan.mark_redirect_records_applied();
            assert_eq!(
                connect_plan.endpoint(),
                endpoint(&base.original_destination)
            );
            assert_eq!(
                connect_plan.ingress_plan().connection_id(),
                vector.capture_connection_id
            );
            assert_eq!(
                connect_plan.ingress_plan().request_id(),
                vector
                    .ingress_request
                    .connector_request
                    .data_plane_request
                    .request_id
            );
            assert_eq!(
                connect_plan.ingress_plan().session_id(),
                vector.ingress_request.connector_request.session_id
            );
            assert_eq!(
                connect_plan.original_local_endpoint(),
                endpoint(&base.original_local_endpoint)
            );
        } else {
            let error = result.expect_err("mismatched admission must fail");
            assert_eq!(
                error.code().as_str(),
                vector.expected_error,
                "{}",
                vector.name
            );
            assert_eq!(error.capture().redirect_records_len(), records.len());
            assert_eq!(
                error.capture().connection_id(),
                vector.capture_connection_id
            );
            assert_eq!(
                error.capture().original_destination(),
                endpoint(&base.original_destination)
            );
            let recovered = error.into_capture();
            let record_plan =
                prepare_windows_wfp_outbound_socket(recovered, &recovery_request, &policy_tables)
                    .expect("failed admission must preserve the one-shot capture");
            assert_eq!(record_plan.redirect_records(), records.as_slice());
            assert_eq!(
                record_plan.mark_redirect_records_applied().endpoint(),
                endpoint(&base.original_destination)
            );
        }
    }
}

#[test]
fn production_service_host_does_not_compose_wfp_capture() {
    for (label, source) in [
        ("service host", include_str!("../src/service_host/v1.rs")),
        ("worker host", include_str!("../src/worker_host/v1.rs")),
        (
            "production binary",
            include_str!("../src/bin/slipstream_windows_service.rs"),
        ),
    ] {
        assert!(
            !source.contains("wfp_capture"),
            "{label} must remain disconnected from WFP capture"
        );
    }
}
