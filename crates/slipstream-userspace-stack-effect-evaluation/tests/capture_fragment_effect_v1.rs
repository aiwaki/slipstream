use slipstream_core::routing_policy::{
    bundled_policy_v1, RouteClass, RoutingPolicyTables, ServiceGroup,
};
use slipstream_userspace_stack_effect_evaluation::capture_fragment_v1::{
    MAX_CAPTURE_BOUND_ASSEMBLIES, MAX_REASSEMBLED_PAYLOAD_BYTES, REASSEMBLY_TIMEOUT_MS,
};
use slipstream_userspace_stack_evaluation::ipv6_fragment_input_v1::{
    Ipv6FragmentReassembler, ReassemblyError, ReassemblyOutcome, FRAGMENT_HEADER_BYTES,
    IPV6_HEADER_BYTES,
};
use slipstream_windows_adapter::packet_adapter::v4::{
    classify_windows_packet_capture, WindowsPacketCaptureAttribution, WindowsPacketCaptureDecision,
    WindowsPacketCaptureObservation, WindowsPacketCapturePassthroughReason,
    WindowsPacketCaptureTransport, WindowsPacketHostnameEvidenceSource,
    WindowsPacketPolicyClassification,
};
use std::net::{IpAddr, Ipv6Addr};

const IPV6_FRAGMENT_NEXT_HEADER: u8 = 44;
const TCP_NEXT_HEADER: u8 = 6;
const UDP_NEXT_HEADER: u8 = 17;
const SOURCE_PORT: u16 = 54_001;
const DESTINATION_PORT: u16 = 443;
const SOURCE: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
const DESTINATION: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0x4400, 0, 0, 0, 0xac40, 0x9b4c);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FragmentKey {
    source: Ipv6Addr,
    destination: Ipv6Addr,
    identification: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FragmentEnvelope {
    key: FragmentKey,
    next_header: u8,
    offset: usize,
    more_fragments: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CaptureFragmentOutcome {
    DirectPassthrough {
        reason: WindowsPacketCapturePassthroughReason,
        packet: Vec<u8>,
    },
    Pending {
        capture_generation: u64,
        flow_id: u64,
    },
    Complete {
        classification: WindowsPacketPolicyClassification,
        packet: Vec<u8>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaptureFragmentError {
    Reassembly(ReassemblyError),
    UnsupportedCaptureTransport,
    SourceAddressMismatch,
    DestinationAddressMismatch,
    TransportMismatch,
    TransportHeaderTooShort,
    SourcePortMismatch,
    DestinationPortMismatch,
    CaptureIdentityConflict,
    AssemblyCapacityExceeded,
    CompletedPacketMismatch,
}

impl From<ReassemblyError> for CaptureFragmentError {
    fn from(error: ReassemblyError) -> Self {
        Self::Reassembly(error)
    }
}

#[derive(Debug)]
struct BoundAssembly {
    observation: WindowsPacketCaptureObservation,
    classification: WindowsPacketPolicyClassification,
    key: FragmentKey,
    expires_at_ms: u64,
    normalizer: Ipv6FragmentReassembler,
}

#[derive(Debug, Default)]
struct CaptureFragmentHarness {
    assemblies: Vec<BoundAssembly>,
}

impl CaptureFragmentHarness {
    fn active_assemblies(&self) -> usize {
        self.assemblies.len()
    }

    fn expire(&mut self, now_ms: u64) -> usize {
        let before = self.assemblies.len();
        self.assemblies
            .retain(|assembly| now_ms < assembly.expires_at_ms);
        before - self.assemblies.len()
    }

    fn ingest(
        &mut self,
        observation: &WindowsPacketCaptureObservation,
        now_ms: u64,
        policy_tables: &RoutingPolicyTables,
        packet: &[u8],
    ) -> Result<CaptureFragmentOutcome, CaptureFragmentError> {
        let classification =
            match classify_windows_packet_capture(observation, now_ms, policy_tables) {
                WindowsPacketCaptureDecision::DirectPassthrough { reason, .. } => {
                    return Ok(CaptureFragmentOutcome::DirectPassthrough {
                        reason,
                        packet: packet.to_vec(),
                    });
                }
                WindowsPacketCaptureDecision::PolicyClassified(classification) => classification,
            };

        let envelope = parse_fragment_envelope(packet)?;
        preflight_fragment(&classification, &envelope, packet)?;

        if envelope.offset == 0 && !envelope.more_fragments {
            let mut normalizer = Ipv6FragmentReassembler::new();
            let ReassemblyOutcome::Complete(packet) = normalizer.ingest(now_ms, packet)? else {
                return Err(CaptureFragmentError::CompletedPacketMismatch);
            };
            verify_completed_packet(&classification, &packet)?;
            return Ok(CaptureFragmentOutcome::Complete {
                classification,
                packet,
            });
        }

        self.expire(now_ms);
        let existing = self
            .assemblies
            .iter()
            .position(|assembly| assembly.key == envelope.key);
        let index = match existing {
            Some(index) => {
                let assembly = &self.assemblies[index];
                if assembly.observation != *observation || assembly.classification != classification
                {
                    return Err(CaptureFragmentError::CaptureIdentityConflict);
                }
                index
            }
            None => {
                if self.assemblies.len() >= MAX_CAPTURE_BOUND_ASSEMBLIES {
                    return Err(CaptureFragmentError::AssemblyCapacityExceeded);
                }
                self.assemblies.push(BoundAssembly {
                    observation: observation.clone(),
                    expires_at_ms: observation
                        .expires_at_ms
                        .min(now_ms.saturating_add(REASSEMBLY_TIMEOUT_MS)),
                    classification,
                    key: envelope.key,
                    normalizer: Ipv6FragmentReassembler::new(),
                });
                self.assemblies.len() - 1
            }
        };

        match self.assemblies[index].normalizer.ingest(now_ms, packet) {
            Ok(ReassemblyOutcome::Pending) => Ok(CaptureFragmentOutcome::Pending {
                capture_generation: observation.capture_generation,
                flow_id: observation.flow_id,
            }),
            Ok(ReassemblyOutcome::Complete(packet)) => {
                let assembly = self.assemblies.swap_remove(index);
                verify_completed_packet(&assembly.classification, &packet)?;
                Ok(CaptureFragmentOutcome::Complete {
                    classification: assembly.classification,
                    packet,
                })
            }
            Err(error) => {
                self.assemblies.swap_remove(index);
                Err(error.into())
            }
        }
    }
}

fn parse_fragment_envelope(packet: &[u8]) -> Result<FragmentEnvelope, ReassemblyError> {
    if packet.len() < IPV6_HEADER_BYTES + FRAGMENT_HEADER_BYTES {
        return Err(ReassemblyError::PacketTooShort);
    }
    if packet[0] >> 4 != 6 {
        return Err(ReassemblyError::NotIpv6);
    }
    let declared_payload = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if declared_payload != packet.len() - IPV6_HEADER_BYTES {
        return Err(ReassemblyError::PayloadLengthMismatch);
    }
    if packet[6] != IPV6_FRAGMENT_NEXT_HEADER {
        return Err(ReassemblyError::FragmentHeaderRequired);
    }
    if !matches!(packet[40], TCP_NEXT_HEADER | UDP_NEXT_HEADER) {
        return Err(ReassemblyError::UnsupportedFragmentNextHeader);
    }
    if packet[41] != 0 {
        return Err(ReassemblyError::ReservedBitsSet);
    }

    let offset_and_flags = u16::from_be_bytes([packet[42], packet[43]]);
    if offset_and_flags & 0x0006 != 0 {
        return Err(ReassemblyError::ReservedBitsSet);
    }
    let payload = &packet[IPV6_HEADER_BYTES + FRAGMENT_HEADER_BYTES..];
    if payload.is_empty() {
        return Err(ReassemblyError::EmptyFragment);
    }
    let more_fragments = offset_and_flags & 1 == 1;
    if more_fragments && !payload.len().is_multiple_of(8) {
        return Err(ReassemblyError::NonFinalFragmentNotAligned);
    }
    let offset = ((offset_and_flags >> 3) as usize)
        .checked_mul(8)
        .ok_or(ReassemblyError::FragmentExceedsBuffer)?;
    if offset
        .checked_add(payload.len())
        .is_none_or(|end| end > MAX_REASSEMBLED_PAYLOAD_BYTES)
    {
        return Err(ReassemblyError::FragmentExceedsBuffer);
    }

    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).expect("fixed source slice"));
    let destination =
        Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).expect("fixed destination slice"));
    Ok(FragmentEnvelope {
        key: FragmentKey {
            source,
            destination,
            identification: u32::from_be_bytes([packet[44], packet[45], packet[46], packet[47]]),
        },
        next_header: packet[40],
        offset,
        more_fragments,
    })
}

fn expected_next_header(
    transport: WindowsPacketCaptureTransport,
) -> Result<u8, CaptureFragmentError> {
    match transport {
        WindowsPacketCaptureTransport::TcpTls => Ok(TCP_NEXT_HEADER),
        WindowsPacketCaptureTransport::UdpQuic => Ok(UDP_NEXT_HEADER),
        WindowsPacketCaptureTransport::Other => {
            Err(CaptureFragmentError::UnsupportedCaptureTransport)
        }
    }
}

fn preflight_fragment(
    classification: &WindowsPacketPolicyClassification,
    envelope: &FragmentEnvelope,
    packet: &[u8],
) -> Result<(), CaptureFragmentError> {
    let source = match classification.source_endpoint().address {
        IpAddr::V6(address) => address,
        IpAddr::V4(_) => return Err(CaptureFragmentError::SourceAddressMismatch),
    };
    let destination = match classification.destination() {
        IpAddr::V6(address) => address,
        IpAddr::V4(_) => return Err(CaptureFragmentError::DestinationAddressMismatch),
    };
    if envelope.key.source != source {
        return Err(CaptureFragmentError::SourceAddressMismatch);
    }
    if envelope.key.destination != destination {
        return Err(CaptureFragmentError::DestinationAddressMismatch);
    }
    if envelope.next_header != expected_next_header(classification.transport())? {
        return Err(CaptureFragmentError::TransportMismatch);
    }
    if envelope.offset == 0 {
        let payload = &packet[IPV6_HEADER_BYTES + FRAGMENT_HEADER_BYTES..];
        verify_ports(classification, payload)?;
    }
    Ok(())
}

fn verify_ports(
    classification: &WindowsPacketPolicyClassification,
    transport_payload: &[u8],
) -> Result<(), CaptureFragmentError> {
    if transport_payload.len() < 4 {
        return Err(CaptureFragmentError::TransportHeaderTooShort);
    }
    let source_port = u16::from_be_bytes([transport_payload[0], transport_payload[1]]);
    let destination_port = u16::from_be_bytes([transport_payload[2], transport_payload[3]]);
    if source_port != classification.source_endpoint().port {
        return Err(CaptureFragmentError::SourcePortMismatch);
    }
    if destination_port != classification.destination_port() {
        return Err(CaptureFragmentError::DestinationPortMismatch);
    }
    Ok(())
}

fn verify_completed_packet(
    classification: &WindowsPacketPolicyClassification,
    packet: &[u8],
) -> Result<(), CaptureFragmentError> {
    if packet.len() < IPV6_HEADER_BYTES + 4 || packet[0] >> 4 != 6 {
        return Err(CaptureFragmentError::CompletedPacketMismatch);
    }
    let declared_payload = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if declared_payload != packet.len() - IPV6_HEADER_BYTES
        || packet[6] != expected_next_header(classification.transport())?
    {
        return Err(CaptureFragmentError::CompletedPacketMismatch);
    }
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).expect("fixed source slice"));
    let destination =
        Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).expect("fixed destination slice"));
    if classification.source_endpoint().address != IpAddr::V6(source)
        || classification.destination() != IpAddr::V6(destination)
    {
        return Err(CaptureFragmentError::CompletedPacketMismatch);
    }
    verify_ports(classification, &packet[IPV6_HEADER_BYTES..])
}

fn observation(
    capture_generation: u64,
    flow_id: u64,
    transport: WindowsPacketCaptureTransport,
    source_port: u16,
    host: &str,
    observed_at_ms: u64,
    expires_at_ms: u64,
) -> WindowsPacketCaptureObservation {
    let source = match transport {
        WindowsPacketCaptureTransport::TcpTls | WindowsPacketCaptureTransport::Other => {
            WindowsPacketHostnameEvidenceSource::TlsClientHelloSni
        }
        WindowsPacketCaptureTransport::UdpQuic => {
            WindowsPacketHostnameEvidenceSource::QuicInitialSni
        }
    };
    WindowsPacketCaptureObservation {
        capture_generation,
        flow_id,
        transport,
        source_address: IpAddr::V6(SOURCE),
        source_port,
        destination: DESTINATION.to_string(),
        destination_port: DESTINATION_PORT,
        observed_at_ms,
        expires_at_ms,
        attribution: WindowsPacketCaptureAttribution::Hostname {
            source,
            host: host.to_owned(),
        },
    }
}

fn openai_observation(flow_id: u64) -> WindowsPacketCaptureObservation {
    observation(
        7,
        flow_id,
        WindowsPacketCaptureTransport::UdpQuic,
        SOURCE_PORT,
        "chatgpt.com",
        1_000,
        5_000,
    )
}

fn transport_packet(observation: &WindowsPacketCaptureObservation, payload: &[u8]) -> Vec<u8> {
    let (next_header, transport_header_len) = match observation.transport {
        WindowsPacketCaptureTransport::TcpTls => (TCP_NEXT_HEADER, 20),
        WindowsPacketCaptureTransport::UdpQuic => (UDP_NEXT_HEADER, 8),
        WindowsPacketCaptureTransport::Other => panic!("test packet requires TCP or UDP"),
    };
    let transport_len = transport_header_len + payload.len();
    let mut packet = vec![0; IPV6_HEADER_BYTES + transport_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(transport_len as u16).to_be_bytes());
    packet[6] = next_header;
    packet[7] = 64;
    let IpAddr::V6(source) = observation.source_address else {
        panic!("test packet requires IPv6 source")
    };
    let destination = observation
        .destination
        .parse::<Ipv6Addr>()
        .expect("test destination must be IPv6");
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    packet[40..42].copy_from_slice(&observation.source_port.to_be_bytes());
    packet[42..44].copy_from_slice(&observation.destination_port.to_be_bytes());
    if observation.transport == WindowsPacketCaptureTransport::UdpQuic {
        packet[44..46].copy_from_slice(&(transport_len as u16).to_be_bytes());
    } else {
        packet[52] = 0x50;
    }
    packet[IPV6_HEADER_BYTES + transport_header_len..].copy_from_slice(payload);
    packet
}

fn fragment(
    packet: &[u8],
    identification: u32,
    offset: usize,
    len: usize,
    more_fragments: bool,
) -> Vec<u8> {
    assert_eq!(offset % 8, 0);
    let payload = &packet[IPV6_HEADER_BYTES + offset..IPV6_HEADER_BYTES + offset + len];
    let mut result = vec![0; IPV6_HEADER_BYTES + FRAGMENT_HEADER_BYTES + len];
    result[..IPV6_HEADER_BYTES].copy_from_slice(&packet[..IPV6_HEADER_BYTES]);
    result[4..6].copy_from_slice(&((FRAGMENT_HEADER_BYTES + len) as u16).to_be_bytes());
    result[6] = IPV6_FRAGMENT_NEXT_HEADER;
    result[40] = packet[6];
    let mut offset_and_flags = ((offset / 8) as u16) << 3;
    if more_fragments {
        offset_and_flags |= 1;
    }
    result[42..44].copy_from_slice(&offset_and_flags.to_be_bytes());
    result[44..48].copy_from_slice(&identification.to_be_bytes());
    result[48..].copy_from_slice(payload);
    result
}

fn fragments(packet: &[u8], identification: u32) -> (Vec<u8>, Vec<u8>) {
    let transport_len = packet.len() - IPV6_HEADER_BYTES;
    let first_len = 256;
    (
        fragment(packet, identification, 0, first_len, true),
        fragment(
            packet,
            identification,
            first_len,
            transport_len - first_len,
            false,
        ),
    )
}

fn completed(outcome: CaptureFragmentOutcome) -> (WindowsPacketPolicyClassification, Vec<u8>) {
    let CaptureFragmentOutcome::Complete {
        classification,
        packet,
    } = outcome
    else {
        panic!("expected completed capture-fragment outcome")
    };
    (classification, packet)
}

#[test]
fn capture_bound_fragments_normalize_exactly_in_both_orders() {
    let tables = bundled_policy_v1();
    let observation = openai_observation(41);
    let packet = transport_packet(&observation, &vec![0x51; 512]);
    let (first, last) = fragments(&packet, 0x1020_3040);

    let mut in_order = CaptureFragmentHarness::default();
    assert!(matches!(
        in_order.ingest(&observation, 1_200, &tables, &first),
        Ok(CaptureFragmentOutcome::Pending { .. })
    ));
    let (classification, normalized) = completed(
        in_order
            .ingest(&observation, 1_300, &tables, &last)
            .unwrap(),
    );
    assert_eq!(normalized, packet);
    assert_eq!(classification.policy().route_class, RouteClass::GeoExit);
    assert_eq!(classification.policy().service_group, ServiceGroup::Openai);
    assert_eq!(in_order.active_assemblies(), 0);

    let mut out_of_order = CaptureFragmentHarness::default();
    assert!(matches!(
        out_of_order.ingest(&observation, 1_200, &tables, &last),
        Ok(CaptureFragmentOutcome::Pending { .. })
    ));
    let (_, normalized) = completed(
        out_of_order
            .ingest(&observation, 1_300, &tables, &first)
            .unwrap(),
    );
    assert_eq!(normalized, packet);
    assert_eq!(out_of_order.active_assemblies(), 0);
}

#[test]
fn direct_passthrough_preserves_packet_and_existing_state() {
    let tables = bundled_policy_v1();
    let observation = openai_observation(42);
    let packet = transport_packet(&observation, &vec![0x52; 512]);
    let (first, _) = fragments(&packet, 1);
    let mut harness = CaptureFragmentHarness::default();
    harness
        .ingest(&observation, 1_200, &tables, &first)
        .unwrap();

    let mut passthrough = observation.clone();
    passthrough.flow_id = 43;
    passthrough.source_port = 0;
    let opaque_packet = vec![0xde, 0xad, 0xbe, 0xef];
    assert_eq!(
        harness.ingest(&passthrough, 1_200, &tables, &opaque_packet),
        Ok(CaptureFragmentOutcome::DirectPassthrough {
            reason: WindowsPacketCapturePassthroughReason::InvalidSourcePort,
            packet: opaque_packet,
        })
    );
    assert_eq!(harness.active_assemblies(), 1);
}

#[test]
fn malformed_or_tuple_mismatched_input_never_allocates() {
    let tables = bundled_policy_v1();
    let observation = openai_observation(44);
    let packet = transport_packet(&observation, &vec![0x53; 512]);
    let (first, _) = fragments(&packet, 2);

    let cases = [
        (
            vec![0u8; 8],
            CaptureFragmentError::Reassembly(ReassemblyError::PacketTooShort),
        ),
        (
            {
                let mut value = first.clone();
                value[23] ^= 1;
                value
            },
            CaptureFragmentError::SourceAddressMismatch,
        ),
        (
            {
                let mut value = first.clone();
                value[39] ^= 1;
                value
            },
            CaptureFragmentError::DestinationAddressMismatch,
        ),
        (
            {
                let mut value = first.clone();
                value[40] = TCP_NEXT_HEADER;
                value
            },
            CaptureFragmentError::TransportMismatch,
        ),
        (
            {
                let mut value = first.clone();
                value[48..50].copy_from_slice(&(SOURCE_PORT + 1).to_be_bytes());
                value
            },
            CaptureFragmentError::SourcePortMismatch,
        ),
        (
            {
                let mut value = first.clone();
                value[50..52].copy_from_slice(&(DESTINATION_PORT + 1).to_be_bytes());
                value
            },
            CaptureFragmentError::DestinationPortMismatch,
        ),
    ];

    for (packet, expected) in cases {
        let mut harness = CaptureFragmentHarness::default();
        assert_eq!(
            harness.ingest(&observation, 1_200, &tables, &packet),
            Err(expected)
        );
        assert_eq!(harness.active_assemblies(), 0);
    }
}

#[test]
fn same_identification_cannot_cross_capture_flow_or_evict_the_owner() {
    let tables = bundled_policy_v1();
    let owner = openai_observation(45);
    let contender = openai_observation(46);
    let packet = transport_packet(&owner, &vec![0x54; 512]);
    let (first, last) = fragments(&packet, 3);
    let mut harness = CaptureFragmentHarness::default();

    harness.ingest(&owner, 1_200, &tables, &first).unwrap();
    assert_eq!(
        harness.ingest(&contender, 1_250, &tables, &last),
        Err(CaptureFragmentError::CaptureIdentityConflict)
    );
    assert_eq!(harness.active_assemblies(), 1);
    let (_, normalized) = completed(harness.ingest(&owner, 1_300, &tables, &last).unwrap());
    assert_eq!(normalized, packet);
}

#[test]
fn same_identification_cannot_cross_capture_generation_or_evict_the_owner() {
    let tables = bundled_policy_v1();
    let owner = openai_observation(46);
    let mut contender = owner.clone();
    contender.capture_generation += 1;
    let packet = transport_packet(&owner, &vec![0x54; 512]);
    let (first, last) = fragments(&packet, 4);
    let mut harness = CaptureFragmentHarness::default();

    harness.ingest(&owner, 1_200, &tables, &first).unwrap();
    assert_eq!(
        harness.ingest(&contender, 1_250, &tables, &last),
        Err(CaptureFragmentError::CaptureIdentityConflict)
    );
    assert_eq!(harness.active_assemblies(), 1);
    let (_, normalized) = completed(harness.ingest(&owner, 1_300, &tables, &last).unwrap());
    assert_eq!(normalized, packet);
}

#[test]
fn assembly_capacity_and_errors_are_exact_owner_scoped() {
    let tables = bundled_policy_v1();
    let observation = openai_observation(47);
    let packet = transport_packet(&observation, &vec![0x55; 512]);
    let (first_one, last_one) = fragments(&packet, 4);
    let (first_two, last_two) = fragments(&packet, 5);
    let (first_three, _) = fragments(&packet, 6);
    let mut harness = CaptureFragmentHarness::default();

    harness
        .ingest(&observation, 1_200, &tables, &first_one)
        .unwrap();
    harness
        .ingest(&observation, 1_200, &tables, &first_two)
        .unwrap();
    assert_eq!(
        harness.ingest(&observation, 1_200, &tables, &first_three),
        Err(CaptureFragmentError::AssemblyCapacityExceeded)
    );
    assert_eq!(harness.active_assemblies(), 2);

    let overlap = fragment(&packet, 4, 128, 256, true);
    assert_eq!(
        harness.ingest(&observation, 1_250, &tables, &overlap),
        Err(CaptureFragmentError::Reassembly(
            ReassemblyError::OverlappingFragment
        ))
    );
    assert_eq!(harness.active_assemblies(), 1);
    let (_, normalized) = completed(
        harness
            .ingest(&observation, 1_300, &tables, &last_two)
            .unwrap(),
    );
    assert_eq!(normalized, packet);
    assert_eq!(harness.active_assemblies(), 0);

    let mut retry = CaptureFragmentHarness::default();
    retry
        .ingest(&observation, 1_200, &tables, &first_one)
        .unwrap();
    let (_, normalized) = completed(
        retry
            .ingest(&observation, 1_300, &tables, &last_one)
            .unwrap(),
    );
    assert_eq!(normalized, packet);
}

#[test]
fn timeout_uses_the_capture_evidence_deadline_and_is_exact() {
    let tables = bundled_policy_v1();
    let first_observation = openai_observation(48);
    let second_observation = observation(
        7,
        49,
        WindowsPacketCaptureTransport::UdpQuic,
        SOURCE_PORT,
        "chatgpt.com",
        3_000,
        8_000,
    );
    let first_packet = transport_packet(&first_observation, &vec![0x56; 512]);
    let second_packet = transport_packet(&second_observation, &vec![0x57; 512]);
    let (first_fragment, _) = fragments(&first_packet, 7);
    let (second_fragment, _) = fragments(&second_packet, 8);
    let mut harness = CaptureFragmentHarness::default();

    harness
        .ingest(&first_observation, 1_200, &tables, &first_fragment)
        .unwrap();
    harness
        .ingest(&second_observation, 3_200, &tables, &second_fragment)
        .unwrap();
    assert_eq!(harness.active_assemblies(), 2);
    assert_eq!(harness.expire(5_000), 1);
    assert_eq!(harness.active_assemblies(), 1);
    assert_eq!(harness.expire(8_000), 1);
    assert_eq!(harness.active_assemblies(), 0);
}

#[test]
fn atomic_fragment_bypasses_matching_and_full_capture_state() {
    let tables = bundled_policy_v1();
    let observation = openai_observation(50);
    let packet = transport_packet(&observation, &vec![0x58; 512]);
    let transport_len = packet.len() - IPV6_HEADER_BYTES;
    let (first_one, last_one) = fragments(&packet, 9);
    let (first_two, _) = fragments(&packet, 10);
    let atomic = fragment(&packet, 9, 0, transport_len, false);
    let mut harness = CaptureFragmentHarness::default();

    harness
        .ingest(&observation, 1_200, &tables, &first_one)
        .unwrap();
    harness
        .ingest(&observation, 1_200, &tables, &first_two)
        .unwrap();
    let (_, normalized) = completed(
        harness
            .ingest(&observation, 4_999, &tables, &atomic)
            .unwrap(),
    );
    assert_eq!(normalized, packet);
    assert_eq!(harness.active_assemblies(), 2);
    let (_, normalized) = completed(
        harness
            .ingest(&observation, 1_300, &tables, &last_one)
            .unwrap(),
    );
    assert_eq!(normalized, packet);
    assert_eq!(harness.active_assemblies(), 1);
}

#[test]
fn discord_capture_stays_local_bypass_after_normalization() {
    let tables = bundled_policy_v1();
    let observation = observation(
        8,
        51,
        WindowsPacketCaptureTransport::TcpTls,
        SOURCE_PORT,
        "gateway.discord.gg",
        1_000,
        5_000,
    );
    let packet = transport_packet(&observation, &vec![0x59; 512]);
    let (first, last) = fragments(&packet, 11);
    let mut harness = CaptureFragmentHarness::default();

    harness
        .ingest(&observation, 1_200, &tables, &first)
        .unwrap();
    let (classification, normalized) =
        completed(harness.ingest(&observation, 1_300, &tables, &last).unwrap());
    assert_eq!(normalized, packet);
    assert_eq!(classification.policy().route_class, RouteClass::LocalBypass);
    assert_eq!(classification.policy().service_group, ServiceGroup::Discord);
}
