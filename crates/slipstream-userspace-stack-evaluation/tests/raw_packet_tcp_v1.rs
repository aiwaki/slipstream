use slipstream_userspace_stack_evaluation::raw_packet_tcp_v1::{
    RawPacketTcpErrorCode, RawPacketTcpPhase, RawPacketTcpStackV1, MAX_RESPONSE_PAYLOAD_BYTES,
};
use std::net::Ipv4Addr;

const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 9);
const CLIENT_PORT: u16 = 40_001;
const SERVER_PORT: u16 = 443;
const CLIENT_SEQUENCE: u32 = 0x1234_5678;
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;
const IPV4_HEADER_BYTES: usize = 20;
const TCP_HEADER_BYTES: usize = 20;

#[derive(Debug)]
struct ParsedTcpPacket<'a> {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgment: u32,
    flags: u8,
    payload: &'a [u8],
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum = sum.wrapping_add(u32::from(word));
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }
    !(sum as u16)
}

#[allow(clippy::too_many_arguments)]
fn ipv4_tcp_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgment: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total_length = IPV4_HEADER_BYTES + TCP_HEADER_BYTES + payload.len();
    let mut packet = vec![0u8; total_length];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&0x534c_u16.to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let ip_checksum = internet_checksum(&packet[..IPV4_HEADER_BYTES]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let tcp = &mut packet[IPV4_HEADER_BYTES..];
    tcp[0..2].copy_from_slice(&source_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&sequence.to_be_bytes());
    tcp[8..12].copy_from_slice(&acknowledgment.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&4096_u16.to_be_bytes());
    tcp[TCP_HEADER_BYTES..].copy_from_slice(payload);

    let tcp_length = tcp.len();
    let mut pseudo_header = Vec::with_capacity(12 + tcp_length);
    pseudo_header.extend_from_slice(&source.octets());
    pseudo_header.extend_from_slice(&destination.octets());
    pseudo_header.push(0);
    pseudo_header.push(6);
    pseudo_header.extend_from_slice(&(tcp_length as u16).to_be_bytes());
    pseudo_header.extend_from_slice(tcp);
    let tcp_checksum = internet_checksum(&pseudo_header);
    packet[IPV4_HEADER_BYTES + 16..IPV4_HEADER_BYTES + 18]
        .copy_from_slice(&tcp_checksum.to_be_bytes());
    packet
}

fn parse_tcp_packet(packet: &[u8]) -> ParsedTcpPacket<'_> {
    assert!(packet.len() >= IPV4_HEADER_BYTES + TCP_HEADER_BYTES);
    assert_eq!(packet[0] >> 4, 4);
    let ip_header_length = usize::from(packet[0] & 0x0f) * 4;
    assert!(ip_header_length >= IPV4_HEADER_BYTES);
    assert_eq!(
        usize::from(u16::from_be_bytes([packet[2], packet[3]])),
        packet.len()
    );
    assert_eq!(internet_checksum(&packet[..ip_header_length]), 0);
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let tcp = &packet[ip_header_length..];
    let tcp_header_length = usize::from(tcp[12] >> 4) * 4;
    assert!(tcp_header_length >= TCP_HEADER_BYTES);
    let mut pseudo_header = Vec::with_capacity(12 + tcp.len());
    pseudo_header.extend_from_slice(&source.octets());
    pseudo_header.extend_from_slice(&destination.octets());
    pseudo_header.push(0);
    pseudo_header.push(6);
    pseudo_header.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    pseudo_header.extend_from_slice(tcp);
    assert_eq!(internet_checksum(&pseudo_header), 0);
    ParsedTcpPacket {
        source,
        destination,
        source_port: u16::from_be_bytes([tcp[0], tcp[1]]),
        destination_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        sequence: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        acknowledgment: u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
        flags: tcp[13],
        payload: &tcp[tcp_header_length..],
    }
}

fn establish_stack(seed: u64) -> (RawPacketTcpStackV1, u32) {
    let mut stack = RawPacketTcpStackV1::new_ipv4(SERVER, 0, SERVER_PORT, seed).unwrap();
    let syn = ipv4_tcp_packet(
        CLIENT,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        CLIENT_SEQUENCE,
        0,
        TCP_SYN,
        &[],
    );
    let syn_ack = stack.accept_syn_ipv4(&syn).unwrap();
    let parsed = parse_tcp_packet(&syn_ack);
    assert_eq!(parsed.source, SERVER);
    assert_eq!(parsed.destination, CLIENT);
    assert_eq!(parsed.source_port, SERVER_PORT);
    assert_eq!(parsed.destination_port, CLIENT_PORT);
    assert_eq!(parsed.acknowledgment, CLIENT_SEQUENCE.wrapping_add(1));
    assert_eq!(parsed.flags & (TCP_SYN | TCP_ACK), TCP_SYN | TCP_ACK);
    assert_eq!(parsed.flags & (TCP_FIN | TCP_RST), 0);
    assert_eq!(stack.phase(), RawPacketTcpPhase::SynAckEmitted);

    let acknowledgment = ipv4_tcp_packet(
        CLIENT,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        CLIENT_SEQUENCE.wrapping_add(1),
        parsed.sequence.wrapping_add(1),
        TCP_ACK,
        &[],
    );
    stack.accept_ack_ipv4(&acknowledgment).unwrap();
    assert_eq!(stack.phase(), RawPacketTcpPhase::Established);
    (stack, parsed.sequence)
}

#[test]
fn raw_ipv4_tcp_handshake_and_payload_cross_the_selected_stack() {
    let (mut stack, server_sequence) = establish_stack(0x534c_1001);
    let request = b"selected-stack-tcp-request";
    let response = b"selected-stack-tcp-response";
    let request_packet = ipv4_tcp_packet(
        CLIENT,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        CLIENT_SEQUENCE.wrapping_add(1),
        server_sequence.wrapping_add(1),
        TCP_PSH | TCP_ACK,
        request,
    );
    let exchange = stack
        .exchange_payload_ipv4(&request_packet, response)
        .unwrap();
    assert_eq!(exchange.request_payload, request);
    assert!(!exchange.response_packets.is_empty());

    let mut response_seen = false;
    for packet in &exchange.response_packets {
        let parsed = parse_tcp_packet(packet);
        assert_eq!(parsed.source, SERVER);
        assert_eq!(parsed.destination, CLIENT);
        assert_eq!(parsed.source_port, SERVER_PORT);
        assert_eq!(parsed.destination_port, CLIENT_PORT);
        assert_eq!(
            parsed.acknowledgment,
            CLIENT_SEQUENCE
                .wrapping_add(1)
                .wrapping_add(request.len() as u32)
        );
        if parsed.payload == response {
            assert_eq!(parsed.flags & TCP_ACK, TCP_ACK);
            response_seen = true;
        }
    }
    assert!(
        response_seen,
        "selected stack emitted no TCP response payload"
    );
}

#[test]
fn handshake_output_is_deterministic_for_the_same_seed() {
    let syn = ipv4_tcp_packet(
        CLIENT,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        CLIENT_SEQUENCE,
        0,
        TCP_SYN,
        &[],
    );
    let mut left = RawPacketTcpStackV1::new_ipv4(SERVER, 0, SERVER_PORT, 77).unwrap();
    let mut right = RawPacketTcpStackV1::new_ipv4(SERVER, 0, SERVER_PORT, 77).unwrap();
    assert_eq!(
        left.accept_syn_ipv4(&syn).unwrap(),
        right.accept_syn_ipv4(&syn).unwrap()
    );
}

#[test]
fn invalid_syn_checksum_is_rejected_without_advancing_phase() {
    let mut stack = RawPacketTcpStackV1::new_ipv4(SERVER, 0, SERVER_PORT, 1).unwrap();
    let mut syn = ipv4_tcp_packet(
        CLIENT,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        CLIENT_SEQUENCE,
        0,
        TCP_SYN,
        &[],
    );
    syn[IPV4_HEADER_BYTES + 16] ^= 1;
    let error = stack.accept_syn_ipv4(&syn).unwrap_err();
    assert_eq!(error.code, RawPacketTcpErrorCode::SegmentRejected);
    assert_eq!(stack.phase(), RawPacketTcpPhase::Listening);
}

#[test]
fn handshake_steps_fail_closed_when_called_out_of_order() {
    let mut stack = RawPacketTcpStackV1::new_ipv4(SERVER, 0, SERVER_PORT, 1).unwrap();
    let acknowledgment = ipv4_tcp_packet(
        CLIENT,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        CLIENT_SEQUENCE.wrapping_add(1),
        1,
        TCP_ACK,
        &[],
    );
    let error = stack.accept_ack_ipv4(&acknowledgment).unwrap_err();
    assert_eq!(error.code, RawPacketTcpErrorCode::UnexpectedPhase);
    assert_eq!(stack.phase(), RawPacketTcpPhase::Listening);
}

#[test]
fn response_must_be_nonempty_and_fit_one_fixed_mtu_segment() {
    let (mut stack, server_sequence) = establish_stack(0x534c_1002);
    let request_packet = ipv4_tcp_packet(
        CLIENT,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        CLIENT_SEQUENCE.wrapping_add(1),
        server_sequence.wrapping_add(1),
        TCP_PSH | TCP_ACK,
        b"request",
    );
    let error = stack
        .exchange_payload_ipv4(&request_packet, &[])
        .unwrap_err();
    assert_eq!(error.code, RawPacketTcpErrorCode::ResponseInvalid);

    let oversized = vec![0; MAX_RESPONSE_PAYLOAD_BYTES + 1];
    let error = stack
        .exchange_payload_ipv4(&request_packet, &oversized)
        .unwrap_err();
    assert_eq!(error.code, RawPacketTcpErrorCode::ResponseInvalid);
}
