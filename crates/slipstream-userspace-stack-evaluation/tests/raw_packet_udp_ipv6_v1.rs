use slipstream_userspace_stack_evaluation::raw_packet_udp_ipv6_v1::{
    RawPacketUdpIpv6StackV1, MAX_RESPONSE_PAYLOAD_BYTES,
};
use slipstream_userspace_stack_evaluation::raw_packet_udp_v1::RawPacketUdpErrorCode;
use std::net::Ipv6Addr;

const SOURCE: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 20);
const DESTINATION: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
const SOURCE_PORT: u16 = 40_001;
const DESTINATION_PORT: u16 = 41_723;
const REQUEST: &[u8] = b"slipstream-wintun-ipv6-request-v1";
const RESPONSE: &[u8] = b"slipstream-wintun-ipv6-response-v1";

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(byte) = chunks.remainder().first() {
        sum += u32::from(*byte) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv6_udp_packet(payload: &[u8]) -> Vec<u8> {
    let udp_length = 8 + payload.len();
    let mut packet = vec![0; 40 + udp_length];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(udp_length as u16).to_be_bytes());
    packet[6] = 17;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&SOURCE.octets());
    packet[24..40].copy_from_slice(&DESTINATION.octets());
    packet[40..42].copy_from_slice(&SOURCE_PORT.to_be_bytes());
    packet[42..44].copy_from_slice(&DESTINATION_PORT.to_be_bytes());
    packet[44..46].copy_from_slice(&(udp_length as u16).to_be_bytes());
    packet[48..].copy_from_slice(payload);
    let mut pseudo_header = Vec::with_capacity(40 + udp_length);
    pseudo_header.extend_from_slice(&SOURCE.octets());
    pseudo_header.extend_from_slice(&DESTINATION.octets());
    pseudo_header.extend_from_slice(&(udp_length as u32).to_be_bytes());
    pseudo_header.extend_from_slice(&[0, 0, 0, 17]);
    pseudo_header.extend_from_slice(&packet[40..]);
    packet[46..48].copy_from_slice(&internet_checksum(&pseudo_header).to_be_bytes());
    packet
}

fn assert_response(packet: &[u8]) {
    assert_eq!(&packet[8..24], &DESTINATION.octets());
    assert_eq!(&packet[24..40], &SOURCE.octets());
    assert_eq!(
        u16::from_be_bytes([packet[40], packet[41]]),
        DESTINATION_PORT
    );
    assert_eq!(u16::from_be_bytes([packet[42], packet[43]]), SOURCE_PORT);
    assert_eq!(&packet[48..], RESPONSE);
    let udp_length = usize::from(u16::from_be_bytes([packet[44], packet[45]]));
    let mut pseudo_header = Vec::with_capacity(40 + udp_length);
    pseudo_header.extend_from_slice(&DESTINATION.octets());
    pseudo_header.extend_from_slice(&SOURCE.octets());
    pseudo_header.extend_from_slice(&(udp_length as u32).to_be_bytes());
    pseudo_header.extend_from_slice(&[0, 0, 0, 17]);
    pseudo_header.extend_from_slice(&packet[40..]);
    assert_eq!(internet_checksum(&pseudo_header), 0);
}

#[test]
fn raw_ipv6_udp_request_round_trips_through_the_selected_stack() {
    let request = ipv6_udp_packet(REQUEST);
    let mut stack = RawPacketUdpIpv6StackV1::new_ipv6(DESTINATION, 0, DESTINATION_PORT, 7)
        .expect("construct bounded IPv6 raw packet stack");
    let exchange = stack
        .exchange_ipv6(&request, RESPONSE)
        .expect("exchange raw IPv6 UDP packet");
    assert_eq!(exchange.request_payload, REQUEST);
    assert_response(&exchange.response_packet);
}

#[test]
fn raw_ipv6_packet_exchange_is_deterministic_for_the_same_seed() {
    let request = ipv6_udp_packet(REQUEST);
    let exchange = || {
        RawPacketUdpIpv6StackV1::new_ipv6(DESTINATION, 0, DESTINATION_PORT, 19)
            .expect("construct deterministic IPv6 stack")
            .exchange_ipv6(&request, RESPONSE)
            .expect("exchange deterministic IPv6 packet")
    };
    assert_eq!(exchange(), exchange());
}

#[test]
fn invalid_ipv6_udp_checksum_is_rejected_without_a_response() {
    let mut request = ipv6_udp_packet(REQUEST);
    let last = request.len() - 1;
    request[last] ^= 0xff;
    let error = RawPacketUdpIpv6StackV1::new_ipv6(DESTINATION, 0, DESTINATION_PORT, 23)
        .expect("construct IPv6 checksum stack")
        .exchange_ipv6(&request, RESPONSE)
        .expect_err("invalid IPv6 checksum must not reach the UDP socket");
    assert_eq!(error.code, RawPacketUdpErrorCode::RequestRejected);
}

#[test]
fn ipv6_response_must_fit_one_fixed_mtu_packet() {
    let request = ipv6_udp_packet(REQUEST);
    let error = RawPacketUdpIpv6StackV1::new_ipv6(DESTINATION, 0, DESTINATION_PORT, 29)
        .expect("construct bounded IPv6 stack")
        .exchange_ipv6(&request, &vec![0; MAX_RESPONSE_PAYLOAD_BYTES + 1])
        .expect_err("oversized IPv6 response must be rejected before stack mutation");
    assert_eq!(error.code, RawPacketUdpErrorCode::ResponseTooLarge);
}

#[test]
fn invalid_ipv6_stack_configuration_fails_closed() {
    let invalid_prefix =
        match RawPacketUdpIpv6StackV1::new_ipv6(DESTINATION, 129, DESTINATION_PORT, 31) {
            Ok(_) => panic!("an invalid IPv6 prefix must be rejected"),
            Err(config_error) => config_error,
        };
    assert_eq!(invalid_prefix.code, RawPacketUdpErrorCode::InvalidConfig);

    let invalid_port = match RawPacketUdpIpv6StackV1::new_ipv6(DESTINATION, 128, 0, 31) {
        Ok(_) => panic!("UDP port zero must be rejected"),
        Err(config_error) => config_error,
    };
    assert_eq!(invalid_port.code, RawPacketUdpErrorCode::InvalidConfig);
}
