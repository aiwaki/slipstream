use slipstream_userspace_stack_evaluation::raw_packet_udp_v1::{
    RawPacketUdpErrorCode, RawPacketUdpStackV1, MAX_RESPONSE_PAYLOAD_BYTES,
};
use std::net::Ipv4Addr;

const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 20);
const DESTINATION: Ipv4Addr = Ipv4Addr::new(1, 0, 0, 2);
const SOURCE_PORT: u16 = 40_001;
const DESTINATION_PORT: u16 = 41_723;
const REQUEST: &[u8] = b"slipstream-wintun-request-v1";
const RESPONSE: &[u8] = b"slipstream-wintun-response-v1";

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let (chunks, remainder) = bytes.as_chunks::<2>();
    for chunk in chunks {
        sum += u32::from(u16::from_be_bytes(*chunk));
    }
    if let Some(byte) = remainder.first() {
        sum += u32::from(*byte) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4_udp_packet(payload: &[u8]) -> Vec<u8> {
    let udp_length = 8 + payload.len();
    let total_length = 20 + udp_length;
    let mut packet = vec![0; total_length];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&SOURCE.octets());
    packet[16..20].copy_from_slice(&DESTINATION.octets());
    let ipv4_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ipv4_checksum.to_be_bytes());
    packet[20..22].copy_from_slice(&SOURCE_PORT.to_be_bytes());
    packet[22..24].copy_from_slice(&DESTINATION_PORT.to_be_bytes());
    packet[24..26].copy_from_slice(&(udp_length as u16).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    let mut pseudo_header = Vec::with_capacity(12 + udp_length);
    pseudo_header.extend_from_slice(&SOURCE.octets());
    pseudo_header.extend_from_slice(&DESTINATION.octets());
    pseudo_header.extend_from_slice(&[0, 17]);
    pseudo_header.extend_from_slice(&(udp_length as u16).to_be_bytes());
    pseudo_header.extend_from_slice(&packet[20..]);
    packet[26..28].copy_from_slice(&internet_checksum(&pseudo_header).to_be_bytes());
    packet
}

fn assert_response(packet: &[u8]) {
    assert_eq!(&packet[12..16], &DESTINATION.octets());
    assert_eq!(&packet[16..20], &SOURCE.octets());
    assert_eq!(
        u16::from_be_bytes([packet[20], packet[21]]),
        DESTINATION_PORT
    );
    assert_eq!(u16::from_be_bytes([packet[22], packet[23]]), SOURCE_PORT);
    assert_eq!(&packet[28..], RESPONSE);
    assert_eq!(internet_checksum(&packet[..20]), 0);
    let udp_length = usize::from(u16::from_be_bytes([packet[24], packet[25]]));
    let mut pseudo_header = Vec::with_capacity(12 + udp_length);
    pseudo_header.extend_from_slice(&DESTINATION.octets());
    pseudo_header.extend_from_slice(&SOURCE.octets());
    pseudo_header.extend_from_slice(&[0, 17]);
    pseudo_header.extend_from_slice(&(udp_length as u16).to_be_bytes());
    pseudo_header.extend_from_slice(&packet[20..]);
    assert_eq!(internet_checksum(&pseudo_header), 0);
}

#[test]
fn raw_ipv4_udp_request_round_trips_through_the_selected_stack() {
    let request = ipv4_udp_packet(REQUEST);
    let mut stack = RawPacketUdpStackV1::new_ipv4(DESTINATION, 0, DESTINATION_PORT, 7)
        .expect("construct bounded raw packet stack");
    let exchange = stack
        .exchange_ipv4(&request, RESPONSE)
        .expect("exchange raw IPv4 UDP packet");
    assert_eq!(exchange.request_payload, REQUEST);
    assert_response(&exchange.response_packet);
}

#[test]
fn raw_packet_exchange_is_deterministic_for_the_same_seed() {
    let request = ipv4_udp_packet(REQUEST);
    let exchange = || {
        RawPacketUdpStackV1::new_ipv4(DESTINATION, 0, DESTINATION_PORT, 19)
            .expect("construct deterministic stack")
            .exchange_ipv4(&request, RESPONSE)
            .expect("exchange deterministic packet")
    };
    assert_eq!(exchange(), exchange());
}

#[test]
fn invalid_udp_checksum_is_rejected_without_a_response() {
    let mut request = ipv4_udp_packet(REQUEST);
    let last = request.len() - 1;
    request[last] ^= 0xff;
    let error = RawPacketUdpStackV1::new_ipv4(DESTINATION, 0, DESTINATION_PORT, 23)
        .expect("construct checksum stack")
        .exchange_ipv4(&request, RESPONSE)
        .expect_err("invalid checksum must not reach the UDP socket");
    assert_eq!(error.code, RawPacketUdpErrorCode::RequestRejected);
}

#[test]
fn response_must_fit_one_fixed_mtu_packet() {
    let request = ipv4_udp_packet(REQUEST);
    let error = RawPacketUdpStackV1::new_ipv4(DESTINATION, 0, DESTINATION_PORT, 29)
        .expect("construct bounded stack")
        .exchange_ipv4(&request, &vec![0; MAX_RESPONSE_PAYLOAD_BYTES + 1])
        .expect_err("oversized response must be rejected before stack mutation");
    assert_eq!(error.code, RawPacketUdpErrorCode::ResponseTooLarge);
}

#[test]
fn invalid_stack_configuration_fails_closed() {
    let invalid_prefix = match RawPacketUdpStackV1::new_ipv4(DESTINATION, 33, DESTINATION_PORT, 31)
    {
        Ok(_) => panic!("an invalid IPv4 prefix must be rejected"),
        Err(error) => error,
    };
    assert_eq!(invalid_prefix.code, RawPacketUdpErrorCode::InvalidConfig);

    let invalid_port = match RawPacketUdpStackV1::new_ipv4(DESTINATION, 32, 0, 31) {
        Ok(_) => panic!("UDP port zero must be rejected"),
        Err(error) => error,
    };
    assert_eq!(invalid_port.code, RawPacketUdpErrorCode::InvalidConfig);
}
