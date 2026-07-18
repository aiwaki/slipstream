//! Version 1 of the pure WFP redirect-context and socket-handoff contract.
//!
//! This module parses data already supplied by a future Windows Filtering
//! Platform adapter. It does not open sockets, register callouts, add filters,
//! or inspect or mutate DNS, proxy, PAC, VPN, or other system state.

use crate::direct_connector::WindowsDirectConnectorEndpoint;
use crate::direct_ingress::{
    prepare_windows_direct_ingress, WindowsDirectIngressPlan, WindowsDirectIngressRequest,
};
use crate::service_lifecycle::WindowsServiceIdentity;
use serde::{Deserialize, Serialize};
use slipstream_core::routing_policy::RoutingPolicyTables;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const WINDOWS_WFP_CAPTURE_CONTRACT_VERSION: u32 = 1;
pub const WINDOWS_WFP_REDIRECT_CONTEXT_VERSION: u16 = 1;
pub const WINDOWS_WFP_REDIRECT_CONTEXT_LENGTH: usize = 128;
pub const MAX_WINDOWS_WFP_REDIRECT_RECORDS_BYTES: usize = 16 * 1024;

const WINDOWS_WFP_REDIRECT_CONTEXT_MAGIC: &[u8; 8] = b"SLIPWFP\0";
const WINDOWS_WFP_TCP_PROTOCOL: u8 = 6;
const IPV4_FAMILY: u8 = 4;
const IPV6_FAMILY: u8 = 6;
const MAGIC_OFFSET: usize = 0;
const VERSION_OFFSET: usize = 8;
const HEADER_LENGTH_OFFSET: usize = 10;
const TOTAL_LENGTH_OFFSET: usize = 12;
const SERVICE_GENERATION_OFFSET: usize = 16;
const TARGET_PID_OFFSET: usize = 24;
const PROTOCOL_OFFSET: usize = 28;
const FAMILY_OFFSET: usize = 29;
const FLAGS_OFFSET: usize = 30;
const ORIGINAL_PORT_OFFSET: usize = 32;
const ORIGINAL_LOCAL_PORT_OFFSET: usize = 34;
const ORIGINAL_ADDRESS_OFFSET: usize = 36;
const ORIGINAL_LOCAL_ADDRESS_OFFSET: usize = 52;
const CAPTURE_INSTANCE_OFFSET: usize = 68;
const EXECUTABLE_SHA256_OFFSET: usize = 84;
const RESERVED_OFFSET: usize = 116;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsWfpCaptureIdentity {
    pub service: WindowsServiceIdentity,
    pub target_pid: u32,
    pub capture_instance_id: String,
    pub listeners: Vec<WindowsDirectConnectorEndpoint>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsWfpCaptureErrorCode {
    InvalidServiceIdentity,
    InvalidServiceGeneration,
    InvalidTargetPid,
    InvalidCaptureInstance,
    InvalidExecutableHash,
    InvalidListenerSet,
    InvalidConnectionId,
    EndpointNotCanonical,
    InvalidPort,
    ListenerNotLoopback,
    ListenerMismatch,
    ListenerFamilyMismatch,
    InvalidContextLength,
    InvalidContextMagic,
    UnsupportedContextVersion,
    InvalidHeaderLength,
    InvalidTotalLength,
    InvalidProtocol,
    InvalidAddressFamily,
    UnsupportedFlags,
    InvalidOriginalPort,
    InvalidAddressEncoding,
    UnsafeOriginalDestination,
    ReservedNotZero,
    StaleServiceGeneration,
    StaleTargetPid,
    StaleCaptureInstance,
    StaleExecutableHash,
    MissingRedirectRecords,
    RedirectRecordsTooLarge,
    InvalidIngressAdmission,
    AdmissionIdentityMismatch,
    AdmissionEndpointMismatch,
}

impl WindowsWfpCaptureErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidServiceIdentity => "invalid_service_identity",
            Self::InvalidServiceGeneration => "invalid_service_generation",
            Self::InvalidTargetPid => "invalid_target_pid",
            Self::InvalidCaptureInstance => "invalid_capture_instance",
            Self::InvalidExecutableHash => "invalid_executable_hash",
            Self::InvalidListenerSet => "invalid_listener_set",
            Self::InvalidConnectionId => "invalid_connection_id",
            Self::EndpointNotCanonical => "endpoint_not_canonical",
            Self::InvalidPort => "invalid_port",
            Self::ListenerNotLoopback => "listener_not_loopback",
            Self::ListenerMismatch => "listener_mismatch",
            Self::ListenerFamilyMismatch => "listener_family_mismatch",
            Self::InvalidContextLength => "invalid_context_length",
            Self::InvalidContextMagic => "invalid_context_magic",
            Self::UnsupportedContextVersion => "unsupported_context_version",
            Self::InvalidHeaderLength => "invalid_header_length",
            Self::InvalidTotalLength => "invalid_total_length",
            Self::InvalidProtocol => "invalid_protocol",
            Self::InvalidAddressFamily => "invalid_address_family",
            Self::UnsupportedFlags => "unsupported_flags",
            Self::InvalidOriginalPort => "invalid_original_port",
            Self::InvalidAddressEncoding => "invalid_address_encoding",
            Self::UnsafeOriginalDestination => "unsafe_original_destination",
            Self::ReservedNotZero => "reserved_not_zero",
            Self::StaleServiceGeneration => "stale_service_generation",
            Self::StaleTargetPid => "stale_target_pid",
            Self::StaleCaptureInstance => "stale_capture_instance",
            Self::StaleExecutableHash => "stale_executable_hash",
            Self::MissingRedirectRecords => "missing_redirect_records",
            Self::RedirectRecordsTooLarge => "redirect_records_too_large",
            Self::InvalidIngressAdmission => "invalid_ingress_admission",
            Self::AdmissionIdentityMismatch => "admission_identity_mismatch",
            Self::AdmissionEndpointMismatch => "admission_endpoint_mismatch",
        }
    }
}

impl fmt::Display for WindowsWfpCaptureErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for WindowsWfpCaptureErrorCode {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsWfpRedirectContextV1 {
    service_generation: u64,
    target_pid: u32,
    original_destination: SocketAddr,
    original_local_endpoint: SocketAddr,
    capture_instance_id: [u8; 16],
    service_executable_sha256: [u8; 32],
}

impl WindowsWfpRedirectContextV1 {
    pub const fn service_generation(&self) -> u64 {
        self.service_generation
    }

    pub const fn target_pid(&self) -> u32 {
        self.target_pid
    }

    pub const fn original_destination(&self) -> SocketAddr {
        self.original_destination
    }

    pub const fn original_local_endpoint(&self) -> SocketAddr {
        self.original_local_endpoint
    }

    pub fn encode(&self) -> [u8; WINDOWS_WFP_REDIRECT_CONTEXT_LENGTH] {
        let mut encoded = [0_u8; WINDOWS_WFP_REDIRECT_CONTEXT_LENGTH];
        encoded[MAGIC_OFFSET..VERSION_OFFSET].copy_from_slice(WINDOWS_WFP_REDIRECT_CONTEXT_MAGIC);
        encoded[VERSION_OFFSET..HEADER_LENGTH_OFFSET]
            .copy_from_slice(&WINDOWS_WFP_REDIRECT_CONTEXT_VERSION.to_le_bytes());
        encoded[HEADER_LENGTH_OFFSET..TOTAL_LENGTH_OFFSET]
            .copy_from_slice(&(WINDOWS_WFP_REDIRECT_CONTEXT_LENGTH as u16).to_le_bytes());
        encoded[TOTAL_LENGTH_OFFSET..SERVICE_GENERATION_OFFSET]
            .copy_from_slice(&(WINDOWS_WFP_REDIRECT_CONTEXT_LENGTH as u32).to_le_bytes());
        encoded[SERVICE_GENERATION_OFFSET..TARGET_PID_OFFSET]
            .copy_from_slice(&self.service_generation.to_le_bytes());
        encoded[TARGET_PID_OFFSET..PROTOCOL_OFFSET].copy_from_slice(&self.target_pid.to_le_bytes());
        encoded[PROTOCOL_OFFSET] = WINDOWS_WFP_TCP_PROTOCOL;
        encoded[FAMILY_OFFSET] = address_family(self.original_destination.ip());
        encoded[FLAGS_OFFSET..ORIGINAL_PORT_OFFSET].copy_from_slice(&0_u16.to_le_bytes());
        encoded[ORIGINAL_PORT_OFFSET..ORIGINAL_LOCAL_PORT_OFFSET]
            .copy_from_slice(&self.original_destination.port().to_be_bytes());
        encoded[ORIGINAL_LOCAL_PORT_OFFSET..ORIGINAL_ADDRESS_OFFSET]
            .copy_from_slice(&self.original_local_endpoint.port().to_be_bytes());
        write_address_slot(
            &mut encoded[ORIGINAL_ADDRESS_OFFSET..ORIGINAL_LOCAL_ADDRESS_OFFSET],
            self.original_destination.ip(),
        );
        write_address_slot(
            &mut encoded[ORIGINAL_LOCAL_ADDRESS_OFFSET..CAPTURE_INSTANCE_OFFSET],
            self.original_local_endpoint.ip(),
        );
        encoded[CAPTURE_INSTANCE_OFFSET..EXECUTABLE_SHA256_OFFSET]
            .copy_from_slice(&self.capture_instance_id);
        encoded[EXECUTABLE_SHA256_OFFSET..RESERVED_OFFSET]
            .copy_from_slice(&self.service_executable_sha256);
        encoded
    }
}

#[derive(Debug)]
pub struct WindowsWfpAcceptedSocketInput {
    pub connection_id: u64,
    pub redirect_context: Vec<u8>,
    pub redirect_records: Vec<u8>,
    pub accepted_local_endpoint: WindowsDirectConnectorEndpoint,
}

#[derive(Debug)]
pub struct WindowsWfpValidatedCapture {
    connection_id: u64,
    context: WindowsWfpRedirectContextV1,
    redirect_records: Vec<u8>,
    accepted_local_endpoint: SocketAddr,
}

impl WindowsWfpValidatedCapture {
    pub const fn connection_id(&self) -> u64 {
        self.connection_id
    }

    pub const fn original_destination(&self) -> SocketAddr {
        self.context.original_destination()
    }

    pub const fn original_local_endpoint(&self) -> SocketAddr {
        self.context.original_local_endpoint()
    }

    pub const fn accepted_local_endpoint(&self) -> SocketAddr {
        self.accepted_local_endpoint
    }

    pub fn redirect_records_len(&self) -> usize {
        self.redirect_records.len()
    }
}

#[derive(Debug)]
pub struct WindowsWfpRedirectRecordPlan {
    capture: WindowsWfpValidatedCapture,
    ingress_plan: WindowsDirectIngressPlan,
}

impl WindowsWfpRedirectRecordPlan {
    pub fn redirect_records(&self) -> &[u8] {
        &self.capture.redirect_records
    }

    pub fn mark_redirect_records_applied(self) -> WindowsWfpConnectPlan {
        WindowsWfpConnectPlan {
            ingress_plan: self.ingress_plan,
            original_local_endpoint: self.capture.context.original_local_endpoint,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsWfpConnectPlan {
    ingress_plan: WindowsDirectIngressPlan,
    original_local_endpoint: SocketAddr,
}

impl WindowsWfpConnectPlan {
    pub const fn endpoint(&self) -> SocketAddr {
        self.ingress_plan.endpoint()
    }

    pub const fn original_local_endpoint(&self) -> SocketAddr {
        self.original_local_endpoint
    }

    pub fn ingress_plan(&self) -> &WindowsDirectIngressPlan {
        &self.ingress_plan
    }

    pub fn into_ingress_plan(self) -> WindowsDirectIngressPlan {
        self.ingress_plan
    }
}

#[derive(Debug)]
pub struct WindowsWfpPrepareError {
    code: WindowsWfpCaptureErrorCode,
    capture: Box<WindowsWfpValidatedCapture>,
}

impl WindowsWfpPrepareError {
    pub const fn code(&self) -> WindowsWfpCaptureErrorCode {
        self.code
    }

    pub const fn capture(&self) -> &WindowsWfpValidatedCapture {
        &self.capture
    }

    pub fn into_capture(self) -> WindowsWfpValidatedCapture {
        *self.capture
    }
}

impl fmt::Display for WindowsWfpPrepareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.code.fmt(formatter)
    }
}

impl std::error::Error for WindowsWfpPrepareError {}

pub fn encode_windows_wfp_redirect_context_v1(
    identity: &WindowsWfpCaptureIdentity,
    original_destination: &WindowsDirectConnectorEndpoint,
    original_local_endpoint: &WindowsDirectConnectorEndpoint,
) -> Result<[u8; WINDOWS_WFP_REDIRECT_CONTEXT_LENGTH], WindowsWfpCaptureErrorCode> {
    let validated_identity = validate_identity(identity)?;
    let original_destination = parse_endpoint(original_destination, false)?;
    validate_original_destination(original_destination.ip())?;
    let original_local_endpoint = parse_endpoint(original_local_endpoint, true)?;
    if address_family(original_destination.ip()) != address_family(original_local_endpoint.ip()) {
        return Err(WindowsWfpCaptureErrorCode::InvalidAddressFamily);
    }
    Ok(WindowsWfpRedirectContextV1 {
        service_generation: identity.service.generation,
        target_pid: identity.target_pid,
        original_destination,
        original_local_endpoint,
        capture_instance_id: validated_identity.capture_instance_id,
        service_executable_sha256: validated_identity.service_executable_sha256,
    }
    .encode())
}

pub fn decode_windows_wfp_redirect_context_v1(
    encoded: &[u8],
) -> Result<WindowsWfpRedirectContextV1, WindowsWfpCaptureErrorCode> {
    if encoded.len() != WINDOWS_WFP_REDIRECT_CONTEXT_LENGTH {
        return Err(WindowsWfpCaptureErrorCode::InvalidContextLength);
    }
    if &encoded[MAGIC_OFFSET..VERSION_OFFSET] != WINDOWS_WFP_REDIRECT_CONTEXT_MAGIC {
        return Err(WindowsWfpCaptureErrorCode::InvalidContextMagic);
    }
    if read_u16_le(encoded, VERSION_OFFSET) != WINDOWS_WFP_REDIRECT_CONTEXT_VERSION {
        return Err(WindowsWfpCaptureErrorCode::UnsupportedContextVersion);
    }
    if read_u16_le(encoded, HEADER_LENGTH_OFFSET) as usize != WINDOWS_WFP_REDIRECT_CONTEXT_LENGTH {
        return Err(WindowsWfpCaptureErrorCode::InvalidHeaderLength);
    }
    if read_u32_le(encoded, TOTAL_LENGTH_OFFSET) as usize != WINDOWS_WFP_REDIRECT_CONTEXT_LENGTH {
        return Err(WindowsWfpCaptureErrorCode::InvalidTotalLength);
    }
    let service_generation = read_u64_le(encoded, SERVICE_GENERATION_OFFSET);
    if service_generation == 0 {
        return Err(WindowsWfpCaptureErrorCode::InvalidServiceGeneration);
    }
    let target_pid = read_u32_le(encoded, TARGET_PID_OFFSET);
    if target_pid == 0 {
        return Err(WindowsWfpCaptureErrorCode::InvalidTargetPid);
    }
    if encoded[PROTOCOL_OFFSET] != WINDOWS_WFP_TCP_PROTOCOL {
        return Err(WindowsWfpCaptureErrorCode::InvalidProtocol);
    }
    let family = encoded[FAMILY_OFFSET];
    if !matches!(family, IPV4_FAMILY | IPV6_FAMILY) {
        return Err(WindowsWfpCaptureErrorCode::InvalidAddressFamily);
    }
    if read_u16_le(encoded, FLAGS_OFFSET) != 0 {
        return Err(WindowsWfpCaptureErrorCode::UnsupportedFlags);
    }
    let original_port = read_u16_be(encoded, ORIGINAL_PORT_OFFSET);
    if original_port == 0 {
        return Err(WindowsWfpCaptureErrorCode::InvalidOriginalPort);
    }
    let original_local_port = read_u16_be(encoded, ORIGINAL_LOCAL_PORT_OFFSET);
    let original_address = read_address_slot(
        family,
        &encoded[ORIGINAL_ADDRESS_OFFSET..ORIGINAL_LOCAL_ADDRESS_OFFSET],
    )?;
    validate_original_destination(original_address)?;
    let original_local_address = read_address_slot(
        family,
        &encoded[ORIGINAL_LOCAL_ADDRESS_OFFSET..CAPTURE_INSTANCE_OFFSET],
    )?;
    let capture_instance_id =
        copy_array::<16>(&encoded[CAPTURE_INSTANCE_OFFSET..EXECUTABLE_SHA256_OFFSET]);
    if capture_instance_id.iter().all(|byte| *byte == 0) {
        return Err(WindowsWfpCaptureErrorCode::InvalidCaptureInstance);
    }
    let service_executable_sha256 =
        copy_array::<32>(&encoded[EXECUTABLE_SHA256_OFFSET..RESERVED_OFFSET]);
    if service_executable_sha256.iter().all(|byte| *byte == 0) {
        return Err(WindowsWfpCaptureErrorCode::InvalidExecutableHash);
    }
    if encoded[RESERVED_OFFSET..].iter().any(|byte| *byte != 0) {
        return Err(WindowsWfpCaptureErrorCode::ReservedNotZero);
    }
    Ok(WindowsWfpRedirectContextV1 {
        service_generation,
        target_pid,
        original_destination: SocketAddr::new(original_address, original_port),
        original_local_endpoint: SocketAddr::new(original_local_address, original_local_port),
        capture_instance_id,
        service_executable_sha256,
    })
}

pub fn validate_windows_wfp_capture(
    input: WindowsWfpAcceptedSocketInput,
    expected_identity: &WindowsWfpCaptureIdentity,
) -> Result<WindowsWfpValidatedCapture, WindowsWfpCaptureErrorCode> {
    let identity = validate_identity(expected_identity)?;
    if input.connection_id == 0 {
        return Err(WindowsWfpCaptureErrorCode::InvalidConnectionId);
    }
    if input.redirect_records.is_empty() {
        return Err(WindowsWfpCaptureErrorCode::MissingRedirectRecords);
    }
    if input.redirect_records.len() > MAX_WINDOWS_WFP_REDIRECT_RECORDS_BYTES {
        return Err(WindowsWfpCaptureErrorCode::RedirectRecordsTooLarge);
    }
    let accepted_local_endpoint = parse_endpoint(&input.accepted_local_endpoint, false)?;
    if !accepted_local_endpoint.ip().is_loopback() {
        return Err(WindowsWfpCaptureErrorCode::ListenerNotLoopback);
    }
    if !identity.listeners.contains(&accepted_local_endpoint) {
        return Err(WindowsWfpCaptureErrorCode::ListenerMismatch);
    }
    let context = decode_windows_wfp_redirect_context_v1(&input.redirect_context)?;
    if address_family(accepted_local_endpoint.ip())
        != address_family(context.original_destination.ip())
    {
        return Err(WindowsWfpCaptureErrorCode::ListenerFamilyMismatch);
    }
    if context.service_generation != expected_identity.service.generation {
        return Err(WindowsWfpCaptureErrorCode::StaleServiceGeneration);
    }
    if context.target_pid != expected_identity.target_pid {
        return Err(WindowsWfpCaptureErrorCode::StaleTargetPid);
    }
    if context.capture_instance_id != identity.capture_instance_id {
        return Err(WindowsWfpCaptureErrorCode::StaleCaptureInstance);
    }
    if context.service_executable_sha256 != identity.service_executable_sha256 {
        return Err(WindowsWfpCaptureErrorCode::StaleExecutableHash);
    }
    Ok(WindowsWfpValidatedCapture {
        connection_id: input.connection_id,
        context,
        redirect_records: input.redirect_records,
        accepted_local_endpoint,
    })
}

pub fn prepare_windows_wfp_outbound_socket(
    capture: WindowsWfpValidatedCapture,
    ingress_request: &WindowsDirectIngressRequest,
    policy_tables: &RoutingPolicyTables,
) -> Result<WindowsWfpRedirectRecordPlan, WindowsWfpPrepareError> {
    let ingress_plan = match prepare_windows_direct_ingress(ingress_request, policy_tables) {
        Ok(plan) => plan,
        Err(_) => {
            return Err(WindowsWfpPrepareError {
                code: WindowsWfpCaptureErrorCode::InvalidIngressAdmission,
                capture: Box::new(capture),
            });
        }
    };
    if ingress_plan.connection_id() != capture.connection_id {
        return Err(WindowsWfpPrepareError {
            code: WindowsWfpCaptureErrorCode::AdmissionIdentityMismatch,
            capture: Box::new(capture),
        });
    }
    if ingress_plan.endpoint() != capture.context.original_destination {
        return Err(WindowsWfpPrepareError {
            code: WindowsWfpCaptureErrorCode::AdmissionEndpointMismatch,
            capture: Box::new(capture),
        });
    }
    Ok(WindowsWfpRedirectRecordPlan {
        capture,
        ingress_plan,
    })
}

struct ValidatedIdentity {
    capture_instance_id: [u8; 16],
    service_executable_sha256: [u8; 32],
    listeners: Vec<SocketAddr>,
}

fn validate_identity(
    identity: &WindowsWfpCaptureIdentity,
) -> Result<ValidatedIdentity, WindowsWfpCaptureErrorCode> {
    identity
        .service
        .validate()
        .map_err(|_| WindowsWfpCaptureErrorCode::InvalidServiceIdentity)?;
    if identity.target_pid == 0 {
        return Err(WindowsWfpCaptureErrorCode::InvalidTargetPid);
    }
    let capture_instance_id = decode_lower_hex::<16>(
        &identity.capture_instance_id,
        WindowsWfpCaptureErrorCode::InvalidCaptureInstance,
    )?;
    if capture_instance_id.iter().all(|byte| *byte == 0) {
        return Err(WindowsWfpCaptureErrorCode::InvalidCaptureInstance);
    }
    let service_executable_sha256 = decode_lower_hex::<32>(
        &identity.service.executable_sha256,
        WindowsWfpCaptureErrorCode::InvalidServiceIdentity,
    )?;
    if service_executable_sha256.iter().all(|byte| *byte == 0) {
        return Err(WindowsWfpCaptureErrorCode::InvalidExecutableHash);
    }
    if identity.listeners.is_empty() || identity.listeners.len() > 2 {
        return Err(WindowsWfpCaptureErrorCode::InvalidListenerSet);
    }
    let mut listeners = Vec::with_capacity(identity.listeners.len());
    let mut has_ipv4 = false;
    let mut has_ipv6 = false;
    for listener in &identity.listeners {
        let listener = parse_endpoint(listener, false)?;
        if !listener.ip().is_loopback() {
            return Err(WindowsWfpCaptureErrorCode::ListenerNotLoopback);
        }
        let duplicate_family = match listener.ip() {
            IpAddr::V4(_) => std::mem::replace(&mut has_ipv4, true),
            IpAddr::V6(_) => std::mem::replace(&mut has_ipv6, true),
        };
        if duplicate_family {
            return Err(WindowsWfpCaptureErrorCode::InvalidListenerSet);
        }
        listeners.push(listener);
    }
    Ok(ValidatedIdentity {
        capture_instance_id,
        service_executable_sha256,
        listeners,
    })
}

fn parse_endpoint(
    endpoint: &WindowsDirectConnectorEndpoint,
    allow_zero_port: bool,
) -> Result<SocketAddr, WindowsWfpCaptureErrorCode> {
    let address: IpAddr = endpoint
        .address
        .parse()
        .map_err(|_| WindowsWfpCaptureErrorCode::EndpointNotCanonical)?;
    if address.to_string() != endpoint.address {
        return Err(WindowsWfpCaptureErrorCode::EndpointNotCanonical);
    }
    if endpoint.port == 0 && !allow_zero_port {
        return Err(WindowsWfpCaptureErrorCode::InvalidPort);
    }
    Ok(SocketAddr::new(address, endpoint.port))
}

fn validate_original_destination(address: IpAddr) -> Result<(), WindowsWfpCaptureErrorCode> {
    let unsafe_address = match address {
        IpAddr::V4(address) => {
            address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || address.is_link_local()
                || address == Ipv4Addr::BROADCAST
        }
        IpAddr::V6(address) => {
            let mapped_ipv4 = ipv4_mapped_address(address);
            address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || (address.segments()[0] & 0xffc0) == 0xfe80
                || mapped_ipv4
                    .map(|address| validate_original_destination(IpAddr::V4(address)).is_err())
                    .unwrap_or(false)
        }
    };
    if unsafe_address {
        Err(WindowsWfpCaptureErrorCode::UnsafeOriginalDestination)
    } else {
        Ok(())
    }
}

fn ipv4_mapped_address(address: Ipv6Addr) -> Option<Ipv4Addr> {
    let octets = address.octets();
    if octets[..10].iter().all(|byte| *byte == 0) && octets[10..12] == [0xff, 0xff] {
        Some(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ))
    } else {
        None
    }
}

const fn address_family(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => IPV4_FAMILY,
        IpAddr::V6(_) => IPV6_FAMILY,
    }
}

fn write_address_slot(slot: &mut [u8], address: IpAddr) {
    match address {
        IpAddr::V4(address) => slot[..4].copy_from_slice(&address.octets()),
        IpAddr::V6(address) => slot.copy_from_slice(&address.octets()),
    }
}

fn read_address_slot(family: u8, slot: &[u8]) -> Result<IpAddr, WindowsWfpCaptureErrorCode> {
    match family {
        IPV4_FAMILY => {
            if slot[4..].iter().any(|byte| *byte != 0) {
                return Err(WindowsWfpCaptureErrorCode::InvalidAddressEncoding);
            }
            Ok(IpAddr::V4(Ipv4Addr::new(
                slot[0], slot[1], slot[2], slot[3],
            )))
        }
        IPV6_FAMILY => Ok(IpAddr::V6(Ipv6Addr::from(copy_array::<16>(slot)))),
        _ => Err(WindowsWfpCaptureErrorCode::InvalidAddressFamily),
    }
}

fn decode_lower_hex<const N: usize>(
    value: &str,
    error: WindowsWfpCaptureErrorCode,
) -> Result<[u8; N], WindowsWfpCaptureErrorCode> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(error);
    }
    let bytes = value.as_bytes();
    let mut decoded = [0_u8; N];
    for (index, output) in decoded.iter_mut().enumerate() {
        *output = (hex_nibble(bytes[index * 2]) << 4) | hex_nibble(bytes[index * 2 + 1]);
    }
    Ok(decoded)
}

const fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

fn copy_array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut output = [0_u8; N];
    output.copy_from_slice(bytes);
    output
}

fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(copy_array::<2>(&bytes[offset..offset + 2]))
}

fn read_u16_be(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(copy_array::<2>(&bytes[offset..offset + 2]))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(copy_array::<4>(&bytes[offset..offset + 4]))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(copy_array::<8>(&bytes[offset..offset + 8]))
}
