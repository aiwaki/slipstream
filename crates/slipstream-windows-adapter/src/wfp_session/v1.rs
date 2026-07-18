//! Version 1 of the WFP dynamic management-session boundary.
//!
//! This module freezes the exact owned object identities, provider-context
//! wire format, activation gate, transaction order, and compensation rules.
//! Native calls live in `windows.rs`; the production service host does not
//! compose either module yet.

use crate::direct_connector::WindowsDirectConnectorEndpoint;
use crate::wfp_capture::{
    validate_windows_wfp_capture_identity, WindowsWfpCaptureErrorCode, WindowsWfpCaptureIdentity,
};
use crate::wfp_runtime::{
    WindowsWfpFilterInspection, WindowsWfpRuntimeBinding, WindowsWfpRuntimeCommand,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const WINDOWS_WFP_SESSION_CONTRACT_VERSION: u32 = 1;
pub const WINDOWS_WFP_PROVIDER_CONTEXT_VERSION: u16 = 1;
pub const WINDOWS_WFP_PROVIDER_CONTEXT_LENGTH: usize = 128;
pub const WINDOWS_WFP_CAPTURE_PROTOCOL: u8 = 6;
pub const WINDOWS_WFP_CAPTURE_REMOTE_PORT: u16 = 443;

pub const WINDOWS_WFP_PROVIDER_KEY: &str = "e5d75aab-4599-476c-8ed2-3b6ac022548c";
pub const WINDOWS_WFP_SUBLAYER_KEY: &str = "758ba833-c351-49ff-8117-91481625b9bc";
pub const WINDOWS_WFP_CALLOUT_V4_KEY: &str = "fb100fc4-40e4-41fd-aaff-29e0d8342f40";
pub const WINDOWS_WFP_CALLOUT_V6_KEY: &str = "2857c4c8-504e-472f-bbe8-4c26e038cab2";
pub const WINDOWS_WFP_PROVIDER_CONTEXT_KEY: &str = "b4f2547a-286b-494a-9fa4-6c1c0ef1b9e5";
pub const WINDOWS_WFP_FILTER_V4_KEY: &str = "3f72d2bc-8378-4df7-abca-fb2e96f7310e";
pub const WINDOWS_WFP_FILTER_V6_KEY: &str = "45c9891e-5beb-481e-99c7-b0fe3a20921a";

#[cfg(windows)]
pub(crate) const WINDOWS_WFP_PROVIDER_KEY_U128: u128 = 0xe5d75aab_4599_476c_8ed2_3b6ac022548c;
#[cfg(windows)]
pub(crate) const WINDOWS_WFP_SUBLAYER_KEY_U128: u128 = 0x758ba833_c351_49ff_8117_91481625b9bc;
#[cfg(windows)]
pub(crate) const WINDOWS_WFP_CALLOUT_V4_KEY_U128: u128 = 0xfb100fc4_40e4_41fd_aaff_29e0d8342f40;
#[cfg(windows)]
pub(crate) const WINDOWS_WFP_CALLOUT_V6_KEY_U128: u128 = 0x2857c4c8_504e_472f_bbe8_4c26e038cab2;
#[cfg(windows)]
pub(crate) const WINDOWS_WFP_PROVIDER_CONTEXT_KEY_U128: u128 =
    0xb4f2547a_286b_494a_9fa4_6c1c0ef1b9e5;
#[cfg(windows)]
pub(crate) const WINDOWS_WFP_FILTER_V4_KEY_U128: u128 = 0x3f72d2bc_8378_4df7_abca_fb2e96f7310e;
#[cfg(windows)]
pub(crate) const WINDOWS_WFP_FILTER_V6_KEY_U128: u128 = 0x45c9891e_5beb_481e_99c7_b0fe3a20921a;

const PROVIDER_CONTEXT_MAGIC: &[u8; 8] = b"SLPWFPMS";
const MAGIC_OFFSET: usize = 0;
const VERSION_OFFSET: usize = 8;
const HEADER_LENGTH_OFFSET: usize = 10;
const TOTAL_LENGTH_OFFSET: usize = 12;
const SERVICE_GENERATION_OFFSET: usize = 16;
const RUNTIME_GENERATION_OFFSET: usize = 24;
const SESSION_GENERATION_OFFSET: usize = 32;
const TARGET_PID_OFFSET: usize = 40;
const FLAGS_OFFSET: usize = 44;
const CAPTURE_INSTANCE_OFFSET: usize = 48;
const EXECUTABLE_SHA256_OFFSET: usize = 64;
const IPV4_PORT_OFFSET: usize = 96;
const IPV6_PORT_OFFSET: usize = 98;
const IPV4_ADDRESS_OFFSET: usize = 100;
const IPV6_ADDRESS_OFFSET: usize = 104;
const REMOTE_PORT_OFFSET: usize = 120;
const PROTOCOL_OFFSET: usize = 122;
const RESERVED_OFFSET: usize = 123;
const HAS_IPV4_LISTENER: u32 = 1;
const HAS_IPV6_LISTENER: u32 = 2;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WindowsWfpManagementObject {
    Provider,
    Sublayer,
    CalloutV4,
    CalloutV6,
    ProviderContext,
    FilterV4,
    FilterV6,
}

impl WindowsWfpManagementObject {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::Sublayer => "sublayer",
            Self::CalloutV4 => "callout_v4",
            Self::CalloutV6 => "callout_v6",
            Self::ProviderContext => "provider_context",
            Self::FilterV4 => "filter_v4",
            Self::FilterV6 => "filter_v6",
        }
    }

    pub const fn key(self) -> &'static str {
        match self {
            Self::Provider => WINDOWS_WFP_PROVIDER_KEY,
            Self::Sublayer => WINDOWS_WFP_SUBLAYER_KEY,
            Self::CalloutV4 => WINDOWS_WFP_CALLOUT_V4_KEY,
            Self::CalloutV6 => WINDOWS_WFP_CALLOUT_V6_KEY,
            Self::ProviderContext => WINDOWS_WFP_PROVIDER_CONTEXT_KEY,
            Self::FilterV4 => WINDOWS_WFP_FILTER_V4_KEY,
            Self::FilterV6 => WINDOWS_WFP_FILTER_V6_KEY,
        }
    }
}

pub const WINDOWS_WFP_TRANSACTION_OBJECT_ORDER: [WindowsWfpManagementObject; 7] = [
    WindowsWfpManagementObject::Provider,
    WindowsWfpManagementObject::Sublayer,
    WindowsWfpManagementObject::CalloutV4,
    WindowsWfpManagementObject::CalloutV6,
    WindowsWfpManagementObject::ProviderContext,
    WindowsWfpManagementObject::FilterV4,
    WindowsWfpManagementObject::FilterV6,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsWfpProviderContextV1 {
    service_generation: u64,
    runtime_generation: u64,
    session_generation: u64,
    target_pid: u32,
    capture_instance_id: [u8; 16],
    executable_sha256: [u8; 32],
    ipv4_listener: SocketAddr,
    ipv6_listener: SocketAddr,
}

impl WindowsWfpProviderContextV1 {
    pub const fn service_generation(&self) -> u64 {
        self.service_generation
    }

    pub const fn runtime_generation(&self) -> u64 {
        self.runtime_generation
    }

    pub const fn session_generation(&self) -> u64 {
        self.session_generation
    }

    pub const fn target_pid(&self) -> u32 {
        self.target_pid
    }

    pub const fn ipv4_listener(&self) -> SocketAddr {
        self.ipv4_listener
    }

    pub const fn ipv6_listener(&self) -> SocketAddr {
        self.ipv6_listener
    }

    pub fn capture_instance_id(&self) -> &[u8; 16] {
        &self.capture_instance_id
    }

    pub fn executable_sha256(&self) -> &[u8; 32] {
        &self.executable_sha256
    }

    pub fn encode(&self) -> [u8; WINDOWS_WFP_PROVIDER_CONTEXT_LENGTH] {
        let mut encoded = [0_u8; WINDOWS_WFP_PROVIDER_CONTEXT_LENGTH];
        encoded[MAGIC_OFFSET..VERSION_OFFSET].copy_from_slice(PROVIDER_CONTEXT_MAGIC);
        encoded[VERSION_OFFSET..HEADER_LENGTH_OFFSET]
            .copy_from_slice(&WINDOWS_WFP_PROVIDER_CONTEXT_VERSION.to_le_bytes());
        encoded[HEADER_LENGTH_OFFSET..TOTAL_LENGTH_OFFSET]
            .copy_from_slice(&(WINDOWS_WFP_PROVIDER_CONTEXT_LENGTH as u16).to_le_bytes());
        encoded[TOTAL_LENGTH_OFFSET..SERVICE_GENERATION_OFFSET]
            .copy_from_slice(&(WINDOWS_WFP_PROVIDER_CONTEXT_LENGTH as u32).to_le_bytes());
        encoded[SERVICE_GENERATION_OFFSET..RUNTIME_GENERATION_OFFSET]
            .copy_from_slice(&self.service_generation.to_le_bytes());
        encoded[RUNTIME_GENERATION_OFFSET..SESSION_GENERATION_OFFSET]
            .copy_from_slice(&self.runtime_generation.to_le_bytes());
        encoded[SESSION_GENERATION_OFFSET..TARGET_PID_OFFSET]
            .copy_from_slice(&self.session_generation.to_le_bytes());
        encoded[TARGET_PID_OFFSET..FLAGS_OFFSET].copy_from_slice(&self.target_pid.to_le_bytes());
        encoded[FLAGS_OFFSET..CAPTURE_INSTANCE_OFFSET]
            .copy_from_slice(&(HAS_IPV4_LISTENER | HAS_IPV6_LISTENER).to_le_bytes());
        encoded[CAPTURE_INSTANCE_OFFSET..EXECUTABLE_SHA256_OFFSET]
            .copy_from_slice(&self.capture_instance_id);
        encoded[EXECUTABLE_SHA256_OFFSET..IPV4_PORT_OFFSET]
            .copy_from_slice(&self.executable_sha256);
        encoded[IPV4_PORT_OFFSET..IPV6_PORT_OFFSET]
            .copy_from_slice(&self.ipv4_listener.port().to_be_bytes());
        encoded[IPV6_PORT_OFFSET..IPV4_ADDRESS_OFFSET]
            .copy_from_slice(&self.ipv6_listener.port().to_be_bytes());
        let IpAddr::V4(ipv4) = self.ipv4_listener.ip() else {
            unreachable!("validated IPv4 listener changed family");
        };
        encoded[IPV4_ADDRESS_OFFSET..IPV6_ADDRESS_OFFSET].copy_from_slice(&ipv4.octets());
        let IpAddr::V6(ipv6) = self.ipv6_listener.ip() else {
            unreachable!("validated IPv6 listener changed family");
        };
        encoded[IPV6_ADDRESS_OFFSET..REMOTE_PORT_OFFSET].copy_from_slice(&ipv6.octets());
        encoded[REMOTE_PORT_OFFSET..PROTOCOL_OFFSET]
            .copy_from_slice(&WINDOWS_WFP_CAPTURE_REMOTE_PORT.to_be_bytes());
        encoded[PROTOCOL_OFFSET] = WINDOWS_WFP_CAPTURE_PROTOCOL;
        encoded
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsWfpDynamicSessionPlan {
    binding: WindowsWfpRuntimeBinding,
    session_generation: u64,
    target_pid: u32,
    provider_context: [u8; WINDOWS_WFP_PROVIDER_CONTEXT_LENGTH],
}

impl WindowsWfpDynamicSessionPlan {
    pub fn binding(&self) -> &WindowsWfpRuntimeBinding {
        &self.binding
    }

    pub const fn session_generation(&self) -> u64 {
        self.session_generation
    }

    pub const fn target_pid(&self) -> u32 {
        self.target_pid
    }

    pub fn provider_context(&self) -> &[u8; WINDOWS_WFP_PROVIDER_CONTEXT_LENGTH] {
        &self.provider_context
    }
}

pub fn prepare_windows_wfp_dynamic_session_plan(
    identity: &WindowsWfpCaptureIdentity,
    binding: &WindowsWfpRuntimeBinding,
    session_generation: u64,
    target_pid: u32,
) -> Result<WindowsWfpDynamicSessionPlan, WindowsWfpSessionError> {
    validate_windows_wfp_capture_identity(identity)
        .map_err(WindowsWfpSessionError::InvalidCaptureIdentity)?;
    validate_binding(identity, binding)?;
    if session_generation == 0 {
        return Err(WindowsWfpSessionError::InvalidSessionGeneration);
    }
    if target_pid != identity.target_pid {
        return Err(WindowsWfpSessionError::TargetPidMismatch);
    }

    let (ipv4_listener, ipv6_listener) = exact_dual_stack_listeners(&identity.listeners)?;
    let provider_context = WindowsWfpProviderContextV1 {
        service_generation: identity.service.generation,
        runtime_generation: binding.runtime_generation,
        session_generation,
        target_pid,
        capture_instance_id: decode_lower_hex::<16>(
            &identity.capture_instance_id,
            WindowsWfpSessionError::InvalidCaptureInstance,
        )?,
        executable_sha256: decode_lower_hex::<32>(
            &identity.service.executable_sha256,
            WindowsWfpSessionError::InvalidExecutableHash,
        )?,
        ipv4_listener,
        ipv6_listener,
    }
    .encode();

    Ok(WindowsWfpDynamicSessionPlan {
        binding: binding.clone(),
        session_generation,
        target_pid,
        provider_context,
    })
}

pub fn decode_windows_wfp_provider_context_v1(
    encoded: &[u8],
) -> Result<WindowsWfpProviderContextV1, WindowsWfpSessionError> {
    if encoded.len() != WINDOWS_WFP_PROVIDER_CONTEXT_LENGTH {
        return Err(WindowsWfpSessionError::InvalidProviderContextLength);
    }
    if &encoded[MAGIC_OFFSET..VERSION_OFFSET] != PROVIDER_CONTEXT_MAGIC {
        return Err(WindowsWfpSessionError::InvalidProviderContextMagic);
    }
    if read_u16_le(encoded, VERSION_OFFSET) != WINDOWS_WFP_PROVIDER_CONTEXT_VERSION {
        return Err(WindowsWfpSessionError::UnsupportedProviderContextVersion);
    }
    if read_u16_le(encoded, HEADER_LENGTH_OFFSET) as usize != WINDOWS_WFP_PROVIDER_CONTEXT_LENGTH
        || read_u32_le(encoded, TOTAL_LENGTH_OFFSET) as usize != WINDOWS_WFP_PROVIDER_CONTEXT_LENGTH
    {
        return Err(WindowsWfpSessionError::InvalidProviderContextLength);
    }
    if read_u32_le(encoded, FLAGS_OFFSET) != HAS_IPV4_LISTENER | HAS_IPV6_LISTENER {
        return Err(WindowsWfpSessionError::UnsupportedProviderContextFlags);
    }
    if read_u16_be(encoded, REMOTE_PORT_OFFSET) != WINDOWS_WFP_CAPTURE_REMOTE_PORT
        || encoded[PROTOCOL_OFFSET] != WINDOWS_WFP_CAPTURE_PROTOCOL
    {
        return Err(WindowsWfpSessionError::InvalidCaptureScope);
    }
    if encoded[RESERVED_OFFSET..].iter().any(|byte| *byte != 0) {
        return Err(WindowsWfpSessionError::ProviderContextReservedNotZero);
    }

    let service_generation = read_u64_le(encoded, SERVICE_GENERATION_OFFSET);
    let runtime_generation = read_u64_le(encoded, RUNTIME_GENERATION_OFFSET);
    let session_generation = read_u64_le(encoded, SESSION_GENERATION_OFFSET);
    let target_pid = read_u32_le(encoded, TARGET_PID_OFFSET);
    if service_generation == 0 || runtime_generation == 0 || session_generation == 0 {
        return Err(WindowsWfpSessionError::InvalidProviderContextGeneration);
    }
    if target_pid == 0 {
        return Err(WindowsWfpSessionError::TargetPidMismatch);
    }

    let capture_instance_id = copy_array::<16>(encoded, CAPTURE_INSTANCE_OFFSET);
    let executable_sha256 = copy_array::<32>(encoded, EXECUTABLE_SHA256_OFFSET);
    if capture_instance_id.iter().all(|byte| *byte == 0) {
        return Err(WindowsWfpSessionError::InvalidCaptureInstance);
    }
    if executable_sha256.iter().all(|byte| *byte == 0) {
        return Err(WindowsWfpSessionError::InvalidExecutableHash);
    }

    let ipv4_listener = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::from(copy_array::<4>(
            encoded,
            IPV4_ADDRESS_OFFSET,
        ))),
        read_u16_be(encoded, IPV4_PORT_OFFSET),
    );
    let ipv6_listener = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::from(copy_array::<16>(
            encoded,
            IPV6_ADDRESS_OFFSET,
        ))),
        read_u16_be(encoded, IPV6_PORT_OFFSET),
    );
    if !ipv4_listener.ip().is_loopback()
        || !ipv6_listener.ip().is_loopback()
        || ipv4_listener.port() == 0
        || ipv6_listener.port() == 0
    {
        return Err(WindowsWfpSessionError::InvalidListenerSet);
    }

    Ok(WindowsWfpProviderContextV1 {
        service_generation,
        runtime_generation,
        session_generation,
        target_pid,
        capture_instance_id,
        executable_sha256,
        ipv4_listener,
        ipv6_listener,
    })
}

pub trait WindowsWfpManagementApi {
    type Session;
    type Error: fmt::Display;

    fn open_dynamic_session(
        &mut self,
        plan: &WindowsWfpDynamicSessionPlan,
    ) -> Result<Self::Session, Self::Error>;
    fn begin_transaction(&mut self, session: &mut Self::Session) -> Result<(), Self::Error>;
    fn add_object(
        &mut self,
        session: &mut Self::Session,
        object: WindowsWfpManagementObject,
        plan: &WindowsWfpDynamicSessionPlan,
    ) -> Result<(), Self::Error>;
    fn commit_transaction(&mut self, session: &mut Self::Session) -> Result<(), Self::Error>;
    fn abort_transaction(&mut self, session: &mut Self::Session) -> Result<(), Self::Error>;
    fn close_dynamic_session(&mut self, session: &mut Self::Session) -> Result<(), Self::Error>;
    fn inspect_owned_filters(
        &mut self,
        binding: &WindowsWfpRuntimeBinding,
        session_generation: Option<u64>,
    ) -> Result<WindowsWfpFilterInspection, Self::Error>;
}

pub struct ActiveWindowsWfpDynamicSession<S> {
    binding: WindowsWfpRuntimeBinding,
    session_generation: u64,
    handle: S,
}

impl<S> ActiveWindowsWfpDynamicSession<S> {
    pub fn binding(&self) -> &WindowsWfpRuntimeBinding {
        &self.binding
    }

    pub const fn session_generation(&self) -> u64 {
        self.session_generation
    }
}

pub fn activate_windows_wfp_dynamic_session<A: WindowsWfpManagementApi>(
    api: &mut A,
    plan: &WindowsWfpDynamicSessionPlan,
) -> Result<ActiveWindowsWfpDynamicSession<A::Session>, WindowsWfpSessionError> {
    let mut session = api
        .open_dynamic_session(plan)
        .map_err(|error| primitive_error("open_dynamic_session", error))?;
    if let Err(error) = api.begin_transaction(&mut session) {
        return Err(compensate_activation_failure(
            api,
            &mut session,
            "begin_transaction",
            error,
            false,
        ));
    }
    for object in WINDOWS_WFP_TRANSACTION_OBJECT_ORDER {
        if let Err(error) = api.add_object(&mut session, object, plan) {
            return Err(compensate_activation_failure(
                api,
                &mut session,
                object.as_str(),
                error,
                true,
            ));
        }
    }
    if let Err(error) = api.commit_transaction(&mut session) {
        return Err(compensate_activation_failure(
            api,
            &mut session,
            "commit_transaction",
            error,
            true,
        ));
    }
    Ok(ActiveWindowsWfpDynamicSession {
        binding: plan.binding.clone(),
        session_generation: plan.session_generation,
        handle: session,
    })
}

fn compensate_activation_failure<A: WindowsWfpManagementApi>(
    api: &mut A,
    session: &mut A::Session,
    stage: &'static str,
    primary: A::Error,
    transaction_open: bool,
) -> WindowsWfpSessionError {
    let abort_error = transaction_open
        .then(|| {
            api.abort_transaction(session)
                .err()
                .map(|error| error.to_string())
        })
        .flatten();
    let close_error = api
        .close_dynamic_session(session)
        .err()
        .map(|error| error.to_string());
    WindowsWfpSessionError::ActivationFailed {
        stage,
        message: primary.to_string(),
        abort_error,
        close_error,
    }
}

pub struct WindowsWfpDynamicSessionController<A: WindowsWfpManagementApi> {
    identity: WindowsWfpCaptureIdentity,
    api: A,
    kernel_binding: Option<WindowsWfpRuntimeBinding>,
    listener_binding: Option<WindowsWfpRuntimeBinding>,
    active: Option<ActiveWindowsWfpDynamicSession<A::Session>>,
    last_session_generation: Option<u64>,
    last_filter_inspection: Option<WindowsWfpFilterInspection>,
}

impl<A: WindowsWfpManagementApi> WindowsWfpDynamicSessionController<A> {
    pub fn new(
        identity: WindowsWfpCaptureIdentity,
        api: A,
    ) -> Result<Self, WindowsWfpSessionError> {
        validate_windows_wfp_capture_identity(&identity)
            .map_err(WindowsWfpSessionError::InvalidCaptureIdentity)?;
        exact_dual_stack_listeners(&identity.listeners)?;
        Ok(Self {
            identity,
            api,
            kernel_binding: None,
            listener_binding: None,
            active: None,
            last_session_generation: None,
            last_filter_inspection: None,
        })
    }

    pub fn api(&self) -> &A {
        &self.api
    }

    pub fn api_mut(&mut self) -> &mut A {
        &mut self.api
    }

    pub fn active_session_generation(&self) -> Option<u64> {
        self.active.as_ref().map(|active| active.session_generation)
    }

    pub fn record_kernel_callouts_registered(
        &mut self,
        binding: &WindowsWfpRuntimeBinding,
    ) -> Result<(), WindowsWfpSessionError> {
        validate_binding(&self.identity, binding)?;
        if self.active.is_some() || self.listener_binding.is_some() {
            return Err(WindowsWfpSessionError::InvalidControllerOrder(
                "kernel registration cannot replace retained resources",
            ));
        }
        if let Some(existing) = &self.kernel_binding {
            if existing == binding {
                return Ok(());
            }
            return Err(WindowsWfpSessionError::InvalidControllerOrder(
                "kernel registration proof cannot change in place",
            ));
        }
        self.kernel_binding = Some(binding.clone());
        self.last_filter_inspection = None;
        Ok(())
    }

    pub fn record_owned_listeners_ready(
        &mut self,
        binding: &WindowsWfpRuntimeBinding,
        listeners: &[WindowsDirectConnectorEndpoint],
    ) -> Result<(), WindowsWfpSessionError> {
        validate_binding(&self.identity, binding)?;
        if self.kernel_binding.as_ref() != Some(binding) {
            return Err(WindowsWfpSessionError::KernelRegistrationMissing);
        }
        if listeners != self.identity.listeners {
            return Err(WindowsWfpSessionError::ListenerIdentityMismatch);
        }
        if self.active.is_some() {
            return Err(WindowsWfpSessionError::SessionAlreadyActive);
        }
        self.listener_binding = Some(binding.clone());
        Ok(())
    }

    pub fn execute(
        &mut self,
        command: &WindowsWfpRuntimeCommand,
    ) -> Result<WindowsWfpSessionCompletion, WindowsWfpSessionError> {
        match command {
            WindowsWfpRuntimeCommand::CommitAtomicDynamicSession {
                binding,
                session_generation,
                target_pid,
            } => {
                self.require_activation_proofs(binding)?;
                if self.active.is_some() {
                    return Err(WindowsWfpSessionError::SessionAlreadyActive);
                }
                let plan = prepare_windows_wfp_dynamic_session_plan(
                    &self.identity,
                    binding,
                    *session_generation,
                    *target_pid,
                )?;
                self.last_session_generation = Some(*session_generation);
                self.last_filter_inspection = None;
                self.active = Some(activate_windows_wfp_dynamic_session(&mut self.api, &plan)?);
                Ok(WindowsWfpSessionCompletion::Activated {
                    binding: binding.clone(),
                    session_generation: *session_generation,
                })
            }
            WindowsWfpRuntimeCommand::CloseDynamicSession {
                binding,
                session_generation,
            } => {
                validate_binding(&self.identity, binding)?;
                let active = self
                    .active
                    .as_mut()
                    .ok_or(WindowsWfpSessionError::NoActiveSession)?;
                if active.binding != *binding || active.session_generation != *session_generation {
                    return Err(WindowsWfpSessionError::ActiveSessionMismatch);
                }
                self.api
                    .close_dynamic_session(&mut active.handle)
                    .map_err(|error| primitive_error("close_dynamic_session", error))?;
                self.active = None;
                Ok(WindowsWfpSessionCompletion::Closed {
                    binding: binding.clone(),
                    session_generation: *session_generation,
                })
            }
            WindowsWfpRuntimeCommand::InspectOwnedFilters {
                binding,
                session_generation,
            } => {
                validate_binding(&self.identity, binding)?;
                if self.active.is_some() {
                    return Err(WindowsWfpSessionError::SessionStillActive);
                }
                if *session_generation != self.last_session_generation {
                    return Err(WindowsWfpSessionError::InspectionSessionMismatch);
                }
                let inspection = self
                    .api
                    .inspect_owned_filters(binding, *session_generation)
                    .map_err(|error| primitive_error("inspect_owned_filters", error))?;
                self.last_filter_inspection = Some(inspection.clone());
                Ok(WindowsWfpSessionCompletion::FiltersInspected(inspection))
            }
            _ => Err(WindowsWfpSessionError::UnsupportedRuntimeCommand(
                command.kind(),
            )),
        }
    }

    pub fn record_owned_listeners_stopped(
        &mut self,
        binding: &WindowsWfpRuntimeBinding,
    ) -> Result<(), WindowsWfpSessionError> {
        self.require_filter_absence(binding)?;
        if self.listener_binding.as_ref() != Some(binding) {
            return Err(WindowsWfpSessionError::InvalidControllerOrder(
                "listener stop completion requires the exact retained listener proof",
            ));
        }
        self.listener_binding = None;
        Ok(())
    }

    pub fn record_kernel_callouts_unregistered(
        &mut self,
        binding: &WindowsWfpRuntimeBinding,
    ) -> Result<(), WindowsWfpSessionError> {
        self.require_filter_absence(binding)?;
        if self.kernel_binding.as_ref() != Some(binding) {
            return Err(WindowsWfpSessionError::InvalidControllerOrder(
                "kernel unregister completion requires the exact retained registration proof",
            ));
        }
        if self.listener_binding.is_some() {
            return Err(WindowsWfpSessionError::InvalidControllerOrder(
                "kernel unregister requires stopped listeners",
            ));
        }
        self.kernel_binding = None;
        self.last_session_generation = None;
        self.last_filter_inspection = None;
        Ok(())
    }

    fn require_activation_proofs(
        &self,
        binding: &WindowsWfpRuntimeBinding,
    ) -> Result<(), WindowsWfpSessionError> {
        validate_binding(&self.identity, binding)?;
        if self.kernel_binding.as_ref() != Some(binding) {
            return Err(WindowsWfpSessionError::KernelRegistrationMissing);
        }
        if self.listener_binding.as_ref() != Some(binding) {
            return Err(WindowsWfpSessionError::ListenerReadinessMissing);
        }
        Ok(())
    }

    fn require_filter_absence(
        &self,
        binding: &WindowsWfpRuntimeBinding,
    ) -> Result<(), WindowsWfpSessionError> {
        validate_binding(&self.identity, binding)?;
        if self.active.is_some() {
            return Err(WindowsWfpSessionError::SessionStillActive);
        }
        let inspection = self
            .last_filter_inspection
            .as_ref()
            .ok_or(WindowsWfpSessionError::FilterAbsenceNotProven)?;
        if inspection.binding != *binding
            || inspection.session_generation != self.last_session_generation
            || !inspection.filters_absent()
        {
            return Err(WindowsWfpSessionError::FilterAbsenceNotProven);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsWfpSessionCompletion {
    Activated {
        binding: WindowsWfpRuntimeBinding,
        session_generation: u64,
    },
    Closed {
        binding: WindowsWfpRuntimeBinding,
        session_generation: u64,
    },
    FiltersInspected(WindowsWfpFilterInspection),
}

#[derive(Clone, Debug, Default)]
pub struct RecordingWindowsWfpManagementApi {
    steps: Vec<String>,
    next_session: u64,
    fail_once: BTreeMap<String, String>,
    installed: BTreeMap<&'static str, u64>,
    retained_filters_on_close: BTreeSet<&'static str>,
}

impl RecordingWindowsWfpManagementApi {
    pub fn steps(&self) -> &[String] {
        &self.steps
    }

    pub fn fail_once(&mut self, stage: impl Into<String>, message: impl Into<String>) {
        self.fail_once.insert(stage.into(), message.into());
    }

    pub fn retain_filter_on_close(&mut self, object: WindowsWfpManagementObject) {
        if matches!(
            object,
            WindowsWfpManagementObject::FilterV4 | WindowsWfpManagementObject::FilterV6
        ) {
            self.retained_filters_on_close.insert(object.key());
        }
    }

    pub fn installed_objects(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.installed.keys().copied()
    }

    fn step(&mut self, stage: &'static str) -> Result<(), RecordingWindowsWfpManagementError> {
        self.steps.push(stage.to_owned());
        if let Some(message) = self.fail_once.remove(stage) {
            return Err(RecordingWindowsWfpManagementError { stage, message });
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct RecordingWindowsWfpSession {
    id: u64,
    transaction_open: bool,
    staged: BTreeSet<&'static str>,
    closed: bool,
}

impl WindowsWfpManagementApi for RecordingWindowsWfpManagementApi {
    type Session = RecordingWindowsWfpSession;
    type Error = RecordingWindowsWfpManagementError;

    fn open_dynamic_session(
        &mut self,
        _plan: &WindowsWfpDynamicSessionPlan,
    ) -> Result<Self::Session, Self::Error> {
        self.step("open_dynamic_session")?;
        self.next_session =
            self.next_session
                .checked_add(1)
                .ok_or_else(|| RecordingWindowsWfpManagementError {
                    stage: "open_dynamic_session",
                    message: "recording session id overflow".to_owned(),
                })?;
        Ok(RecordingWindowsWfpSession {
            id: self.next_session,
            transaction_open: false,
            staged: BTreeSet::new(),
            closed: false,
        })
    }

    fn begin_transaction(&mut self, session: &mut Self::Session) -> Result<(), Self::Error> {
        self.step("begin_transaction")?;
        session.transaction_open = true;
        Ok(())
    }

    fn add_object(
        &mut self,
        session: &mut Self::Session,
        object: WindowsWfpManagementObject,
        _plan: &WindowsWfpDynamicSessionPlan,
    ) -> Result<(), Self::Error> {
        self.step(object.as_str())?;
        session.staged.insert(object.key());
        Ok(())
    }

    fn commit_transaction(&mut self, session: &mut Self::Session) -> Result<(), Self::Error> {
        self.step("commit_transaction")?;
        for key in &session.staged {
            self.installed.insert(key, session.id);
        }
        session.staged.clear();
        session.transaction_open = false;
        Ok(())
    }

    fn abort_transaction(&mut self, session: &mut Self::Session) -> Result<(), Self::Error> {
        self.step("abort_transaction")?;
        session.staged.clear();
        session.transaction_open = false;
        Ok(())
    }

    fn close_dynamic_session(&mut self, session: &mut Self::Session) -> Result<(), Self::Error> {
        self.step("close_dynamic_session")?;
        self.installed.retain(|key, session_id| {
            *session_id != session.id || self.retained_filters_on_close.contains(key)
        });
        session.staged.clear();
        session.transaction_open = false;
        session.closed = true;
        Ok(())
    }

    fn inspect_owned_filters(
        &mut self,
        binding: &WindowsWfpRuntimeBinding,
        session_generation: Option<u64>,
    ) -> Result<WindowsWfpFilterInspection, Self::Error> {
        self.step("inspect_owned_filters")?;
        Ok(WindowsWfpFilterInspection {
            binding: binding.clone(),
            session_generation,
            ipv4_present: self.installed.contains_key(WINDOWS_WFP_FILTER_V4_KEY),
            ipv6_present: self.installed.contains_key(WINDOWS_WFP_FILTER_V6_KEY),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingWindowsWfpManagementError {
    stage: &'static str,
    message: String,
}

impl fmt::Display for RecordingWindowsWfpManagementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.stage, self.message)
    }
}

impl std::error::Error for RecordingWindowsWfpManagementError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsWfpSessionError {
    InvalidCaptureIdentity(WindowsWfpCaptureErrorCode),
    InvalidRuntimeBinding,
    InvalidSessionGeneration,
    TargetPidMismatch,
    InvalidCaptureInstance,
    InvalidExecutableHash,
    InvalidListenerSet,
    ListenerIdentityMismatch,
    InvalidProviderContextLength,
    InvalidProviderContextMagic,
    UnsupportedProviderContextVersion,
    UnsupportedProviderContextFlags,
    InvalidProviderContextGeneration,
    InvalidCaptureScope,
    ProviderContextReservedNotZero,
    KernelRegistrationMissing,
    ListenerReadinessMissing,
    SessionAlreadyActive,
    NoActiveSession,
    ActiveSessionMismatch,
    SessionStillActive,
    InspectionSessionMismatch,
    FilterAbsenceNotProven,
    InvalidControllerOrder(&'static str),
    UnsupportedRuntimeCommand(&'static str),
    NativeOperationFailed {
        stage: &'static str,
        message: String,
    },
    ActivationFailed {
        stage: &'static str,
        message: String,
        abort_error: Option<String>,
        close_error: Option<String>,
    },
}

impl fmt::Display for WindowsWfpSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCaptureIdentity(code) => {
                write!(formatter, "invalid capture identity: {code}")
            }
            Self::InvalidRuntimeBinding => formatter.write_str("invalid WFP runtime binding"),
            Self::InvalidSessionGeneration => formatter.write_str("invalid WFP session generation"),
            Self::TargetPidMismatch => formatter.write_str("WFP target PID mismatch"),
            Self::InvalidCaptureInstance => formatter.write_str("invalid WFP capture instance"),
            Self::InvalidExecutableHash => formatter.write_str("invalid service executable hash"),
            Self::InvalidListenerSet => {
                formatter.write_str("WFP session requires exact IPv4 and IPv6 loopback listeners")
            }
            Self::ListenerIdentityMismatch => formatter.write_str("WFP listener identity mismatch"),
            Self::InvalidProviderContextLength => {
                formatter.write_str("invalid WFP provider-context length")
            }
            Self::InvalidProviderContextMagic => {
                formatter.write_str("invalid WFP provider-context magic")
            }
            Self::UnsupportedProviderContextVersion => {
                formatter.write_str("unsupported WFP provider-context version")
            }
            Self::UnsupportedProviderContextFlags => {
                formatter.write_str("unsupported WFP provider-context flags")
            }
            Self::InvalidProviderContextGeneration => {
                formatter.write_str("invalid WFP provider-context generation")
            }
            Self::InvalidCaptureScope => formatter.write_str("invalid WFP capture scope"),
            Self::ProviderContextReservedNotZero => {
                formatter.write_str("WFP provider-context reserved bytes are not zero")
            }
            Self::KernelRegistrationMissing => {
                formatter.write_str("kernel callout registration proof is missing")
            }
            Self::ListenerReadinessMissing => {
                formatter.write_str("owned listener readiness proof is missing")
            }
            Self::SessionAlreadyActive => {
                formatter.write_str("WFP dynamic session is already active")
            }
            Self::NoActiveSession => formatter.write_str("WFP dynamic session is not active"),
            Self::ActiveSessionMismatch => {
                formatter.write_str("active WFP dynamic session identity mismatch")
            }
            Self::SessionStillActive => formatter.write_str("WFP dynamic session is still active"),
            Self::InspectionSessionMismatch => {
                formatter.write_str("WFP filter inspection session generation mismatch")
            }
            Self::FilterAbsenceNotProven => {
                formatter.write_str("exact owned-filter absence is not proven")
            }
            Self::InvalidControllerOrder(message) => {
                write!(formatter, "invalid WFP controller order: {message}")
            }
            Self::UnsupportedRuntimeCommand(command) => {
                write!(formatter, "unsupported WFP runtime command: {command}")
            }
            Self::NativeOperationFailed { stage, message } => {
                write!(formatter, "{stage} failed: {message}")
            }
            Self::ActivationFailed {
                stage,
                message,
                abort_error,
                close_error,
            } => {
                write!(
                    formatter,
                    "atomic WFP activation failed at {stage}: {message}"
                )?;
                if let Some(error) = abort_error {
                    write!(formatter, "; abort failed: {error}")?;
                }
                if let Some(error) = close_error {
                    write!(formatter, "; close failed: {error}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for WindowsWfpSessionError {}

fn validate_binding(
    identity: &WindowsWfpCaptureIdentity,
    binding: &WindowsWfpRuntimeBinding,
) -> Result<(), WindowsWfpSessionError> {
    if binding.service_generation != identity.service.generation
        || binding.capture_instance_id != identity.capture_instance_id
        || binding.runtime_generation == 0
    {
        return Err(WindowsWfpSessionError::InvalidRuntimeBinding);
    }
    Ok(())
}

fn exact_dual_stack_listeners(
    listeners: &[WindowsDirectConnectorEndpoint],
) -> Result<(SocketAddr, SocketAddr), WindowsWfpSessionError> {
    let mut ipv4 = None;
    let mut ipv6 = None;
    for listener in listeners {
        let address: IpAddr = listener
            .address
            .parse()
            .map_err(|_| WindowsWfpSessionError::InvalidListenerSet)?;
        if address.to_string() != listener.address || !address.is_loopback() || listener.port == 0 {
            return Err(WindowsWfpSessionError::InvalidListenerSet);
        }
        let endpoint = SocketAddr::new(address, listener.port);
        match address {
            IpAddr::V4(_) if ipv4.replace(endpoint).is_some() => {
                return Err(WindowsWfpSessionError::InvalidListenerSet)
            }
            IpAddr::V6(_) if ipv6.replace(endpoint).is_some() => {
                return Err(WindowsWfpSessionError::InvalidListenerSet)
            }
            _ => {}
        }
    }
    match (ipv4, ipv6) {
        (Some(ipv4), Some(ipv6)) if listeners.len() == 2 => Ok((ipv4, ipv6)),
        _ => Err(WindowsWfpSessionError::InvalidListenerSet),
    }
}

fn decode_lower_hex<const N: usize>(
    value: &str,
    error: WindowsWfpSessionError,
) -> Result<[u8; N], WindowsWfpSessionError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(error);
    }
    let mut decoded = [0_u8; N];
    for (index, byte) in decoded.iter_mut().enumerate() {
        let offset = index * 2;
        *byte =
            (hex_nibble(value.as_bytes()[offset]) << 4) | hex_nibble(value.as_bytes()[offset + 1]);
    }
    Ok(decoded)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("validated lower hexadecimal byte"),
    }
}

fn primitive_error(error_stage: &'static str, error: impl fmt::Display) -> WindowsWfpSessionError {
    WindowsWfpSessionError::NativeOperationFailed {
        stage: error_stage,
        message: error.to_string(),
    }
}

fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(copy_array(bytes, offset))
}

fn read_u16_be(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(copy_array(bytes, offset))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(copy_array(bytes, offset))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(copy_array(bytes, offset))
}

fn copy_array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    bytes[offset..offset + N]
        .try_into()
        .expect("validated provider-context bounds")
}
