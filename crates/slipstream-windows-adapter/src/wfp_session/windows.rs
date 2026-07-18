//! Native Windows Filtering Platform management-session primitives.
//!
//! The implementation can create the exact v1 provider, sublayer, management
//! callouts, provider context, and V4/V6 filters in one dynamic transaction.
//! It is deliberately not composed into the production service host. The
//! disposable CI probe opens an empty dynamic session, begins and aborts an
//! empty transaction, and proves the owned filter keys remain absent; live
//! filter commit stays closed until a disposable kernel callout is registered.

use super::{
    WindowsWfpDynamicSessionPlan, WindowsWfpManagementApi, WindowsWfpManagementObject,
    WINDOWS_WFP_CALLOUT_V4_KEY_U128, WINDOWS_WFP_CALLOUT_V6_KEY_U128, WINDOWS_WFP_CAPTURE_PROTOCOL,
    WINDOWS_WFP_CAPTURE_REMOTE_PORT, WINDOWS_WFP_FILTER_V4_KEY_U128,
    WINDOWS_WFP_FILTER_V6_KEY_U128, WINDOWS_WFP_PROVIDER_CONTEXT_KEY_U128,
    WINDOWS_WFP_PROVIDER_KEY_U128, WINDOWS_WFP_SUBLAYER_KEY_U128,
};
use crate::wfp_runtime::{WindowsWfpFilterInspection, WindowsWfpRuntimeBinding};
use std::ffi::c_void;
use std::fmt;
use std::ptr::{null, null_mut};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, FWP_E_FILTER_NOT_FOUND, HANDLE};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmCalloutAdd0, FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterGetByKey0,
    FwpmFreeMemory0, FwpmProviderAdd0, FwpmProviderContextAdd0, FwpmSubLayerAdd0,
    FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_ACTION0,
    FWPM_ACTION0_0, FWPM_CALLOUT0, FWPM_CALLOUT_FLAG_USES_PROVIDER_CONTEXT,
    FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0, FWPM_FILTER0,
    FWPM_FILTER0_0, FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT,
    FWPM_GENERAL_CONTEXT, FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
    FWPM_PROVIDER0, FWPM_PROVIDER_CONTEXT0, FWPM_PROVIDER_CONTEXT0_0, FWPM_SESSION0,
    FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWP_ACTION_CALLOUT_TERMINATING, FWP_BYTE_BLOB,
    FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_EMPTY, FWP_MATCH_EQUAL, FWP_UINT16,
    FWP_UINT8, FWP_VALUE0,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

const TRANSACTION_WAIT_TIMEOUT_MS: u32 = 1_000;
const SUBLAYER_WEIGHT: u16 = 0x7fff;

#[derive(Default)]
pub struct WindowsFwpmManagementApi;

pub struct WindowsFwpmSession {
    handle: HANDLE,
    transaction_open: bool,
}

impl Drop for WindowsFwpmSession {
    fn drop(&mut self) {
        if self.handle.is_null() {
            return;
        }
        if self.transaction_open {
            unsafe {
                FwpmTransactionAbort0(self.handle);
            }
            self.transaction_open = false;
        }
        unsafe {
            FwpmEngineClose0(self.handle);
        }
        self.handle = null_mut();
    }
}

impl WindowsWfpManagementApi for WindowsFwpmManagementApi {
    type Session = WindowsFwpmSession;
    type Error = WindowsFwpmError;

    fn open_dynamic_session(
        &mut self,
        plan: &WindowsWfpDynamicSessionPlan,
    ) -> Result<Self::Session, Self::Error> {
        open_engine(Some(plan))
    }

    fn begin_transaction(&mut self, session: &mut Self::Session) -> Result<(), Self::Error> {
        require_session_open(session, "begin_transaction")?;
        if session.transaction_open {
            return Err(WindowsFwpmError::state(
                "begin_transaction",
                "transaction is already open",
            ));
        }
        check_code("FwpmTransactionBegin0", unsafe {
            FwpmTransactionBegin0(session.handle, 0)
        })?;
        session.transaction_open = true;
        Ok(())
    }

    fn add_object(
        &mut self,
        session: &mut Self::Session,
        object: WindowsWfpManagementObject,
        plan: &WindowsWfpDynamicSessionPlan,
    ) -> Result<(), Self::Error> {
        require_transaction_open(session, object.as_str())?;
        match object {
            WindowsWfpManagementObject::Provider => add_provider(session.handle),
            WindowsWfpManagementObject::Sublayer => add_sublayer(session.handle),
            WindowsWfpManagementObject::CalloutV4 => add_callout(
                session.handle,
                WINDOWS_WFP_CALLOUT_V4_KEY_U128,
                FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
                "Slipstream connect redirect V4",
            ),
            WindowsWfpManagementObject::CalloutV6 => add_callout(
                session.handle,
                WINDOWS_WFP_CALLOUT_V6_KEY_U128,
                FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
                "Slipstream connect redirect V6",
            ),
            WindowsWfpManagementObject::ProviderContext => {
                add_provider_context(session.handle, plan.provider_context())
            }
            WindowsWfpManagementObject::FilterV4 => add_filter(
                session.handle,
                WINDOWS_WFP_FILTER_V4_KEY_U128,
                WINDOWS_WFP_CALLOUT_V4_KEY_U128,
                FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
                "Slipstream TCP/443 redirect V4",
            ),
            WindowsWfpManagementObject::FilterV6 => add_filter(
                session.handle,
                WINDOWS_WFP_FILTER_V6_KEY_U128,
                WINDOWS_WFP_CALLOUT_V6_KEY_U128,
                FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
                "Slipstream TCP/443 redirect V6",
            ),
        }
    }

    fn commit_transaction(&mut self, session: &mut Self::Session) -> Result<(), Self::Error> {
        require_transaction_open(session, "commit_transaction")?;
        check_code("FwpmTransactionCommit0", unsafe {
            FwpmTransactionCommit0(session.handle)
        })?;
        session.transaction_open = false;
        Ok(())
    }

    fn abort_transaction(&mut self, session: &mut Self::Session) -> Result<(), Self::Error> {
        require_transaction_open(session, "abort_transaction")?;
        check_code("FwpmTransactionAbort0", unsafe {
            FwpmTransactionAbort0(session.handle)
        })?;
        session.transaction_open = false;
        Ok(())
    }

    fn close_dynamic_session(&mut self, session: &mut Self::Session) -> Result<(), Self::Error> {
        require_session_open(session, "close_dynamic_session")?;
        if session.transaction_open {
            return Err(WindowsFwpmError::state(
                "close_dynamic_session",
                "transaction must commit or abort before close",
            ));
        }
        check_code("FwpmEngineClose0", unsafe {
            FwpmEngineClose0(session.handle)
        })?;
        session.handle = null_mut();
        Ok(())
    }

    fn inspect_owned_filters(
        &mut self,
        binding: &WindowsWfpRuntimeBinding,
        session_generation: Option<u64>,
    ) -> Result<WindowsWfpFilterInspection, Self::Error> {
        let mut observer = open_engine(None)?;
        let ipv4_present = filter_present(
            observer.handle,
            GUID::from_u128(WINDOWS_WFP_FILTER_V4_KEY_U128),
        )?;
        let ipv6_present = filter_present(
            observer.handle,
            GUID::from_u128(WINDOWS_WFP_FILTER_V6_KEY_U128),
        )?;
        self.close_dynamic_session(&mut observer)?;
        Ok(WindowsWfpFilterInspection {
            binding: binding.clone(),
            session_generation,
            ipv4_present,
            ipv6_present,
        })
    }
}

fn open_engine(
    plan: Option<&WindowsWfpDynamicSessionPlan>,
) -> Result<WindowsFwpmSession, WindowsFwpmError> {
    let mut display_name = plan.map(|plan| {
        wide(&format!(
            "Slipstream WFP runtime {}:{}:{}",
            plan.binding().service_generation,
            plan.binding().runtime_generation,
            plan.session_generation()
        ))
    });
    let mut description = plan.map(|_| wide("Ephemeral Slipstream WFP redirect session"));
    let mut session = FWPM_SESSION0::default();
    if let Some(plan) = plan {
        session.sessionKey = session_key(plan);
        session.displayData = FWPM_DISPLAY_DATA0 {
            name: display_name
                .as_mut()
                .expect("dynamic session display name")
                .as_mut_ptr(),
            description: description
                .as_mut()
                .expect("dynamic session description")
                .as_mut_ptr(),
        };
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        session.txnWaitTimeoutInMSec = TRANSACTION_WAIT_TIMEOUT_MS;
    }

    let mut handle: HANDLE = null_mut();
    check_code("FwpmEngineOpen0", unsafe {
        FwpmEngineOpen0(
            null(),
            RPC_C_AUTHN_WINNT,
            null(),
            if plan.is_some() { &session } else { null() },
            &mut handle,
        )
    })?;
    if handle.is_null() {
        return Err(WindowsFwpmError::state(
            "FwpmEngineOpen0",
            "WFP returned a null engine handle",
        ));
    }
    Ok(WindowsFwpmSession {
        handle,
        transaction_open: false,
    })
}

fn add_provider(handle: HANDLE) -> Result<(), WindowsFwpmError> {
    let mut name = wide("Slipstream");
    let mut description = wide("Slipstream ephemeral WFP provider");
    let provider = FWPM_PROVIDER0 {
        providerKey: GUID::from_u128(WINDOWS_WFP_PROVIDER_KEY_U128),
        displayData: display_data(&mut name, &mut description),
        flags: 0,
        providerData: FWP_BYTE_BLOB::default(),
        serviceName: null_mut(),
    };
    check_code("FwpmProviderAdd0", unsafe {
        FwpmProviderAdd0(handle, &provider, null_mut())
    })
}

fn add_sublayer(handle: HANDLE) -> Result<(), WindowsFwpmError> {
    let mut provider_key = GUID::from_u128(WINDOWS_WFP_PROVIDER_KEY_U128);
    let mut name = wide("Slipstream redirect");
    let mut description = wide("Slipstream ephemeral connect-redirect sublayer");
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: GUID::from_u128(WINDOWS_WFP_SUBLAYER_KEY_U128),
        displayData: display_data(&mut name, &mut description),
        flags: 0,
        providerKey: &mut provider_key,
        providerData: FWP_BYTE_BLOB::default(),
        weight: SUBLAYER_WEIGHT,
    };
    check_code("FwpmSubLayerAdd0", unsafe {
        FwpmSubLayerAdd0(handle, &sublayer, null_mut())
    })
}

fn add_callout(
    handle: HANDLE,
    callout_key: u128,
    layer_key: GUID,
    label: &str,
) -> Result<(), WindowsFwpmError> {
    let mut provider_key = GUID::from_u128(WINDOWS_WFP_PROVIDER_KEY_U128);
    let mut name = wide(label);
    let mut description = wide("Slipstream ephemeral management callout");
    let callout = FWPM_CALLOUT0 {
        calloutKey: GUID::from_u128(callout_key),
        displayData: display_data(&mut name, &mut description),
        flags: FWPM_CALLOUT_FLAG_USES_PROVIDER_CONTEXT,
        providerKey: &mut provider_key,
        providerData: FWP_BYTE_BLOB::default(),
        applicableLayer: layer_key,
        calloutId: 0,
    };
    let mut callout_id = 0;
    check_code("FwpmCalloutAdd0", unsafe {
        FwpmCalloutAdd0(handle, &callout, null_mut(), &mut callout_id)
    })
}

fn add_provider_context(handle: HANDLE, context: &[u8]) -> Result<(), WindowsFwpmError> {
    let mut provider_key = GUID::from_u128(WINDOWS_WFP_PROVIDER_KEY_U128);
    let mut name = wide("Slipstream runtime identity");
    let mut description = wide("Exact owned listener and service identity");
    let mut data = FWP_BYTE_BLOB {
        size: context.len() as u32,
        data: context.as_ptr().cast_mut(),
    };
    let provider_context = FWPM_PROVIDER_CONTEXT0 {
        providerContextKey: GUID::from_u128(WINDOWS_WFP_PROVIDER_CONTEXT_KEY_U128),
        displayData: display_data(&mut name, &mut description),
        flags: 0,
        providerKey: &mut provider_key,
        providerData: FWP_BYTE_BLOB::default(),
        r#type: FWPM_GENERAL_CONTEXT,
        Anonymous: FWPM_PROVIDER_CONTEXT0_0 {
            dataBuffer: &mut data,
        },
        providerContextId: 0,
    };
    let mut provider_context_id = 0;
    check_code("FwpmProviderContextAdd0", unsafe {
        FwpmProviderContextAdd0(
            handle,
            &provider_context,
            null_mut(),
            &mut provider_context_id,
        )
    })
}

fn add_filter(
    handle: HANDLE,
    filter_key: u128,
    callout_key: u128,
    layer_key: GUID,
    label: &str,
) -> Result<(), WindowsFwpmError> {
    let mut provider_key = GUID::from_u128(WINDOWS_WFP_PROVIDER_KEY_U128);
    let mut name = wide(label);
    let mut description = wide("Slipstream TCP/443 connect redirect");
    let mut conditions = [
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_PROTOCOL,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint8: WINDOWS_WFP_CAPTURE_PROTOCOL,
                },
            },
        },
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT16,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint16: WINDOWS_WFP_CAPTURE_REMOTE_PORT,
                },
            },
        },
    ];
    let filter = FWPM_FILTER0 {
        filterKey: GUID::from_u128(filter_key),
        displayData: display_data(&mut name, &mut description),
        flags: FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT,
        providerKey: &mut provider_key,
        providerData: FWP_BYTE_BLOB::default(),
        layerKey: layer_key,
        subLayerKey: GUID::from_u128(WINDOWS_WFP_SUBLAYER_KEY_U128),
        weight: FWP_VALUE0 {
            r#type: FWP_EMPTY,
            ..FWP_VALUE0::default()
        },
        numFilterConditions: conditions.len() as u32,
        filterCondition: conditions.as_mut_ptr(),
        action: FWPM_ACTION0 {
            r#type: FWP_ACTION_CALLOUT_TERMINATING,
            Anonymous: FWPM_ACTION0_0 {
                calloutKey: GUID::from_u128(callout_key),
            },
        },
        Anonymous: FWPM_FILTER0_0 {
            providerContextKey: GUID::from_u128(WINDOWS_WFP_PROVIDER_CONTEXT_KEY_U128),
        },
        reserved: null_mut(),
        filterId: 0,
        effectiveWeight: FWP_VALUE0::default(),
    };
    let mut filter_id = 0;
    check_code("FwpmFilterAdd0", unsafe {
        FwpmFilterAdd0(handle, &filter, null_mut(), &mut filter_id)
    })
}

fn filter_present(handle: HANDLE, key: GUID) -> Result<bool, WindowsFwpmError> {
    let mut filter = null_mut::<FWPM_FILTER0>();
    let code = unsafe { FwpmFilterGetByKey0(handle, &key, &mut filter) };
    if code == ERROR_SUCCESS {
        let mut erased = filter.cast::<c_void>();
        unsafe {
            FwpmFreeMemory0(&mut erased);
        }
        return Ok(true);
    }
    if code == FWP_E_FILTER_NOT_FOUND as u32 {
        return Ok(false);
    }
    Err(WindowsFwpmError::code("FwpmFilterGetByKey0", code))
}

fn session_key(plan: &WindowsWfpDynamicSessionPlan) -> GUID {
    let binding = plan.binding();
    let value = WINDOWS_WFP_PROVIDER_KEY_U128
        ^ ((binding.service_generation as u128) << 64)
        ^ ((binding.runtime_generation as u128) << 32)
        ^ plan.session_generation() as u128;
    GUID::from_u128(value)
}

fn require_session_open(
    session: &WindowsFwpmSession,
    stage: &'static str,
) -> Result<(), WindowsFwpmError> {
    if session.handle.is_null() {
        return Err(WindowsFwpmError::state(stage, "engine session is closed"));
    }
    Ok(())
}

fn require_transaction_open(
    session: &WindowsFwpmSession,
    stage: &'static str,
) -> Result<(), WindowsFwpmError> {
    require_session_open(session, stage)?;
    if !session.transaction_open {
        return Err(WindowsFwpmError::state(stage, "transaction is not open"));
    }
    Ok(())
}

fn display_data(name: &mut [u16], description: &mut [u16]) -> FWPM_DISPLAY_DATA0 {
    FWPM_DISPLAY_DATA0 {
        name: name.as_mut_ptr(),
        description: description.as_mut_ptr(),
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn check_code(stage: &'static str, code: u32) -> Result<(), WindowsFwpmError> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(WindowsFwpmError::code(stage, code))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsFwpmError {
    stage: &'static str,
    detail: WindowsFwpmErrorDetail,
}

impl WindowsFwpmError {
    fn code(stage: &'static str, code: u32) -> Self {
        Self {
            stage,
            detail: WindowsFwpmErrorDetail::Code(code),
        }
    }

    fn state(stage: &'static str, message: &'static str) -> Self {
        Self {
            stage,
            detail: WindowsFwpmErrorDetail::State(message),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum WindowsFwpmErrorDetail {
    Code(u32),
    State(&'static str),
}

impl fmt::Display for WindowsFwpmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.detail {
            WindowsFwpmErrorDetail::Code(code) => {
                write!(formatter, "{} returned 0x{code:08x}", self.stage)
            }
            WindowsFwpmErrorDetail::State(message) => {
                write!(formatter, "{}: {message}", self.stage)
            }
        }
    }
}

impl std::error::Error for WindowsFwpmError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::direct_connector::WindowsDirectConnectorEndpoint;
    use crate::service_lifecycle::{WindowsServiceIdentity, WINDOWS_SERVICE_NAME};
    use crate::wfp_capture::WindowsWfpCaptureIdentity;
    use crate::wfp_session::prepare_windows_wfp_dynamic_session_plan;

    #[test]
    fn empty_dynamic_session_transaction_is_disposable_and_filter_free() {
        if std::env::var("SLIPSTREAM_WINDOWS_WFP_SESSION_CI").as_deref() != Ok("1") {
            return;
        }

        let identity = WindowsWfpCaptureIdentity {
            service: WindowsServiceIdentity {
                service_name: WINDOWS_SERVICE_NAME.to_owned(),
                executable_sha256:
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_owned(),
                generation: 7,
            },
            target_pid: std::process::id(),
            capture_instance_id: "00112233445566778899aabbccddeeff".to_owned(),
            listeners: vec![
                WindowsDirectConnectorEndpoint {
                    address: "127.0.0.1".to_owned(),
                    port: 1443,
                },
                WindowsDirectConnectorEndpoint {
                    address: "::1".to_owned(),
                    port: 1443,
                },
            ],
        };
        let binding = WindowsWfpRuntimeBinding {
            service_generation: identity.service.generation,
            capture_instance_id: identity.capture_instance_id.clone(),
            runtime_generation: 1,
        };
        let plan =
            prepare_windows_wfp_dynamic_session_plan(&identity, &binding, 1, identity.target_pid)
                .expect("prepare disposable WFP session");
        let mut api = WindowsFwpmManagementApi;

        let before = api
            .inspect_owned_filters(&binding, Some(1))
            .expect("inspect filters before probe");
        assert!(before.filters_absent());

        let mut session = api
            .open_dynamic_session(&plan)
            .expect("open dynamic WFP session");
        api.begin_transaction(&mut session)
            .expect("begin empty WFP transaction");
        api.abort_transaction(&mut session)
            .expect("abort empty WFP transaction");
        api.close_dynamic_session(&mut session)
            .expect("close dynamic WFP session");

        let after = api
            .inspect_owned_filters(&binding, Some(1))
            .expect("inspect filters after probe");
        assert!(after.filters_absent());
    }
}
