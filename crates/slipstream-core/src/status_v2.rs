//! Privacy-bounded public daemon status schema shared by platform adapters.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const STATUS_SCHEMA_V2: u64 = 2;

type ExtraFields = BTreeMap<String, Value>;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct DaemonStatusV2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connections: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts_learned: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead_hosts: Option<i64>,
    #[serde(default, flatten)]
    pub extra: ExtraFields,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct RouteStatusV2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<f64>,
    #[serde(default, flatten)]
    pub extra: ExtraFields,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct RoutesStatusV2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_bypass: Option<RouteStatusV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geo_exit: Option<RouteStatusV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_passthrough: Option<RouteStatusV2>,
    #[serde(default, flatten)]
    pub extra: ExtraFields,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct LocalEngineStatusV2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, flatten)]
    pub extra: ExtraFields,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct AutoGeoExitStatusV2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub learned: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<f64>,
    #[serde(default, flatten)]
    pub extra: ExtraFields,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct GephStatusV2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owned: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_conflict: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_detected: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_recommended: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_sessions: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_geo_exit: Option<AutoGeoExitStatusV2>,
    #[serde(default, flatten)]
    pub extra: ExtraFields,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct TelegramStatusV2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested: Option<bool>,
    #[serde(default, flatten)]
    pub extra: ExtraFields,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct BackendsStatusV2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_engine: Option<LocalEngineStatusV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geph: Option<GephStatusV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telegram: Option<TelegramStatusV2>,
    #[serde(default, flatten)]
    pub extra: ExtraFields,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct PfStatusV2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules_loaded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interceptor_conflict: Option<bool>,
    #[serde(default, flatten)]
    pub extra: ExtraFields,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct ProxyStatusV2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_by_slipstream: Option<bool>,
    #[serde(default, flatten)]
    pub extra: ExtraFields,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct DnsStatusV2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub providers: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_by_slipstream: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_state: Option<String>,
    #[serde(default, flatten)]
    pub extra: ExtraFields,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct EnvironmentStatusV2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pf: Option<PfStatusV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<ProxyStatusV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsStatusV2>,
    #[serde(default, flatten)]
    pub extra: ExtraFields,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct RecoveryStatusV2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
    #[serde(default, flatten)]
    pub extra: ExtraFields,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CanaryStatusV2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub running: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warnings: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub degraded: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unknown: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_due_in: Option<i64>,
    #[serde(default, flatten)]
    pub extra: ExtraFields,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct StatusV2 {
    pub schema_version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon: Option<DaemonStatusV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routes: Option<RoutesStatusV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backends: Option<BackendsStatusV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<EnvironmentStatusV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryStatusV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canaries: Option<CanaryStatusV2>,
    #[serde(default, flatten)]
    pub extra: ExtraFields,
}

impl StatusV2 {
    pub fn updated_at(&self) -> f64 {
        self.daemon
            .as_ref()
            .and_then(|daemon| daemon.updated_at)
            .unwrap_or(0.0)
    }

    pub fn is_terminal_conflict(&self) -> bool {
        self.daemon
            .as_ref()
            .and_then(|daemon| daemon.state.as_deref())
            == Some("conflict")
    }
}

pub fn status_v2_from_value(value: Value) -> Result<StatusV2, String> {
    let status: StatusV2 =
        serde_json::from_value(value).map_err(|error| format!("invalid StatusV2: {error}"))?;
    if status.schema_version != STATUS_SCHEMA_V2 {
        return Err(format!(
            "unsupported status schema {}, expected {STATUS_SCHEMA_V2}",
            status.schema_version
        ));
    }
    Ok(status)
}
