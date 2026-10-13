//! Privacy-bounded public daemon status schema shared by platform adapters.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const STATUS_SCHEMA_V2: u64 = 2;

type ExtraFields = BTreeMap<String, Value>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonPhaseV2 {
    Starting,
    Active,
    Recovering,
    Stopping,
}

impl DaemonPhaseV2 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Active => "active",
            Self::Recovering => "recovering",
            Self::Stopping => "stopping",
        }
    }
}

/// Fixed-cardinality, public relay counts. No host history or extensible fields.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(default)]
pub struct RelayEndCountersV2 {
    pub upstream_eof: u32,
    pub upstream_read_error: u32,
    pub upstream_reset: u32,
    pub client_eof: u32,
    pub client_read_error: u32,
    pub local_partial_record_watchdog: u32,
    pub local_half_close_idle: u32,
    pub authorized_retry: u32,
    pub cancellation: u32,
    pub write_error: u32,
    pub internal_error: u32,
    pub unknown: u32,
}

/// Observations only: these counts never establish route health or route proof.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RelayDiagnosticsV2 {
    pub schema_version: u32,
    pub available: bool,
    pub counters: RelayEndCountersV2,
    pub counter_saturated: bool,
}

fn deserialize_relay_diagnostics<'de, D>(
    deserializer: D,
) -> Result<Option<RelayDiagnosticsV2>, D::Error>
where
    D: Deserializer<'de>,
{
    // Malformed optional observations must not invalidate the daemon heartbeat.
    // Decode into a typed projection; never retain the temporary JSON value.
    let value = Value::deserialize(deserializer)?;
    Ok(serde_json::from_value::<RelayDiagnosticsV2>(value)
        .ok()
        .filter(|diagnostics| diagnostics.schema_version == 1))
}

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
    /// Wall-clock publication time for the lightweight daemon heartbeat.
    ///
    /// This is intentionally separate from `updated_at`: health collection can
    /// be slow while the daemon and its listener remain alive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat_at: Option<String>,
    /// Monotonic sequence published by the independent heartbeat loop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat_seq: Option<u64>,
    /// Wall-clock time at which the slower health payload was last refreshed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_updated_at: Option<String>,
    /// Coarse lifecycle phase (`starting`, `active`, `recovering`, `stopping`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<DaemonPhaseV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connections: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts_learned: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead_hosts: Option<i64>,
    #[serde(
        default,
        deserialize_with = "deserialize_relay_diagnostics",
        skip_serializing_if = "Option::is_none"
    )]
    pub relay_diagnostics: Option<RelayDiagnosticsV2>,
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

#[cfg(test)]
mod relay_diagnostics_tests {
    use super::status_v2_from_value;
    use serde_json::{json, Value};

    #[test]
    fn relay_diagnostics_roundtrip_keeps_only_fixed_public_counts() {
        let value = json!({
            "schema_version": 2,
            "daemon": {
                "state": "active",
                "relay_diagnostics": {
                    "schema_version": 1,
                    "available": true,
                    "counter_saturated": false,
                    "counters": {
                        "upstream_eof": 2,
                        "upstream_read_error": 3,
                        "upstream_reset": 4,
                        "client_eof": 5,
                        "client_read_error": 6,
                        "local_partial_record_watchdog": 7,
                        "local_half_close_idle": 13,
                        "authorized_retry": 8,
                        "cancellation": 9,
                        "write_error": 10,
                        "internal_error": 14,
                        "unknown": 11,
                        "private.example": 12,
                    },
                    "recent": [{"host": "private.example"}],
                    "url": "https://private.example/path?token=secret",
                },
            },
        });
        let status = status_v2_from_value(value).unwrap();
        let encoded = serde_json::to_value(&status).unwrap();
        let diagnostics = &encoded["daemon"]["relay_diagnostics"];
        assert_eq!(diagnostics["counters"]["local_partial_record_watchdog"], 7);
        assert_eq!(diagnostics["counters"]["authorized_retry"], 8);
        assert_eq!(diagnostics["counters"].as_object().unwrap().len(), 12);
        assert_eq!(diagnostics.as_object().unwrap().len(), 4);
        assert!(!encoded.to_string().contains("private.example"));
        assert!(!encoded.to_string().contains("secret"));
        assert_eq!(status_v2_from_value(encoded).unwrap(), status);
    }

    #[test]
    fn relay_diagnostics_missing_or_invalid_does_not_break_the_heartbeat() {
        for diagnostics in [
            Value::Null,
            json!("https://private.example/secret"),
            json!({}),
            json!({"schema_version": 2, "available": true,
                   "counters": {}, "counter_saturated": false}),
            json!({"schema_version": 1, "available": true,
                   "counters": {"upstream_eof": -1}, "counter_saturated": false}),
            json!({"schema_version": 1, "available": true,
                   "counters": {"upstream_eof": 4294967296u64}, "counter_saturated": false}),
        ] {
            let status = status_v2_from_value(json!({
                "schema_version": 2,
                "daemon": {"state": "active", "heartbeat_seq": 7,
                           "relay_diagnostics": diagnostics},
            }))
            .unwrap();
            let daemon = status.daemon.as_ref().unwrap();
            assert_eq!(daemon.heartbeat_seq, Some(7));
            assert!(daemon.relay_diagnostics.is_none());
            assert!(serde_json::to_value(&status).unwrap()["daemon"]
                .get("relay_diagnostics")
                .is_none());
        }
        let status = status_v2_from_value(json!({"schema_version": 2, "daemon": {}})).unwrap();
        assert!(status.daemon.unwrap().relay_diagnostics.is_none());
    }

    #[test]
    fn relay_diagnostics_unavailable_stays_explicitly_unavailable() {
        let status = status_v2_from_value(json!({
            "schema_version": 2,
            "daemon": {"relay_diagnostics": {
                "schema_version": 1, "available": false,
                "counters": {}, "counter_saturated": false,
            }},
        }))
        .unwrap();
        assert!(!status.daemon.unwrap().relay_diagnostics.unwrap().available);
    }
}
