use std::fs;

use serde_json::{json, Map, Value};
use slipstream_core::status_v2::{status_v2_from_value, StatusV2, STATUS_SCHEMA_V2};

pub(crate) const STATUS_PATH: &str = "/var/run/slipstream.status";
const STATUS_STALE_AFTER_SECS: f64 = 15.0;

enum ParsedStatus {
    V1(Value),
    V2(Box<StatusV2>),
}

impl ParsedStatus {
    fn from_value(status: Value) -> Option<Self> {
        if status.get("schema_version").and_then(Value::as_u64) == Some(STATUS_SCHEMA_V2) {
            return status_v2_from_value(status)
                .ok()
                .map(Box::new)
                .map(Self::V2);
        }
        Some(Self::V1(status))
    }

    fn updated_at(&self) -> f64 {
        match self {
            Self::V1(status) => status.get("ts").and_then(Value::as_f64).unwrap_or(0.0),
            Self::V2(status) => status.updated_at(),
        }
    }

    fn is_terminal_conflict(&self) -> bool {
        match self {
            Self::V1(status) => status.get("state").and_then(Value::as_str) == Some("conflict"),
            Self::V2(status) => status.is_terminal_conflict(),
        }
    }

    fn into_tray(self) -> Value {
        match self {
            Self::V1(status) => status,
            Self::V2(status) => v2_status_for_tray(&status),
        }
    }
}

#[cfg(test)]
fn status_updated_at(status: &Value) -> f64 {
    ParsedStatus::from_value(status.clone())
        .map(|status| status.updated_at())
        .unwrap_or(0.0)
}

fn v2_status_for_tray(status: &StatusV2) -> Value {
    let daemon = status.daemon.as_ref();
    let routes = status.routes.as_ref();
    let mut route_health = Map::new();
    for (route_class, route) in [
        (
            "local_bypass",
            routes.and_then(|routes| routes.local_bypass.as_ref()),
        ),
        (
            "geo_exit",
            routes.and_then(|routes| routes.geo_exit.as_ref()),
        ),
        (
            "direct_passthrough",
            routes.and_then(|routes| routes.direct_passthrough.as_ref()),
        ),
    ] {
        let state = route
            .and_then(|route| route.state.as_deref())
            .unwrap_or("unknown");
        route_health.insert(
            route_class.to_string(),
            json!({
                "state": state,
                "last_route_class": route_class,
            }),
        );
    }

    let environment = status.environment.as_ref();
    let dns = environment.and_then(|environment| environment.dns.as_ref());
    let mut system_dns = dns
        .map(|dns| serde_json::to_value(dns).expect("StatusV2 DNS must serialize"))
        .unwrap_or_else(|| json!({"state": "unknown"}));
    if let Value::Object(dns) = &mut system_dns {
        let resolution_state = status
            .environment
            .as_ref()
            .and_then(|environment| environment.dns.as_ref())
            .and_then(|dns| dns.resolution_state.as_deref())
            .unwrap_or("unknown")
            .to_string();
        dns.insert(
            "resolution_checks".to_string(),
            json!({"state": resolution_state}),
        );
    }

    let backends = status.backends.as_ref();
    let geph = backends.and_then(|backends| backends.geph.as_ref());
    let telegram = backends.and_then(|backends| backends.telegram.as_ref());
    let recovery = status.recovery.as_ref();
    json!({
        "schema_version": STATUS_SCHEMA_V2,
        "state": daemon.and_then(|daemon| daemon.state.as_deref()).unwrap_or("off"),
        "version": daemon.and_then(|daemon| daemon.version.as_deref()).unwrap_or("unknown"),
        "pid": daemon.and_then(|daemon| daemon.pid).unwrap_or(0),
        "ts": daemon.and_then(|daemon| daemon.updated_at).unwrap_or(0.0),
        "conns": daemon.and_then(|daemon| daemon.connections).unwrap_or(0),
        "hosts_learned": daemon.and_then(|daemon| daemon.hosts_learned).unwrap_or(0),
        "dead": daemon.and_then(|daemon| daemon.dead_hosts).unwrap_or(0),
        "geph": geph.and_then(|geph| geph.state.as_deref()).unwrap_or("off"),
        "geph_detail": geph.map(|geph| serde_json::to_value(geph).expect("StatusV2 Geph must serialize")).unwrap_or_else(|| json!({})),
        "auto_geo_exit": geph.and_then(|geph| geph.auto_geo_exit.as_ref()).map(|auto| serde_json::to_value(auto).expect("StatusV2 auto geo-exit must serialize")).unwrap_or_else(|| json!({})),
        "telegram_proxy": telegram.and_then(|telegram| telegram.state.as_deref()).unwrap_or("unknown"),
        "telegram_proxy_suggest": telegram.and_then(|telegram| telegram.suggested).unwrap_or(false),
        "route_health": route_health,
        "system_proxy": environment.and_then(|environment| environment.proxy.as_ref()).map(|proxy| serde_json::to_value(proxy).expect("StatusV2 proxy must serialize")).unwrap_or_else(|| json!({"state": "unknown", "kind": ""})),
        "system_dns": system_dns,
        "pf_state": environment.and_then(|environment| environment.pf.as_ref()).map(|pf| serde_json::to_value(pf).expect("StatusV2 PF must serialize")).unwrap_or_else(|| json!({"applied": false, "enabled": false, "rules_loaded": false})),
        "rearm": {
            "last_at": recovery.and_then(|recovery| recovery.updated_at).unwrap_or(0.0),
            "last_reason": recovery.and_then(|recovery| recovery.last_action.as_deref()).unwrap_or(""),
            "count": recovery.and_then(|recovery| recovery.count).unwrap_or(0),
        },
        "canaries": status.canaries.as_ref().map(|canaries| serde_json::to_value(canaries).expect("StatusV2 canaries must serialize")).unwrap_or_else(|| json!({})),
    })
}

#[cfg(test)]
fn status_for_tray(status: Value) -> Value {
    ParsedStatus::from_value(status)
        .map(ParsedStatus::into_tray)
        .unwrap_or(Value::Null)
}

fn status_from_raw(raw: &str, now: f64) -> Option<Value> {
    let status = ParsedStatus::from_value(serde_json::from_str(raw).ok()?)?;
    if now - status.updated_at() > STATUS_STALE_AFTER_SECS && !status.is_terminal_conflict() {
        return None;
    }
    Some(status.into_tray())
}

/// Daemon status, or `None` if the file is missing or has a stale live state.
pub(crate) fn read_status() -> Option<Value> {
    let raw = fs::read_to_string(STATUS_PATH).ok()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0);
    status_from_raw(&raw, now)
}

#[cfg(test)]
mod tests {
    use super::{status_for_tray, status_from_raw, status_updated_at};
    use crate::{routing_health_summary, system_proxy_from_status};
    use serde_json::json;

    const STATUS_V2_V1: &str = include_str!("../../../contracts/status-v2-v1.json");

    #[test]
    fn shared_status_v2_fixture_preserves_the_existing_tray_projection() {
        let contract: serde_json::Value = serde_json::from_str(STATUS_V2_V1).unwrap();
        let case = &contract["vectors"][0];
        assert_eq!(
            status_for_tray(case["status"].clone()),
            case["expected_tray"]
        );
    }

    #[test]
    fn status_v2_projects_to_the_existing_tray_contract() {
        let raw = json!({
            "schema_version": 2,
            "daemon": {
                "state": "active",
                "version": "0.1.8",
                "pid": 42,
                "updated_at": 100.0,
                "connections": 7,
                "hosts_learned": 23,
                "dead_hosts": 1,
            },
            "routes": {
                "local_bypass": {"state": "ok", "updated_at": 99.0},
                "geo_exit": {"state": "degraded", "updated_at": 98.0},
                "direct_passthrough": {"state": "unknown", "updated_at": 0.0},
            },
            "backends": {
                "geph": {
                    "state": "up",
                    "owned": true,
                    "auto_geo_exit": {"enabled": true, "learned": 1, "pending": 0},
                },
                "telegram": {"state": "ready", "suggested": false},
            },
            "environment": {
                "proxy": {"state": "active", "kind": "pac"},
                "dns": {
                    "state": "xbox_dns",
                    "providers": "xbox_dns",
                    "resolution_state": "ok",
                },
                "pf": {"applied": true, "enabled": true, "rules_loaded": true},
            },
            "recovery": {"state": "idle", "last_action": "none", "updated_at": 90.0, "count": 1},
            "canaries": {"total": 3, "ok": 2, "warnings": 0, "degraded": 1},
        });

        let status = status_for_tray(raw.clone());
        assert_eq!(status_updated_at(&raw), 100.0);
        assert_eq!(status["state"], "active");
        assert_eq!(status["version"], "0.1.8");
        assert_eq!(status["conns"], 7);
        assert_eq!(status["geph"], "up");
        assert_eq!(status["route_health"]["local_bypass"]["state"], "ok");
        assert_eq!(
            status["route_health"]["geo_exit"]["last_route_class"],
            "geo_exit"
        );
        assert_eq!(status["system_dns"]["resolution_checks"]["state"], "ok");
        assert_eq!(
            system_proxy_from_status(Some(&status)),
            Some((true, "pac".to_string()))
        );
        assert_eq!(
            routing_health_summary(Some(&status), "up", false),
            Some("Restoring access to external services".to_string())
        );
        assert!(!serde_json::to_string(&status)
            .unwrap()
            .contains("chatgpt.com"));

        let v1 = json!({"state": "active", "ts": 50.0});
        assert_eq!(status_updated_at(&v1), 50.0);
        assert_eq!(status_for_tray(v1.clone()), v1);
    }

    #[test]
    fn status_reader_accepts_fresh_v1_and_v2_and_rejects_bad_input() {
        let v1 = status_from_raw(r#"{"state":"active","ts":90.0}"#, 105.0).unwrap();
        assert_eq!(v1["state"], "active");

        let v2 = status_from_raw(
            r#"{"schema_version":2,"daemon":{"state":"active","updated_at":100.0}}"#,
            115.0,
        )
        .unwrap();
        assert_eq!(v2["schema_version"], 2);
        assert_eq!(v2["state"], "active");

        assert!(status_from_raw(r#"{"state":"active","ts":89.99}"#, 105.0).is_none());
        assert!(status_from_raw("not-json", 105.0).is_none());
    }

    #[test]
    fn status_reader_preserves_stale_terminal_conflict() {
        let v1 = status_from_raw(r#"{"state":"conflict","ts":1.0}"#, 100.0).unwrap();
        assert_eq!(v1["state"], "conflict");

        let v2 = status_from_raw(
            r#"{"schema_version":2,"daemon":{"state":"conflict","updated_at":1.0}}"#,
            100.0,
        )
        .unwrap();
        assert_eq!(v2["state"], "conflict");
    }
}
