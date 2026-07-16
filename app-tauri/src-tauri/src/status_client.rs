use std::fs;

use serde_json::{json, Map, Value};

pub(crate) const STATUS_PATH: &str = "/var/run/slipstream.status";
const STATUS_SCHEMA_V2: u64 = 2;
const STATUS_STALE_AFTER_SECS: f64 = 15.0;

fn status_updated_at(status: &Value) -> f64 {
    if status.get("schema_version").and_then(Value::as_u64) == Some(STATUS_SCHEMA_V2) {
        return status
            .pointer("/daemon/updated_at")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
    }
    status.get("ts").and_then(Value::as_f64).unwrap_or(0.0)
}

fn status_is_terminal_conflict(status: &Value) -> bool {
    if status.get("schema_version").and_then(Value::as_u64) == Some(STATUS_SCHEMA_V2) {
        return status.pointer("/daemon/state").and_then(Value::as_str) == Some("conflict");
    }
    status.get("state").and_then(Value::as_str) == Some("conflict")
}

fn v2_status_for_tray(status: &Value) -> Value {
    let daemon = status.get("daemon").unwrap_or(&Value::Null);
    let routes = status.get("routes").unwrap_or(&Value::Null);
    let mut route_health = Map::new();
    for route_class in ["local_bypass", "geo_exit", "direct_passthrough"] {
        let state = routes
            .get(route_class)
            .and_then(|route| route.get("state"))
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        route_health.insert(
            route_class.to_string(),
            json!({
                "state": state,
                "last_route_class": route_class,
            }),
        );
    }

    let mut system_dns = status
        .pointer("/environment/dns")
        .cloned()
        .unwrap_or_else(|| json!({"state": "unknown"}));
    if let Value::Object(dns) = &mut system_dns {
        let resolution_state = dns
            .get("resolution_state")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        dns.insert(
            "resolution_checks".to_string(),
            json!({"state": resolution_state}),
        );
    }

    let recovery = status.get("recovery").unwrap_or(&Value::Null);
    json!({
        "schema_version": STATUS_SCHEMA_V2,
        "state": daemon.get("state").and_then(Value::as_str).unwrap_or("off"),
        "version": daemon.get("version").and_then(Value::as_str).unwrap_or("unknown"),
        "pid": daemon.get("pid").and_then(Value::as_i64).unwrap_or(0),
        "ts": daemon.get("updated_at").and_then(Value::as_f64).unwrap_or(0.0),
        "conns": daemon.get("connections").and_then(Value::as_i64).unwrap_or(0),
        "hosts_learned": daemon.get("hosts_learned").and_then(Value::as_i64).unwrap_or(0),
        "dead": daemon.get("dead_hosts").and_then(Value::as_i64).unwrap_or(0),
        "geph": status.pointer("/backends/geph/state").and_then(Value::as_str).unwrap_or("off"),
        "geph_detail": status.pointer("/backends/geph").cloned().unwrap_or_else(|| json!({})),
        "auto_geo_exit": status.pointer("/backends/geph/auto_geo_exit").cloned().unwrap_or_else(|| json!({})),
        "telegram_proxy": status.pointer("/backends/telegram/state").and_then(Value::as_str).unwrap_or("unknown"),
        "telegram_proxy_suggest": status.pointer("/backends/telegram/suggested").and_then(Value::as_bool).unwrap_or(false),
        "route_health": route_health,
        "system_proxy": status.pointer("/environment/proxy").cloned().unwrap_or_else(|| json!({"state": "unknown", "kind": ""})),
        "system_dns": system_dns,
        "pf_state": status.pointer("/environment/pf").cloned().unwrap_or_else(|| json!({"applied": false, "enabled": false, "rules_loaded": false})),
        "rearm": {
            "last_at": recovery.get("updated_at").and_then(Value::as_f64).unwrap_or(0.0),
            "last_reason": recovery.get("last_action").and_then(Value::as_str).unwrap_or(""),
            "count": recovery.get("count").and_then(Value::as_i64).unwrap_or(0),
        },
        "canaries": status.get("canaries").cloned().unwrap_or_else(|| json!({})),
    })
}

fn status_for_tray(status: Value) -> Value {
    if status.get("schema_version").and_then(Value::as_u64) == Some(STATUS_SCHEMA_V2) {
        v2_status_for_tray(&status)
    } else {
        status
    }
}

fn status_from_raw(raw: &str, now: f64) -> Option<Value> {
    let status: Value = serde_json::from_str(raw).ok()?;
    if now - status_updated_at(&status) > STATUS_STALE_AFTER_SECS
        && !status_is_terminal_conflict(&status)
    {
        return None;
    }
    Some(status_for_tray(status))
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
