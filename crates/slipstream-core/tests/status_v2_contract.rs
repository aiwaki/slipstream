use serde_json::{json, Value};
use slipstream_core::status_v2::{status_v2_from_value, STATUS_SCHEMA_V2};

const STATUS_V2_V1: &str = include_str!("../../../contracts/status-v2-v1.json");

fn contract() -> Value {
    serde_json::from_str(STATUS_V2_V1).expect("StatusV2 contract must be valid JSON")
}

#[test]
fn rust_round_trips_the_status_v2_contract_without_losing_extensions() {
    let contract = contract();
    let case = &contract["vectors"][0];
    let status = status_v2_from_value(case["status"].clone()).unwrap();

    assert_eq!(status.schema_version, STATUS_SCHEMA_V2);
    assert_eq!(status.updated_at(), 100.0);
    assert!(!status.is_terminal_conflict());
    assert_eq!(serde_json::to_value(status).unwrap(), case["status"]);
}

#[test]
fn status_v2_accepts_partial_transition_payloads_and_preserves_conflicts() {
    let raw = json!({
        "schema_version": 2,
        "daemon": {"state": "conflict", "updated_at": 1.0},
    });
    let status = status_v2_from_value(raw.clone()).unwrap();

    assert_eq!(status.updated_at(), 1.0);
    assert!(status.is_terminal_conflict());
    assert_eq!(serde_json::to_value(status).unwrap(), raw);
}

#[test]
fn status_v2_rejects_a_different_schema() {
    let error = status_v2_from_value(json!({"schema_version": 1})).unwrap_err();
    assert!(error.contains("unsupported status schema 1"));
}

#[test]
fn shared_status_fixture_contains_no_private_values() {
    let contract = contract();
    let public_status = serde_json::to_string(&contract["vectors"][0]["status"]).unwrap();
    for value in contract["privacy_forbidden_values"].as_array().unwrap() {
        assert!(!public_status.contains(value.as_str().unwrap()));
    }
}
