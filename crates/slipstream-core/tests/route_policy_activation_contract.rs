use serde_json::{Map, Value};
use slipstream_core::route_policy_activation::{
    reduce_policy_activation, PolicyActivationErrorCode, PolicyActivationEvent,
    PolicyActivationState, PolicyIdentity, PolicyKind,
};

const CONTRACT_V1: &str = include_str!("../../../contracts/route-policy-activation-v1.json");

fn contract() -> Value {
    serde_json::from_str(CONTRACT_V1).expect("activation contract must be valid JSON")
}

fn resolve_policy_refs(value: &Value, policies: &Map<String, Value>) -> Value {
    match value {
        Value::Object(object) if object.len() == 1 && object.contains_key("$policy") => {
            let name = object["$policy"]
                .as_str()
                .expect("policy reference must be a string");
            policies
                .get(name)
                .unwrap_or_else(|| panic!("unknown policy reference {name}"))
                .clone()
        }
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, item)| (key.clone(), resolve_policy_refs(item, policies)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| resolve_policy_refs(item, policies))
                .collect(),
        ),
        _ => value.clone(),
    }
}

#[test]
fn rust_executes_route_policy_activation_v1_contract() {
    let contract = contract();
    let policies = contract["policies"]
        .as_object()
        .expect("policy catalog must be an object");

    for case in contract["vectors"].as_array().unwrap() {
        let mut state: PolicyActivationState =
            serde_json::from_value(resolve_policy_refs(&case["initial_state"], policies)).unwrap();
        let events = case["events"].as_array().unwrap();
        let expected = case["expected"].as_array().unwrap();
        assert_eq!(events.len(), expected.len(), "{}", case["name"]);

        for (event_value, expected_value) in events.iter().zip(expected) {
            let event: PolicyActivationEvent =
                serde_json::from_value(resolve_policy_refs(event_value, policies)).unwrap();
            let before = state.clone();
            let result = reduce_policy_activation(&state, &event);
            if expected_value["ok"].as_bool().unwrap() {
                let transition = result.unwrap_or_else(|error| {
                    panic!("{} unexpectedly failed: {error}", case["name"])
                });
                let actual = serde_json::to_value(&transition).unwrap();
                assert_eq!(
                    actual["decision"], expected_value["decision"],
                    "{}",
                    case["name"]
                );
                assert_eq!(
                    actual["reason"], expected_value["reason"],
                    "{}",
                    case["name"]
                );
                assert_eq!(
                    actual["actions"],
                    resolve_policy_refs(&expected_value["actions"], policies),
                    "{}",
                    case["name"]
                );
                state = transition.state;
            } else {
                let error = result.expect_err("contract expected an activation error");
                assert_eq!(
                    serde_json::to_value(error.code).unwrap(),
                    expected_value["error"]["code"],
                    "{}",
                    case["name"]
                );
                assert_eq!(
                    error.path, expected_value["error"]["path"],
                    "{}",
                    case["name"]
                );
                assert!(
                    error.to_string().contains(
                        expected_value["error"]["message_contains"]
                            .as_str()
                            .unwrap()
                    ),
                    "{}",
                    case["name"]
                );
                assert_eq!(state, before, "{}", case["name"]);
            }
        }

        let expected_state: PolicyActivationState =
            serde_json::from_value(resolve_policy_refs(&case["expected_final_state"], policies))
                .unwrap();
        assert_eq!(state, expected_state, "{}", case["name"]);
    }
}

#[test]
fn policy_source_limit_is_measured_in_utf8_bytes() {
    let bundled = PolicyIdentity {
        kind: PolicyKind::Bundled,
        source: "bundled:v1".into(),
        sha256: "0".repeat(64),
    };
    let state = PolicyActivationState {
        bundled: bundled.clone(),
        active: bundled.clone(),
        previous: None,
        candidate: None,
        phase: slipstream_core::route_policy_activation::PolicyActivationPhase::Stable,
    };
    let event = PolicyActivationEvent::BeginTrial {
        expected_active_sha256: bundled.sha256,
        policy: PolicyIdentity {
            kind: PolicyKind::Signed,
            source: "я".repeat(65),
            sha256: "5".repeat(64),
        },
    };

    let error = reduce_policy_activation(&state, &event).unwrap_err();
    assert_eq!(error.code, PolicyActivationErrorCode::InvalidSource);
    assert_eq!(error.path, "$.event.policy.source");
}
