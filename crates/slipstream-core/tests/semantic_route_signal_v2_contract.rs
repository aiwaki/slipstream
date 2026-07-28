use serde::Deserialize;
use serde_json::{Map, Value};
use slipstream_core::semantic_route_signal::{
    parse_semantic_route_signal_v1, parse_semantic_route_signal_v2,
    reduce_semantic_route_signal_v2, validate_semantic_route_signal, SemanticRouteSignalContext,
    SemanticRouteSignalDecision, SemanticSignalErrorCode,
};

#[derive(Debug, Deserialize)]
struct Contract {
    signal_defaults: Value,
    context_defaults: Value,
    parser_vectors: Vec<ParserVector>,
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct ParserVector {
    name: String,
    remove: Option<String>,
    #[serde(default)]
    replace: Map<String, Value>,
    #[serde(default)]
    add: Map<String, Value>,
    expected_error: SemanticSignalErrorCode,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    #[serde(default)]
    signal: Value,
    #[serde(default)]
    context: Value,
    expected: SemanticRouteSignalDecision,
}

fn merge(defaults: &Value, override_value: &Value) -> Value {
    let mut merged = defaults
        .as_object()
        .expect("defaults must be an object")
        .clone();
    if let Some(overrides) = override_value.as_object() {
        for (key, value) in overrides {
            merged.insert(key.clone(), value.clone());
        }
    }
    Value::Object(merged)
}

fn contract() -> Contract {
    serde_json::from_str(include_str!(
        "../../../contracts/semantic-route-signal-v2.json"
    ))
    .expect("semantic signal v2 contract must parse")
}

#[test]
fn rust_executes_semantic_route_signal_v2_contract() {
    let contract = contract();
    for vector in contract.vectors {
        let signal_value = merge(&contract.signal_defaults, &vector.signal);
        let signal_bytes = serde_json::to_vec(&signal_value).expect("signal must encode");
        let signal = parse_semantic_route_signal_v2(&signal_bytes).expect("signal must be valid");
        let context: SemanticRouteSignalContext =
            serde_json::from_value(merge(&contract.context_defaults, &vector.context))
                .expect("context must parse");

        let decision = reduce_semantic_route_signal_v2(&signal, &context);

        assert_eq!(decision, vector.expected, "{}", vector.name);
    }
}

#[test]
fn rust_executes_semantic_route_signal_v2_parser_contract() {
    let contract = contract();
    for vector in contract.parser_vectors {
        let mut payload = contract
            .signal_defaults
            .as_object()
            .expect("signal defaults must be an object")
            .clone();
        if let Some(field) = vector.remove {
            payload.remove(&field);
        }
        payload.extend(vector.replace);
        payload.extend(vector.add);

        let error = parse_semantic_route_signal_v2(
            &serde_json::to_vec(&Value::Object(payload)).expect("payload must encode"),
        )
        .expect_err("invalid parser vector must fail closed");

        assert_eq!(error.code, vector.expected_error, "{}", vector.name);
    }
}

#[test]
fn dispatcher_accepts_both_frozen_v1_and_additive_v2() {
    let v1 = include_bytes!("../../../contracts/semantic-route-signal-v1.json");
    let v1_contract: Value = serde_json::from_slice(v1).expect("v1 contract must parse");
    let v1_signal =
        serde_json::to_vec(&v1_contract["signal_defaults"]).expect("v1 signal must encode");
    let v2_signal = serde_json::to_vec(&contract().signal_defaults).expect("v2 signal must encode");

    assert!(parse_semantic_route_signal_v1(&v1_signal).is_ok());
    assert!(validate_semantic_route_signal(&v1_signal).is_ok());
    assert!(validate_semantic_route_signal(&v2_signal).is_ok());
}
