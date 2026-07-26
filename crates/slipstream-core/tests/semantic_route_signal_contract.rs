use serde::Deserialize;
use serde_json::{Map, Value};
use slipstream_core::semantic_route_signal::{
    parse_semantic_route_signal_v1, reduce_semantic_route_signal, SemanticRouteSignalContext,
    SemanticRouteSignalDecision, SemanticSignalErrorCode, MAX_SEMANTIC_SIGNAL_BYTES,
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
        "../../../contracts/semantic-route-signal-v1.json"
    ))
    .expect("semantic signal contract must parse")
}

#[test]
fn rust_executes_semantic_route_signal_contract() {
    let contract = contract();
    for vector in contract.vectors {
        let signal_value = merge(&contract.signal_defaults, &vector.signal);
        let signal_bytes = serde_json::to_vec(&signal_value).expect("signal must encode");
        let signal = parse_semantic_route_signal_v1(&signal_bytes).expect("signal must be valid");
        let context: SemanticRouteSignalContext =
            serde_json::from_value(merge(&contract.context_defaults, &vector.context))
                .expect("context must parse");

        let decision = reduce_semantic_route_signal(&signal, &context);

        assert_eq!(decision, vector.expected, "{}", vector.name);
    }
}

#[test]
fn rust_executes_semantic_route_signal_parser_contract() {
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

        let error = parse_semantic_route_signal_v1(
            &serde_json::to_vec(&Value::Object(payload)).expect("payload must encode"),
        )
        .expect_err("invalid parser vector must fail closed");

        assert_eq!(error.code, vector.expected_error, "{}", vector.name);
    }
}

#[test]
fn parser_rejects_oversized_input() {
    let input = vec![b' '; MAX_SEMANTIC_SIGNAL_BYTES + 1];

    let error =
        parse_semantic_route_signal_v1(&input).expect_err("oversized payload must fail closed");

    assert_eq!(error.code, SemanticSignalErrorCode::PayloadTooLarge);
}

#[test]
fn parser_rejects_non_host_identifiers() {
    let contract = contract();
    for host in [
        "localhost",
        "127.0.0.1",
        ".weather.com",
        "weather..com",
        "-weather.com",
        "weather.com/path",
        " weather.com",
    ] {
        let mut payload = contract
            .signal_defaults
            .as_object()
            .expect("signal defaults must be an object")
            .clone();
        payload.insert("host".to_owned(), Value::String(host.to_owned()));
        let bytes = serde_json::to_vec(&Value::Object(payload)).expect("payload must encode");

        let error =
            parse_semantic_route_signal_v1(&bytes).expect_err("invalid hostname must fail closed");

        assert_eq!(error.code, SemanticSignalErrorCode::InvalidHost, "{host}");
    }
}
