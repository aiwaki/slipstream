use serde_json::{Map, Value};
use slipstream_core::routing_policy::{
    bundled_policy_v1, classify_route_policy, GeoExitRoutePolicy, RouteClass, RoutingPolicyTables,
    ServiceGroup, StrategySet,
};
use slipstream_core::routing_recovery::{
    reduce_connection_outcome, ConnectionOutcome, RecoveryActionKind, RecoveryContext,
};

const POLICY_V1: &str = include_str!("../../../contracts/routing-policy-v1.json");
const RECOVERY_V1: &str = include_str!("../../../contracts/recovery-v1.json");

fn parse_contract(raw: &str) -> Value {
    serde_json::from_str(raw).expect("routing contract must be valid JSON")
}

fn merge(defaults: &Value, overrides: Option<&Value>) -> Value {
    let mut merged: Map<String, Value> = defaults
        .as_object()
        .expect("contract defaults must be an object")
        .clone();
    if let Some(overrides) = overrides.and_then(Value::as_object) {
        for (key, value) in overrides {
            merged.insert(key.clone(), value.clone());
        }
    }
    Value::Object(merged)
}

#[test]
fn rust_executes_routing_policy_v1_contract() {
    let contract = parse_contract(POLICY_V1);
    let tables = bundled_policy_v1();

    for case in contract["vectors"].as_array().unwrap() {
        let host = case["host"].as_str().unwrap();
        let actual = classify_route_policy(host, &tables);
        assert_eq!(
            serde_json::to_value(actual).unwrap(),
            case["expected"],
            "{}",
            case["name"]
        );
    }
}

#[test]
fn russian_direct_route_precedes_geo_exit_table() {
    let tables = RoutingPolicyTables {
        static_routes: Vec::new(),
        geo_exit_routes: vec![GeoExitRoutePolicy {
            domains: vec!["yandex.com".into()],
            service_group: ServiceGroup::Generic,
        }],
    };

    let actual = classify_route_policy("Yandex.Com.", &tables);
    assert_eq!(actual.route_class, RouteClass::DirectPassthrough);
    assert_eq!(actual.strategy_set, StrategySet::Direct);
}

#[test]
fn bundled_protected_groups_have_only_local_policy_edges() {
    for policy in bundled_policy_v1()
        .static_routes
        .into_iter()
        .filter(|policy| policy.service_group.is_protected_local_bypass())
    {
        assert_eq!(policy.route_class, RouteClass::LocalBypass);
        assert_eq!(policy.strategy_set, StrategySet::FakeOnly);
    }
}

#[test]
fn rust_executes_recovery_v1_contract() {
    let contract = parse_contract(RECOVERY_V1);
    let outcome_defaults = &contract["outcome_defaults"];
    let context_defaults = &contract["context_defaults"];

    for case in contract["vectors"].as_array().unwrap() {
        let outcome: ConnectionOutcome =
            serde_json::from_value(merge(outcome_defaults, case.get("outcome"))).unwrap();
        let context: RecoveryContext =
            serde_json::from_value(merge(context_defaults, case.get("context"))).unwrap();

        let actual = reduce_connection_outcome(&outcome, &context);
        assert_eq!(
            serde_json::to_value(&actual).unwrap(),
            case["expected"],
            "{}",
            case["name"]
        );

        if let Some(prohibited) = case.get("prohibited_actions").and_then(Value::as_array) {
            let serialized = serde_json::to_value(&actual).unwrap();
            let kinds: Vec<&str> = serialized
                .as_array()
                .unwrap()
                .iter()
                .map(|action| action["kind"].as_str().unwrap())
                .collect();
            for kind in prohibited {
                assert!(!kinds.contains(&kind.as_str().unwrap()), "{}", case["name"]);
            }
        }
    }
}

#[test]
fn recovery_reason_is_bounded_by_unicode_characters() {
    let outcome = ConnectionOutcome {
        host: "chatgpt.com".into(),
        service_group: ServiceGroup::Openai,
        route_class: RouteClass::GeoExit,
        backend: "geph".into(),
        failure_phase: "first_payload".into(),
        bytes_received: 0,
        duration: 1.0,
        reason: "я".repeat(250),
        ok: false,
    };
    let actions = reduce_connection_outcome(&outcome, &RecoveryContext::default());

    assert_eq!(actions[0].kind, RecoveryActionKind::Recheck);
    assert_eq!(actions[0].reason.chars().count(), 200);
}
