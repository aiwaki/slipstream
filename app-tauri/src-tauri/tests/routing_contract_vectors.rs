use serde_json::Value;
use slipstream_lib::address_attempts::{
    plan_address_attempts, AddressAttempt, AddressCandidate, AddressPlanContext,
};
use slipstream_lib::route_circuit::{
    circuit_snapshot, reduce_route_circuit, CircuitConfig, CircuitEvent, CircuitStates,
};
use slipstream_lib::route_circuit_registry::{RouteCircuitRegistry, RouteCircuitRegistryConfig};
use std::collections::HashSet;

const POLICY_V1: &str = include_str!("../../../contracts/routing-policy-v1.json");
const RECOVERY_V1: &str = include_str!("../../../contracts/recovery-v1.json");
const ADDRESS_ATTEMPTS_V1: &str = include_str!("../../../contracts/address-attempts-v1.json");
const ROUTE_CIRCUIT_V1: &str = include_str!("../../../contracts/route-circuit-v1.json");
const ROUTE_CIRCUIT_REGISTRY_V1: &str =
    include_str!("../../../contracts/route-circuit-registry-v1.json");
const CONNECTION_RACE_V1: &str = include_str!("../../../contracts/connection-race-v1.json");

fn parse_contract(raw: &str) -> Value {
    serde_json::from_str(raw).expect("routing contract must be valid JSON")
}

#[test]
fn rust_reads_versioned_language_neutral_contracts() {
    for (raw, name) in [
        (POLICY_V1, "slipstream.routing_policy"),
        (RECOVERY_V1, "slipstream.recovery"),
        (ADDRESS_ATTEMPTS_V1, "slipstream.address_attempts"),
        (ROUTE_CIRCUIT_V1, "slipstream.route_circuit"),
        (
            ROUTE_CIRCUIT_REGISTRY_V1,
            "slipstream.route_circuit_registry",
        ),
        (CONNECTION_RACE_V1, "slipstream.connection_race"),
    ] {
        let contract = parse_contract(raw);
        assert_eq!(contract["schema_version"], 1);
        assert_eq!(contract["contract"], name);
        assert_eq!(contract["contract_version"], 1);
        let vectors = contract["vectors"]
            .as_array()
            .expect("vectors must be an array");
        assert!(!vectors.is_empty());
        let names: HashSet<&str> = vectors
            .iter()
            .map(|vector| {
                vector["name"]
                    .as_str()
                    .expect("vector name must be a string")
            })
            .collect();
        assert_eq!(names.len(), vectors.len(), "vector names must be unique");
    }
}

#[test]
fn rust_executes_address_attempt_contract() {
    let contract = parse_contract(ADDRESS_ATTEMPTS_V1);
    for case in contract["vectors"].as_array().unwrap() {
        let input = &case["input"];
        let candidates: Vec<AddressCandidate> =
            serde_json::from_value(input["candidates"].clone()).unwrap();
        let attempts: Vec<AddressAttempt> =
            serde_json::from_value(input["attempts"].clone()).unwrap();
        let context: AddressPlanContext = serde_json::from_value(input["context"].clone()).unwrap();

        let actual = plan_address_attempts(&candidates, &attempts, &context)
            .unwrap_or_else(|error| panic!("{}: {error}", case["name"]));

        assert_eq!(
            serde_json::to_value(actual).unwrap(),
            case["expected"],
            "{}",
            case["name"]
        );
    }
}

#[test]
fn rust_executes_route_circuit_contract() {
    let contract = parse_contract(ROUTE_CIRCUIT_V1);
    let config: CircuitConfig = serde_json::from_value(contract["config"].clone()).unwrap();
    for case in contract["vectors"].as_array().unwrap() {
        let mut states = CircuitStates::new();
        let mut decisions = Vec::new();
        for raw_event in case["events"].as_array().unwrap() {
            let event: CircuitEvent = serde_json::from_value(raw_event.clone()).unwrap();
            let (updated, decision) = reduce_route_circuit(&states, &event, &config)
                .unwrap_or_else(|error| panic!("{}: {error}", case["name"]));
            states = updated;
            decisions.push(decision);
        }

        assert_eq!(
            serde_json::to_value(decisions).unwrap(),
            case["expected_decisions"],
            "{} decisions",
            case["name"]
        );
        assert_eq!(
            serde_json::to_value(circuit_snapshot(&states)).unwrap(),
            case["expected_states"],
            "{} states",
            case["name"]
        );
    }
}

#[test]
fn rust_executes_route_circuit_registry_contract() {
    let contract = parse_contract(ROUTE_CIRCUIT_REGISTRY_V1);
    let circuit_config: CircuitConfig =
        serde_json::from_value(contract["circuit_config"].clone()).unwrap();
    let registry_config: RouteCircuitRegistryConfig =
        serde_json::from_value(contract["registry_config"].clone()).unwrap();
    for case in contract["vectors"].as_array().unwrap() {
        let mut registry =
            RouteCircuitRegistry::new(circuit_config.clone(), registry_config.clone()).unwrap();
        let mut decisions = Vec::new();
        for raw_event in case["events"].as_array().unwrap() {
            let event: CircuitEvent = serde_json::from_value(raw_event.clone()).unwrap();
            decisions.push(
                registry
                    .apply(&event)
                    .unwrap_or_else(|error| panic!("{}: {error}", case["name"])),
            );
        }

        assert_eq!(
            serde_json::to_value(decisions).unwrap(),
            case["expected_decisions"],
            "{} decisions",
            case["name"]
        );
        assert_eq!(
            serde_json::to_value(registry.snapshot()).unwrap(),
            case["expected_entries"],
            "{} entries",
            case["name"]
        );
    }
}

#[test]
fn protected_groups_have_no_geph_edge_in_shared_vectors() {
    let policy = parse_contract(POLICY_V1);
    let recovery = parse_contract(RECOVERY_V1);
    let protected = recovery["invariants"]["protected_local_bypass_groups"]
        .as_array()
        .unwrap();
    let forbidden = recovery["invariants"]["forbidden_protected_action"]
        .as_str()
        .unwrap();

    for case in policy["vectors"].as_array().unwrap() {
        let expected = &case["expected"];
        if protected.contains(&expected["service_group"]) {
            assert_eq!(expected["route_class"], "local_bypass");
            assert_eq!(expected["strategy_set"], "fake_only");
        }
    }

    let defaults = recovery["outcome_defaults"].as_object().unwrap();
    for case in recovery["vectors"].as_array().unwrap() {
        let group = case["outcome"]
            .get("service_group")
            .or_else(|| defaults.get("service_group"))
            .unwrap();
        if protected.contains(group) {
            let kinds: Vec<&str> = case["expected"]
                .as_array()
                .unwrap()
                .iter()
                .map(|action| action["kind"].as_str().unwrap())
                .collect();
            assert!(!kinds.contains(&forbidden));
        }
    }
}
