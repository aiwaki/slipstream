use serde_json::Value;

const POLICY_V1: &str = include_str!("../../../contracts/routing-policy-v1.json");
const RECOVERY_V1: &str = include_str!("../../../contracts/recovery-v1.json");

fn parse_contract(raw: &str) -> Value {
    serde_json::from_str(raw).expect("routing contract must be valid JSON")
}

#[test]
fn rust_reads_versioned_language_neutral_contracts() {
    for (raw, name) in [
        (POLICY_V1, "slipstream.routing_policy"),
        (RECOVERY_V1, "slipstream.recovery"),
    ] {
        let contract = parse_contract(raw);
        assert_eq!(contract["schema_version"], 1);
        assert_eq!(contract["contract"], name);
        assert_eq!(contract["contract_version"], 1);
        assert!(!contract["vectors"].as_array().unwrap().is_empty());
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
