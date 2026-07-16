use serde_json::Value;
use slipstream_core::route_policy_bundle::{
    route_policy_canonical_bytes, route_policy_hash, verify_signed_route_policy_bundle,
    verify_signed_route_policy_bundle_json, RoutePolicyBundleErrorCode,
    ROUTE_POLICY_BUNDLE_CONTRACT_VERSION,
};
use slipstream_core::route_policy_manifest::parse_route_policy_manifest;
use std::collections::BTreeMap;

const BUNDLE_V1: &str = include_str!("../../../contracts/route-policy-bundle-v1.json");
const MANIFEST_V1: &str = include_str!("../../../contracts/route-policy-manifest-v1.json");

fn parse_json(raw: &str, label: &str) -> Value {
    serde_json::from_str(raw).unwrap_or_else(|error| panic!("{label} must be valid JSON: {error}"))
}

fn path_index(segment: &Value) -> usize {
    segment
        .as_u64()
        .expect("array path segment must be an unsigned integer") as usize
}

fn value_at_mut<'a>(root: &'a mut Value, path: &[Value]) -> &'a mut Value {
    let mut current = root;
    for segment in path {
        current = match (current, segment) {
            (Value::Object(object), Value::String(key)) => object
                .get_mut(key)
                .unwrap_or_else(|| panic!("object path segment {key:?} must exist")),
            (Value::Array(array), number) if number.is_u64() => {
                let index = path_index(number);
                array
                    .get_mut(index)
                    .unwrap_or_else(|| panic!("array path index {index} must exist"))
            }
            _ => panic!("mutation path must match the JSON value shape"),
        };
    }
    current
}

fn apply_mutations(root: &mut Value, mutations: &[Value]) {
    for mutation in mutations {
        let operation = mutation["op"]
            .as_str()
            .expect("mutation op must be a string");
        let path = mutation["path"]
            .as_array()
            .expect("mutation path must be an array");
        let (leaf, parent_path) = path
            .split_last()
            .expect("contract mutation path must not be empty");
        let parent = value_at_mut(root, parent_path);
        match (operation, parent, leaf) {
            ("set", Value::Object(object), Value::String(key)) => {
                object.insert(key.clone(), mutation["value"].clone());
            }
            ("set", Value::Array(array), number) if number.is_u64() => {
                let index = path_index(number);
                *array
                    .get_mut(index)
                    .unwrap_or_else(|| panic!("array path index {index} must exist")) =
                    mutation["value"].clone();
            }
            ("remove", Value::Object(object), Value::String(key)) => {
                assert!(
                    object.remove(key).is_some(),
                    "object key {key:?} must exist"
                );
            }
            ("remove", Value::Array(array), number) if number.is_u64() => {
                let index = path_index(number);
                assert!(index < array.len(), "array path index {index} must exist");
                array.remove(index);
            }
            _ => panic!("unsupported fixture mutation {operation:?}"),
        }
    }
}

fn resolved_bundle(contract: &Value, manifest_contract: &Value) -> Value {
    let mut bundle = contract["base_bundle"].clone();
    assert_eq!(
        bundle["manifest"]["$ref"],
        "route-policy-manifest-v1.json#/normalized_manifest"
    );
    bundle["manifest"] = manifest_contract["normalized_manifest"].clone();
    bundle
}

fn trusted_keys(contract: &Value) -> BTreeMap<String, String> {
    serde_json::from_value(contract["trusted_keys"].clone())
        .expect("trusted key fixture must be a string map")
}

#[test]
fn canonical_hashes_match_python_v1_for_ascii_unicode_and_controls() {
    let contract = parse_json(BUNDLE_V1, "route-policy bundle contract");
    let manifest_contract = parse_json(MANIFEST_V1, "route-policy manifest contract");

    for case in contract["canonical_vectors"].as_array().unwrap() {
        let mut value = manifest_contract["normalized_manifest"].clone();
        value["source"] = case["source"].clone();
        let manifest = parse_route_policy_manifest(&value)
            .unwrap_or_else(|error| panic!("{}: {error}", case["name"]));
        let canonical = route_policy_canonical_bytes(&manifest);

        assert!(
            canonical.is_ascii(),
            "{} canonical output must use ASCII JSON escapes",
            case["name"]
        );
        assert_eq!(
            route_policy_hash(&manifest),
            case["expected_sha256"].as_str().unwrap(),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn rust_executes_route_policy_bundle_v1_contract() {
    let contract = parse_json(BUNDLE_V1, "route-policy bundle contract");
    let manifest_contract = parse_json(MANIFEST_V1, "route-policy manifest contract");
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(contract["contract"], "slipstream.route_policy_bundle");
    assert_eq!(
        contract["contract_version"],
        ROUTE_POLICY_BUNDLE_CONTRACT_VERSION
    );

    for case in contract["vectors"].as_array().unwrap() {
        let mut bundle = resolved_bundle(&contract, &manifest_contract);
        apply_mutations(&mut bundle, case["bundle_mutations"].as_array().unwrap());
        let mut key_value = contract["trusted_keys"].clone();
        apply_mutations(
            &mut key_value,
            case["trusted_key_mutations"].as_array().unwrap(),
        );
        let keys: BTreeMap<String, String> = serde_json::from_value(key_value).unwrap();
        let expected = &case["expected"];
        let actual = verify_signed_route_policy_bundle(&bundle, &keys);

        if expected["ok"].as_bool().unwrap() {
            let manifest = actual.unwrap_or_else(|error| panic!("{}: {error}", case["name"]));
            assert_eq!(
                serde_json::to_value(manifest).unwrap(),
                manifest_contract["normalized_manifest"],
                "{}",
                case["name"]
            );
            continue;
        }

        let error = actual.expect_err("invalid vector must be rejected");
        assert_eq!(
            error.code.as_str(),
            expected["error_code"].as_str().unwrap(),
            "{} error code",
            case["name"]
        );
        assert_eq!(
            error.path,
            expected["path"].as_str().unwrap(),
            "{} error path",
            case["name"]
        );
        assert!(
            error
                .message
                .contains(expected["message_contains"].as_str().unwrap()),
            "{} message: {}",
            case["name"],
            error.message
        );
        if let Some(manifest_code) = expected.get("manifest_error_code") {
            assert_eq!(
                error.manifest_error_code.map(|code| code.as_str()),
                manifest_code.as_str(),
                "{} nested manifest error",
                case["name"]
            );
        }
    }
}

#[test]
fn malformed_json_and_non_object_bundle_have_structured_root_errors() {
    let contract = parse_json(BUNDLE_V1, "route-policy bundle contract");
    let keys = trusted_keys(&contract);

    let malformed = verify_signed_route_policy_bundle_json("{", &keys).unwrap_err();
    assert_eq!(malformed.code, RoutePolicyBundleErrorCode::InvalidJson);
    assert_eq!(malformed.path, "$");

    let non_object = verify_signed_route_policy_bundle(&Value::Null, &keys).unwrap_err();
    assert_eq!(non_object.code, RoutePolicyBundleErrorCode::InvalidType);
    assert_eq!(non_object.path, "$");
}
