use serde_json::Value;
use slipstream_core::route_policy_manifest::{
    parse_route_policy_manifest, parse_route_policy_manifest_json, RoutePolicyManifestErrorCode,
    ROUTE_POLICY_MANIFEST_CONTRACT_VERSION,
};

const MANIFEST_V1: &str = include_str!("../../../contracts/route-policy-manifest-v1.json");

fn parse_contract() -> Value {
    serde_json::from_str(MANIFEST_V1).expect("route-policy manifest contract must be valid JSON")
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

fn set_at_path(root: &mut Value, path: &[Value], value: Value) {
    let (leaf, parent_path) = path.split_last().expect("set path must not be empty");
    let parent = value_at_mut(root, parent_path);
    match (parent, leaf) {
        (Value::Object(object), Value::String(key)) => {
            object.insert(key.clone(), value);
        }
        (Value::Array(array), number) if number.is_u64() => {
            let index = path_index(number);
            *array
                .get_mut(index)
                .unwrap_or_else(|| panic!("array path index {index} must exist")) = value;
        }
        _ => panic!("set path must end at an object key or array index"),
    }
}

fn remove_at_path(root: &mut Value, path: &[Value]) {
    let (leaf, parent_path) = path.split_last().expect("remove path must not be empty");
    let parent = value_at_mut(root, parent_path);
    match (parent, leaf) {
        (Value::Object(object), Value::String(key)) => {
            assert!(
                object.remove(key).is_some(),
                "object key {key:?} must exist"
            );
        }
        (Value::Array(array), number) if number.is_u64() => {
            let index = path_index(number);
            assert!(index < array.len(), "array path index {index} must exist");
            array.remove(index);
        }
        _ => panic!("remove path must end at an object key or array index"),
    }
}

fn apply_mutations(manifest: &mut Value, mutations: &[Value]) {
    for mutation in mutations {
        let operation = mutation["op"]
            .as_str()
            .expect("mutation op must be a string");
        let path = mutation["path"]
            .as_array()
            .expect("mutation path must be an array");
        match operation {
            "set" => set_at_path(manifest, path, mutation["value"].clone()),
            "remove" => remove_at_path(manifest, path),
            "append" => value_at_mut(manifest, path)
                .as_array_mut()
                .expect("append target must be an array")
                .push(mutation["value"].clone()),
            "insert" => {
                let index = mutation["index"]
                    .as_u64()
                    .expect("insert index must be an unsigned integer")
                    as usize;
                let array = value_at_mut(manifest, path)
                    .as_array_mut()
                    .expect("insert target must be an array");
                assert!(index <= array.len(), "insert index must be in bounds");
                array.insert(index, mutation["value"].clone());
            }
            other => panic!("unsupported fixture mutation {other:?}"),
        }
    }
}

#[test]
fn rust_executes_route_policy_manifest_v1_contract() {
    let contract = parse_contract();
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(contract["contract"], "slipstream.route_policy_manifest");
    assert_eq!(
        contract["contract_version"],
        ROUTE_POLICY_MANIFEST_CONTRACT_VERSION
    );

    for case in contract["vectors"].as_array().unwrap() {
        let mut manifest = contract["base_manifest"].clone();
        apply_mutations(
            &mut manifest,
            case["mutations"]
                .as_array()
                .expect("mutations must be an array"),
        );
        let expected = &case["expected"];
        let actual = parse_route_policy_manifest(&manifest);
        if expected["ok"].as_bool().unwrap() {
            let actual = actual.unwrap_or_else(|error| panic!("{}: {error}", case["name"]));
            assert_eq!(
                serde_json::to_value(actual).unwrap(),
                contract["normalized_manifest"],
                "{}",
                case["name"]
            );
        } else {
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
        }
    }
}

#[test]
fn malformed_json_has_a_structured_root_error() {
    let error = parse_route_policy_manifest_json("{").unwrap_err();
    assert_eq!(error.code, RoutePolicyManifestErrorCode::InvalidJson);
    assert_eq!(error.path, "$");
}

#[test]
fn normalized_manifest_builds_the_same_first_match_tables() {
    let contract = parse_contract();
    let manifest = parse_route_policy_manifest(&contract["base_manifest"]).unwrap();
    let tables = manifest.routing_tables();

    assert_eq!(tables.static_routes.len(), 4);
    assert_eq!(tables.geo_exit_routes.len(), 1);
    assert_eq!(tables.geo_exit_routes[0].domains, ["chatgpt.com"]);
}
