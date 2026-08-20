use serde::Deserialize;
use serde_json::{json, Value};
use slipstream_core::route_preflight::{
    parse_route_preflight_job_v1, parse_route_preflight_result_v1,
    validate_route_preflight_result_v1, RoutePreflightDecisionReason, RoutePreflightErrorCode,
    RoutePreflightOutcome,
};

#[derive(Debug, Deserialize)]
struct Contract {
    candidate_routes: Vec<String>,
    outcomes: Vec<String>,
    privacy: Privacy,
    job_defaults: Value,
    result_defaults: Value,
}

#[derive(Debug, Deserialize)]
struct Privacy {
    forbidden_fields: Vec<String>,
}

fn contract() -> Contract {
    serde_json::from_str(include_str!("../../../contracts/route-preflight-v1.json"))
        .expect("route preflight contract must parse")
}

#[test]
fn exact_job_and_result_are_capability_host_route_and_deadline_bound() {
    let contract = contract();
    let job = parse_route_preflight_job_v1(
        &serde_json::to_vec(&contract.job_defaults).expect("job must encode"),
    )
    .expect("job must parse");
    let result = parse_route_preflight_result_v1(
        &serde_json::to_vec(&contract.result_defaults).expect("result must encode"),
    )
    .expect("result must parse");

    let accepted = validate_route_preflight_result_v1(&job, &result, 1_000_600, false);
    assert!(accepted.accepted);
    assert_eq!(accepted.reason, RoutePreflightDecisionReason::Accepted);

    let mut mismatched = result.clone();
    mismatched.host = "other.example".to_owned();
    assert_eq!(
        validate_route_preflight_result_v1(&job, &mismatched, 1_000_600, false).reason,
        RoutePreflightDecisionReason::BindingMismatch
    );

    let mut unlisted = result.clone();
    unlisted.candidate_route = slipstream_core::route_preflight::RoutePreflightCandidate::AppDoh;
    assert_eq!(
        validate_route_preflight_result_v1(&job, &unlisted, 1_000_600, false).reason,
        RoutePreflightDecisionReason::CandidateNotAllowed
    );
    assert_eq!(
        validate_route_preflight_result_v1(&job, &result, 1_008_001, false).reason,
        RoutePreflightDecisionReason::Expired
    );
    assert_eq!(
        validate_route_preflight_result_v1(&job, &result, 1_000_600, true).reason,
        RoutePreflightDecisionReason::Replay
    );
}

#[test]
fn contract_lists_only_fixed_candidates_and_privacy_bounded_outcomes() {
    let contract = contract();
    assert_eq!(
        contract.candidate_routes,
        ["system", "app_doh", "local_strategy", "owned_geph"]
    );
    assert_eq!(
        contract.outcomes,
        [
            "navigation_pending",
            "regional_access_denied",
            "edge_access_denied",
            "challenge_or_auth",
            "usable",
            "terminal_error",
        ]
    );

    for outcome in contract.outcomes {
        let mut value = contract.result_defaults.clone();
        value["outcome"] = json!(outcome);
        parse_route_preflight_result_v1(&serde_json::to_vec(&value).expect("result must encode"))
            .expect("fixed outcome must parse");
    }

    for forbidden in contract.privacy.forbidden_fields {
        let mut value = contract.result_defaults.clone();
        value[&forbidden] = json!("private");
        let error = parse_route_preflight_result_v1(
            &serde_json::to_vec(&value).expect("result must encode"),
        )
        .expect_err("privacy-expanding result must fail");
        assert_eq!(
            error.code,
            RoutePreflightErrorCode::InvalidShape,
            "{forbidden}"
        );
    }
}

#[test]
fn jobs_reject_duplicate_candidates_and_deadlines_above_eight_seconds() {
    let contract = contract();
    let mut duplicate = contract.job_defaults.clone();
    duplicate["candidate_routes"] = json!(["system", "system"]);
    assert_eq!(
        parse_route_preflight_job_v1(&serde_json::to_vec(&duplicate).expect("job must encode"))
            .expect_err("duplicates must fail")
            .code,
        RoutePreflightErrorCode::InvalidCandidateRoutes
    );

    let mut long = contract.job_defaults;
    long["deadline_unix_ms"] = json!(1_008_001);
    assert_eq!(
        parse_route_preflight_job_v1(&serde_json::to_vec(&long).expect("job must encode"))
            .expect_err("long deadline must fail")
            .code,
        RoutePreflightErrorCode::InvalidDeadline
    );
}

#[test]
fn denial_is_observation_not_route_authority() {
    let contract = contract();
    let job = parse_route_preflight_job_v1(
        &serde_json::to_vec(&contract.job_defaults).expect("job must encode"),
    )
    .expect("job must parse");
    let mut value = contract.result_defaults;
    value["outcome"] = json!("edge_access_denied");
    let result =
        parse_route_preflight_result_v1(&serde_json::to_vec(&value).expect("result must encode"))
            .expect("result must parse");
    let decision = validate_route_preflight_result_v1(&job, &result, 1_000_600, false);

    assert!(decision.accepted);
    assert_eq!(decision.outcome, RoutePreflightOutcome::EdgeAccessDenied);
}
