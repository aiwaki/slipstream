//! Versioned signed route-policy bundle verification.

mod v1;

pub use v1::{
    route_policy_canonical_bytes, route_policy_hash, verify_signed_route_policy_bundle,
    verify_signed_route_policy_bundle_json, RoutePolicyBundleError, RoutePolicyBundleErrorCode,
    ROUTE_POLICY_BUNDLE_CONTRACT_VERSION,
};
