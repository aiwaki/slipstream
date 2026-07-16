//! Versioned, platform-neutral route-policy manifest validation.
//!
//! Contract v1 is isolated in `v1` so future policy formats can be added
//! without silently changing already-qualified adapters.

mod v1;

pub use v1::{
    parse_route_policy_manifest, parse_route_policy_manifest_json, ManifestRoutePolicy,
    RoutePolicyManifest, RoutePolicyManifestError, RoutePolicyManifestErrorCode,
    ROUTE_POLICY_MANIFEST_CONTRACT_VERSION,
};
