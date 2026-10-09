use slipstream_core::route_circuit::{
    CircuitConfig, CircuitDecisionKind, CircuitEvent, CircuitEventKind, RouteCircuitKey,
};
use slipstream_core::route_circuit_registry::{RouteCircuitRegistry, RouteCircuitRegistryConfig};

#[test]
fn rejected_retries_do_not_extend_abandoned_half_open_permit() {
    let config = CircuitConfig {
        failure_threshold: 2,
        open_duration_ms: 1000,
        half_open_max_in_flight: 1,
        success_threshold: 1,
    };
    let mut registry = RouteCircuitRegistry::new(
        config,
        RouteCircuitRegistryConfig {
            max_entries: 8,
            idle_ttl_ms: 5000,
        },
    )
    .unwrap();
    let key = RouteCircuitKey {
        service_group: "openai".into(),
        route_class: "geo_exit".into(),
        backend_id: "geph".into(),
    };
    for now_ms in [0, 1] {
        registry
            .apply(&CircuitEvent {
                kind: CircuitEventKind::RecordFailure,
                key: key.clone(),
                now_ms,
            })
            .unwrap();
    }
    let admitted = registry
        .apply(&CircuitEvent {
            kind: CircuitEventKind::BeforeRequest,
            key: key.clone(),
            now_ms: 1001,
        })
        .unwrap();
    assert_eq!(admitted.kind, CircuitDecisionKind::Allow);
    assert_eq!(admitted.reason, "half_open_probe");
    // Cancellation loses this result. Denied retries are not backend activity.
    for now_ms in [2000, 3000, 4000, 5000, 6000] {
        let denied = registry
            .apply(&CircuitEvent {
                kind: CircuitEventKind::BeforeRequest,
                key: key.clone(),
                now_ms,
            })
            .unwrap();
        assert_eq!(denied.kind, CircuitDecisionKind::Reject);
    }
    assert_eq!(registry.snapshot()[0].last_touched_ms, 1001);
    let recovered = registry
        .apply(&CircuitEvent {
            kind: CircuitEventKind::BeforeRequest,
            key,
            now_ms: 6001,
        })
        .unwrap();
    assert_eq!(recovered.kind, CircuitDecisionKind::Allow);
    assert_eq!(recovered.reason, "closed");
}
