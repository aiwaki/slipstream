use slipstream_core::route_circuit::{
    CircuitConfig, CircuitDecisionKind, CircuitEvent, CircuitEventKind, RouteCircuitKey,
};
use slipstream_core::route_circuit_registry::{RouteCircuitRegistry, RouteCircuitRegistryConfig};

fn registry() -> RouteCircuitRegistry {
    RouteCircuitRegistry::new(
        CircuitConfig {
            failure_threshold: 2,
            open_duration_ms: 1000,
            half_open_max_in_flight: 1,
            success_threshold: 1,
        },
        RouteCircuitRegistryConfig {
            max_entries: 8,
            idle_ttl_ms: 5000,
        },
    )
    .unwrap()
}

fn event(kind: CircuitEventKind, now_ms: u64) -> CircuitEvent {
    CircuitEvent {
        kind,
        key: RouteCircuitKey {
            service_group: "openai".into(),
            route_class: "geo_exit".into(),
            backend_id: "geph".into(),
        },
        now_ms,
    }
}

#[test]
fn rejected_retries_do_not_extend_abandoned_half_open_permit() {
    let mut registry = registry();
    for now_ms in [0, 1] {
        registry
            .apply(&event(CircuitEventKind::RecordFailure, now_ms))
            .unwrap();
    }
    let admitted = registry
        .apply(&event(CircuitEventKind::BeforeRequest, 1001))
        .unwrap();
    assert_eq!(admitted.kind, CircuitDecisionKind::Allow);
    assert_eq!(admitted.reason, "half_open_probe");
    // Cancellation loses the admitted result. Denied retries are not activity.
    for now_ms in [2000, 3000, 4000, 5000, 6000] {
        let denied = registry
            .apply(&event(CircuitEventKind::BeforeRequest, now_ms))
            .unwrap();
        assert_eq!(denied.kind, CircuitDecisionKind::Reject);
    }
    assert_eq!(registry.snapshot()[0].last_touched_ms, 1001);
    let recovered = registry
        .apply(&event(CircuitEventKind::BeforeRequest, 6001))
        .unwrap();
    assert_eq!(recovered.kind, CircuitDecisionKind::Allow);
    assert_eq!(recovered.reason, "closed");
}

#[test]
fn ignored_completion_does_not_renew_open_circuit() {
    let mut registry = registry();
    for now_ms in [0, 1] {
        registry
            .apply(&event(CircuitEventKind::RecordFailure, now_ms))
            .unwrap();
    }
    let ignored = registry
        .apply(&event(CircuitEventKind::RecordSuccess, 100))
        .unwrap();
    assert_eq!(ignored.kind, CircuitDecisionKind::Ignore);
    assert_eq!(ignored.reason, "stale_completion");
    assert_eq!(registry.snapshot()[0].last_touched_ms, 1);
    let recovered = registry
        .apply(&event(CircuitEventKind::BeforeRequest, 5001))
        .unwrap();
    assert_eq!(recovered.kind, CircuitDecisionKind::Allow);
    assert_eq!(recovered.reason, "closed");
}
