import pytest

import tproxy


def outcome(
    *,
    host="example.com",
    group=tproxy.SERVICE_GENERIC,
    route=tproxy.ROUTE_UNKNOWN,
    backend=tproxy.BACKEND_LOCAL_ENGINE,
    ok=False,
    reason="runtime probe did not return payload",
):
    return tproxy.ConnectionOutcome(
        host=host,
        service_group=group,
        route_class=route,
        backend=backend,
        failure_phase=tproxy.FAILURE_PHASE_FIRST_PAYLOAD,
        bytes_received=0,
        duration=3.0,
        reason=reason,
        ok=ok,
    )


def kinds(actions):
    return [action.kind for action in actions]


def test_successful_outcome_requires_no_recovery():
    actions = tproxy.reduce_connection_outcome(outcome(ok=True))

    assert actions == (tproxy.RecoveryAction(tproxy.RECOVERY_NONE),)


@pytest.mark.parametrize(
    ("host", "group"),
    [
        ("updates.discord.com", tproxy.SERVICE_DISCORD),
        ("rr2---sn-ntq7yner.googlevideo.com", tproxy.SERVICE_YOUTUBE),
    ],
)
def test_protected_local_groups_never_produce_geph_actions(host, group):
    actions = tproxy.reduce_connection_outcome(
        outcome(
            host=host,
            group=group,
            route=tproxy.ROUTE_GEO_EXIT,
            backend=tproxy.GEO_BACKEND_GEPH,
        ),
        tproxy.RecoveryContext(
            backend_owned=True,
            restart_recommended=True,
            strategy_invalidation_recommended=True,
        ),
    )

    assert kinds(actions) == [
        tproxy.RECOVERY_INVALIDATE_STRATEGY,
        tproxy.RECOVERY_RESWEEP_EXACT_HOST,
        tproxy.RECOVERY_RECHECK,
    ]
    assert tproxy.RECOVERY_RESTART_OWNED_GEPH not in kinds(actions)
    assert actions[0].target == group
    assert actions[1].target == host


def test_geo_exit_restart_requires_owned_backend_and_available_cooldown():
    event = outcome(
        host="billing.openai.com",
        group=tproxy.SERVICE_OPENAI,
        route=tproxy.ROUTE_GEO_EXIT,
        backend=tproxy.GEO_BACKEND_GEPH,
    )

    unowned = tproxy.reduce_connection_outcome(
        event,
        tproxy.RecoveryContext(restart_recommended=True),
    )
    owned = tproxy.reduce_connection_outcome(
        event,
        tproxy.RecoveryContext(backend_owned=True, restart_recommended=True),
    )
    cooling_down = tproxy.reduce_connection_outcome(
        event,
        tproxy.RecoveryContext(
            backend_owned=True,
            restart_recommended=True,
            restart_rate_limited=True,
        ),
    )

    assert kinds(unowned) == [tproxy.RECOVERY_RECHECK]
    assert kinds(owned) == [tproxy.RECOVERY_RESTART_OWNED_GEPH]
    assert kinds(cooling_down) == [tproxy.RECOVERY_RECHECK]


def test_external_backend_produces_warning_only():
    actions = tproxy.reduce_connection_outcome(
        outcome(
            host="chatgpt.com",
            group=tproxy.SERVICE_OPENAI,
            route=tproxy.ROUTE_GEO_EXIT,
            backend=tproxy.BACKEND_EXTERNAL,
        ),
        tproxy.RecoveryContext(
            backend_owned=False,
            restart_recommended=True,
            strategy_invalidation_recommended=True,
            external_state=True,
        ),
    )

    assert kinds(actions) == [tproxy.RECOVERY_WARN_EXTERNAL]


def test_unknown_host_recheck_requires_repeated_local_evidence():
    event = outcome(host="payments.example.com")

    first = tproxy.reduce_connection_outcome(event)
    repeated = tproxy.reduce_connection_outcome(
        event,
        tproxy.RecoveryContext(recheck_recommended=True),
    )

    assert kinds(first) == [tproxy.RECOVERY_NONE]
    assert kinds(repeated) == [tproxy.RECOVERY_RECHECK]
    assert repeated[0].target == "payments.example.com"


def test_outcome_factory_uses_routing_policy_and_normalizes_metrics():
    event = tproxy.connection_outcome_for_host(
        "UPDATES.DISCORD.COM.",
        False,
        tproxy.BACKEND_LOCAL_ENGINE,
        failure_phase=tproxy.FAILURE_PHASE_CONNECT,
        bytes_received=-1,
        duration=-2,
        reason="x" * 300,
    )

    assert event.host == "updates.discord.com"
    assert event.service_group == tproxy.SERVICE_DISCORD
    assert event.route_class == tproxy.ROUTE_LOCAL_BYPASS
    assert event.bytes_received == 0
    assert event.duration == 0.0
    assert len(event.reason) == 200
