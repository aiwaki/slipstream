import route_policy_activation as activation
import route_policy_activation_adapter as adapter


def policy(kind, source, character):
    return activation.PolicyIdentity(kind, source, character * 64)


def stable_state(*, active=None, previous=None, generation=0):
    bundled = policy(activation.POLICY_BUNDLED, "bundled", "0")
    return activation.PolicyActivationState(
        bundled=bundled,
        active=active or bundled,
        previous=previous,
        trial_generation=generation,
    )


def candidate_effects(calls, *, health=None, commit=None):
    return adapter.CandidateEffects(
        activate_trial=lambda value: calls.append(("activate", value.sha256)),
        run_health_gate=(
            health
            or (
                lambda value, generation: calls.append(
                    ("health", value.sha256, generation)
                )
                or adapter.HealthEvidence(completed=True, ok=1)
            )
        ),
        commit_candidate=(
            commit
            or (
                lambda value, previous, generation: calls.append(
                    ("commit", value.sha256, previous.sha256, generation)
                )
                or "saved"
            )
        ),
        restore_active=lambda value: calls.append(("restore", value.sha256)),
        record_rejection=lambda value, reason, detail: calls.append(
            ("reject", value.sha256, reason, detail)
        ),
    )


def test_candidate_success_executes_reducer_actions_in_order():
    calls = []
    state = stable_state()
    candidate = policy(activation.POLICY_SIGNED, "signed:a", "a")

    result = adapter.activate_candidate(
        state,
        candidate,
        candidate_effects(calls),
    )

    assert result.accepted is True
    assert result.value == "saved"
    assert result.state.active == candidate
    assert result.state.previous == state.active
    assert result.state.trial_generation == 1
    assert calls == [
        ("activate", candidate.sha256),
        ("health", candidate.sha256, 1),
        ("commit", candidate.sha256, state.active.sha256, 1),
    ]


def test_health_rejection_restores_active_before_recording_rejection():
    calls = []
    state = stable_state()
    candidate = policy(activation.POLICY_SIGNED, "signed:a", "a")
    effects = candidate_effects(
        calls,
        health=lambda value, generation: calls.append(
            ("health", value.sha256, generation)
        )
        or adapter.HealthEvidence(
            completed=True,
            ok=2,
            degraded=1,
            detail="health gate degraded=1 ok=2",
        ),
    )

    result = adapter.activate_candidate(state, candidate, effects)

    assert result.accepted is False
    assert result.state.active == state.active
    assert result.state.trial_generation == 1
    assert calls[-2:] == [
        ("restore", state.active.sha256),
        (
            "reject",
            candidate.sha256,
            activation.REASON_HEALTH_DEGRADED,
            "health gate degraded=1 ok=2",
        ),
    ]


def test_commit_failure_aborts_trial_and_restores_active():
    calls = []
    state = stable_state()
    candidate = policy(activation.POLICY_SIGNED, "signed:a", "a")

    def fail_commit(value, previous, generation):
        calls.append(("commit", value.sha256, previous.sha256, generation))
        raise OSError("disk full")

    result = adapter.activate_candidate(
        state,
        candidate,
        candidate_effects(calls, commit=fail_commit),
    )

    assert result.accepted is False
    assert result.state.active == state.active
    assert result.state.trial_generation == 1
    assert result.error == "commit_candidate effect failed: disk full"
    assert calls[-2:] == [
        ("restore", state.active.sha256),
        (
            "reject",
            candidate.sha256,
            activation.REASON_ROLLBACK_REQUESTED,
            "commit_candidate effect failed: disk full",
        ),
    ]


def test_rollback_effect_failure_keeps_original_reducer_state():
    bundled = policy(activation.POLICY_BUNDLED, "bundled", "0")
    active = policy(activation.POLICY_SIGNED, "signed:b", "b")
    previous = policy(activation.POLICY_SIGNED, "signed:a", "a")
    state = activation.PolicyActivationState(
        bundled=bundled,
        active=active,
        previous=previous,
        trial_generation=4,
    )
    effects = adapter.RollbackEffects(
        commit_rollback=lambda _value, _generation: (_ for _ in ()).throw(
            OSError("read-only filesystem")
        ),
        restore_active=lambda _value: None,
        record_rejection=lambda _value, _reason, _detail: None,
    )

    result = adapter.rollback_policy(state, effects)

    assert result.accepted is False
    assert result.state == state
    assert result.error == "commit_rollback effect failed: read-only filesystem"
