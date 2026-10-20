"""Pure visibility-phase tests: no GUI, process launch, or native API calls."""
from unittest import mock

import pytest

from scripts import public_update_visibility as visibility

FRONT = "ASN:0x0-0x100:"
OTHER = "ASN:0x0-0x200:"


def snapshot(**changes):
    return {"frontmost_asn": FRONT, "security_agent_front": False,
            "window_ids": [], "dock_visible": False, **changes}


def monitor():
    value = visibility.PublicUpdateVisibility()
    value.started = 10.0
    value._now = lambda: 11.0
    value._snapshot = snapshot
    value._capture()
    value._capture()
    return value


def terminal(value):
    value.set_phase("terminal")
    return value.close()


def test_pass_reports_actual_samples_and_does_not_claim_full_visibility_or_delivery():
    value = monitor()
    value.set_phase("interaction")
    value._snapshot = lambda: snapshot(frontmost_asn=OTHER, security_agent_front=True,
                                      window_ids=[12])
    value._capture()
    value.set_phase("handoff")
    value._snapshot = snapshot
    value._capture()
    result = terminal(value)
    assert result["status"] == "passed"
    assert result["security_agent_interaction_samples"] == 1
    assert result["phase_sample_counts"] == dict(discovery=2, interaction=1, handoff=1, terminal=1)
    assert result["full_transition_invisibility_qualified"] is False
    assert result["notification_delivery_qualified"] is False
    assert result["interaction_focus_window_interval_qualified"] is False
    assert value.close() == result
    assert value.assert_passed() == result


@pytest.mark.parametrize("phase", ["discovery", "handoff", "terminal"])
@pytest.mark.parametrize("change,code", [
    ({"frontmost_asn": OTHER}, "background_frontmost_change"),
    ({"window_ids": [1]}, "background_window"),
    ({"dock_visible": True}, "dock_visible"),
])
def test_background_violation_cannot_be_hidden_by_later_clean_sample(phase, change, code):
    value = monitor()
    value.set_phase(phase)
    value._snapshot = lambda: snapshot(**change)
    value._capture()
    value._snapshot = snapshot
    assert code in terminal(value)["failures"]
    with pytest.raises(visibility.VisibilityError, match=code):
        value.assert_passed()


def test_interaction_never_excuses_a_dock_tile():
    value = monitor()
    value.set_phase("interaction")
    value._snapshot = lambda: snapshot(dock_visible=True)
    value._capture()
    assert "dock_visible" in terminal(value)["failures"]


def test_cross_phase_read_is_retained_but_not_counted_as_strict_coverage():
    value = monitor()
    def changing():
        value.set_phase("interaction")
        return snapshot(frontmost_asn=OTHER)
    value._snapshot = changing
    value._capture()
    value._snapshot = snapshot
    result = terminal(value)
    assert result["samples"][2]["crossed_phase_boundary"] is True
    assert result["phase_sample_counts"]["discovery"] == 2
    assert result["status"] == "passed"


@pytest.mark.parametrize("change", [
    {"frontmost_asn": ""}, {"dock_visible": 1}, {"security_agent_front": None},
    {"window_ids": [True]}, {"window_ids": [-1]}, {"window_ids": list(range(1, 131))},
])
def test_malformed_native_observation_fails_closed(change):
    value = monitor()
    value._snapshot = lambda: snapshot(**change)
    assert "snapshot_unavailable" in terminal(value)["failures"]


def test_deadline_and_sample_budget_are_terminal_not_retried_until_clean():
    value = monitor()
    value._now = lambda: 911.0
    result = terminal(value)
    assert "observation_deadline_exceeded" in result["failures"]
    assert value._stop.is_set()
    value = monitor()
    with mock.patch.object(visibility, "MAX_SAMPLES", 2):
        assert "snapshot_unavailable" in terminal(value)["failures"]


def test_missing_terminal_and_backwards_phase_cannot_pass():
    value = monitor()
    value.set_phase("handoff")
    with pytest.raises(visibility.VisibilityError, match="backwards"):
        value.set_phase("discovery")
    assert "required_phase_not_observed" in value.close()["failures"]


def test_only_exact_security_agent_front_record_is_classified():
    block = f'''1) {OTHER} "SecurityAgent"
    bundleID="com.apple.SecurityAgent"
    executable path="{visibility.SECURITY_AGENT}"
    '''
    assert visibility.security_agent_front(block, OTHER)
    assert visibility.security_agent_front("\n  " + block, OTHER)
    assert not visibility.security_agent_front(block, FRONT)
    assert not visibility.security_agent_front(block + block, OTHER)
    assert not visibility.security_agent_front(block.replace(visibility.SECURITY_AGENT, "/tmp/actor"), OTHER)
    assert not visibility.security_agent_front(block.replace("com.apple.SecurityAgent", "other"), OTHER)


def test_start_close_use_one_thread_and_never_call_native_in_fixture():
    value = visibility.PublicUpdateVisibility()
    with mock.patch.object(value, "_snapshot", side_effect=lambda: snapshot()), \
            mock.patch.object(visibility.threading, "Thread") as thread:
        thread.return_value.is_alive.return_value = False
        value.start()
        value._capture()
        result = terminal(value)
        assert result["status"] == "passed"
        thread.assert_called_once()
        thread.return_value.start.assert_called_once()
        thread.return_value.join.assert_called_once_with(timeout=16.0)
        with pytest.raises(visibility.VisibilityError, match="already started"):
            value.start()
