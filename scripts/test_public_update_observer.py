"""No native commands: real-UI authorization protocol and cancellation boundaries."""
import copy
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import public_update_observer as public
import public_update_menu_smoke as menu
import public_update_ax as ax
from native_root_update import Refused


@pytest.fixture(autouse=True)
def no_native(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("native command or signal forbidden")
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "kill", forbidden)
    monkeypatch.setattr(public.native_ui, "auth_action", forbidden)


class Clock:
    def __init__(self): self.now = 0.0
    def __call__(self): return self.now
    def sleep(self, seconds): self.now += seconds


def test_cancel_retries_only_preclick_then_once():
    clock, calls = Clock(), []
    responses = iter([{"state": "ax_error", "stage": "lookup", "code": -1728}, "absent", "cancelled"])
    def actor(prompt, **kwargs):
        calls.append((prompt, kwargs))
        return next(responses)
    assert public.cancel_dialog(actor, timeout=3, clock=clock, sleep=clock.sleep) == {
        "mode": "cancel", "cancelled": True, "cancel_clicks": 1}
    assert len(calls) == 3
    assert all(prompt == public.UPDATE_PROMPT and kw["cancel"] is True and kw["timeout"] <= 3 for prompt, kw in calls)
    assert all("username" not in kw and "password" not in kw for _, kw in calls)


@pytest.mark.parametrize("response", ["pending", "submitted", "rejected", {"state": "ax_error", "stage": "cancel", "code": -1728},
    {"state": "ax_error", "stage": "prompt_match", "code": -1728}, {"state": "ax_error", "stage": "lookup", "code": -999}])
def test_cancel_uncertain_action_never_replayed(response):
    calls = []
    with pytest.raises(Refused):
        public.cancel_dialog(lambda *_a, **_k: calls.append(1) or response, timeout=3)
    assert calls == [1]


def test_cancel_deadline_and_late_reply():
    clock = Clock()
    with pytest.raises(Refused, match="deadline"):
        public.cancel_dialog(lambda *_a, **_k: "absent", timeout=1, clock=clock, sleep=clock.sleep)
    assert clock.now == 1
    def late(*_a, **_k):
        clock.sleep(2)
        return "cancelled"
    with pytest.raises(Refused, match="arrived after"):
        public.cancel_dialog(late, timeout=1, clock=clock)


def configured():
    value = public.PublicObserver.__new__(public.PublicObserver)
    value.authorization = None
    value.authorization_mode = "confirm"
    value._authorization_credentials = ("ephemeral-user", "fixture-password-never-reported")
    value.authorization_children = [{"pid": 12, "uid": 501, "started": "birth"}]
    value.identity = {"nonce": "a" * 32, "prepare_deadline_unix": 12345}
    value.last_journal = {"phase": "prepared"}
    value.authorization_confirmed = False
    value.deadline = 720
    value.events = []
    value.record = lambda kind, evidence: value.events.append((kind, copy.deepcopy(evidence)))
    return value


def test_confirm_single_submit_then_readonly_and_separate_lease(monkeypatch):
    value, clock, calls = configured(), Clock(), []
    monkeypatch.setattr(public.native_ui.time, "monotonic", clock)
    monkeypatch.setattr(public.native_ui.time, "sleep", clock.sleep)
    def actor(prompt, **kwargs):
        calls.append((prompt, kwargs))
        return "submitted" if kwargs["submit"] else "absent"
    value.interact_authorization(actor=actor, clock=clock)
    value.interact_authorization(actor=lambda *_a, **_k: pytest.fail("replayed"), clock=clock)
    assert [kw["submit"] for _, kw in calls] == [True, False]
    assert all(prompt == public.UPDATE_PROMPT for prompt, _ in calls)
    assert value.authorization_confirmed and value._authorization_credentials is None
    assert value.deadline == 720 and value.identity["prepare_deadline_unix"] == 12345
    assert value.authorization["gui_budget_seconds"] == 90
    assert "fixture-password" not in repr(value.events) and "ephemeral-user" not in repr(value.events)
    assert value.authorization["scope"] == "native_submission_and_prompt_disappearance"


def test_confirm_uncertain_submission_is_not_replayed(monkeypatch):
    value, clock, calls = configured(), Clock(), []
    monkeypatch.setattr(public.native_ui.time, "monotonic", clock)
    monkeypatch.setattr(public.native_ui.time, "sleep", clock.sleep)
    def actor(*_a, **kwargs):
        calls.append(kwargs["submit"])
        return {"state": "ax_error", "stage": "confirm", "code": -1728} if kwargs["submit"] else "absent"
    with pytest.raises(public.native_ui.QualificationError):
        value.interact_authorization(actor=actor, clock=clock)
    value.interact_authorization(actor=actor, clock=clock)
    assert calls == [True, False] and not value.authorization_confirmed
    assert value._authorization_credentials is None


@pytest.mark.parametrize("change", ["unbound", "wrong_phase", "two_children"])
def test_auth_refuses_unbound_dialog(change):
    value = configured()
    if change == "unbound": value.identity = None
    if change == "wrong_phase": value.last_journal["phase"] = "successor_launched"
    if change == "two_children": value.authorization_children *= 2
    with pytest.raises(Refused):
        value.interact_authorization(actor=lambda *_a, **_k: pytest.fail("must not act"), clock=lambda: 0)


def proof(heartbeat=1):
    return {"process": {"uid": 0, "started": "daemon-birth", "command": "canonical daemon"},
            "proof": {"daemon_pid": 333, "daemon_sha256": "d" * 64, "heartbeat_seq": heartbeat},
            "current_tree_sha256": "c" * 64, "active_index_absent": True, "root_operation_absent": True}


@pytest.fixture
def cancelled(tmp_path):
    value = configured()
    value.authorization_mode = "cancel"
    value.authorization = {"cancelled": True}
    value.authorization_children = []
    value.root_status = value.ack = None
    value.cancel_log_offset = 0
    value.cancel_before = proof()
    value.cancel_runtime_proof = lambda _nonce=None: proof(2)
    value.original_exited = False
    value.original_process = SimpleNamespace(poll=lambda: None)
    value.initiator = {"pid": 111, "uid": os.getuid(), "started": "tray-birth", "command": "canonical tray", "state": "S"}
    value.uid = os.getuid()
    value.process_snapshot = lambda _pid: value.initiator
    value.observe_once = lambda: None
    value.target = tmp_path / "old.app"
    value.args = SimpleNamespace(output_dir=tmp_path)
    value.journal_path, value.ack_path, value.stage, value.agent = [tmp_path / name for name in ("journal", "ack", "stage", "agent")]
    value.last_journal["backup"] = str(tmp_path / "backup")
    value.expected = {"old": {"bundle_tree_sha256": "b" * 64}}
    value.tproxy = SimpleNamespace(_daemon_update_tree=lambda *_a, **_k: "b" * 64)
    value.retain_public_diagnostic = lambda: value.record("timeout", {})
    log = tmp_path / "normal-old-tray.log"
    log.write_text("update installation unavailable: update authorization cancelled\n")
    log.chmod(0o600)
    return value


def test_cancel_requires_clean_old_runtime_before_retry(cancelled):
    result = cancelled.wait_cancelled(clock=lambda: 0)
    assert result["native_cancel_qualified"] and result["local_preparation_removed"]
    assert result["nonce"] == cancelled.identity["nonce"]
    assert result["before"]["proof"]["heartbeat_seq"] < result["after"]["proof"]["heartbeat_seq"]
    reset = []
    cancelled.menu = SimpleNamespace(click_verified=True, reset_after_cancel=lambda: reset.append(1))
    cancelled.reset_after_cancel()
    assert reset == [1] and cancelled.identity is None and cancelled.last_journal is None
    assert cancelled.deadline == 720 and cancelled.initiator["pid"] == 111


@pytest.mark.parametrize("change", ["daemon_birth", "daemon_pid", "daemon_hash", "runtime_tree", "app_tree", "stage", "root_started", "tray_exit"])
def test_cancel_rejects_changed_or_pending_state(cancelled, change):
    after = proof(2)
    if change == "daemon_birth": after["process"]["started"] = "different"
    if change == "daemon_pid": after["proof"]["daemon_pid"] += 1
    if change == "daemon_hash": after["proof"]["daemon_sha256"] = "different"
    if change == "runtime_tree": after["current_tree_sha256"] = "different"
    cancelled.cancel_runtime_proof = lambda _nonce: after
    if change == "app_tree": cancelled.tproxy._daemon_update_tree = lambda *_a, **_k: "different"
    if change == "stage": cancelled.stage.mkdir()
    if change == "root_started": cancelled.root_status = {"phase": "prepared"}
    if change == "tray_exit": cancelled.original_process.poll = lambda: 0
    with pytest.raises(Refused): cancelled.wait_cancelled(clock=lambda: 0)
    assert not hasattr(cancelled, "cancelled_proof")


def test_cancel_requires_advancing_heartbeat_within_original_observation_budget(cancelled):
    clock = Clock()
    cancelled.deadline = 91
    cancelled.cancel_runtime_proof = lambda _nonce: proof()
    with pytest.raises(Refused, match="deadline"):
        cancelled.wait_cancelled(clock=clock, sleep=clock.sleep)
    assert clock.now == 1 and cancelled.events[-1][0] == "timeout"


def test_reset_cannot_clear_unproven_intent(cancelled):
    cancelled.cancelled_proof = None
    with pytest.raises(Refused, match="definitive"):
        cancelled.reset_after_cancel()
    assert cancelled.identity is not None


def test_cancel_late_runtime_proof_cannot_admit_retry(cancelled):
    clock = Clock()
    cancelled.deadline = 91
    def late(_nonce):
        clock.sleep(1)
        return proof(2)
    cancelled.cancel_runtime_proof = late
    with pytest.raises(Refused, match="arrived after"):
        cancelled.wait_cancelled(clock=clock, sleep=clock.sleep)
    assert not hasattr(cancelled, "cancelled_proof")


def test_readonly_cancel_proof_reuses_canonical_validator(monkeypatch, tmp_path):
    proxy = SimpleNamespace(_DAEMON_UPDATE_ROOT=str(tmp_path / "absent-root"), INSTALL_DIR="installed",
                            _daemon_update_tree=lambda p: "c" * 64 if p == "installed" else pytest.fail("unexpected tree"))
    calls = []
    monkeypatch.setattr(public, "readonly_runtime_proof", lambda p, h: calls.append((p, h)) or proof())
    value = public.readonly_cancel_proof(proxy, "d" * 64, "a" * 32)
    assert calls == [(proxy, "d" * 64)] and value["root_operation_absent"]
    assert value["nonce"] == "a" * 32


@pytest.mark.parametrize("present", ["active.json", "a" * 32, ".prepare-" + "a" * 32])
def test_readonly_cancel_refuses_root_operation_without_reading_runtime(monkeypatch, tmp_path, present):
    root = tmp_path / "root"
    root.mkdir()
    (root / present).touch()
    real_lstat = Path.lstat
    monkeypatch.setattr(Path, "lstat", lambda p: SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
                        if p == root else real_lstat(p))
    proxy = SimpleNamespace(_DAEMON_UPDATE_ROOT=str(root))
    monkeypatch.setattr(public, "readonly_runtime_proof", lambda *_a: pytest.fail("runtime proof after pending root"))
    with pytest.raises(Refused): public.readonly_cancel_proof(proxy, "d" * 64, "a" * 32)


def test_retry_uses_one_actual_check_action_and_keeps_install_distinct():
    original = {"pid": 1, "uid": 501, "started": "birth"}
    exe = Path("/Applications/Slipstream.app/Contents/MacOS/slipstream")
    report = {"identity": {**original, "executable": str(exe), "executable_sha256": "a" * 64},
              "status": "check_pressed", "installation_attempted": False,
              "actions": [{"kind": "press_check", "attempted": True, "ax_error": 0, "title": "Check for Updates…"}]}
    menu.validate_ax(report, original, exe, "a" * 64, checked=True)
    with pytest.raises(Refused): menu.validate_ax(report, original, exe, "a" * 64, pressed=True)
    report["actions"] *= 2
    with pytest.raises(Refused): menu.validate_ax(report, original, exe, "a" * 64, checked=True)


@pytest.mark.parametrize(("flag", "status"), [("--press-check", "check_pressed"), ("--open-menu", "menu_observed_after_timeout")])
def test_check_menu_cli_reports_success_exit(tmp_path, monkeypatch, flag, status):
    output = tmp_path / "check.json"
    monkeypatch.setattr(sys, "argv", ["public_update_ax.py", "--pid", "111", "--uid", "501",
        "--executable", "/Applications/Slipstream.app/Contents/MacOS/slipstream",
        "--exe-sha256", "a" * 64, "--output", str(output), flag])
    monkeypatch.setattr(ax.signal, "signal", lambda *_a: None)
    monkeypatch.setattr(ax.signal, "alarm", lambda *_a: None)
    def observed(args, report):
        assert args.press_check == (flag == "--press-check") and not args.press_update
        report["status"] = status
    monkeypatch.setattr(ax, "run", observed)
    assert ax.main() == 0


def menu_nodes(enabled=True):
    tray = {"element": 11, "path": "AXExtrasMenuBar/AXChildren[0]", "role": "AXMenuBarItem", "title": "", "enabled": True}
    submenu = {"element": 12, "path": tray["path"] + "/AXChildren[0]", "role": "AXMenu", "title": "", "enabled": True}
    item = {"element": 13, "path": submenu["path"] + "/AXChildren[0]", "role": "AXMenuItem",
            "title": f"Install Slipstream {menu.VERSION}…", "enabled": enabled}
    return [tray, submenu, item]


def timeout_visibility(nodes):
    return {"post_read": True, "visible": True, "visibility_method": "visible_children",
            "tray_path": nodes[0]["path"], "menu_path": nodes[1]["path"], "item_path": nodes[2]["path"],
            "title": nodes[2]["title"], "expected_version": menu.VERSION}


def ax_actor_fixture(monkeypatch, *, error=-25204, kind="open_menu", post=None, visible=True, drift=False):
    nodes, calls, identities = menu_nodes(), [], []
    original = {"pid": 111, "uid": 501, "started": "birth", "executable": "/Applications/Slipstream.app/Contents/MacOS/slipstream",
                "executable_sha256": "a" * 64}
    class Client:
        def __init__(self, _pid):
            self.nodes, self.reads = [], 0
        def inspect(self):
            self.reads += 1
            calls.append("read")
            self.nodes = copy.deepcopy(menu_nodes(False) if self.reads == 1 and kind == "open_menu" else (post or nodes))
            return []
        def press(self, node):
            calls.append(("press", node["element"]))
            return error
        def menu_visibility(self, node, tray, observation):
            calls.append("visibility")
            assert self.reads > 1 and node["enabled"] is True and tray["element"] == 11
            observation["stage"] = "visibility"
            if not visible:
                raise ax.Blocked("menu is not visibly present")
            return timeout_visibility(self.nodes)
        def close(self): calls.append("close")
    def identity(*_args):
        identities.append(1)
        return {**original, "started": "other"} if drift and len(identities) >= 5 else original
    monkeypatch.setattr(ax, "AX", Client)
    monkeypatch.setattr(ax, "identity", identity)
    monkeypatch.setattr(sys, "platform", "darwin")
    for key, value in {"CI": "true", "GITHUB_ACTIONS": "true", "RUNNER_OS": "macOS", "SLIPSTREAM_DISPOSABLE_CI": "1"}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(os, "getuid", lambda: 501)
    real_stat = os.stat
    monkeypatch.setattr(os, "stat", lambda path, *a, **kw: SimpleNamespace(st_uid=501) if str(path) == "/dev/console" else real_stat(path, *a, **kw))
    monkeypatch.setattr(Path, "resolve", lambda self, *_a, **_k: self)
    monkeypatch.setattr(ax.time, "sleep", lambda _seconds: None)
    args = SimpleNamespace(pid=111, uid=501, executable=Path(original["executable"]), exe_sha256="a" * 64,
                           open_menu=kind == "open_menu", press_update=kind == "press_update", press_check=kind == "press_check",
                           expected_version=menu.VERSION)
    report = {"status": "blocked", "actions": [], "installation_attempted": False}
    return args, report, calls, original


def test_menu_timeout_uses_one_action_then_fresh_visible_postcondition(monkeypatch):
    args, report, calls, original = ax_actor_fixture(monkeypatch)
    ax.run(args, report)
    assert report["status"] == "menu_observed_after_timeout"
    assert [call for call in calls if isinstance(call, tuple)] == [("press", 11)]
    assert calls == ["read", ("press", 11), "read", "visibility", "close"]
    assert report["actions"][0]["ax_error"] == -25204
    assert report["actions"][0]["postcondition"] == timeout_visibility(menu_nodes())
    menu.validate_ax(report, {key: original[key] for key in ("pid", "uid", "started")}, args.executable, "a" * 64)


@pytest.mark.parametrize("case", ["hidden", "disabled", "duplicate", "wrong_version", "identity", "other_error"])
def test_menu_timeout_refuses_uncertain_postcondition_without_replay(monkeypatch, case):
    nodes = menu_nodes(enabled=case != "disabled")
    if case == "duplicate": nodes.append(copy.deepcopy(nodes[-1]))
    if case == "wrong_version": nodes[-1]["title"] = "Install Slipstream 0.1.9-preview.99…"
    args, report, calls, _ = ax_actor_fixture(monkeypatch, post=nodes, visible=case != "hidden",
        drift=case == "identity", error=-25202 if case == "other_error" else -25204)
    with pytest.raises(ax.Blocked): ax.run(args, report)
    assert len([call for call in calls if isinstance(call, tuple)]) == 1
    assert report["status"] == "blocked"


def test_install_timeout_stays_failure_without_postread_or_replay(monkeypatch):
    args, report, calls, _ = ax_actor_fixture(monkeypatch, kind="press_update")
    with pytest.raises(ax.Blocked): ax.run(args, report)
    assert calls == ["read", ("press", 13), "close"]
    assert report["installation_attempted"] is True


def test_check_timeout_stays_failure_without_postread_or_replay(monkeypatch):
    nodes = menu_nodes()
    nodes[-1]["title"] = "Check for Updates…"
    args, report, calls, _ = ax_actor_fixture(monkeypatch, kind="press_check", post=nodes)
    with pytest.raises(ax.Blocked): ax.run(args, report)
    assert calls == ["read", ("press", 13), "close"]
    assert report["installation_attempted"] is False


@pytest.mark.parametrize("mutation", ["missing_proof", "pre_read", "hidden", "unknown_method", "wrong_version", "wrong_title",
    "wrong_parent", "missing_nodes", "ambiguous_nodes", "missing_offer", "duplicate_offer", "disabled", "extra_action", "rewritten_error",
    "false_status", "identity", "malformed_method", "malformed_title"])
def test_timeout_report_rejects_incomplete_or_mismatched_proof(monkeypatch, mutation):
    args, report, _, original = ax_actor_fixture(monkeypatch)
    ax.run(args, report)
    action = report["actions"][0]
    p = action["postcondition"]
    if mutation == "missing_proof": del action["postcondition"]
    if mutation == "pre_read": p["post_read"] = False
    if mutation == "hidden": p["visible"] = False
    if mutation == "unknown_method": p["visibility_method"] = "enabled_is_enough"
    if mutation == "malformed_method": p["visibility_method"] = []
    if mutation == "malformed_title": p["title"] = []
    if mutation == "wrong_version": p["expected_version"] = "0.1.9-preview.99"
    if mutation == "wrong_title": p["title"] = "Check for Updates…"
    if mutation == "wrong_parent": p["tray_path"] = "another tray"
    if mutation == "missing_nodes": del report["nodes"]
    if mutation == "ambiguous_nodes": report["nodes"].append(copy.deepcopy(report["nodes"][-1]))
    if mutation == "missing_offer": report["update_items"] = []
    if mutation == "duplicate_offer": report["update_items"] *= 2
    if mutation == "disabled": report["nodes"][-1]["enabled"] = False
    if mutation == "extra_action": report["actions"] *= 2
    if mutation == "rewritten_error": action["ax_error"] = 0
    if mutation == "false_status": report["status"] = "menu_opened"
    if mutation == "identity": report["identity"] = {**original, "started": "other"}
    with pytest.raises(Refused):
        menu.validate_ax(report, {key: original[key] for key in ("pid", "uid", "started")}, args.executable, "a" * 64)


def visibility_client(*, error=0, children=(13,), hit=13, frame=(10, 20, 80, 16), parent=12, hit_error=0,
                      tray_parent=11, tray_children=(12,), menu_children=(13,), forward_error=0, forward_value=32):
    client = ax.AX.__new__(ax.AX)
    client.nodes, client.refs, client.pid = menu_nodes(), [], 111
    calls = []
    values = {11: "element", 12: "element", 13: "element", 14: "element", 31: "array", 32: "array", 33: "array", 41: "value", 42: "value"}
    arrays = {31: children, 32: tray_children, 33: menu_children}
    attributes = {(13, "AXParent"): (0, parent), (12, "AXParent"): (0, tray_parent),
                  (11, "AXChildren"): (forward_error, forward_value), (12, "AXChildren"): (0, 33),
                  (12, "AXVisibleChildren"): (error, 31 if error == 0 else None),
                  (13, "AXPosition"): (0, 41), (13, "AXSize"): (0, 42)}
    def attribute(element, name):
        calls.append((element, name))
        return attributes[element, name]
    def check(element):
        calls.append(("check", element))
        if element not in {11, 12, 13}: raise ax.Blocked("foreign PID")
    def copy_hit(system, x, y, target):
        calls.append(("hit", system, x, y))
        ax.C.cast(target, ax.C.POINTER(ax.C.c_void_p))[0] = ax.C.c_void_p(hit)
        return hit_error
    def get_value(value, kind, pointer):
        target = ax.C.cast(pointer, ax.C.POINTER(ax.Point if kind == 1 else ax.Size)).contents
        if kind == 1: target.x, target.y = frame[:2]
        else: target.width, target.height = frame[2:]
        return True
    client.attribute, client.check = attribute, check
    client.cf = SimpleNamespace(CFEqual=lambda a, b: a == b, CFGetTypeID=lambda value: values.get(value),
        CFArrayGetTypeID=lambda: "array", CFArrayGetCount=lambda value: len(arrays[value]),
        CFArrayGetValueAtIndex=lambda value, index: arrays[value][index])
    client.ax = SimpleNamespace(AXUIElementGetTypeID=lambda: "element", AXValueGetTypeID=lambda: "value",
        AXValueGetType=lambda value: value - 40, AXValueGetValue=get_value,
        AXUIElementCreateSystemWide=lambda: 99, AXUIElementSetMessagingTimeout=lambda *_a: 0,
        AXUIElementCopyElementAtPosition=copy_hit)
    return client, calls


@pytest.mark.parametrize("error", [0, -25205, -25212])
def test_positive_menu_visibility_uses_owned_parent_or_exact_global_hit(error):
    client, calls = visibility_client(error=error)
    result = client.menu_visibility(client.nodes[-1], client.nodes[0])
    assert result["visible"] and result["post_read"]
    assert result["visibility_method"] == ("visible_children" if error == 0 else "global_hit_test")
    hits = [call for call in calls if call[0] == "hit"]
    assert hits == ([] if error == 0 else [("hit", 99, 50.0, 28.0)])
    assert result["tray_path"] == client.nodes[0]["path"] and result["item_path"] == client.nodes[-1]["path"]


@pytest.mark.parametrize("reverse", [{"parent": 11}, {"tray_parent": 12}])
def test_fresh_forward_containment_does_not_require_reverse_parent_identity(reverse):
    client, calls = visibility_client(**reverse)
    result = client.menu_visibility(client.nodes[-1], client.nodes[0])
    assert result["visible"] is True
    assert [(element, attribute) for element, attribute in calls if attribute == "AXChildren"] == [
        (11, "AXChildren"), (12, "AXChildren")]
    assert not any(call[1] == "AXParent" for call in calls)


@pytest.mark.parametrize(("kwargs", "edge", "status", "count", "matches"), [
    ({"tray_children": ()}, "tray_to_menu", "child_not_unique", 0, 0),
    ({"tray_children": (12, 12)}, "tray_to_menu", "child_not_unique", 2, 2),
    ({"tray_children": (13,)}, "tray_to_menu", "child_not_unique", 1, 0),
    ({"tray_children": (14,)}, "tray_to_menu", "child_check_failed", 1, 0),
    ({"tray_children": (41,)}, "tray_to_menu", "invalid_child", 1, 0),
    ({"tray_children": (12,) * 65}, "tray_to_menu", "count_out_of_bounds", 65, None),
    ({"forward_error": -25204}, "tray_to_menu", "read_failed", None, None),
    ({"forward_value": 11}, "tray_to_menu", "invalid_array", None, None),
    ({"forward_value": None}, "tray_to_menu", "invalid_array", None, None),
    ({"menu_children": ()}, "menu_to_item", "child_not_unique", 0, 0),
    ({"menu_children": (13, 13)}, "menu_to_item", "child_not_unique", 2, 2),
    ({"menu_children": (11,)}, "menu_to_item", "child_not_unique", 1, 0),
    ({"menu_children": (14,)}, "menu_to_item", "child_check_failed", 1, 0),
])
def test_fresh_containment_refuses_and_retains_exact_partial_edge(kwargs, edge, status, count, matches):
    client, calls = visibility_client(**kwargs)
    observation = {"stage": "menu_selection", "edges": []}
    with pytest.raises(ax.Blocked): client.menu_visibility(client.nodes[-1], client.nodes[0], observation)
    assert observation["stage"] == "forward_containment"
    last = observation["edges"][-1]
    assert (last["edge"], last["status"], last["count"], last["match_count"]) == (edge, status, count, matches)
    assert len(observation["edges"]) == (1 if edge == "tray_to_menu" else 2)
    if edge == "menu_to_item": assert observation["edges"][0]["status"] == "matched"
    assert not any(call[1] in {"AXParent", "AXVisibleChildren"} for call in calls)


def test_actor_preserves_partial_containment_diagnostic_before_failure(monkeypatch):
    args, report, calls, _ = ax_actor_fixture(monkeypatch)
    def fail(self, node, tray, observation):
        observation["stage"] = "forward_containment"
        observation["edges"].append({"edge": "menu_to_item", "ax_error": -25204, "status": "read_failed"})
        raise ax.Blocked("fresh menu children read failed")
    monkeypatch.setattr(ax.AX, "menu_visibility", fail)
    with pytest.raises(ax.Blocked): ax.run(args, report)
    assert report["actions"][0]["observation"] == {
        "stage": "forward_containment", "edges": [{"edge": "menu_to_item", "ax_error": -25204, "status": "read_failed"}]}
    assert report["actions"][0]["ax_error"] == -25204
    assert "postcondition" not in report["actions"][0]
    assert [call for call in calls if isinstance(call, tuple)] == [("press", 11)]


@pytest.mark.parametrize("kwargs", [
    {"children": ()}, {"children": (13, 13)}, {"children": (14,)}, {"error": -25204},
    {"error": -25205, "hit": 14}, {"error": -25205, "hit": 12}, {"error": -25205, "hit": None},
    {"error": -25205, "hit_error": -25204}, {"error": -25205, "frame": (0, 0, 0, 10)},
    {"error": -25205, "frame": (float("nan"), 0, 10, 10)}, {"error": -25205, "frame": (0, 0, float("inf"), 10)},
])
def test_menu_visibility_refuses_hidden_foreign_unknown_or_invalid_geometry(kwargs):
    client, _ = visibility_client(**kwargs)
    with pytest.raises(ax.Blocked): client.menu_visibility(client.nodes[-1], client.nodes[0])
