"""Inert fixtures only: no native command, payload, signal, or installation."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
import packaged_update_observer as observer

FIXTURE = json.loads((REPO / "contracts/update-daemon-status-v1.json").read_text())
STATUSES = {vector["name"]: vector["status"] for vector in FIXTURE["vectors"]}
PREPARED = STATUSES["prepared"]
IDENTITY = {key: value for key, value in PREPARED.items() if key not in {
    "manifest_sha256", "phase", "decision", "accepted_sequence", "deadline_unix",
    "worker_pid", "daemon_pid", "daemon_sha256", "heartbeat_seq", "install_attestation_sha256",
    "writer_quiescent", "error"}}
UID = IDENTITY["uid"]
START = "Mon Oct 19 12:34:56 2026"
EXPECTED = {side: {"version": IDENTITY[side + "_version"], "source_commit": digit * 40,
                  "archive_sha256": IDENTITY["archive_sha256"],
                  **{key: IDENTITY[side + "_" + key] for key in
                     ("app_executable_sha256", "daemon_sha256", "bundle_tree_sha256")}}
            for side, digit in (("old", "a"), ("new", "b"))}


@pytest.fixture(autouse=True)
def no_native(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("native command/signal forbidden in observer fixture")
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "kill", forbidden)


def private(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
    path.chmod(0o600)
    return path


@pytest.fixture
def journal(tmp_path):
    target, state = tmp_path / "Applications/Slipstream.app", tmp_path / "state"
    nonce = IDENTITY["nonce"]
    return {"schema_version": 2, "nonce": nonce, "uid": UID, "initiator_pid": 111,
            "target": str(target), "backup": str(target.parent / (".Slipstream.app.slipstream-backup-" + nonce)),
            "stage": str(target.parent / (".Slipstream.app.slipstream-stage-" + nonce)),
            "helper": str(state / "runtime/slipstream-update-watchdog"),
            "launch_agent": str(Path.home() / "Library/LaunchAgents" / (observer.WATCHDOG + ".plist")),
            "current_version": EXPECTED["old"]["version"], "expected_version": EXPECTED["new"]["version"],
            "archive_sha256": IDENTITY["archive_sha256"], "watchdog_sha256": "9" * 64,
            "old_executable_sha256": IDENTITY["old_app_executable_sha256"],
            "new_executable_sha256": IDENTITY["new_app_executable_sha256"],
            "phase": "successor_launched", "successor_pid": 222, "successor_started": START,
            "successor_deadline_unix": 4102444800, "last_error": None,
            "daemon_update": {"identity": copy.deepcopy(IDENTITY), "manifest_sha256": PREPARED["manifest_sha256"],
                              "sequence": 1, "action": "activate", "authorization_started": True}}


def valid_journal(value):
    return observer.validate_journal(value, EXPECTED, IDENTITY, UID,
        Path(value["helper"]).parent.parent, Path(value["target"]), "9" * 64)


def ack_for(journal):
    return {"schema_version": 1, "nonce": journal["nonce"], "uid": UID, "pid": journal["successor_pid"],
            "version": journal["expected_version"], "target": journal["target"],
            "executable_sha256": journal["new_executable_sha256"], "heartbeat_seq": 7}


def process_for(journal):
    return {"pid": journal["successor_pid"], "uid": UID, "started": journal["successor_started"],
            "state": "S", "command": journal["target"] + "/Contents/MacOS/slipstream"}


def test_private_reader_missing_incomplete_and_complete_receipt(tmp_path):
    path = tmp_path / "receipt.json"
    assert observer.private_json(path, os.getuid()) is None
    private(path, b'{"ready":')
    assert observer.private_json(path, os.getuid(), writing=True) is None
    with pytest.raises(observer.Refused, match="incomplete"):
        observer.private_json(path, os.getuid())
    private(path, {"ready": True})
    assert observer.private_json(path, os.getuid()) == {"ready": True}


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "mode", "owner", "oversize", "array", "duplicate", "nan"])
def test_private_reader_rejects_unsafe_or_ambiguous_input(tmp_path, kind):
    path = private(tmp_path / "value.json", {"ok": True})
    uid = os.getuid()
    if kind == "symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(path)
        path = alias
    elif kind == "hardlink":
        os.link(path, tmp_path / "extra")
    elif kind == "fifo":
        path.unlink()
        os.mkfifo(path, 0o600)
    elif kind == "mode":
        path.chmod(0o644)
    elif kind == "owner":
        uid += 1
    elif kind == "oversize":
        private(path, b"x" * 100)
    elif kind == "array":
        private(path, [])
    elif kind == "duplicate":
        private(path, b'{"ok":true,"ok":false}')
    elif kind == "nan":
        private(path, b'{"ok":NaN}')
    with pytest.raises(observer.Refused):
        observer.private_json(path, uid, limit=64, writing=True)


def test_private_reader_accepts_open_snapshot_during_atomic_replacement(tmp_path, monkeypatch):
    path = private(tmp_path / "value.json", {"generation": 1})
    replacement = private(tmp_path / "new.json", {"generation": 2})
    original_fstat, calls = os.fstat, []
    def replace_after_first_stat(fd):
        info = original_fstat(fd)
        calls.append(fd)
        if len(calls) == 1:
            os.replace(replacement, path)
        return info
    monkeypatch.setattr(os, "fstat", replace_after_first_stat)
    assert observer.private_json(path, os.getuid()) == {"generation": 1}
    assert json.loads(path.read_text()) == {"generation": 2}


def test_journal_and_ack_use_actual_root_fixture_identity(journal):
    assert valid_journal(journal) == journal
    assert observer.validate_ack(ack_for(journal), journal) == ack_for(journal)
    for value in STATUSES.values():
        assert observer.validate_root(value, IDENTITY, set(PREPARED), None) == value


@pytest.mark.parametrize("key,value", [
    ("schema_version", True), ("uid", True), ("nonce", "f" * 32), ("archive_sha256", "0" * 64),
    ("watchdog_sha256", "0" * 64), ("backup", "/tmp/foreign"), ("stage", "/tmp/foreign"),
    ("helper", "/tmp/foreign"), ("launch_agent", "/tmp/foreign"), ("initiator_pid", True),
    ("successor_pid", 2**31), ("successor_started", None), ("successor_deadline_unix", True),
    ("last_error", 1), ("phase", "unknown")])
def test_journal_rejects_identity_path_and_type_drift(journal, key, value):
    journal[key] = value
    with pytest.raises(observer.Refused):
        # Expected paths are independent of the modified journal field.
        observer.validate_journal(journal, EXPECTED, IDENTITY, UID,
            Path(journal["target"]).parents[1] / "state", Path(journal["target"]), "9" * 64)


@pytest.mark.parametrize("key,value", [("sequence", True), ("sequence", -1), ("manifest_sha256", "f"),
    ("action", "drop"), ("authorization_started", 1)])
def test_journal_binding_is_typed(journal, key, value):
    journal["daemon_update"][key] = value
    with pytest.raises(observer.Refused):
        valid_journal(journal)


def test_journal_binding_rejects_bool_identity_and_unknown_fields(journal):
    journal["daemon_update"]["identity"]["schema_version"] = True
    with pytest.raises(observer.Refused):
        valid_journal(journal)
    journal["daemon_update"]["identity"] = copy.deepcopy(IDENTITY)
    journal["daemon_update"]["unknown"] = 0
    with pytest.raises(observer.Refused):
        valid_journal(journal)


def test_cleanup_intent_is_checked_without_requiring_deleted_tree(journal):
    journal["phase"] = "cleanup_failed"
    journal["cleanup_intent"] = {"kind": "committed", "backup": {"device": 1, "inode": 2}, "stage": None}
    valid_journal(journal)
    journal["cleanup_intent"]["backup"]["inode"] = 0
    with pytest.raises(observer.Refused, match="cleanup slot"):
        valid_journal(journal)


@pytest.mark.parametrize("key,value", [("schema_version", True), ("nonce", "f" * 32), ("uid", True),
    ("pid", 223), ("version", "wrong"), ("executable_sha256", "0" * 64), ("heartbeat_seq", 0), ("heartbeat_seq", True)])
def test_ack_requires_exact_successor_not_only_commit(journal, key, value):
    ack = ack_for(journal)
    ack[key] = value
    with pytest.raises(observer.Refused):
        observer.validate_ack(ack, journal)


def test_commit_does_not_infer_transient_ack_from_root_or_cleanup():
    with pytest.raises(observer.Refused, match="real successor ACK"):
        observer.committed(STATUSES["committed"], None)


def test_process_parser_pins_birth_and_full_argv(journal):
    expected = process_for(journal)
    raw = f" 222 {UID} S Mon Oct 19 12:34:56 2026 {expected['command']}\n"
    assert observer.parse_process(raw) == expected
    assert observer.exact_successor(expected, journal)
    for key, value in (("pid", 223), ("uid", UID + 1), ("started", "Mon Oct 19 12:34:57 2026"),
                       ("command", expected["command"] + " --foreign"), ("state", "Z"), ("state", "T")):
        assert not observer.exact_successor({**expected, key: value}, journal)
    with pytest.raises(observer.Refused):
        observer.parse_process(raw + "another process")


def test_future_fault_eligibility_never_signals_and_revalidates_exact_identity(journal):
    process = process_for(journal)
    assert observer.pre_ack_candidate(journal, None, STATUSES["ready"], process, process) == process
    for after in ({**process, "started": "Mon Oct 19 12:34:57 2026"}, {**process, "command": "/other"}, None):
        with pytest.raises(observer.Refused):
            observer.pre_ack_candidate(journal, None, STATUSES["ready"], process, after)
    with pytest.raises(observer.Refused):
        observer.pre_ack_candidate(journal, ack_for(journal), STATUSES["ready"], process, process)


def test_fault_cli_refuses_before_guard_or_setup(monkeypatch):
    monkeypatch.setattr(observer, "guard", lambda: pytest.fail("guard must not run"))
    args = []
    for name in ("repo", "pair-manifest", "old-candidate-dir", "new-candidate-dir", "old-app", "new-app", "trigger-dir", "output"):
        args += ["--" + name, "/not-used"]
    with pytest.raises(observer.Refused, match="not implemented or qualified"):
        observer.main([*args, "--mode", "kill-successor-before-ack", "--gh", "/not-used"])


@pytest.mark.parametrize("key,value", [("writer_quiescent", 1), ("worker_pid", True), ("daemon_pid", True),
    ("heartbeat_seq", True), ("daemon_sha256", "bad"), ("phase", "unknown"), ("decision", "commit")])
def test_root_status_rejects_invalid_wire_values(key, value):
    with pytest.raises(observer.Refused):
        observer.validate_root({**PREPARED, key: value}, IDENTITY, set(PREPARED), None)


def test_root_durable_decision_manifest_and_sequence_cannot_regress():
    with pytest.raises(observer.Refused, match="manifest changed"):
        observer.validate_root(PREPARED, IDENTITY, set(PREPARED), "0" * 64)
    with pytest.raises(observer.Refused, match="decision/sequence regressed"):
        observer.validate_root(STATUSES["aborted"], IDENTITY, set(PREPARED), None, STATUSES["committed"])
    with pytest.raises(observer.Refused, match="decision/sequence regressed"):
        observer.validate_root(PREPARED, IDENTITY, set(PREPARED), None, {**PREPARED, "accepted_sequence": 2})


def bare_observer(journal):
    result = object.__new__(observer.Observer)
    result.events, result.last_event, result.expected = [], {}, copy.deepcopy(EXPECTED)
    result.identity, result.manifest, result.root_status = copy.deepcopy(IDENTITY), None, None
    result.uid, result.last_journal = UID, copy.deepcopy(journal)
    result.fields, result.operation = set(PREPARED), Path("/inert/operation")
    result.initiator = {"pid": journal["initiator_pid"], "uid": UID, "started": START,
                        "command": "/inert/trigger --prepare", "state": "S"}
    result.receipt = {"prepared": True}
    result.ack, result.ack_process = ack_for(journal), process_for(journal)
    result.watchdog = {"pid": 333}
    result.deadline = 91
    return result


def test_root_status_dedup_is_per_kind_and_immutable(journal):
    backend = bare_observer(journal)
    backend.tproxy = SimpleNamespace(_update_read_json=lambda *a, **k: copy.deepcopy(PREPARED))
    for count in range(600):
        backend.status()
        backend.record("app_journal", {"unchanged": True})
    assert len(backend.events) == 2
    assert backend.events[0]["value"] == PREPARED
    mutable = {"nested": [1]}
    backend.record("snapshot", mutable)
    mutable["nested"].append(2)
    assert backend.events[-1]["value"] == {"nested": [1]}
    backend.events = [{}] * 512
    with pytest.raises(observer.Refused, match="bound exceeded"):
        backend.record("new", {})


class Clock:
    def __init__(self):
        self.now = 0.0
    def __call__(self):
        return self.now
    def sleep(self, seconds):
        self.now += seconds


def waiting(journal, *, complete=True):
    backend = bare_observer(journal)
    sequence = [copy.deepcopy(journal), None] if complete else [copy.deepcopy(journal)]
    def observe_once():
        current = sequence.pop(0) if len(sequence) > 1 else sequence[0]
        backend.root_status = copy.deepcopy(STATUSES["committed"] if current is None else STATUSES["ready"])
        return current
    backend.observe_once = observe_once
    backend.status = lambda: copy.deepcopy(backend.root_status)
    backend.watchdog_finished = lambda: True
    backend.process_snapshot = lambda _pid: None
    return backend


def test_bounded_wait_consumes_real_observation_not_only_absent_journal(journal):
    backend, clock = waiting(journal), Clock()
    assert backend.wait_transaction(clock=clock, sleep=clock.sleep)["decision"] == "commit"
    assert clock.now == 0.02
    backend = waiting(journal)
    backend.ack = None
    with pytest.raises(observer.Refused, match="real successor ACK"):
        backend.wait_transaction(clock=clock, sleep=clock.sleep)


def terminal_watchdog_fixture(journal):
    backend = waiting(journal)
    backend.uid = os.getuid()
    backend.state = Path(journal["helper"]).parent.parent
    backend.journal_path = backend.state / observer.JOURNAL
    backend.ack_path = backend.journal_path.with_suffix(".ack.json")
    backend.agent = backend.state / "absent-agent.plist"
    backend.stage = Path(journal["stage"])
    helper = private(Path(journal["helper"]), b"inert watchdog")
    helper.chmod(0o700)
    backend.watchdog_hash = observer.digest(helper)
    backend.observed_watchdog_policy = {
        "Label": observer.WATCHDOG, "ProgramArguments": [str(helper), "--journal", str(backend.journal_path)],
        "RunAtLoad": True, "KeepAlive": {"SuccessfulExit": False}, "ProcessType": "Background",
        "StandardOutPath": str(backend.state / "update-watchdog.stdout.log"),
        "StandardErrorPath": str(backend.state / "update-watchdog.stderr.log")}
    private(backend.journal_path.with_suffix(".lock"), b"")
    backend.job_text = (f"gui/{backend.uid}/{observer.WATCHDOG} = {{\n"
        f"\tactive count = 0\n\tprogram = {helper}\n\targuments = {{\n"
        f"\t\t{helper}\n\t\t--journal\n\t\t{backend.journal_path}\n\t}}\n"
        "\tstate = not running\n\truns = 1\n\tlast exit code = 0\n}\n").encode()
    backend.run = lambda *_a, **_k: SimpleNamespace(returncode=0, stdout=backend.job_text, stderr=b"")
    backend.watchdog_absent = lambda: False  # Exact allowed loaded, successfully exited job.
    del backend.watchdog_finished
    return backend


def test_commit_accepts_exact_successfully_exited_loaded_watchdog(journal):
    backend, clock = terminal_watchdog_fixture(journal), Clock()
    assert backend.wait_transaction(clock=clock, sleep=clock.sleep)["decision"] == "commit"
    assert clock.now == 0.02
    assert backend.events[-1]["kind"] == "watchdog_completion"
    assert backend.events[-1]["value"]["lock"] == "available"


def final_watchdog_fixture(journal):
    backend, clock = terminal_watchdog_fixture(journal), Clock()
    backend.target = Path(journal["target"])
    backend.tproxy = SimpleNamespace(_daemon_update_tree=lambda *_a, **_k: EXPECTED["new"]["bundle_tree_sha256"])
    backend.process_snapshot = lambda pid: process_for(journal) if pid == journal["successor_pid"] else None
    def query(argv, **_kwargs):
        if argv[0] == "/bin/launchctl":
            return SimpleNamespace(returncode=0, stdout=backend.job_text, stderr=b"")
        if argv[0] == "/usr/bin/pgrep":
            return SimpleNamespace(returncode=0, stdout=b"222\n")
        assert argv[0] == "/bin/ps"
        return SimpleNamespace(returncode=0, stdout=f"222 333 {UID} S {START}\n".encode())
    backend.run = query
    # Use the real bounded wait with a deterministic clock. The old final_app
    # bypasses this helper and fails on its single busy-lock observation.
    def wait(deadline, **_kwargs):
        assert deadline == backend.deadline - 90
        return observer.Observer.wait_watchdog_finished(backend, deadline, clock=clock, sleep=clock.sleep)
    backend.wait_watchdog_finished = wait
    return backend, clock


def test_final_app_rechecks_transient_lock_after_observed_completion(journal):
    backend, clock = final_watchdog_fixture(journal)
    assert backend.watchdog_finished() is True
    with backend.journal_path.with_suffix(".lock").open("rb") as held:
        observer.fcntl.flock(held, observer.fcntl.LOCK_EX | observer.fcntl.LOCK_NB)
        def release(seconds):
            clock.now += seconds
            observer.fcntl.flock(held, observer.fcntl.LOCK_UN)
        clock.sleep = release
        backend.final_app()
    assert clock.now == 0.02 and backend.deadline == 91
    assert any(e["kind"] == "completion_diagnostic" and e["value"]["lock"] == "busy" for e in backend.events)
    assert backend.tray == process_for(journal)
    assert backend.events[-1]["kind"] == "final_app"


def test_final_app_permanent_lock_contention_exhausts_existing_budget(journal):
    backend, clock = final_watchdog_fixture(journal)
    with backend.journal_path.with_suffix(".lock").open("rb") as held:
        observer.fcntl.flock(held, observer.fcntl.LOCK_EX | observer.fcntl.LOCK_NB)
        with pytest.raises(observer.Refused, match="terminal watchdog deadline exhausted"):
            backend.final_app()
    assert clock.now == 1 and backend.deadline == 91
    assert backend.events[-1]["value"]["lock"] == "busy"
    assert not any(e["kind"] == "final_app" for e in backend.events)


def test_final_app_expired_budget_cannot_accept_even_terminal_watchdog(journal):
    backend, clock = final_watchdog_fixture(journal)
    clock.now = backend.deadline - 90
    with pytest.raises(observer.Refused, match="terminal watchdog deadline exhausted"):
        backend.final_app()
    assert clock.now == 1 and not backend.events


def test_final_app_unsafe_terminal_lock_is_not_retried(journal):
    backend, clock = final_watchdog_fixture(journal)
    backend.journal_path.with_suffix(".lock").chmod(0o644)
    with pytest.raises(observer.Refused, match="unsafe terminal transaction lock"):
        backend.final_app()
    assert clock.now == 0
    assert not any(e["kind"] == "final_app" for e in backend.events)


def test_final_app_rechecks_bundle_after_waiting_for_lock(journal):
    backend, clock = final_watchdog_fixture(journal)
    with backend.journal_path.with_suffix(".lock").open("rb") as held:
        observer.fcntl.flock(held, observer.fcntl.LOCK_EX | observer.fcntl.LOCK_NB)
        def change_bundle(seconds):
            clock.now += seconds
            backend.tproxy._daemon_update_tree = lambda *_a, **_k: "0" * 64
            observer.fcntl.flock(held, observer.fcntl.LOCK_UN)
        clock.sleep = change_bundle
        with pytest.raises(observer.Refused, match="final app tree mismatch"):
            backend.final_app()
    assert clock.now == 0.02
    assert not any(e["kind"] == "final_app" for e in backend.events)


def test_preack_rollback_accepts_same_terminal_watchdog_contract(journal):
    from packaged_update_preack import PreAckObserver
    backend, clock = terminal_watchdog_fixture(journal), Clock()
    backend.args = SimpleNamespace(mode="kill-successor-before-ack")
    backend.fault_process, backend.ack = process_for(journal), None
    backend.root_status = copy.deepcopy(STATUSES["aborted"])
    backend.observe_once = lambda: None
    backend.final_old_app = lambda **kw: backend.events.append({"kind": "old-proof"})
    backend.prove = lambda *_a, **_k: backend.events.append({"kind": "daemon-proof"})
    result = PreAckObserver.qualify_app(backend, clock=clock, sleep=clock.sleep)
    assert result["successor_exit_before_ack_rollback_qualified"] is True
    assert [event["kind"] for event in backend.events][-3:] == ["old-proof", "daemon-proof", "old-proof"]


@pytest.mark.parametrize("before,after", [
    ("gui/", "system/"), ("program = ", "program = /foreign/"),
    ("\t\t--journal", "\t\t--foreign"), ("last exit code = 0", "last exit code = 1"),
    ("active count = 0", "active count = 1"), ("runs = 1", "runs = 0"),
    ("state = not running", "state = waiting"),
])
def test_terminal_job_wrong_identity_or_restartable_outcome_refused(journal, before, after):
    backend = terminal_watchdog_fixture(journal)
    backend.job_text = backend.job_text.replace(before.encode(), after.encode())
    with pytest.raises(observer.Refused):
        backend.watchdog_finished()
    assert backend.events[-1]["kind"] == "completion_diagnostic"


def test_terminal_running_job_and_busy_lock_remain_pending(journal):
    backend = terminal_watchdog_fixture(journal)
    original = backend.job_text
    backend.job_text = original.replace(b"state = not running", b"state = running\n\tpid = 333")
    assert backend.watchdog_finished() is False
    backend.job_text = original
    with backend.journal_path.with_suffix(".lock").open("rb") as held:
        observer.fcntl.flock(held, observer.fcntl.LOCK_EX | observer.fcntl.LOCK_NB)
        try:
            assert backend.watchdog_finished() is False
            assert backend.completion_diagnostic["lock"] == "busy"
        finally:
            observer.fcntl.flock(held, observer.fcntl.LOCK_UN)
    assert backend.watchdog_finished() is True


@pytest.mark.parametrize("change", ["missing", "mode", "symlink", "hardlink", "fifo", "owner"])
def test_terminal_lock_must_be_existing_private_owned_regular_file(journal, change):
    backend = terminal_watchdog_fixture(journal)
    lock = backend.journal_path.with_suffix(".lock")
    if change == "mode":
        lock.chmod(0o644)
    elif change == "owner":
        backend.uid += 1
        backend.job_text = backend.job_text.replace(f"gui/{os.getuid()}/".encode(), f"gui/{backend.uid}/".encode())
    elif change == "hardlink":
        os.link(lock, lock.with_suffix(".alias"))
    else:
        lock.unlink()
        if change == "symlink":
            lock.symlink_to(private(lock.with_suffix(".other"), b""))
        elif change == "fifo":
            os.mkfifo(lock, 0o600)
    with pytest.raises(observer.Refused):
        backend.watchdog_finished()
    if change == "missing":
        assert not lock.exists()


def test_terminal_watchdog_reused_pid_is_not_proven_gone(journal):
    backend = terminal_watchdog_fixture(journal)
    backend.watchdog = {"pid": 333, "uid": backend.uid, "state": "S", "started": START, "command": "/old"}
    backend.process_snapshot = lambda _pid: {**backend.watchdog, "started": "Tue Oct 20 12:00:00 2026"}
    with pytest.raises(observer.Refused, match="PID was reused"):
        backend.watchdog_finished()


def test_terminal_loaded_job_requires_captured_exact_policy(journal):
    backend = terminal_watchdog_fixture(journal)
    backend.observed_watchdog_policy["KeepAlive"] = True
    with pytest.raises(observer.Refused, match="policy differs"):
        backend.watchdog_finished()
    backend.observed_watchdog_policy = None
    with pytest.raises(observer.Refused, match="not captured"):
        backend.watchdog_finished()


def test_terminal_proven_absence_still_requires_quiescent_files_and_lock(journal):
    backend = terminal_watchdog_fixture(journal)
    backend.run = lambda *_a, **_k: SimpleNamespace(returncode=113, stdout=b"", stderr=b"owned job absent")
    backend.tproxy = SimpleNamespace(_launchd_job_absent=lambda reply: reply.returncode == 113)
    assert backend.watchdog_finished() is True
    private(backend.ack_path, b"retained ACK")
    assert backend.watchdog_finished() is False


def test_timeout_retains_decisive_snapshot_without_environment(journal):
    backend, clock = terminal_watchdog_fixture(journal), Clock()
    private(backend.agent, b"retained LaunchAgent")
    backend.job_text = backend.job_text.replace(b"\truns", b"\tenvironment = {\n\t\tPRIVATE = not-retained\n\t}\n\truns")
    with pytest.raises(observer.Refused, match="deadline exhausted"):
        backend.wait_transaction(clock=clock, sleep=clock.sleep)
    evidence = backend.events[-1]
    assert evidence["kind"] == "completion_diagnostic"
    assert evidence["value"]["paths_present"]["agent"] is True
    assert evidence["value"]["lock"] == "available"
    assert "PRIVATE" not in json.dumps(evidence)


def test_wait_timeout_and_abort_are_deterministic(journal):
    backend, clock = waiting(journal, complete=False), Clock()
    with pytest.raises(observer.Refused, match="deadline exhausted"):
        backend.wait_transaction(clock=clock, sleep=clock.sleep)
    assert 1 <= clock.now < 1.03
    backend, clock = waiting(journal), Clock()
    def aborted():
        backend.root_status = copy.deepcopy(STATUSES["aborted"])
        return journal
    backend.observe_once = aborted
    with pytest.raises(observer.Refused, match="aborted"):
        backend.wait_transaction(clock=clock, sleep=clock.sleep)
    assert clock.now == 0


def test_journal_absence_before_trigger_does_not_complete(journal):
    backend, clock = waiting(journal), Clock()
    backend.identity = backend.receipt = backend.root_status = None
    backend.observe_once = lambda: None
    backend.status = lambda: pytest.fail("no root identity yet")
    with pytest.raises(observer.Refused, match="deadline exhausted"):
        backend.wait_transaction(clock=clock, sleep=clock.sleep)


def test_qualification_requires_packaged_watchdog_and_fresh_daemon_proof(journal):
    backend = bare_observer(journal)
    backend.args = SimpleNamespace(mode="commit")
    backend.wait_transaction = lambda: STATUSES["committed"]
    backend.tray = process_for(journal)
    events = []
    backend.final_app = lambda: events.append("app")
    backend.prove = lambda side: events.append("proof:" + side)
    backend.process_snapshot = lambda _pid: process_for(journal)
    assert backend.qualify_app()["packaged_transaction_qualified"]
    assert events == ["app", "proof:new"]
    backend.watchdog = None
    with pytest.raises(observer.Refused, match="packaged watchdog"):
        backend.qualify_app()


def build_fixture(tmp_path):
    args = SimpleNamespace(trigger_dir=tmp_path / "trigger", repo=tmp_path / "repo",
        pair_manifest=tmp_path / "pair.json", old_candidate_dir=tmp_path / "old", new_candidate_dir=tmp_path / "new")
    expected = copy.deepcopy(EXPECTED)
    pair = {"schema_version": 1}
    for side, number in (("old", 1), ("new", 2)):
        manifest = private(getattr(args, side + "_candidate_dir") / "release-candidate-manifest.json", {"side": side})
        pair[side] = {"source_commit": expected[side]["source_commit"], "candidate_manifest_sha256": observer.digest(manifest),
                      "run_id": number, "run_attempt": 1}
    private(args.pair_manifest, pair)
    binary = private(args.trigger_dir / "target/debug" / observer.BIN, b"inert-binary")
    private(args.repo / "scripts/packaged_update_trigger.rs", b"inert-source")
    archive = private(args.new_candidate_dir / "Slipstream.app.tar.gz", b"inert-archive")
    signature = private(args.new_candidate_dir / "Slipstream.app.tar.gz.sig", b"inert-signature")
    expected["new"]["archive_sha256"] = observer.digest(archive)
    plan = {"schema_version": 1, "expected": expected, "uid": UID, "runner_temp": str(tmp_path),
            "output_dir": str(args.trigger_dir), "pair": {"path": str(args.pair_manifest), "sha256": observer.digest(args.pair_manifest)},
            "manifests": {side: {"path": str(getattr(args, side + "_candidate_dir") / "release-candidate-manifest.json"),
                                 "sha256": pair[side]["candidate_manifest_sha256"]} for side in ("old", "new")},
            "archive_path": str(archive), "signature": {"path": str(signature), "sha256": observer.digest(signature)}}
    private(args.trigger_dir / "pinned-plan.json", plan)
    for name in ("Cargo.toml", "Cargo.lock", "bridge.rs"):
        private(args.trigger_dir / name, b"inert-input")
    build = {"schema_version": 1, "built": True, "pair": pair, "pair_sha256": observer.digest(args.pair_manifest),
             "binary": str(binary), "binary_sha256": observer.digest(binary),
             "generated_sha256": {name: observer.digest(args.trigger_dir / name) for name in
                                  ("Cargo.toml", "Cargo.lock", "bridge.rs", "pinned-plan.json")},
             "trigger_sha256": observer.digest(args.repo / "scripts/packaged_update_trigger.rs"),
             "old_source_sha256": {"app-tauri/src-tauri/src/" + name + ".rs": "a" * 64 for name in observer.MODULES}}
    return args, pair, expected, build, plan


def test_build_receipt_pins_authenticated_pair_archive_and_actual_binary(tmp_path):
    args, pair, expected, build, plan = build_fixture(tmp_path)
    assert observer.validate_build(build, plan, pair, expected, args, UID) == args.trigger_dir / "target/debug" / observer.BIN
    for key, value in (("binary_sha256", "0" * 64), ("pair_sha256", "0" * 64), ("trigger_sha256", "0" * 64),
                       ("old_source_sha256", {})):
        with pytest.raises(observer.Refused):
            observer.validate_build({**build, key: value}, plan, pair, expected, args, UID)
    plan["expected"]["old"]["source_commit"] = "c" * 40
    with pytest.raises(observer.Refused, match="manifest mismatch"):
        observer.validate_build(build, plan, pair, expected, args, UID)


def test_build_receipt_detects_changed_compiled_plan_and_signature(tmp_path):
    args, pair, expected, build, plan = build_fixture(tmp_path)
    private(args.new_candidate_dir / "Slipstream.app.tar.gz.sig", b"different")
    with pytest.raises(observer.Refused, match="archive/signature"):
        observer.validate_build(build, plan, pair, expected, args, UID)
    private(args.trigger_dir / "pinned-plan.json", {"changed": True})
    with pytest.raises(observer.Refused, match="generated trigger"):
        observer.validate_build(build, plan, pair, expected, args, UID)


def test_bind_requires_live_exact_initiator_and_pins_nonce(journal):
    backend = bare_observer(journal)
    backend.identity = backend.last_journal = backend.initiator = None
    backend.state = Path(journal["helper"]).parent.parent
    backend.target, backend.watchdog_hash, backend.root = Path(journal["target"]), "9" * 64, Path("/inert/root")
    backend.binary = Path("/inert/trigger")
    backend.tproxy = SimpleNamespace(_daemon_update_identity=lambda value: value)
    backend.process_snapshot = lambda _pid: {"pid": journal["initiator_pid"], "uid": UID, "state": "S", "started": START,
                                           "command": "/inert/trigger --prepare"}
    backend.bind(journal)
    assert backend.identity == IDENTITY and backend.initiator["pid"] == journal["initiator_pid"]
    changed = copy.deepcopy(journal)
    changed["daemon_update"]["identity"]["nonce"] = "f" * 32
    with pytest.raises(observer.Refused, match="identity changed"):
        backend.bind(changed)
    backend.initiator = None
    backend.process_snapshot = lambda _pid: None
    with pytest.raises(observer.Refused, match="exact trigger process not observed"):
        backend.bind(journal)


def test_receipt_cannot_replace_unobserved_journal_or_change_identity(tmp_path, journal):
    backend = bare_observer(journal)
    backend.args = SimpleNamespace(trigger_dir=tmp_path)
    backend.uid = os.getuid()
    backend.journal_path = tmp_path / observer.JOURNAL
    backend.process_snapshot = lambda _pid: None
    value = {"schema_version": 1, "prepared": True, "journal_path": str(backend.journal_path),
             "initiator_pid": journal["initiator_pid"], "identity": IDENTITY, "expected": EXPECTED, "error": None}
    path = private(tmp_path / "prepare-result.json", value)
    backend.receipt = None
    backend.read_receipt()
    assert backend.receipt == value
    backend.identity = None
    with pytest.raises(observer.Refused, match="incomplete evidence"):
        backend.read_receipt()
    private(path, b'{"incomplete":')
    with pytest.raises(observer.Refused, match="incomplete private"):
        backend.read_receipt()


def test_observes_real_fixture_journal_ack_receipt_then_cleanup_without_mutation(tmp_path, journal, monkeypatch):
    """Exercise actual observer reads/validators; only OS process/root proof queries are inert."""
    backend = bare_observer(journal)
    backend.identity = backend.last_journal = backend.initiator = backend.receipt = backend.ack = backend.watchdog = None
    backend.binary = tmp_path / "trigger/target/debug" / observer.BIN
    backend.args = SimpleNamespace(trigger_dir=tmp_path / "trigger", mode="commit")
    backend.state = Path(journal["helper"]).parent.parent
    backend.target, backend.root = Path(journal["target"]), tmp_path / "root"
    backend.journal_path = backend.state / observer.JOURNAL
    backend.ack_path = backend.journal_path.with_suffix(".ack.json")
    backend.agent = tmp_path / "agent.plist"
    helper = private(Path(journal["helper"]), b"inert-watchdog")
    backend.watchdog_hash = observer.digest(helper)
    private(backend.agent, observer.plistlib.dumps({
        "Label": observer.WATCHDOG, "ProgramArguments": [str(helper), "--journal", str(backend.journal_path)],
        "RunAtLoad": True, "KeepAlive": {"SuccessfulExit": False}, "ProcessType": "Background",
        "StandardOutPath": str(backend.state / "update-watchdog.stdout.log"),
        "StandardErrorPath": str(backend.state / "update-watchdog.stderr.log")}))
    journal["watchdog_sha256"] = backend.watchdog_hash
    current_root = [copy.deepcopy(PREPARED)]
    backend.tproxy = SimpleNamespace(_daemon_update_identity=lambda value: value,
        _update_read_json=lambda *a, **k: copy.deepcopy(current_root[0]),
        _daemon_update_tree=lambda path, **kwargs: EXPECTED["new"]["bundle_tree_sha256"])
    trigger = {"pid": 111, "uid": UID, "state": "S", "started": START, "command": f"{backend.binary} --prepare"}
    watchdog = {"pid": 333, "uid": UID, "state": "S", "started": START,
                "command": f"{helper} --journal {backend.journal_path}"}
    processes = {111: trigger, 333: watchdog, 222: process_for(journal)}
    backend.process_snapshot = lambda process_id: copy.deepcopy(processes.get(process_id))
    queries = []
    def query(argv, **_kwargs):
        queries.append(argv)
        if argv[:2] == ["/bin/launchctl", "print"]:
            return SimpleNamespace(returncode=0, stdout=b"\tpid = 333\n")
        if argv[0] == "/bin/ps":
            assert argv == ["/bin/ps", "-p", "222", "-o", "pid=,pgid=,uid=,state=,lstart="]
            assert _kwargs == {"check": False, "timeout": 1}
            return SimpleNamespace(returncode=0, stdout=f"222 333 {UID} S {START}\n".encode())
        assert argv == ["/usr/bin/pgrep", "-x", "slipstream"]
        return SimpleNamespace(returncode=0, stdout=b"222\n")
    backend.run = query
    # Fixture file owner may differ from the inert UID in the shared wire vector.
    real_reader = observer.private_json
    monkeypatch.setattr(observer, "private_json", lambda path, _uid, **kwargs: real_reader(path, os.getuid(), **kwargs))
    real_bytes = observer.private_bytes
    monkeypatch.setattr(observer, "private_bytes", lambda path, _uid, **kwargs: real_bytes(path, os.getuid(), **kwargs))
    prepared = {**journal, "phase": "prepared", "successor_pid": None, "successor_started": None}
    private(backend.journal_path, prepared)
    private(backend.root / IDENTITY["nonce"] / "status.json", {})
    assert backend.observe_once() == prepared
    assert backend.initiator == trigger and backend.watchdog == watchdog and backend.ack is None
    current_root[0] = copy.deepcopy(STATUSES["ready"])
    private(backend.journal_path, journal)
    private(backend.ack_path, ack_for(journal))
    receipt = {"schema_version": 1, "prepared": True, "journal_path": str(backend.journal_path),
               "initiator_pid": 111, "identity": IDENTITY, "expected": EXPECTED, "error": None}
    private(backend.args.trigger_dir / "prepare-result.json", receipt)
    assert backend.observe_once() == journal
    assert backend.ack == ack_for(journal) and backend.receipt == receipt
    # Simulate production cleanup only in this test-owned temporary directory.
    backend.journal_path.unlink()
    backend.ack_path.unlink()
    processes.pop(111)
    backend.agent.unlink()
    current_root[0] = copy.deepcopy(STATUSES["committed"])
    backend.watchdog_finished = lambda: True
    clock = Clock()
    assert backend.wait_transaction(clock=clock, sleep=clock.sleep)["decision"] == "commit"
    backend.final_app(clock=clock, sleep=clock.sleep)
    assert backend.tray == process_for(journal)
    assert [entry["value"]["phase"] for entry in backend.events if entry["kind"] == "root_status"] == ["prepared", "ready", "committed"]
    assert len([entry for entry in backend.events if entry["kind"] == "successor_ack"]) == 1
    assert helper.read_bytes() == b"inert-watchdog"
    assert json.loads((backend.args.trigger_dir / "prepare-result.json").read_text()) == receipt
    assert all(argv[0] in {"/bin/launchctl", "/usr/bin/pgrep", "/bin/ps"} for argv in queries)
    sample = backend.last_event["final_tray_processes"]
    assert sample["outcome"] == "observed"
    assert sample["processes"] == [{"pid": 222, "pgid": 333, "uid": UID, "state": "S", "started": START}]


@pytest.mark.parametrize("returncode,stdout,outcome", [
    (1, b"", "no_candidates"),
    (0, b"222\n444\n", "multiple_candidates"),
    (2, b"", "query_error"),
])
def test_final_tray_refusal_retains_query_without_relaxing_acceptance(journal, tmp_path, returncode, stdout, outcome):
    backend = bare_observer(journal)
    backend.target, backend.stage = Path(journal["target"]), Path(journal["stage"])
    backend.journal_path, backend.ack_path, backend.agent = (tmp_path / name for name in ("journal", "ack", "agent"))
    backend.tproxy = SimpleNamespace(_daemon_update_tree=lambda *args, **kwargs: EXPECTED["new"]["bundle_tree_sha256"])
    backend.watchdog_finished = lambda: True
    queries = []
    def query(argv, **kwargs):
        queries.append(argv)
        if argv[0] == "/usr/bin/pgrep":
            return SimpleNamespace(returncode=returncode, stdout=stdout)
        raise observer.Refused("inert optional diagnostic failure")
    backend.run = query
    clock = Clock()
    with pytest.raises(observer.Refused, match="one final tray must be alive"):
        backend.final_app(clock=clock, sleep=clock.sleep)
    assert backend.last_event["final_tray_query"]["returncode"] == returncode
    assert backend.last_event["final_tray_query"]["outcome"] == outcome
    assert sum(argv[0] == "/usr/bin/pgrep" for argv in queries) == 1


def test_final_tray_diagnostics_bound_candidates_and_omit_raw_output(journal):
    backend = bare_observer(journal)
    queries = []
    def query(argv, **kwargs):
        queries.append(argv)
        assert kwargs == {"check": False, "timeout": 1}
        # Extra/foreign output must not leak into the retained process metadata.
        return SimpleNamespace(returncode=0, stdout=b"222 333 501 S Mon Oct 19 12:34:56 2026\nprivate argv\n",
                               stderr=b"private stderr")
    backend.run = query
    result = SimpleNamespace(returncode=0, stdout=("\n".join(map(str, range(222, 232))) + "\n").encode())
    backend.retain_final_tray_query("new", result)
    assert backend.last_event["final_tray_query"] == {"side": "new", "returncode": 0,
        "outcome": "multiple_candidates", "candidate_count": 10, "pids": list(range(222, 230)), "pids_truncated": True}
    assert queries == [["/bin/ps", "-p", ",".join(map(str, range(222, 230))), "-o",
                        "pid=,pgid=,uid=,state=,lstart="]]
    assert backend.last_event["final_tray_processes"]["processes"] == []
    assert backend.last_event["final_tray_processes"]["outcome"] == "invalid_output"
    backend.retain_final_tray_query("new", SimpleNamespace(returncode=2, stdout=b"private pgrep stderr"))
    assert backend.last_event["final_tray_query"]["outcome"] == "query_error"
    assert "private" not in json.dumps(backend.events)


@pytest.mark.parametrize("failure", ["query", "timeout", "gone", "invalid", "evidence_bound"])
def test_optional_final_process_diagnostic_failure_does_not_fail_observation(journal, failure):
    backend = bare_observer(journal)
    def query(argv, **kwargs):
        if failure == "timeout":
            raise observer.Refused("inert diagnostic timeout")
        if failure == "query":
            raise OSError("inert query error")
        return SimpleNamespace(returncode=1 if failure == "gone" else 0,
                               stdout=b"" if failure == "gone" else b"\xff")
    backend.run = query
    if failure == "evidence_bound":
        backend.events = [{}] * 512
    backend.retain_final_tray_query("new", SimpleNamespace(returncode=0, stdout=b"222\n"))


def test_main_failure_writes_only_private_evidence_without_teardown(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setattr(observer, "guard", lambda: os.getuid())
    monkeypatch.setattr(observer, "modules", lambda _repo: (None, None))
    args = []
    for name in ("repo", "old-candidate-dir", "new-candidate-dir", "old-app", "new-app", "trigger-dir"):
        path = tmp_path / name
        path.mkdir()
        args.extend(["--" + name, str(path)])
    pair = private(tmp_path / "pair.json", {})
    output = tmp_path / "evidence.json"
    args += ["--pair-manifest", str(pair), "--output", str(output), "--mode", "commit", "--gh", "/unused"]
    before = set(tmp_path.rglob("*"))
    class FakeObserver:
        def __init__(self, *_args):
            self.events, self.identity = [], None
        def setup_observation(self):
            raise observer.Refused("inert validation failure")
        def teardown(self):
            pytest.fail("read-only observer must not tear down product state")
    monkeypatch.setattr(observer, "Observer", FakeObserver)
    nested = list(args)
    nested[nested.index("--output") + 1] = str(tmp_path / "old-app/evidence.json")
    with pytest.raises(observer.Refused, match="new CI evidence"):
        observer.main(nested)
    assert set(tmp_path.rglob("*")) == before
    assert observer.main(args) == 2
    evidence = json.loads(output.read_text())
    assert evidence["status"] == "failed" and evidence["observation_only"]
    assert evidence["packaged_transaction_qualified"] is False
    assert evidence["reason"] == "inert validation failure"
    assert set(tmp_path.rglob("*")) == before | {output}
    assert output.stat().st_mode & 0o777 == 0o600
    original = output.read_bytes()
    with pytest.raises(observer.Refused, match="new CI evidence"):
        observer.main(args)
    assert output.read_bytes() == original


@pytest.mark.parametrize("state", ["Z", "T"])
def test_qualification_rechecks_successor_liveness_after_daemon_proof(journal, state):
    backend = bare_observer(journal)
    backend.args = SimpleNamespace(mode="commit")
    backend.wait_transaction = lambda: STATUSES["committed"]
    backend.tray = process_for(journal)
    backend.final_app = lambda: None
    backend.prove = lambda side: None
    backend.process_snapshot = lambda _pid: {**process_for(journal), "state": state}
    with pytest.raises(observer.Refused, match="final tray died"):
        backend.qualify_app()
