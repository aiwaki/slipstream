"""Driver tests: no subprocesses, native services, or root execution."""
import copy
import importlib.util
import json
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[1]
PATH = REPO / "scripts/native_root_update.py"
SPEC = importlib.util.spec_from_file_location("native_root_update", PATH)
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)
FIXTURE = json.loads((REPO / "contracts/update-daemon-status-v1.json").read_text())
PREPARED = FIXTURE["vectors"][0]["status"]
IDENTITY = {k: v for k, v in PREPARED.items() if k not in {
    "manifest_sha256", "phase", "decision", "accepted_sequence", "deadline_unix",
    "worker_pid", "daemon_pid", "daemon_sha256", "heartbeat_seq", "install_attestation_sha256",
    "writer_quiescent", "error"}}


@pytest.fixture(autouse=True)
def no_native(monkeypatch):
    monkeypatch.setattr(driver.subprocess, "run", lambda *a, **k: pytest.fail("native command forbidden"))


class Fake:
    def __init__(self):
        self.events = []
        self.value = copy.deepcopy(PREPARED)

    def prepare(self, identity):
        assert identity == IDENTITY
        self.events.append("prepare")

    def wait(self, phase):
        self.events.append("wait:" + phase)
        self.value["phase"] = phase
        if phase in {"aborted", "committed"}:
            self.value["decision"] = "abort" if phase == "aborted" else "commit"
        return copy.deepcopy(self.value)

    def request(self, sequence, action):
        self.events.append("request:" + action)
        if self.value["decision"] is None:
            self.value["accepted_sequence"] = sequence

    def prove(self, side, **kwargs):
        self.events.append("prove:" + side + (":exact" if kwargs.get("exact_snapshot") else ""))

    def kill_ready_worker(self, ready):
        self.events.append("kill")
        self.value["worker_pid"] = ready["worker_pid"] + 1
        return ready["worker_pid"]

    def arm_terminal_replay(self):
        self.events.append("arm-replay")

    def wait_late_refusal(self, accepted):
        self.events.append("wait:late-refusal")
        assert self.value["accepted_sequence"] == accepted
        return copy.deepcopy(self.value)


def test_commit_requires_prepared_ready_and_proves_new_before_commit():
    fake = Fake()
    result = driver.qualify(fake, IDENTITY, "commit")
    assert result["root_protocol_qualified"] and not result["public_pair_qualified"]
    assert fake.events == ["prepare", "wait:prepared", "prove:old", "request:activate", "wait:ready",
                           "prove:new", "request:commit", "wait:committed", "prove:new"]


def test_crash_requires_restoration_and_real_terminal_replay_before_success():
    fake = Fake()
    result = driver.qualify(fake, IDENTITY, "crash-before-commit")
    assert result["root_protocol_qualified"]
    assert fake.events[-7:] == ["kill", "wait:aborted", "prove:old:exact", "arm-replay",
                               "request:commit", "wait:late-refusal", "prove:old:exact"]


def test_fault_that_does_not_restart_worker_fails_closed():
    fake = Fake()
    fake.kill_ready_worker = lambda ready: ready["worker_pid"]
    with pytest.raises(driver.Refused, match="restart did not abort"):
        driver.qualify(fake, IDENTITY, "crash-before-commit")
    assert "request:commit" not in fake.events


def test_late_commit_changing_decision_fails_qualification():
    fake = Fake()
    fake.wait_late_refusal = lambda _: {**fake.value, "decision": "commit"}
    with pytest.raises(driver.Refused, match="late commit changed"):
        driver.qualify(fake, IDENTITY, "crash-before-commit")


@pytest.mark.parametrize("key,value", [("prepare_deadline_unix", IDENTITY["prepare_deadline_unix"] + 1),
    ("deadline_unix", IDENTITY["prepare_deadline_unix"] + 1), ("uid", True), ("nonce", "f" * 32)])
def test_status_rejects_identity_or_original_deadline_drift(key, value):
    status = {**PREPARED, key: value}
    with pytest.raises(driver.Refused):
        driver.validate_status(status, IDENTITY, set(PREPARED))


def test_status_consumes_actual_production_fixture_shape():
    for vector in FIXTURE["vectors"]:
        assert driver.validate_status(vector["status"], IDENTITY, set(PREPARED)) == vector["status"]


def test_status_rejects_extra_fields_and_manifest_change():
    with pytest.raises(driver.Refused, match="schema"):
        driver.validate_status({**PREPARED, "unknown": 1}, IDENTITY, set(PREPARED))
    with pytest.raises(driver.Refused, match="manifest changed"):
        driver.validate_status(PREPARED, IDENTITY, set(PREPARED), "c" * 64)


def test_identical_daemon_pair_rejected_before_native_effects():
    old = {"version": "1", "archive_sha256": "a" * 64, "app_executable_sha256": "b" * 64,
           "daemon_sha256": "c" * 64, "bundle_tree_sha256": "d" * 64}
    new = {**old, "version": "2", "app_executable_sha256": "e" * 64}
    with pytest.raises(driver.Refused, match="daemon bytes are identical"):
        driver.make_identity(SimpleNamespace(_daemon_update_identity=lambda v: v), old, new, "0" * 32, 501, 1)


def test_workstation_guard_refuses_even_on_macos_without_ci(monkeypatch):
    monkeypatch.setattr(driver.sys, "platform", "darwin")
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    with pytest.raises(driver.Refused, match="disposable CI guard"):
        driver.guard()


def test_non_macos_guard_refuses_before_filesystem_or_privilege(monkeypatch):
    monkeypatch.setattr(driver.sys, "platform", "linux")
    with pytest.raises(driver.Refused, match="hosted macOS"):
        driver.guard()


def test_root_process_identity_requires_exact_operation_argv():
    native = object.__new__(driver.Native)
    native.operation = Path("/var/db/dev.slipstream-update") / IDENTITY["nonce"]
    native.identity = IDENTITY
    expected = f"{native.operation}/private/worker-runtime/slipstreamd --update-worker {IDENTITY['nonce']}"
    native.run = lambda args: SimpleNamespace(stdout=f"101 0 Mon Oct 19 12:34:56 2026 {expected}\n".encode())
    assert native.process(101)["started"] == "Mon Oct 19 12:34:56 2026"
    native.run = lambda args: SimpleNamespace(stdout=f"101 0 Mon Oct 19 12:34:56 2026 /usr/local/slipstream/slipstreamd\n".encode())
    with pytest.raises(driver.Refused, match="command mismatch"):
        native.process(101)


@pytest.fixture
def readonly_observations(monkeypatch):
    """Real proof control flow, replacing only external OS/product observations."""
    installed = "/usr/local/slipstream/slipstreamd"
    evidence = "/Library/Application Support/dev.slipstream.tray/install-attestation.json"
    status_path = "/var/run/slipstream.status"
    sha = "a" * 64
    daemon = {"state": "active", "updated_at": 1000.0, "pid": 101, "heartbeat_seq": 17}
    raw = {"schema_version": 2, "daemon": daemon, "recovery": {}}
    arguments = [installed, "--port", "4433"]
    metadata = SimpleNamespace(st_mode=stat.S_IFREG | 0o700, st_uid=0, st_gid=0,
        st_dev=1, st_ino=2, st_nlink=2, st_size=50, st_mtime=123.0, st_mtime_ns=123000000000)
    witness = copy.copy(metadata)
    attestation = {"schema_version": 3, "source_sha256": sha,
        "daemon": {"path": installed, "sha256": sha, "uid": 0, "gid": 0, "mode": 0o700},
        "witness": {"path": evidence + ".daemon", "dev": 1, "ino": 2, "size": 50,
                    "mtime": 123, "mtime_nsec": 0},
        "launchd": {"label": "dev.slipstream.tproxy", "pid": 101},
        "listener": {"host": "127.0.0.1", "hosts": ["127.0.0.1", "::1"], "port": 4433},
        "state": "active", "pf_active": True}
    state = SimpleNamespace(raw=raw, attestation=attestation, witness=witness,
        command=" ".join(arguments), job_pid=101, listener_pids=[101],
        addresses={"127.0.0.1", "::1"}, pf=True, installed_sha=sha, process_reads=0,
        birth="Mon Oct 19 12:34:56 2026")
    original_lstat = driver.os.lstat
    monkeypatch.setattr(driver.os, "lstat", lambda path, *a, **k:
        metadata if str(path) == installed else witness if str(path) == evidence + ".daemon"
        else original_lstat(path, *a, **k))
    monkeypatch.setattr(driver.time, "time", lambda: 1000.0)

    def run(*args):
        if args[0] == "/bin/ps":
            state.process_reads += 1
            text = f"0 {state.birth} {state.command}\n"
        else:
            assert args == ("/bin/launchctl", "print", "system/dev.slipstream.tproxy")
            text = f"\tpid = {state.job_pid}\n\tprogram = {installed}\n"
        return SimpleNamespace(returncode=0, stdout=text)

    def read_json(path, **kwargs):
        if path == evidence:
            return state.attestation
        if path == status_path:
            return state.raw
        assert path == "/fake/private/journal.json"
        return {"snapshot_ready": True, "old_runtime_sha256": "d" * 64}

    tproxy = SimpleNamespace(INSTALL_DIR="/usr/local/slipstream", PROXY_PORT=4433,
        STATUS_PATH=status_path, STATUS_SCHEMA_VERSION=2, LAUNCHD_LABEL="dev.slipstream.tproxy",
        INSTALL_ATTESTATION_PATH=evidence, INSTALL_ATTESTATION_SCHEMA_VERSION=3,
        BASELINE_GUARD_BLOCK_REASON="baseline-block", BASELINE_GUARD_ROLLBACK_REASON="baseline-rollback",
        PF_LOOPBACK_UNAVAILABLE_REASON="pf-unavailable", _update_read_json=read_json,
        _run=run, _daemon_update_read_plist=lambda: ({"ProgramArguments": arguments}, "0" * 64),
        _listener_pids=lambda port: state.listener_pids,
        _listener_bind_addresses=lambda port, pid: state.addresses,
        pf_state_snapshot=lambda port: {"rules_loaded": state.pf},
        _install_attestation_witness_path=lambda path: path + ".daemon",
        _sha256_regular_file=lambda path: state.installed_sha if path == installed else "b" * 64,
        _daemon_update_tree=lambda path: "d" * 64,
        _daemon_update_paths=lambda nonce: ("/fake", "/fake/private/journal.json"))
    # No implicit readiness/attestation helper is supplied: any call fails.
    return tproxy, state, sha


def test_root_proof_works_under_python_without_implicit_frozen_executable(monkeypatch, capsys, readonly_observations):
    tproxy, state, sha = readonly_observations
    executable = driver.sys.executable
    assert Path(executable).name != "slipstreamd"
    monkeypatch.setattr(driver, "guard", lambda **kwargs: 501)
    monkeypatch.setattr(driver, "modules", lambda repo: (tproxy, None))
    driver.root_proof(SimpleNamespace(repo=REPO, root_proof=sha, nonce="0" * 32))
    result = json.loads(capsys.readouterr().out)
    assert result["proof"] == {"daemon_pid": 101, "daemon_sha256": sha,
        "heartbeat_seq": 17, "install_attestation_sha256": "b" * 64}
    assert result["process"]["command"] == "/usr/local/slipstream/slipstreamd --port 4433"
    assert result["current_tree_sha256"] == result["old_runtime_sha256"]
    assert state.process_reads == 2 and driver.sys.executable == executable


@pytest.mark.parametrize("fault", ["stale", "recovery", "wrong-exe", "launchd", "listener",
    "ipv6", "pf", "witness", "hash", "attestation"])
def test_readonly_proof_refuses_missing_runtime_evidence(readonly_observations, fault):
    tproxy, state, sha = readonly_observations
    if fault == "stale": state.raw["daemon"]["updated_at"] = 900
    elif fault == "recovery": state.raw["recovery"]["reason"] = "baseline-block"
    elif fault == "wrong-exe": state.command = "/usr/local/slipstream/python3 --port 4433"
    elif fault == "launchd": state.job_pid = 102
    elif fault == "listener": state.listener_pids = [101, 102]
    elif fault == "ipv6": state.addresses = {"127.0.0.1"}
    elif fault == "pf": state.pf = False
    elif fault == "witness": state.witness.st_ino = 99
    elif fault == "hash": state.installed_sha = "c" * 64
    elif fault == "attestation": state.attestation["launchd"]["pid"] = 102
    with pytest.raises(driver.Refused):
        driver.readonly_runtime_proof(tproxy, sha)


def test_fault_injection_signals_exact_launchd_job_not_numeric_pid():
    native = object.__new__(driver.Native)
    native.identity, native.events = IDENTITY, []
    ready = {"worker_pid": 101, "phase": "ready", "decision": None}
    native.process = lambda pid: {"pid": pid, "uid": 0, "started": "birth", "argv": ["worker"]}
    native.run = lambda args: SimpleNamespace(stdout=b"pid = 101\n")
    native.status = lambda: ready
    commands = []
    native.sudo = lambda *args: commands.append(args)
    assert native.kill_ready_worker(ready) == 101
    assert commands == [("/bin/launchctl", "kill", "SIGKILL", "system/dev.slipstream.update." + IDENTITY["nonce"])]


def test_closed_ready_window_does_not_signal():
    native = object.__new__(driver.Native)
    native.identity = IDENTITY
    native.process = lambda pid: {"pid": pid}
    native.run = lambda args: SimpleNamespace(stdout=b"pid = 101\n")
    native.status = lambda: {"worker_pid": 101, "phase": "committed", "decision": "commit"}
    native.sudo = lambda *args: pytest.fail("must not signal outside undecided Ready")
    with pytest.raises(driver.Refused, match="window closed"):
        native.kill_ready_worker({"worker_pid": 101})
