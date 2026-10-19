#!/usr/bin/env python3
"""Real root updater qualification on a fresh disposable hosted Mac.

Does not exercise app discovery, administrator UI, the app watchdog, or ACK.
No product fixture hooks. Run each case on a separate clean runner.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import time
from types import SimpleNamespace


class Refused(RuntimeError):
    pass


def require(ok, message):
    if not ok:
        raise Refused(message)


def digest(path):
    require(path.is_file() and not path.is_symlink(), "regular hash input required")
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def document(path, limit=1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, "unsafe JSON file")
        return json.loads(stream.read(limit + 1))


def guard(*, root=False):
    require(sys.platform == "darwin", "requires disposable hosted macOS")
    expected = {"CI": "true", "GITHUB_ACTIONS": "true", "SLIPSTREAM_DISPOSABLE_CI": "1", "RUNNER_OS": "macOS"}
    require(all(os.environ.get(k) == v for k, v in expected.items()), "disposable CI guard missing")
    uid = int(os.environ.get("SUDO_UID", "0")) if root else os.getuid()
    require(uid > 0 and os.stat("/dev/console").st_uid == uid, "console UID mismatch")
    require((os.geteuid() == 0) == root, "incorrect driver privilege")
    return uid


def modules(repo):
    require((repo / "spike/tproxy.py").is_file(), "production source unavailable")
    sys.path[:0] = [str(repo / "spike"), str(repo / "scripts")]
    import tproxy
    import release_candidate
    return tproxy, release_candidate


def make_identity(tproxy, old, new, nonce, uid, now):
    value = {
        "schema_version": 1, "nonce": nonce, "uid": uid,
        "prepare_deadline_unix": int(now) + 300,
        "old_version": old["version"], "new_version": new["version"],
        "archive_sha256": new["archive_sha256"],
    }
    for side, artifact in (("old", old), ("new", new)):
        for name in ("app_executable_sha256", "daemon_sha256", "bundle_tree_sha256"):
            value[side + "_" + name] = artifact[name]
    require(value["old_version"] != value["new_version"], "pair versions are identical")
    require(value["old_app_executable_sha256"] != value["new_app_executable_sha256"], "tray bytes are identical")
    require(value["old_daemon_sha256"] != value["new_daemon_sha256"], "daemon bytes are identical")
    return tproxy._daemon_update_identity(value)


def validate_status(value, identity, fields, manifest=None):
    require(set(value) == fields, "root status schema differs from production fixture")
    require(all(type(value.get(k)) is type(v) and value[k] == v for k, v in identity.items()), "root status identity differs")
    require(value["deadline_unix"] == identity["prepare_deadline_unix"], "root lease was renewed")
    require(re.fullmatch(r"[0-9a-f]{64}", value["manifest_sha256"]) is not None, "invalid root manifest")
    require(manifest is None or value["manifest_sha256"] == manifest, "root manifest changed")
    require(type(value["accepted_sequence"]) is int and value["accepted_sequence"] >= 0, "invalid accepted sequence")
    return value


def qualify(backend, identity, mode):
    """Observable protocol steps; fake backends exercise the same ordering."""
    backend.prepare(identity)
    prepared = backend.wait("prepared")
    require(prepared["writer_quiescent"] and prepared["decision"] is None, "prepare is not idle")
    backend.prove("old")
    backend.request(1, "activate")
    ready = backend.wait("ready")
    require(ready["writer_quiescent"] and ready["accepted_sequence"] == 1, "activation is not complete")
    backend.prove("new")
    if mode == "commit":
        backend.request(2, "commit")
        terminal = backend.wait("committed")
        require(terminal["decision"] == "commit" and terminal["accepted_sequence"] == 2, "commit was not durable")
        backend.prove("new")
    else:
        require(mode == "crash-before-commit", "unknown case")
        worker = backend.kill_ready_worker(ready)
        terminal = backend.wait("aborted")
        require(terminal["decision"] == "abort" and terminal["worker_pid"] != worker, "worker restart did not abort")
        backend.prove("old", exact_snapshot=True)
        accepted = terminal["accepted_sequence"]
        backend.arm_terminal_replay()
        backend.request(2, "commit")
        # The mailbox write must wake the exited root worker without an
        # observer kickstart, and the durable abort must remain authoritative.
        after = backend.wait_late_refusal(accepted)
        require(after["decision"] == "abort" and after["accepted_sequence"] == accepted, "late commit changed abort")
        backend.prove("old", exact_snapshot=True)
    require(terminal["writer_quiescent"], "terminal writer is not quiescent")
    return {"mode": mode, "root_protocol_qualified": True, "public_pair_qualified": False}


class Native:
    def __init__(self, args, uid, tproxy, candidate):
        self.args, self.uid, self.tproxy, self.candidate = args, uid, tproxy, candidate
        self.deadline = time.monotonic() + 720
        self.events, self.created, self.install_attempted = [], [], False
        self.identity = self.manifest = None
        self.target = Path(tproxy._DAEMON_UPDATE_TARGET)
        self.root = Path(tproxy._DAEMON_UPDATE_ROOT)
        self.installed = Path(tproxy.INSTALL_DIR) / "slipstreamd"
        self.operation = self.mailbox = self.stage = None
        self.env = {k: os.environ[k] for k in ("HOME", "USER", "LOGNAME", "TMPDIR", "LANG") if k in os.environ}
        self.env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
        self.fields = set(document(args.repo / "contracts/update-daemon-status-v1.json")["vectors"][0]["status"])

    def run(self, argv, *, timeout=30, check=True, github=False, env=None):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "driver deadline exhausted; runner destruction required")
        actual_env = dict(self.env if env is None else env)
        if github:
            actual_env.update({k: os.environ[k] for k in ("GH_TOKEN", "GITHUB_TOKEN") if k in os.environ})
        result = subprocess.run([str(x) for x in argv], capture_output=True, env=actual_env,
                                timeout=min(timeout, remaining), check=False)
        require(len(result.stdout) <= 4 * 1024 * 1024, "command output exceeded bound")
        if check:
            require(result.returncode == 0, "command failed: " + Path(str(argv[0])).name)
        return result

    def sudo(self, *argv, **kwargs):
        return self.run(["/usr/bin/sudo", "-n", *argv], **kwargs)

    def verified_manifest(self, pinned, directory, app=None):
        path = directory / self.candidate.MANIFEST_NAME
        require(digest(path) == pinned["candidate_manifest_sha256"], "candidate manifest pin mismatch")
        manifest = document(path)
        source = manifest["source"]
        require(source["repository"] == self.args.repository and source["commit"] == pinned["source_commit"], "candidate source mismatch")
        require(manifest["builder"]["run_id"] == pinned["run_id"] and manifest["builder"]["run_attempt"] == pinned["run_attempt"], "candidate run mismatch")
        # Authenticated provenance precedes any install; this does not trust a
        # local manifest's claimed source identity by itself.
        self.run([self.args.gh, "attestation", "verify", path, "--repo", self.args.repository,
                  "--signer-workflow", self.args.repository + "/.github/workflows/ci.yml",
                  "--source-digest", source["commit"], "--source-ref", "refs/heads/main",
                  "--deny-self-hosted-runners"], github=True, timeout=60)
        metadata = json.loads(self.run([self.args.gh, "api", f"repos/{self.args.repository}/actions/runs/{pinned['run_id']}/attempts/{pinned['run_attempt']}"], github=True).stdout)
        require(metadata.get("head_sha") == source["commit"] and metadata.get("head_branch") == "main"
                and metadata.get("event") == "push" and metadata.get("conclusion") == "success"
                and metadata.get("path") == ".github/workflows/ci.yml", "candidate build was not successful exact main CI")
        self.candidate.validate_manifest(candidate_dir=directory, repository=self.args.repository,
            version=manifest["version"], source_commit=source["commit"], source_tree=source["tree"],
            source_archive_sha256=source["archive_sha256"], source_date_epoch=source["source_date_epoch"],
            target="aarch64-apple-darwin", expected_workflow_run_id=pinned["run_id"],
            expected_workflow_run_attempt=pinned["run_attempt"], app_tree=app)
        return manifest

    def artifact(self, side, pinned, app, directory):
        manifest = self.verified_manifest(pinned, directory, app)
        source = manifest["source"]
        self.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", app])
        self.run(["/usr/bin/lipo", app / "Contents/Resources/slipstreamd/slipstreamd", "-verify_arch", "arm64"])
        value = {"version": manifest["version"], "source_commit": source["commit"],
                 "archive_sha256": digest(directory / "Slipstream.app.tar.gz"),
                 "app_executable_sha256": digest(app / "Contents/MacOS/slipstream"),
                 "daemon_sha256": digest(app / "Contents/Resources/slipstreamd/slipstreamd"),
                 "bundle_tree_sha256": self.tproxy._daemon_update_tree(app, readable=True)}
        self.events.append({"kind": "artifact", "side": side, **value})
        return value

    def absence(self, label):
        result = self.run(["/bin/launchctl", "print", "system/" + label], check=False)
        decoded = SimpleNamespace(returncode=result.returncode, stdout=result.stdout.decode(), stderr=result.stderr.decode())
        require(self.tproxy._launchd_job_absent(decoded), "owned service absence unproven")

    def copy_app(self, source, target, expected):
        target.mkdir()  # Claim exclusively; track even a partially failed copy.
        info = target.lstat()
        record = {"path": target, "sha256": expected, "inode": (info.st_dev, info.st_ino), "complete": False}
        self.created.append(record)
        shutil.copytree(source, target, symlinks=True, dirs_exist_ok=True)
        require(self.tproxy._daemon_update_tree(target, readable=True) == expected, "copied candidate changed")
        record["complete"] = True

    def setup(self):
        require(time.monotonic() < self.deadline - 500, "insufficient qualification budget")
        for path in (self.target, Path(self.tproxy.INSTALL_DIR), Path(self.tproxy.LAUNCHD_PLIST),
                     Path(self.tproxy.STATUS_PATH), self.root, Path(self.tproxy._DAEMON_UPDATE_REQUESTS),
                     Path(self.tproxy.INSTALL_ATTESTATION_DIR)):
            require(not os.path.lexists(path), "preexisting owned path: " + str(path))
        self.absence(self.tproxy.LAUNCHD_LABEL)
        result = self.run(["/usr/bin/pgrep", "-x", "slipstream(d)?"], check=False)
        require(result.returncode == 1, "preexisting Slipstream process or probe failure")
        self.sudo("/usr/bin/true")
        pins = document(self.args.pair_manifest)
        require(pins.get("schema_version") == 1 and set(pins) == {"schema_version", "old", "new"}, "invalid pair pins")
        old = self.artifact("old", pins["old"], self.args.old_app, self.args.old_candidate_dir)
        new = self.artifact("new", pins["new"], self.args.new_app, self.args.new_candidate_dir)
        nonce = secrets.token_hex(16)
        # Reject an ineffective pair before creating an installation.
        make_identity(self.tproxy, old, new, nonce, self.uid, time.time())
        self.approved_hashes = {old["daemon_sha256"], new["daemon_sha256"]}
        self.copy_app(self.args.old_app, self.target, old["bundle_tree_sha256"])
        self.install_attempted = True
        self.sudo(self.target / "Contents/Resources/slipstreamd/slipstreamd", "--install", timeout=110)
        self.operation = self.root / nonce
        self.stage = self.target.parent / (".Slipstream.app.slipstream-stage-" + nonce)
        self.mailbox = Path(self.tproxy._DAEMON_UPDATE_REQUESTS) / f"{self.uid}-{nonce}"
        self.copy_app(self.args.new_app, self.stage, new["bundle_tree_sha256"])
        # The immutable lease begins after installation/staging, before prepare.
        self.identity = make_identity(self.tproxy, old, new, nonce, self.uid, time.time())
        return self.identity

    def prepare(self, identity):
        self.sudo(self.installed, "--update-prepare", json.dumps(identity, separators=(",", ":")), timeout=90)

    def status(self):
        value = self.tproxy._update_read_json(str(self.operation / "status.json"), mode=0o644)
        validate_status(value, self.identity, self.fields, self.manifest)
        self.manifest = value["manifest_sha256"]
        if not self.events or self.events[-1].get("status") != value:
            require(len(self.events) < 512, "status observation bound exceeded")
            self.events.append({"kind": "root_status", "status": value})
        return value

    def wait(self, phase, timeout=100):
        until = min(time.monotonic() + timeout, self.deadline - 90)
        while time.monotonic() < until:
            value = self.status()
            if value["phase"] == phase:
                return value
            require(value["phase"] not in {"committed", "aborted"}, "unexpected terminal root decision")
            time.sleep(0.1)
        raise Refused("root phase deadline: " + phase)

    def request(self, sequence, action):
        info = self.mailbox.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == self.uid and stat.S_IMODE(info.st_mode) == 0o700, "mailbox ownership mismatch")
        path = self.mailbox / "request.json"
        temp = self.mailbox / (".request-" + secrets.token_hex(8))
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump({"schema_version": 1, "nonce": self.identity["nonce"], "sequence": sequence, "action": action}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        self.tproxy._update_sync_directory(str(self.mailbox))
        self.events.append({"kind": "request", "sequence": sequence, "action": action})

    def process(self, pid):
        require(type(pid) is int and pid > 1, "invalid worker PID")
        raw = self.run(["/bin/ps", "-ww", "-p", str(pid), "-o", "pid=,uid=,lstart=,command="]).stdout.decode().strip()
        fields = raw.split(None, 7)
        require(len(fields) == 8 and int(fields[0]) == pid and fields[1] == "0", "root worker process missing")
        expected = [str(self.operation / "private/worker-runtime/slipstreamd"), "--update-worker", self.identity["nonce"]]
        require(shlex.split(fields[7]) == expected, "root worker command mismatch")
        return {"pid": pid, "uid": 0, "started": " ".join(fields[2:7]), "argv": expected}

    def kill_ready_worker(self, ready):
        pid = ready["worker_pid"]
        first = self.process(pid)
        job = self.run(["/bin/launchctl", "print", "system/dev.slipstream.update." + self.identity["nonce"]]).stdout.decode()
        require(re.search(r"^\s*pid = " + str(pid) + r"\s*$", job, re.M), "worker launchd PID mismatch")
        current = self.status()
        require(current["phase"] == "ready" and current["decision"] is None and current["worker_pid"] == pid,
                "precommit fault window closed")
        require(self.process(pid) == first, "worker identity changed before injection")
        target = "system/dev.slipstream.update." + self.identity["nonce"]
        # launchd addresses this operation's job even if the observed PID exits
        # before sudo starts; never signal an independently recycled numeric PID.
        self.sudo("/bin/launchctl", "kill", "SIGKILL", target)
        self.events.append({"kind": "injection", "signal": "SIGKILL", "target": target, "process": first})
        return pid

    def arm_terminal_replay(self):
        value = self.status()
        require(value["phase"] == "aborted" and value["decision"] == "abort" and value["writer_quiescent"], "not a terminal abort")
        target = "system/dev.slipstream.update." + self.identity["nonce"]
        until = time.monotonic() + 10
        while time.monotonic() < until:
            state = self.run(["/bin/launchctl", "print", target]).stdout.decode()
            runs = re.search(r"^\s*runs = (\d+)\s*$", state, re.M)
            require(runs is not None, "worker launch count unavailable")
            if (not re.search(r"^\s*pid = \d+\s*$", state, re.M)
                    and re.search(r"^\s*last exit code = 0\s*$", state, re.M)):
                self.terminal_runs_before = int(runs.group(1))
                return
            time.sleep(0.05)
        raise Refused("terminal worker did not exit before mailbox wake")

    def wait_late_refusal(self, accepted):
        # Terminal worker exits successfully; LastExitStatus proves a launched
        # consumer finished. Polling the unchanged receipt alone is insufficient.
        until = time.monotonic() + 10
        while time.monotonic() < until:
            state = self.run(["/bin/launchctl", "print", "system/dev.slipstream.update." + self.identity["nonce"]]).stdout.decode()
            runs = re.search(r"^\s*runs = (\d+)\s*$", state, re.M)
            value = self.status()
            require(value["phase"] == "aborted" and value["decision"] == "abort"
                    and value["accepted_sequence"] == accepted, "late request changed terminal abort")
            if (runs and int(runs.group(1)) > self.terminal_runs_before
                    and not re.search(r"^\s*pid = \d+\s*$", state, re.M)
                    and re.search(r"^\s*last exit code = 0\s*$", state, re.M)):
                return value
            time.sleep(0.05)
        raise Refused("terminal replay consumer exit not observed")

    def prove(self, side, *, exact_snapshot=False):
        env = ["/usr/bin/env", "CI=true", "GITHUB_ACTIONS=true", "SLIPSTREAM_DISPOSABLE_CI=1", "RUNNER_OS=macOS"]
        command = [*env, sys.executable, Path(__file__).resolve(), "--repo", self.args.repo,
                   "--root-proof", self.identity[side + "_daemon_sha256"], "--nonce", self.identity["nonce"]]
        first = json.loads(self.sudo(*command).stdout)
        until = time.monotonic() + 8
        second = first
        while time.monotonic() < until and second["proof"]["heartbeat_seq"] <= first["proof"]["heartbeat_seq"]:
            time.sleep(0.25)
            second = json.loads(self.sudo(*command).stdout)
        require(first["proof"]["daemon_pid"] == second["proof"]["daemon_pid"]
                and first["process"] == second["process"]
                and second["proof"]["heartbeat_seq"] > first["proof"]["heartbeat_seq"], "daemon heartbeat did not advance on same PID")
        status = self.status()
        for key in ("daemon_pid", "daemon_sha256", "install_attestation_sha256"):
            require(status[key] == second["proof"][key], "root receipt differs from fresh daemon proof")
        if exact_snapshot:
            require(second["snapshot_ready"] and second["current_tree_sha256"] == second["old_runtime_sha256"], "old runtime was not restored exactly")
        self.events.append({"kind": "daemon_proof", "side": side, "first": first, "second": second})

    def teardown(self):
        if self.identity and self.operation.exists():
            value = self.status()
            if value["decision"] is None:
                self.request(max(3, value["accepted_sequence"] + 1), "abort")
                value = self.wait("aborted")
            elif value["phase"] not in {"committed", "aborted"}:
                value = self.wait("committed" if value["decision"] == "commit" else "aborted")
            require(value["writer_quiescent"], "teardown refused: root writer still active")
        if self.install_attempted:
            installed_hash = self.sudo("/usr/bin/shasum", "-a", "256", self.installed).stdout.decode().split()[0]
            require(installed_hash in self.approved_hashes, "refusing unrecognized installed cleanup executable")
            self.sudo(self.installed, "--uninstall", timeout=100)
            self.absence(self.tproxy.LAUNCHD_LABEL)
            if self.identity:
                self.absence("dev.slipstream.update." + self.identity["nonce"])
            for path in (Path(self.tproxy.INSTALL_DIR), Path(self.tproxy.LAUNCHD_PLIST),
                         Path(self.tproxy.STATUS_PATH), self.root / "active.json", self.operation, self.mailbox):
                require(path is None or not os.path.lexists(path), "owned teardown residue: " + str(path))
            require(not list(self.root.glob("*/private/worker-runtime")) and not list(self.root.glob(".prepare-*")), "retained runtime residue")
        for record in reversed(self.created):
            path = record["path"]
            info = path.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == self.uid
                    and (info.st_dev, info.st_ino) == record["inode"], "refusing replaced app cleanup")
            if record["complete"]:
                require(self.tproxy._daemon_update_tree(path, readable=True) == record["sha256"], "refusing changed app cleanup")
            shutil.rmtree(path)
        # Fixed root installer.lock inode and empty roots are intentionally kept.


def readonly_runtime_proof(tproxy, expected_sha):
    """Verify a frozen installed daemon from Python, without executable guessing.

    The production installer proof assumes it runs inside the frozen launcher.
    This observer instead names the installed executable explicitly and retains
    the same attestation witness, status, listener and PF evidence boundaries.
    """
    installed = str(Path(tproxy.INSTALL_DIR) / "slipstreamd")
    port = tproxy.PROXY_PORT
    raw = tproxy._update_read_json(tproxy.STATUS_PATH, mode=0o644, limit=1024 * 1024)
    require(raw.get("schema_version") == tproxy.STATUS_SCHEMA_VERSION, "StatusV2 required")
    status, recovery = raw.get("daemon"), raw.get("recovery", {})
    require(isinstance(status, dict) and isinstance(recovery, dict), "invalid daemon status")
    updated = status.get("updated_at", status.get("ts"))
    require(type(updated) in {int, float} and -2 <= time.time() - updated <= 15,
            "daemon status is not fresh")
    require(status.get("state") in {"active", "dormant"}, "daemon is not ready")
    require(recovery.get("reason") not in {tproxy.BASELINE_GUARD_BLOCK_REASON,
            tproxy.BASELINE_GUARD_ROLLBACK_REASON, tproxy.PF_LOOPBACK_UNAVAILABLE_REASON},
            "daemon recovery prevents readiness")
    pid, heartbeat = status.get("pid"), status.get("heartbeat_seq")
    require(type(pid) is int and pid > 1 and type(heartbeat) is int and heartbeat >= 0,
            "invalid daemon PID or heartbeat")
    plist, _ = tproxy._daemon_update_read_plist()
    require(plist["ProgramArguments"][0] == installed, "installed daemon executable mismatch")

    def process():
        result = tproxy._run("/bin/ps", "-ww", "-p", str(pid), "-o", "uid=,lstart=,command=")
        fields = result.stdout.strip().split(None, 6)
        require(result.returncode == 0 and len(fields) == 7 and fields[0] == "0"
                and shlex.split(fields[6]) == plist["ProgramArguments"], "daemon process identity mismatch")
        return {"uid": 0, "started": " ".join(fields[1:6]), "command": fields[6]}

    birth = process()
    job = tproxy._run("/bin/launchctl", "print", "system/" + tproxy.LAUNCHD_LABEL)
    require(job.returncode == 0 and re.search(r"^\s*pid = " + str(pid) + r"\s*$", job.stdout, re.M)
            and re.search(r"^\s*program = " + re.escape(installed) + r"\s*$", job.stdout, re.M),
            "installed daemon launchd binding mismatch")
    require(tproxy._listener_pids(port) == [pid]
            and tproxy._listener_bind_addresses(port, pid) == {"127.0.0.1", "::1"},
            "daemon does not exclusively own both loopback listeners")
    pf_active = bool(tproxy.pf_state_snapshot(port).get("rules_loaded"))
    require(pf_active == (status["state"] == "active"), "daemon PF state mismatch")
    evidence = tproxy.INSTALL_ATTESTATION_PATH
    attestation = tproxy._update_read_json(evidence, mode=0o644)
    witness_path = tproxy._install_attestation_witness_path(evidence)
    file_stat, witness = os.lstat(installed), os.lstat(witness_path)
    require(stat.S_ISREG(file_stat.st_mode) and file_stat.st_uid == 0
            and stat.S_IMODE(file_stat.st_mode) == 0o700, "unsafe installed daemon file")
    require(stat.S_ISREG(witness.st_mode) and witness.st_uid == file_stat.st_uid
            and witness.st_gid == file_stat.st_gid and stat.S_IMODE(witness.st_mode) == 0o700
            and (witness.st_dev, witness.st_ino) == (file_stat.st_dev, file_stat.st_ino)
            and witness.st_nlink >= 2, "daemon witness identity mismatch")
    require(tproxy._sha256_regular_file(installed) == expected_sha, "installed daemon hash mismatch")
    fresh = {"schema_version": tproxy.INSTALL_ATTESTATION_SCHEMA_VERSION,
        "source_sha256": expected_sha,
        "daemon": {"path": os.path.realpath(installed), "sha256": expected_sha,
                   "uid": file_stat.st_uid, "gid": file_stat.st_gid, "mode": 0o700},
        "witness": {"path": os.path.realpath(witness_path), "dev": witness.st_dev,
                    "ino": witness.st_ino, "size": witness.st_size, "mtime": int(witness.st_mtime),
                    "mtime_nsec": witness.st_mtime_ns % 1_000_000_000},
        "launchd": {"label": tproxy.LAUNCHD_LABEL, "pid": pid},
        "listener": {"host": "127.0.0.1", "hosts": ["127.0.0.1", "::1"], "port": port},
        "state": status["state"], "pf_active": pf_active}
    require(fresh == attestation, "installed daemon attestation drift")
    require(process() == birth, "daemon process changed during proof")
    return {"proof": {"daemon_pid": pid, "daemon_sha256": expected_sha,
                      "heartbeat_seq": heartbeat,
                      "install_attestation_sha256": tproxy._sha256_regular_file(evidence)},
            "process": birth}


def root_proof(args):
    guard(root=True)
    require(re.fullmatch(r"[0-9a-f]{64}", args.root_proof) and re.fullmatch(r"[0-9a-f]{32}", args.nonce or ""), "invalid readonly proof identity")
    tproxy, _ = modules(args.repo)
    value = readonly_runtime_proof(tproxy, args.root_proof)
    value["current_tree_sha256"] = tproxy._daemon_update_tree(tproxy.INSTALL_DIR)
    operation, path = tproxy._daemon_update_paths(args.nonce)
    journal = tproxy._update_read_json(path)
    value.update(snapshot_ready=journal["snapshot_ready"], old_runtime_sha256=journal["old_runtime_sha256"])
    print(json.dumps(value, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--root-proof", help=argparse.SUPPRESS)
    parser.add_argument("--nonce", help=argparse.SUPPRESS)
    parser.add_argument("--mode", choices=("commit", "crash-before-commit"))
    parser.add_argument("--repository", default="aiwaki/slipstream")
    parser.add_argument("--pair-manifest", type=Path)
    parser.add_argument("--old-app", type=Path)
    parser.add_argument("--new-app", type=Path)
    parser.add_argument("--old-candidate-dir", type=Path)
    parser.add_argument("--new-candidate-dir", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--gh", default="/opt/homebrew/bin/gh")
    args = parser.parse_args()
    args.repo = args.repo.resolve(strict=True)
    if args.root_proof:
        root_proof(args)
        return 0
    uid = guard()
    require(all(getattr(args, field) is not None for field in ("mode", "pair_manifest", "old_app", "new_app", "old_candidate_dir", "new_candidate_dir", "output")), "missing qualification input")
    output = args.output.resolve()
    require(Path(os.environ["RUNNER_TEMP"]).resolve() in output.parents and not output.exists(), "output must be a new RUNNER_TEMP file")
    tproxy, candidate = modules(args.repo)
    backend = Native(args, uid, tproxy, candidate)
    result = {"schema_version": 1, "status": "failed", "mode": args.mode, "root_protocol_qualified": False,
              "public_pair_qualified": False, "new_daemon_preinstalled": False,
              "driver_sha256": digest(Path(__file__).resolve()), "cleanup_errors": []}
    try:
        identity = backend.setup()
        result.update(qualify(backend, identity, args.mode), status="passed", identity=identity)
    except Exception as error:
        result.update(error_type=type(error).__name__, reason=str(error)[:512])
    finally:
        try:
            backend.teardown()
        except Exception as error:
            result["cleanup_errors"].append({"type": type(error).__name__, "reason": str(error)[:512]})
            result.update(status="failed", root_protocol_qualified=False)
        result["events"] = backend.events
        output.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write("\n")
    return 0 if result["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
