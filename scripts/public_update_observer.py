#!/usr/bin/env python3
"""External, test-only observer of a real .23 -> .24 updater transaction.

Never creates/edits an updater journal, starts the app, or clicks its menu.
A PASS covers the observed transaction only, not public discovery or visibility.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import signal
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import macos_update_notification_smoke as existing

JOURNAL = "app-update-transaction-v1.json"
ACK = "app-update-transaction-v1.ack.json"
HASH_FIELDS = ("archive_sha256", "old_executable_sha256", "new_executable_sha256", "watchdog_sha256")
IDENTITY_FIELDS = ("uid", "target", "current_version", "expected_version", *HASH_FIELDS)
PHASES = {"prepared", "backup_moved", "new_activated", "successor_launch_planned",
          "successor_launched", "acknowledged", "rollback_planned", "new_quarantined",
          "rolled_back", "old_relaunched", "cleanup_failed"}


class Stop(RuntimeError):
    pass


def require(ok, message):
    if not ok:
        raise Stop(message)


def save_report(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def read_document(path: Path, uid: int | None = None):
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if uid is not None:
        require(metadata.st_uid == uid and stat.S_IMODE(metadata.st_mode) == 0o600,
                "transaction file owner/mode mismatch")
    payload = existing._read_bounded_regular_file(path, 32768)
    value = json.loads(payload)
    require(isinstance(value, dict), "document is not an object")
    return value


def parse_process(line):
    fields = line.split(None, 8)
    require(len(fields) == 9, "invalid ps identity")
    return {"pid": int(fields[0]), "uid": int(fields[1]), "state": fields[2],
            "started": " ".join(fields[3:8]), "command": fields[8].strip()}


def process_snapshot(pid):
    result = subprocess.run(["/bin/ps", "-ww", "-p", str(pid), "-o",
                             "pid=,uid=,state=,lstart=,command="],
                            capture_output=True, text=True, timeout=3)
    if result.returncode == 1 and not result.stdout.strip():
        return None
    require(result.returncode == 0, "ps identity unavailable")
    return parse_process(result.stdout.strip())


def executable(target):
    return Path(target) / "Contents/MacOS/slipstream"


def matching_process(snapshot, *, pid, uid, started, target):
    return bool(snapshot and snapshot["pid"] == pid and snapshot["uid"] == uid
                and snapshot["started"] == started and not snapshot["state"].startswith("Z")
                and snapshot["command"] == str(executable(target)))


def validate_bindings(value):
    require(value["current_version"] == "0.1.9-preview.23"
            and value["expected_version"] == "0.1.9-preview.24", "wrong version pair")
    require(type(value["uid"]) is int and value["uid"] > 0, "non-console UID")
    require(type(value["initial_pid"]) is int and value["initial_pid"] > 1, "invalid old PID")
    require(isinstance(value["initial_started"], str) and value["initial_started"], "missing old birth time")
    for field in HASH_FIELDS:
        require(re.fullmatch(r"[0-9a-f]{64}", value[field]) is not None, f"invalid {field}")
    for field in ("target", "state_dir", "launch_agents_dir"):
        require(Path(value[field]).is_absolute(), f"non-absolute {field}")
    require(value["old_executable_sha256"] != value["new_executable_sha256"], "identical app hashes")


class Observation:
    def __init__(self, bindings, mode):
        validate_bindings(bindings)
        require(mode in ("success", "rollback"), "invalid observation mode")
        self.bindings, self.mode = bindings, mode
        self.first = self.latest = self.ack = self.failed = None
        self.injected = False
        self.events = []

    def journal(self, value):
        b = self.bindings
        require(type(value.get("schema_version")) is int and value["schema_version"] == 1,
                "unknown journal schema")
        require(all(value.get(k) == b[k] for k in IDENTITY_FIELDS), "journal identity mismatch")
        require(value.get("initiator_pid") == b["initial_pid"], "wrong initiating .23 PID")
        nonce = value.get("nonce", "")
        require(re.fullmatch(r"[0-9a-f]{32}", nonce) is not None, "invalid nonce")
        parent = Path(b["target"]).parent
        paths = {"backup": parent / f".Slipstream.app.slipstream-backup-{nonce}",
                 "stage": parent / f".Slipstream.app.slipstream-stage-{nonce}",
                 "helper": Path(b["state_dir"]) / "runtime/slipstream-update-watchdog",
                 "launch_agent": Path(b["launch_agents_dir"]) / "dev.slipstream.update-watchdog.plist"}
        require(all(value.get(k) == str(p) for k, p in paths.items()), "journal path mismatch")
        require(value.get("phase") in PHASES, "unknown transaction phase")
        if self.first is None:
            self.first = value.copy()
        require(all(value.get(k) == self.first.get(k) for k in
                    (*IDENTITY_FIELDS, "nonce", "initiator_pid", *paths)), "transaction replaced")
        if self.latest and self.latest.get("successor_pid") is not None:
            require(all(value.get(k) == self.latest.get(k) for k in
                        ("successor_pid", "successor_started", "successor_deadline_unix")),
                    "successor identity changed within transaction")
        self.latest = value.copy()
        if not self.events or self.events[-1] != value:
            require(len(self.events) < 64, "transaction event limit")
            self.events.append(value.copy())

    def successor(self, value, snapshot):
        require(type(value.get("successor_pid")) is int and value["successor_pid"] > 1,
                "successor PID is unavailable")
        require(matching_process(snapshot, pid=value["successor_pid"], uid=value["uid"],
                                 started=value["successor_started"], target=value["target"]),
                "successor PID/UID/birth/path mismatch")

    def acknowledgement(self, value):
        j = self.latest
        require(j is not None, "ack appeared without observed journal")
        expected = {"schema_version": 1, "nonce": j["nonce"], "uid": j["uid"],
                    "pid": j["successor_pid"], "version": j["expected_version"],
                    "target": j["target"], "executable_sha256": j["new_executable_sha256"]}
        require(all(value.get(k) == v for k, v in expected.items()), "ack identity mismatch")
        require(all(type(value.get(k)) is int for k in ("schema_version", "uid", "pid")),
                "ack identity types mismatch")
        require(type(value.get("heartbeat_seq")) is int and value["heartbeat_seq"] > 0,
                "ack heartbeat missing")
        require(self.mode != "rollback", "ack raced rollback injection; rollback was not qualified")
        self.ack = value.copy()

    def inject(self, reread, snapshot, digest, send_signal, clock=time.time):
        require(self.mode == "rollback" and not self.injected, "injection is not authorized or already spent")
        journal, ack = reread()
        require(journal is not None and ack is None, "rollback window closed")
        self.journal(journal)
        require(journal["phase"] == "successor_launched", "successor is not awaiting ack")
        require(type(journal.get("successor_deadline_unix")) is int
                and journal["successor_deadline_unix"] > clock(), "successor deadline elapsed")
        require(digest(executable(journal["target"])) == journal["new_executable_sha256"],
                "successor executable hash mismatch")
        identity = snapshot(journal["successor_pid"])
        self.successor(journal, identity)
        again, ack = reread()
        require(again == journal and ack is None, "transaction changed before injection")
        self.successor(journal, snapshot(journal["successor_pid"]))
        self.injected = True  # Never retry even if the OS signal returns an error.
        send_signal(journal["successor_pid"], signal.SIGKILL)

    def failure_journal(self, value):
        self.journal(value)
        require(self.mode == "rollback" and self.injected and value["phase"] == "old_relaunched",
                "rollback completion was not observed after this injection")
        self.failed = value.copy()

    def terminal(self, *, digest, version, processes, cleaned):
        require(self.latest is not None and cleaned, "transaction cleanup incomplete")
        b = self.bindings
        if self.mode == "success":
            require(self.ack is not None and not self.injected, "no observed matching success ack")
            wanted_hash, wanted_version = b["new_executable_sha256"], b["expected_version"]
            j = self.latest
            require(len(processes) == 1, "successor process is absent or ambiguous")
            self.successor(j, processes[0])
        else:
            require(self.failed is not None and self.injected and self.ack is None, "no qualified rollback")
            wanted_hash, wanted_version = b["old_executable_sha256"], b["current_version"]
            require(len(processes) == 1 and processes[0]["pid"] != b["initial_pid"]
                    and processes[0]["pid"] != self.latest["successor_pid"]
                    and processes[0]["uid"] == b["uid"]
                    and processes[0]["command"] == str(executable(b["target"]))
                    and not processes[0]["state"].startswith("Z"), "old app was not relaunched")
        require(digest == wanted_hash and version == wanted_version, "terminal bundle identity mismatch")


def target_processes(bindings):
    result = subprocess.run(["/bin/ps", "-ww", "-axo", "pid=,uid=,state=,lstart=,command="],
                            capture_output=True, text=True, timeout=3)
    require(result.returncode == 0, "cannot enumerate target processes")
    matches = []
    for line in result.stdout.splitlines():
        item = parse_process(line)
        if item["uid"] == bindings["uid"] and item["command"] == str(executable(bindings["target"])):
            matches.append(item)
    return matches


def bundle_version(target):
    data = existing._read_bounded_regular_file(Path(target) / "Contents/Info.plist", 65536)
    info = plistlib.loads(data)
    require(info.get("CFBundleIdentifier") == existing.BUNDLE_IDENTIFIER
            and info.get("CFBundleExecutable") == "slipstream" and info.get("LSUIElement") is True,
            "terminal bundle metadata mismatch")
    return info.get("CFBundleShortVersionString")


def run(bindings, mode, output, timeout, *, on_ready=None, on_observation=None):
    existing._require_disposable_macos_ci()
    validate_bindings(bindings)
    require(bindings["uid"] == os.getuid() == os.stat("/dev/console").st_uid != 0,
            "observer must be the console UID")
    require(Path(bindings["target"]) == Path("/Applications/Slipstream.app"), "wrong production app path")
    require(Path(bindings["state_dir"]).is_relative_to(Path.home()), "state directory is not user-owned")
    require(Path(bindings["launch_agents_dir"]) == Path.home() / "Library/LaunchAgents", "wrong LaunchAgents path")
    require(60 <= timeout <= 600, "timeout must be 60..600 seconds")
    journal_path = Path(bindings["state_dir"]) / JOURNAL
    ack_path = journal_path.with_name(ACK)
    uid = bindings["uid"]
    read_pair = lambda: (read_document(journal_path, uid), read_document(ack_path, uid))
    require(read_pair() == (None, None), "transaction already exists; start before the real tray action")
    require(existing._sha256(executable(bindings["target"])) == bindings["old_executable_sha256"]
            and bundle_version(bindings["target"]) == bindings["current_version"], "initial .23 identity mismatch")
    require(matching_process(process_snapshot(bindings["initial_pid"]),
                             pid=bindings["initial_pid"], uid=uid,
                             started=bindings["initial_started"], target=bindings["target"]), "initial .23 process mismatch")
    observation = Observation(bindings, mode)
    report = {"schema_version": 1, "scope": "external_transaction_observer_only",
              "public_pair_qualified": False, "mode": mode, "bindings": bindings,
              "canonical_bindings_sha256": hashlib.sha256(json.dumps(bindings, sort_keys=True).encode()).hexdigest(),
              "observer_sha256": existing._sha256(Path(__file__)),
              "helper_sha256": existing._sha256(Path(existing.__file__)),
              "status": "FAIL", "remaining_gates": ["public discovery and genuine tray action",
                  "native notification delivery", "visibility over the actual transition",
                  "independently observed owned-daemon heartbeat", "disposable-host final cleanup"]}
    started = time.monotonic()
    stable = 0
    print(json.dumps({"status": "READY", "mode": mode, "waiting_for": "real old-app tray action"}), flush=True)
    try:
        if on_ready is not None:
            on_ready()
        while time.monotonic() - started < timeout:
            journal, ack = read_pair()
            if journal is not None:
                observation.journal(journal)
                require(existing._sha256(Path(journal["helper"])) == bindings["watchdog_sha256"], "old watchdog hash mismatch")
            if ack is not None:
                observation.acknowledgement(ack)
            if on_observation is not None:
                on_observation(observation)
            if journal and mode == "rollback" and not observation.injected and journal["phase"] == "successor_launched":
                observation.inject(read_pair, process_snapshot, existing._sha256, os.kill)
            if observation.first:
                failed_path = journal_path.with_name(f"app-update-transaction-failed-{observation.first['nonce']}.json")
                failed = read_document(failed_path, uid)
                if failed:
                    if mode == "success":
                        observation.journal(failed)
                        observation.failed = failed.copy()
                        raise Stop("real updater rolled back; success was not qualified")
                    observation.failure_journal(failed)
                paths = [journal_path, ack_path, *(Path(observation.first[k]) for k in ("backup", "stage", "launch_agent"))]
                cleaned = all(not p.exists() and not p.is_symlink() for p in paths)
                if cleaned and (observation.ack or observation.failed):
                    processes = target_processes(bindings)
                    observation.terminal(digest=existing._sha256(executable(bindings["target"])),
                                         version=bundle_version(bindings["target"]), processes=processes, cleaned=True)
                    stable += 1
                    if stable == 3:
                        report.update(status="PASS", terminal_processes=processes)
                        return report
                else:
                    stable = 0
            time.sleep(0.1)
        raise Stop("bounded observation timed out; no automatic retry")
    except Exception as error:
        report["failure"] = str(error)
        raise
    finally:
        report.update(elapsed_seconds=round(time.monotonic() - started, 3),
                      journal_observations=observation.events, ack=observation.ack,
                      failed_journal=observation.failed, signal_attempted=observation.injected)
        save_report(output / "transaction-report.json", report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bindings", type=Path, required=True)
    parser.add_argument("--mode", choices=("success", "rollback"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--allow-owned-successor-sigkill", action="store_true")
    args = parser.parse_args()
    require(args.mode != "rollback" or args.allow_owned_successor_sigkill, "explicit one-shot injector authorization missing")
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    try:
        bindings = read_document(args.bindings)
        run(bindings, args.mode, args.output, args.timeout)
    except Exception as error:
        if not (args.output / "transaction-report.json").exists():
            save_report(args.output / "preflight-failure.json", {"status": "FAIL", "failure": str(error)})
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
