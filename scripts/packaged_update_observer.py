#!/usr/bin/env python3
"""Read-only observation of an externally started packaged update on disposable CI.

Start this observer first, then invoke the separately built OLD-source trigger
only after observer_ready. This tool never installs, launches, signals, requests
a root decision, or cleans product state. Its sole write is its evidence file.
Fault injection and native qualification of this draft remain separate gates.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import re
import stat
import time

from build_packaged_update_trigger import BIN, MODULES, pins
from native_root_update import (Native, Refused, digest, document, guard,
                                make_identity, modules, require, validate_status)

JOURNAL = "app-update-transaction-v1.json"
WATCHDOG = "dev.slipstream.update-watchdog"
PHASES = {"prepared", "backup_moved", "new_activated", "successor_launch_planned",
          "successor_launched", "daemon_commit_requested", "committed_launch_planned",
          "committed_launched", "acknowledged", "rollback_planned", "new_quarantined",
          "rolled_back", "old_relaunched", "cleanup_failed"}
JOURNAL_REQUIRED = {"schema_version", "nonce", "uid", "initiator_pid", "target", "backup", "stage",
                    "helper", "launch_agent", "current_version", "expected_version", "archive_sha256",
                    "watchdog_sha256", "old_executable_sha256", "new_executable_sha256", "phase",
                    "successor_pid", "successor_started", "successor_deadline_unix", "last_error", "daemon_update"}
U64_MAX = 2**64 - 1


def integer(value, minimum=0, maximum=U64_MAX):
    return type(value) is int and minimum <= value <= maximum


def pid(value):
    return integer(value, 2, 2**31 - 1)


def sha(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def birth(value):
    return (type(value) is str and 20 <= len(value) <= 64
            and re.fullmatch(r"[A-Za-z0-9 :\-]+", value) is not None)


def exact_equal(left, right):
    # Python's True == 1 must not relax a typed wire identity.
    return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate observation field")
        result[key] = value
    return result


def reject_constant(_value):
    raise Refused("nonfinite observation value")


def private_json(path, uid, *, limit=32768, writing=False):
    """Bounded no-follow regular-file read; only the trigger writes in place."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise Refused("cannot open private observation: " + path.name) from error
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink <= 1
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= limit,
                "unsafe private observation: " + path.name)
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    require(len(raw) <= limit and after.st_size <= limit, "private observation grew beyond bound")
    # Atomic replacement may unlink this already-open, immutable snapshot.
    # That is safe; extra hardlinks or metadata/content changes are not.
    require((info.st_uid, info.st_mode) == (after.st_uid, after.st_mode) and after.st_nlink <= 1,
            "private observation metadata changed")
    changed = ((info.st_size, info.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
               or (info.st_ctime_ns != after.st_ctime_ns and info.st_nlink == after.st_nlink))
    if changed and writing:
        return None
    require(not changed, "private observation changed during read")
    try:
        value = json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (json.JSONDecodeError, UnicodeError) as error:
        if writing:
            return None
        raise Refused("incomplete private observation: " + path.name) from error
    require(isinstance(value, dict), "private observation must be an object")
    return value


def validate_journal(value, expected, identity, uid, state, target, watchdog_hash):
    require(JOURNAL_REQUIRED <= set(value) <= JOURNAL_REQUIRED | {"cleanup_intent"}, "unexpected app journal schema")
    require(type(value["schema_version"]) is int and value["schema_version"] == 2
            and value["phase"] in PHASES, "unsupported app journal")
    require(type(value["uid"]) is int and value["uid"] == uid and value["nonce"] == identity["nonce"], "app journal owner mismatch")
    nonce = identity["nonce"]
    fixed = {"target": str(target), "backup": str(target.parent / (".Slipstream.app.slipstream-backup-" + nonce)),
             "stage": str(target.parent / (".Slipstream.app.slipstream-stage-" + nonce)),
             "helper": str(state / "runtime/slipstream-update-watchdog"),
             "launch_agent": str(Path.home() / "Library/LaunchAgents" / (WATCHDOG + ".plist")),
             "current_version": expected["old"]["version"], "expected_version": expected["new"]["version"],
             "archive_sha256": expected["new"]["archive_sha256"], "watchdog_sha256": watchdog_hash,
             "old_executable_sha256": expected["old"]["app_executable_sha256"],
             "new_executable_sha256": expected["new"]["app_executable_sha256"]}
    require(all(value[k] == v for k, v in fixed.items()), "app journal differs from pinned pair/paths")
    binding = value["daemon_update"]
    require(isinstance(binding, dict) and set(binding) == {"identity", "manifest_sha256", "sequence", "action", "authorization_started"}
            and exact_equal(binding["identity"], identity), "app/root identity mismatch")
    require((binding["manifest_sha256"] is None or sha(binding["manifest_sha256"]))
            and integer(binding["sequence"]) and binding["action"] in (None, "activate", "commit", "abort")
            and type(binding["authorization_started"]) is bool, "invalid app/root binding")
    require(pid(value["initiator_pid"]), "invalid initiator")
    require((value["successor_pid"] is None and value["successor_started"] is None)
            or (pid(value["successor_pid"]) and birth(value["successor_started"])), "invalid successor identity")
    require(value["successor_deadline_unix"] is None or integer(value["successor_deadline_unix"], 1), "invalid successor deadline")
    require(value["last_error"] is None or type(value["last_error"]) is str, "invalid journal error")
    cleanup = value.get("cleanup_intent")
    if cleanup is not None:
        require(isinstance(cleanup, dict) and set(cleanup) == {"kind", "backup", "stage"}, "invalid cleanup intent")
        require((cleanup["kind"] == "prepared_cancelled" and value["phase"] == "prepared" and cleanup["backup"] is None)
                or (cleanup["kind"] == "committed" and value["phase"] in {"successor_launched", "daemon_commit_requested",
                    "committed_launch_planned", "committed_launched", "acknowledged", "cleanup_failed"}), "invalid cleanup phase")
        for slot in (cleanup["backup"], cleanup["stage"]):
            require(slot is None or (isinstance(slot, dict) and set(slot) == {"device", "inode"}
                    and integer(slot["device"]) and integer(slot["inode"], 1)), "invalid cleanup slot")
    return value


def validate_ack(ack, journal):
    fields = {"schema_version", "nonce", "uid", "pid", "version", "target", "executable_sha256", "heartbeat_seq"}
    require(set(ack) == fields and type(ack["schema_version"]) is int and ack["schema_version"] == 1, "unexpected successor ACK schema")
    expected = {"nonce": journal["nonce"], "uid": journal["uid"], "pid": journal["successor_pid"],
                "version": journal["expected_version"], "target": journal["target"],
                "executable_sha256": journal["new_executable_sha256"]}
    require(all(type(ack[k]) is type(v) and ack[k] == v for k, v in expected.items()), "successor ACK identity mismatch")
    require(pid(ack["pid"]) and integer(ack["heartbeat_seq"], 1), "successor ACK lacks liveness")
    return ack


def parse_process(raw):
    fields = raw.strip().split(None, 8)
    require(len(fields) == 9 and fields[0].isdigit() and fields[1].isdigit(), "process observation incomplete")
    value = {"pid": int(fields[0]), "uid": int(fields[1]), "state": fields[2][0],
             "started": " ".join(fields[3:8]), "command": fields[8]}
    require(pid(value["pid"]) and integer(value["uid"], 1, 2**32 - 1) and birth(value["started"])
            and "\n" not in value["command"] and "\r" not in value["command"], "invalid process observation")
    return value


def same_process(left, right):
    return left is not None and right is not None and all(left[k] == right[k] for k in ("pid", "uid", "started", "command"))


def exact_successor(process, journal):
    return (process is not None and process["pid"] == journal["successor_pid"]
            and process["uid"] == journal["uid"] and process["started"] == journal["successor_started"]
            and process["state"] not in {"Z", "T"} and process["command"] == journal["target"] + "/Contents/MacOS/slipstream")


def pre_ack_candidate(journal, ack, status, before, after):
    """Pure eligibility check, not authority to signal a future numeric PID."""
    require(journal is not None and journal["phase"] == "successor_launched" and ack is None
            and status["phase"] == "ready" and status["decision"] is None and status["writer_quiescent"] is True,
            "pre-ACK fault window closed")
    require(all(type(status.get(key)) is type(value) and status[key] == value
                for key, value in journal["daemon_update"]["identity"].items()), "pre-ACK root identity mismatch")
    require(exact_successor(before, journal) and exact_successor(after, journal) and same_process(before, after),
            "pre-ACK process identity changed")
    return copy.deepcopy(after)


def require_commit_mode(mode):
    require(mode == "commit", "fault mode is not implemented or qualified; no signals are permitted")


def committed(root, ack):
    require(root["writer_quiescent"] is True, "terminal root writer is still active")
    require(root["phase"] == "committed" and root["decision"] == "commit", "root did not commit")
    require(ack is not None, "incomplete evidence: real successor ACK was not captured")


def validate_root(value, identity, fields, manifest, previous=None):
    validate_status(value, identity, fields, manifest)
    phase, decision = value["phase"], value["decision"]
    require(phase in {"prepared", "activating", "ready", "committing", "committed", "aborting", "aborted"}
            and decision in (None, "commit", "abort") and type(value["writer_quiescent"]) is bool, "invalid root phase")
    require((phase in {"prepared", "activating", "ready"} and decision is None)
            or (phase in {"committing", "committed"} and decision == "commit")
            or (phase in {"aborting", "aborted"} and decision == "abort"), "root phase/decision mismatch")
    require(integer(value["worker_pid"], 0, 2**31 - 1) and type(value["deadline_unix"]) is int
            and integer(value["accepted_sequence"]), "invalid root counters")
    require(value["daemon_pid"] is None or pid(value["daemon_pid"]), "invalid root daemon PID")
    require(value["heartbeat_seq"] is None or integer(value["heartbeat_seq"]), "invalid root heartbeat")
    for name in ("daemon_sha256", "install_attestation_sha256"):
        require(value[name] is None or sha(value[name]), "invalid root digest")
    require(value["error"] is None or type(value["error"]) is str, "invalid root error")
    if previous is not None:
        require(value["accepted_sequence"] >= previous["accepted_sequence"]
                and (previous["decision"] is None or decision == previous["decision"]), "root decision/sequence regressed")
    return value


def validate_build(build, plan, pair, expected, args, uid):
    binary = args.trigger_dir / "target/debug" / BIN
    require(type(build.get("schema_version")) is int and build["schema_version"] == 1
            and build.get("built") is True and exact_equal(build["pair"], pair)
            and build["pair_sha256"] == digest(args.pair_manifest)
            and build["binary"] == str(binary) and build["binary_sha256"] == digest(binary), "trigger build identity mismatch")
    require(type(plan.get("schema_version")) is int and plan["schema_version"] == 1 and exact_equal(plan["expected"], expected)
            and type(plan["uid"]) is int and plan["uid"] == uid
            and plan["output_dir"] == str(args.trigger_dir)
            and plan["runner_temp"] == str(args.trigger_dir.parent)
            and plan["pair"] == {"path": str(args.pair_manifest), "sha256": build["pair_sha256"]}, "compiled trigger plan mismatch")
    require(set(build["generated_sha256"]) == {"Cargo.toml", "Cargo.lock", "bridge.rs", "pinned-plan.json"}
            and all(sha(value) and digest(args.trigger_dir / name) == value for name, value in build["generated_sha256"].items()),
            "generated trigger input changed")
    require(sha(build["trigger_sha256"]) and digest(args.repo / "scripts/packaged_update_trigger.rs") == build["trigger_sha256"],
            "trigger source changed after build")
    sources = build["old_source_sha256"]
    require(isinstance(sources, dict) and all("app-tauri/src-tauri/src/" + name + ".rs" in sources for name in MODULES)
            and all(sha(value) for value in sources.values()), "OLD production source evidence missing")
    for side in ("old", "new"):
        path = getattr(args, side + "_candidate_dir") / "release-candidate-manifest.json"
        require(plan["manifests"][side] == {"path": str(path), "sha256": pair[side]["candidate_manifest_sha256"]}
                and digest(path) == pair[side]["candidate_manifest_sha256"]
                and expected[side]["source_commit"] == pair[side]["source_commit"], "trigger candidate manifest mismatch")
    archive = args.new_candidate_dir / "Slipstream.app.tar.gz"
    signature = args.new_candidate_dir / "Slipstream.app.tar.gz.sig"
    require(plan["archive_path"] == str(archive) and digest(archive) == expected["new"]["archive_sha256"]
            and plan["signature"] == {"path": str(signature), "sha256": digest(signature)}, "trigger archive/signature mismatch")
    return binary


class Observer(Native):
    def __init__(self, args, uid, tproxy, candidate):
        super().__init__(args, uid, tproxy, candidate)
        self.state = Path.home() / "Library/Application Support/dev.slipstream.tray"
        self.journal_path = self.state / JOURNAL
        self.ack_path = self.journal_path.with_suffix(".ack.json")
        self.agent = Path.home() / "Library/LaunchAgents" / (WATCHDOG + ".plist")
        self.last_journal = self.ack = self.ack_process = self.receipt = self.watchdog = None
        self.initiator = self.root_status = self.tray = None
        self.expected, self.last_event = {}, {}

    def record(self, kind, value):
        if self.last_event.get(kind) != value:
            require(len(self.events) < 512, "observer evidence bound exceeded")
            snapshot = copy.deepcopy(value)
            self.events.append({"kind": kind, "value": snapshot})
            self.last_event[kind] = snapshot

    def setup_observation(self):
        require_commit_mode(self.args.mode)
        self.authenticate_observation()

    def authenticate_observation(self):
        pair = pins(document(self.args.pair_manifest))
        require(type(pair["schema_version"]) is int, "invalid pair schema version")
        for side in ("old", "new"):
            self.expected[side] = self.artifact(side, pair[side], getattr(self.args, side + "_app"),
                                               getattr(self.args, side + "_candidate_dir"))
        build = private_json(self.args.trigger_dir / "build-receipt.json", self.uid, limit=1024 * 1024)
        plan = private_json(self.args.trigger_dir / "pinned-plan.json", self.uid, limit=1024 * 1024)
        require(build is not None and plan is not None, "trigger build receipt/plan missing")
        self.binary = validate_build(build, plan, pair, self.expected, self.args, self.uid)
        self.watchdog_hash = digest(self.args.old_app / "Contents/MacOS/slipstream-update-watchdog")
        require(self.tproxy._daemon_update_tree(self.target, readable=True) == self.expected["old"]["bundle_tree_sha256"],
                "installed OLD app tree differs from authenticated pair")
        require(self.watchdog_absent(), "preexisting app watchdog")
        require(self.run(["/usr/bin/pgrep", "-x", "slipstream"], check=False).returncode == 1, "old tray must not be running")
        for path in (self.journal_path, self.ack_path, self.args.trigger_dir / "prepare-result.json"):
            require(not os.path.lexists(path), "observer started after transaction: " + path.name)
        self.record("authenticated_trigger", build)
        self.record("observer_ready", {"state_dir": str(self.state), "pair": pair, "expected": self.expected})

    def bind(self, journal):
        binding = journal.get("daemon_update")
        require(isinstance(binding, dict) and isinstance(binding.get("identity"), dict), "coordinated journal required")
        identity = self.tproxy._daemon_update_identity(binding["identity"])
        expected = make_identity(self.tproxy, self.expected["old"], self.expected["new"], identity["nonce"],
                                 self.uid, identity["prepare_deadline_unix"] - 300)
        require(exact_equal(identity, expected) and (self.identity is None or exact_equal(self.identity, identity)), "production identity changed")
        validate_journal(journal, self.expected, identity, self.uid, self.state, self.target, self.watchdog_hash)
        if self.initiator is None:
            process = self.process_snapshot(journal["initiator_pid"])
            require(process is not None and process["uid"] == self.uid and process["state"] not in {"Z", "T"}
                    and process["command"] == f"{self.binary} --prepare", "incomplete evidence: exact trigger process not observed")
            self.initiator = process
            self.record("initiator", process)
        require(journal["initiator_pid"] == self.initiator["pid"], "journal initiator changed")
        if self.last_journal is not None:
            old_manifest = self.last_journal["daemon_update"]["manifest_sha256"]
            require(old_manifest is None or binding["manifest_sha256"] == old_manifest, "journal manifest changed")
            require(binding["sequence"] >= self.last_journal["daemon_update"]["sequence"], "journal sequence regressed")
        require(self.manifest is None or binding["manifest_sha256"] in (None, self.manifest), "journal/root manifest mismatch")
        self.identity = identity
        self.operation = self.root / identity["nonce"]
        self.stage = Path(journal["stage"])
        self.last_journal = copy.deepcopy(journal)
        self.record("app_journal", journal)

    def process_snapshot(self, process_id):
        require(pid(process_id), "invalid observed PID")
        value = self.run(["/bin/ps", "-ww", "-p", str(process_id), "-o", "pid=,uid=,state=,lstart=,command="], check=False)
        if value.returncode == 1 and not value.stdout.strip():
            return None
        require(value.returncode == 0, "process query failed")
        process = parse_process(value.stdout.decode())
        require(process["pid"] == process_id, "process query returned another PID")
        return process

    def watchdog_absent(self):
        value = self.run(["/bin/launchctl", "print", f"gui/{self.uid}/{WATCHDOG}"], check=False)
        if value.returncode == 0:
            return False
        from types import SimpleNamespace
        require(self.tproxy._launchd_job_absent(SimpleNamespace(returncode=value.returncode,
                stdout=value.stdout.decode(), stderr=value.stderr.decode())), "app watchdog absence unproven")
        return True

    def observe_watchdog(self):
        if self.watchdog is not None:
            return
        value = self.run(["/bin/launchctl", "print", f"gui/{self.uid}/{WATCHDOG}"], check=False)
        if value.returncode != 0:
            return  # Completion still requires positive packaged-watchdog evidence.
        match = re.search(rb"^\s*pid = (\d+)\s*$", value.stdout, re.M)
        if match is None:
            return
        process = self.process_snapshot(int(match[1]))
        helper = self.state / "runtime/slipstream-update-watchdog"
        require(process is not None and process["uid"] == self.uid and process["state"] not in {"Z", "T"}
                and process["command"] == f"{helper} --journal {self.journal_path}"
                and digest(helper) == self.watchdog_hash, "packaged watchdog process mismatch")
        self.watchdog = process
        self.record("packaged_watchdog", process)

    def status(self):
        value = self.tproxy._update_read_json(str(self.operation / "status.json"), mode=0o644)
        validate_root(value, self.identity, self.fields, self.manifest, self.root_status)
        journal_manifest = self.last_journal["daemon_update"]["manifest_sha256"]
        require(journal_manifest is None or journal_manifest == value["manifest_sha256"], "journal/root manifest mismatch")
        self.manifest = value["manifest_sha256"]
        self.root_status = copy.deepcopy(value)
        self.record("root_status", value)  # Per-kind dedup; app snapshots cannot inflate this stream.
        return value

    def read_receipt(self):
        path = self.args.trigger_dir / "prepare-result.json"
        value = private_json(path, self.uid, writing=True)
        if value is None:
            if (os.path.lexists(path) and self.initiator is not None
                    and not same_process(self.initiator, self.process_snapshot(self.initiator["pid"]))):
                private_json(path, self.uid)  # A dead writer cannot complete malformed JSON.
            return
        require(set(value) == {"schema_version", "prepared", "journal_path", "initiator_pid", "identity", "expected", "error"}
                and type(value["schema_version"]) is int and value["schema_version"] == 1
                and pid(value["initiator_pid"]) and type(value["prepared"]) is bool
                and exact_equal(value["expected"], self.expected), "trigger receipt identity mismatch")
        require(value["prepared"] is True and value["error"] is None, "production preparation failed")
        require(self.initiator is not None and value["initiator_pid"] == self.initiator["pid"]
                and value["journal_path"] == str(self.journal_path) and exact_equal(self.identity, value["identity"]),
                "incomplete evidence: receipt differs from observed trigger/journal")
        require(self.receipt is None or exact_equal(value, self.receipt), "trigger receipt changed")
        self.receipt = value
        self.record("prepare_receipt", value)

    def observe_once(self):
        journal = private_json(self.journal_path, self.uid)
        if journal is not None:
            self.bind(journal)
        ack = private_json(self.ack_path, self.uid, limit=8192)
        if ack is not None:
            require(self.last_journal is not None, "ACK without observed journal")
            # Journal and ACK are separate atomic files. A new successor may have
            # been journaled just after our first snapshot; refresh once, never infer.
            if ack.get("pid") != self.last_journal["successor_pid"]:
                current = private_json(self.journal_path, self.uid)
                if current is not None:
                    self.bind(current)
            validate_ack(ack, self.last_journal)
            process = self.process_snapshot(ack["pid"])
            require(exact_successor(process, self.last_journal), "ACK process is not the bound successor")
            self.ack, self.ack_process = copy.deepcopy(ack), process
            self.record("successor_ack", {"ack": ack, "process": process})
        if self.identity:
            self.observe_watchdog()
            if os.path.lexists(self.operation / "status.json"):
                self.status()
        self.read_receipt()
        return journal

    def wait_transaction(self, *, clock=time.monotonic, sleep=time.sleep):
        while clock() < self.deadline - 90:
            journal = self.observe_once()
            if self.root_status is not None:
                require(self.root_status["decision"] != "abort", "production transaction aborted; commit not qualified")
            if self.receipt is not None and journal is None and self.identity is not None:
                root = self.status()
                if root["phase"] == "committed" and root["writer_quiescent"] and self.watchdog_absent():
                    committed(root, self.ack)
                    require(not same_process(self.initiator, self.process_snapshot(self.initiator["pid"])),
                            "trigger still running after transaction cleanup")
                    return root
            sleep(0.02)
        raise Refused("packaged transaction deadline exhausted; observation incomplete")

    def final_app(self):
        expected = self.expected["new"]
        require(self.tproxy._daemon_update_tree(self.target, readable=True) == expected["bundle_tree_sha256"], "final app tree mismatch")
        for path in (self.journal_path, self.ack_path, self.stage, Path(self.last_journal["backup"]), self.agent):
            require(not os.path.lexists(path), "app transaction cleanup incomplete: " + str(path))
        require(self.watchdog_absent(), "app watchdog remains loaded")
        result = self.run(["/usr/bin/pgrep", "-x", "slipstream"], check=False)
        values = result.stdout.decode().split()
        require(result.returncode == 0 and len(values) == 1 and values[0].isdigit(), "one final tray must be alive")
        tray = self.process_snapshot(int(values[0]))
        require(self.ack is not None and tray is not None and tray["pid"] == self.ack["pid"]
                and exact_successor(tray, self.last_journal) and same_process(tray, self.ack_process),
                "final tray is not acknowledged successor")
        self.tray = tray
        self.record("final_app", {"side": "new", "process": tray, "bundle_tree_sha256": expected["bundle_tree_sha256"]})

    def qualify_app(self):
        require_commit_mode(self.args.mode)
        terminal = self.wait_transaction()
        require(self.watchdog is not None, "incomplete evidence: real packaged watchdog was not observed")
        committed(terminal, self.ack)
        self.final_app()
        # Existing read-only inspector checks root ownership, launchd, attestation
        # and two fresh heartbeats. It executes Python, never a candidate payload.
        self.prove("new")
        current = self.process_snapshot(self.tray["pid"])
        require(exact_successor(current, self.last_journal) and same_process(self.tray, current),
                "final tray died during daemon proof")
        return {"packaged_transaction_qualified": True, "public_pair_qualified": False, "side": "new"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "pair-manifest", "old-candidate-dir", "new-candidate-dir", "old-app", "new-app", "trigger-dir", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--mode", choices=("commit", "kill-successor-before-ack"), required=True)
    parser.add_argument("--gh", required=True)
    parser.add_argument("--repository", default="aiwaki/slipstream")
    args = parser.parse_args(argv)
    require_commit_mode(args.mode)  # Refuse before guard, setup, or any file creation.
    uid = guard()
    temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    for name in ("repo", "trigger_dir", "pair_manifest", "old_candidate_dir", "new_candidate_dir", "old_app", "new_app"):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    args.output = args.output.absolute()
    require(args.trigger_dir.parent == temp and args.output.parent == temp and not os.path.lexists(args.output),
            "new CI evidence and trigger paths required")
    tproxy, candidate = modules(args.repo)
    backend = Observer(args, uid, tproxy, candidate)
    result = {"schema_version": 1, "status": "failed", "mode": args.mode, "observation_only": True,
              "packaged_transaction_qualified": False, "public_pair_qualified": False,
              "not_qualified": ["old tray exit", "release discovery", "administrator dialog", "rollback", "browser routing"]}
    # Reserve evidence before declaring readiness; product state remains read-only.
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        try:
            backend.setup_observation()
            print(json.dumps({"observer_ready": True, "journal_path": str(backend.journal_path)}), flush=True)
            result.update(backend.qualify_app(), status="passed", identity=backend.identity)
        except Exception as error:
            result.update(error_type=type(error).__name__, reason=str(error)[:512], identity=backend.identity)
        finally:
            result["events"] = backend.events
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    return 0 if result["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
