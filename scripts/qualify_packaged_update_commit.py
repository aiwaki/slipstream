#!/usr/bin/env python3
"""Disposable packaged commit or one pre-ACK rollback gate; not old-tray Quit or public update proof."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import time

from build_packaged_update_trigger import pins
from native_root_update import Native, Refused, digest, document, guard, modules, require
from packaged_update_observer import Observer, exact_equal, exact_successor, same_process
from packaged_update_preack import PreAckObserver


MODES = ("commit", "crash-before-commit")
UNQUALIFIED = ["old tray exit", "release discovery", "administrator dialog",
               "app rollback", "exit before ACK", "exit after ACK", "browser routing"]


def prerequisite(metadata, directory, pair, expected, run_id, attempt):
    """Require successful root qualification of this complete app candidate pair."""
    require(metadata.get("id") == run_id and metadata.get("run_attempt") == attempt
            and metadata.get("head_sha") == pair["new"]["source_commit"]
            and metadata.get("head_branch") == "main" and metadata.get("event") == "workflow_dispatch"
            and metadata.get("path") == ".github/workflows/native-root-update-qualification.yml"
            and metadata.get("status") == "completed" and metadata.get("conclusion") == "success",
            "root prerequisite must be successful exact NEW main workflow/attempt")
    require(expected["old"]["version"] == "0.1.9-preview.27"
            and expected["new"]["version"] == "0.1.9-preview.28", "this gate requires normal .27 -> .28 candidates")
    root_pair = None
    receipt_hashes = {}
    for mode in MODES:
        folder = directory / f"native-root-update-{mode}-{run_id}-{attempt}"
        root_pins = pins(document(folder / "pair.json"))
        require(exact_equal(root_pins, pair), "root and app gates must use the same exact candidate pair")
        require(root_pair is None or exact_equal(root_pair, root_pins), "root cases used different pairs")
        root_pair = root_pins
        outcome = document(folder / "workflow-outcome.json")
        require(outcome.get("source_sha") == pair["new"]["source_commit"]
                and outcome.get("run_id") == str(run_id) and outcome.get("run_attempt") == str(attempt)
                and outcome.get("mode") == mode and outcome.get("job_status_before_upload") == "success"
                and outcome.get("steps", {}).get("qualify") == "success", "root case workflow outcome mismatch")
        result = document(folder / "result.json")
        require(result.get("status") == "passed" and result.get("mode") == mode
                and result.get("root_protocol_qualified") is True
                and result.get("public_pair_qualified") is False
                and result.get("new_daemon_preinstalled") is False
                and result.get("cleanup_errors") == [], "root case failed or cleanup incomplete")
        events = result.get("events")
        require(isinstance(events, list) and all(isinstance(item, dict) for item in events),
                "root artifact observations malformed")
        artifacts = [item for item in events if item.get("kind") == "artifact"]
        require(len(artifacts) == 2, "root case needs exactly one OLD and one NEW artifact")
        for side in ("old", "new"):
            records = [item for item in artifacts if item.get("side") == side]
            require(len(records) == 1 and exact_equal(
                {k: v for k, v in records[0].items() if k not in {"kind", "side"}}, expected[side]),
                "root artifact differs from authenticated " + side + " payload")
        identity = result.get("identity", {})
        expected_identity = {"archive_sha256": expected["new"]["archive_sha256"]}
        for side in ("old", "new"):
            for field in ("version", "app_executable_sha256", "daemon_sha256", "bundle_tree_sha256"):
                expected_identity[side + "_" + field] = expected[side][field]
        require(isinstance(identity, dict) and all(exact_equal(identity.get(key), value)
                for key, value in expected_identity.items()), "root identity mismatch")
        receipt_hashes[mode] = {name: digest(folder / name)
                               for name in ("pair.json", "workflow-outcome.json", "result.json")}
    return {"run_id": run_id, "run_attempt": attempt, "pair": root_pair, "sha256": receipt_hashes}


def verify_harness_source(backend, pair):
    """The app observer runs from the same main source as the successor/root gate."""
    expected = pair["new"]["source_commit"]
    require(os.environ.get("GITHUB_SHA") == expected, "app workflow SHA differs from exact NEW source")
    head = backend.run(["/usr/bin/git", "-C", str(backend.args.repo), "rev-parse", "HEAD"]).stdout.decode("ascii").strip()
    require(head == expected, "app checkout HEAD differs from exact NEW source")


def install_old(backend):
    """Same ordinary OLD installation as the root gate; never stage NEW here."""
    for path in (backend.target, Path(backend.tproxy.INSTALL_DIR), Path(backend.tproxy.LAUNCHD_PLIST),
                 Path(backend.tproxy.STATUS_PATH), backend.root, Path(backend.tproxy._DAEMON_UPDATE_REQUESTS),
                 Path(backend.tproxy.INSTALL_ATTESTATION_DIR), backend.state, backend.agent):
        require(not os.path.lexists(path), "preexisting owned path: " + str(path))
    backend.absence(backend.tproxy.LAUNCHD_LABEL)
    require(backend.watchdog_absent(), "preexisting app watchdog")
    require(backend.run(["/usr/bin/pgrep", "-x", "slipstream(d)?"], check=False).returncode == 1,
            "preexisting Slipstream process or probe failure")
    backend.sudo("/usr/bin/true")
    backend.copy_app(backend.args.old_app, backend.target, backend.expected["old"]["bundle_tree_sha256"])
    backend.approved_hashes = {item["daemon_sha256"] for item in backend.expected.values()}
    backend.install_attempted = True
    backend.sudo(backend.target / "Contents/Resources/slipstreamd/slipstreamd", "--install", timeout=110)


def stop_acknowledged_successor(backend, *, send=os.kill, clock=time.monotonic, sleep=time.sleep):
    """Cleanup only, after the actual ACK/commit; never signal an uncertain transaction."""
    require(backend.tray is not None and backend.ack is not None
            and backend.tray["pid"] == backend.ack["pid"], "acknowledged successor missing")
    current = backend.process_snapshot(backend.tray["pid"])
    require(exact_successor(current, backend.last_journal) and same_process(current, backend.tray),
            "cleanup successor PID/birth/UID/argv changed")
    send(current["pid"], signal.SIGTERM)
    deadline = min(clock() + 15, backend.deadline)
    while clock() < deadline:
        current = backend.process_snapshot(backend.tray["pid"])
        if current is None:
            return
        require(same_process(current, backend.tray), "successor PID was reused during cleanup")
        sleep(0.1)
    raise Refused("successor did not exit; no forced kill, runner destruction required")


def cleanup_committed(backend):
    # Recheck authoritative completion immediately before cleanup. Native.teardown
    # is reused only after this terminal proof, so its abort path cannot decide
    # an outstanding app transaction on this gate's behalf.
    backend.final_app()
    status = backend.status()
    require(status["phase"] == "committed" and status["decision"] == "commit" and status["writer_quiescent"],
            "cleanup requires a quiescent root commit")
    stop_acknowledged_successor(backend)
    require(backend.run(["/usr/bin/pgrep", "-x", "slipstream"], check=False).returncode == 1,
            "a tray remains after cleanup signal")
    info = backend.target.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == backend.uid, "cleanup target ownership mismatch")
    # Rename activation changes the canonical inode. Adopt only the fully checked
    # successor, not the now-deleted original installation's inode.
    backend.created = [{"path": backend.target, "sha256": backend.expected["new"]["bundle_tree_sha256"],
                        "inode": (info.st_dev, info.st_ino), "complete": True}]
    backend.mailbox = Path(backend.tproxy._DAEMON_UPDATE_REQUESTS) / f"{backend.uid}-{backend.identity['nonce']}"
    Native.teardown(backend)


def drive(backend, *, start=subprocess.Popen, cleanup=None):
    install_old(backend)
    backend.setup_observation()  # Real observer is ready before the trigger exists.
    backend.trigger_started = True  # Even a lost Popen reply makes cleanup uncertain.
    with (backend.args.trigger_dir / "trigger.log").open("xb") as log:
        env = {**backend.env, **{key: os.environ[key] for key in
               ("CI", "GITHUB_ACTIONS", "SLIPSTREAM_DISPOSABLE_CI", "RUNNER_OS", "RUNNER_TEMP")}}
        process = start([str(backend.binary), "--prepare"], stdout=log, stderr=subprocess.STDOUT, env=env)
        result = backend.qualify_app()
        require(process.wait(timeout=5) == 0, "trigger did not return successful preparation")
    backend.transaction_observed = True
    if cleanup is None:
        cleanup = cleanup_committed if backend.args.mode == "commit" else lambda value: value.cleanup_rollback()
    cleanup(backend)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "pair-manifest", "old-candidate-dir", "new-candidate-dir", "old-app", "new-app",
                 "trigger-dir", "root-gate-dir", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--root-gate-run-id", required=True)
    parser.add_argument("--root-gate-attempt", required=True)
    parser.add_argument("--gh", required=True)
    parser.add_argument("--repository", default="aiwaki/slipstream")
    parser.add_argument("--mode", choices=("commit", "kill-successor-before-ack"), default="commit")
    args = parser.parse_args(argv)
    uid = guard()
    temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    for name in ("repo", "pair_manifest", "old_candidate_dir", "new_candidate_dir", "old_app", "new_app", "trigger_dir", "root_gate_dir"):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    args.output = args.output.absolute()
    require(args.output.parent == temp and args.trigger_dir.parent == temp and args.root_gate_dir.parent == temp,
            "gate output and private working directories must be direct RUNNER_TEMP children")
    require(all(re.fullmatch(r"[1-9][0-9]*", value) for value in (args.root_gate_run_id, args.root_gate_attempt)),
            "positive exact root run/attempt required")
    run_id, attempt = int(args.root_gate_run_id), int(args.root_gate_attempt)
    tproxy, candidate = modules(args.repo)
    backend_type = Observer if args.mode == "commit" else PreAckObserver
    backend = backend_type(args, uid, tproxy, candidate)
    backend.trigger_started = backend.transaction_observed = False
    result = {"schema_version": 1, "status": "failed", "mode": args.mode, "packaged_transaction_qualified": False,
              "successor_exit_before_ack_rollback_qualified": False,
              "public_pair_qualified": False, "transaction_observed": False, "not_qualified": (UNQUALIFIED if args.mode == "commit" else
                  ["old tray exit", "release discovery", "administrator dialog", "other app rollback faults",
                   "exit after ACK", "browser routing"]),
              "driver_sha256": digest(Path(__file__)), "cleanup_errors": []}
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as output:
        try:
            pair = pins(document(args.pair_manifest))
            verify_harness_source(backend, pair)
            for side in ("old", "new"):
                backend.expected[side] = backend.artifact(side, pair[side], getattr(args, side + "_app"),
                                                           getattr(args, side + "_candidate_dir"))
            metadata = json.loads(backend.run([args.gh, "api",
                f"repos/{args.repository}/actions/runs/{run_id}/attempts/{attempt}"], github=True).stdout)
            result["root_prerequisite"] = prerequisite(metadata, args.root_gate_dir, pair, backend.expected, run_id, attempt)
            result.update(drive(backend), status="passed")
        except Exception as error:
            result.update(error_type=type(error).__name__, reason=str(error)[:512])
            if backend.trigger_started:
                # Keep the original failed evidence. No abort/kill/kickstart or
                # deletion is permitted while app ownership/outcome is unknown.
                result["cleanup_errors"].append("transaction not cleanly qualified; disposable runner destruction required")
            else:
                try:
                    Native.teardown(backend)
                except Exception as cleanup_error:
                    result["cleanup_errors"].append(str(cleanup_error)[:512])
        finally:
            result.update(transaction_observed=backend.transaction_observed, events=backend.events, identity=backend.identity)
            json.dump(result, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
    return 0 if result["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
