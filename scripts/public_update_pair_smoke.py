#!/usr/bin/env python3
"""Observe one genuine public .23 -> .24 update on a disposable hosted Mac."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import signal
import subprocess
import sys
import time

import public_update_menu_smoke as menu
import public_update_observer as observer

NEW_VERSION = "0.1.9-preview.24"
NEW_ARCHIVE = "f297fce1dd8c7c234ced882731570845921824fd279f93d608546d5dfdf1624d"
NEW_TRAY = "72fa150bea866c2181e11f8bbaf8419f30166284cd371a67fd8efbfe2f83339f"
NEW_DAEMON = "d3846df0bf47c2d1d90886ed3adc98f86503b0539436f084385f8df3901f862d"
OLD_TRAY = "2b5cc4b87ceb03f6ecbf295690971d13374c3e3ebbdcba3458daf2ad8deee2cd"
OLD_DAEMON = "c8619a97c9d163939fe4fb080ba6c088f574290771631ef1385bfcc1acfc9145"


def offered(menu_report):
    titles = {f"Install Slipstream {NEW_VERSION}…", f"Установить Slipstream {NEW_VERSION}…"}
    return (menu_report.get("status") == "inspected" and menu_report.get("actions") == []
            and len([row for row in menu_report.get("update_items", [])
                     if row.get("role") == "AXMenuItem" and row.get("title") in titles
                     and row.get("enabled") is True]) == 1)


def daemon_sample(context, label):
    """Independent installed bytes, root process, launchd and fresh StatusV2."""
    result = {"observed_at": time.time()}
    try:
        value = json.loads(observer.existing._read_bounded_regular_file(menu.STATUS, 1024 * 1024))
        status = value["daemon"] if value.get("schema_version") == 2 else value
        result["status"] = {key: status.get(key) for key in ("pid", "state", "version", "heartbeat_seq", "updated_at", "ts")}
        command = context["command"]
        digest = command(label + "-sha", ["/usr/bin/sudo", "-n", "/usr/bin/shasum", "-a", "256", str(menu.INSTALLED_DAEMON)], timeout=3)
        result["installed_sha256"] = digest.stdout.decode().split()[0]
        info = plistlib.loads(observer.existing._read_bounded_regular_file(menu.PLIST, 65536))
        args = info.get("ProgramArguments", [])
        pid = status.get("pid")
        observer.require(type(pid) is int and pid > 1, "daemon PID unavailable")
        snapshot = observer.process_snapshot(pid)
        result["process"] = snapshot
        state = command(label + "-launchd", ["/bin/launchctl", "print", menu.JOB], timeout=3).stdout.decode()
        age = time.time() - float(status.get("updated_at", status.get("ts", 0)))
        result["owned_fresh"] = bool(args[:1] == [str(menu.INSTALLED_DAEMON)] and snapshot
            and snapshot["uid"] == 0 and not snapshot["state"].startswith("Z")
            and snapshot["command"] == " ".join(args)
            and re.search(r"^\s*pid = " + str(pid) + r"\s*$", state, re.M)
            and status.get("state") == "active" and 0 <= age < 15
            and type(status.get("heartbeat_seq")) is int and status["heartbeat_seq"] > 0)
    except Exception as error:
        result.update(owned_fresh=False, error_type=type(error).__name__, reason=str(error)[:512])
    return result


def require_new_daemon(first, second):
    for sample in (first, second):
        observer.require(sample.get("owned_fresh") is True and sample.get("installed_sha256") == NEW_DAEMON
                         and sample.get("status", {}).get("version") == NEW_VERSION,
                         "app ACK does not prove exact public .24 root daemon; observed daemon mismatch")
    a, b = first["status"], second["status"]
    observer.require(a["pid"] == b["pid"] and first["process"]["started"] == second["process"]["started"]
                     and b["heartbeat_seq"] > a["heartbeat_seq"], "new daemon heartbeat/identity did not advance")


def privilege_children(successor_pid, uid):
    """Retain identity only for the successor's real administrator request."""
    result = subprocess.run(["/bin/ps", "-ww", "-axo", "pid=,ppid=,uid=,lstart=,command="],
                            capture_output=True, text=True, timeout=3, check=True)
    found = []
    for line in result.stdout.splitlines():
        fields = line.split(None, 8)
        if len(fields) != 9 or fields[1:3] != [str(successor_pid), str(uid)]:
            continue
        command = fields[8]
        if (command.startswith("/usr/bin/osascript -e ") and str(menu.BUNDLED_DAEMON) in command
                and "--install" in command and "with administrator privileges" in command):
            pid = int(fields[0])
            observer.require(menu.process_path(pid) == "/usr/bin/osascript", "privilege child path mismatch")
            found.append({"pid": pid, "ppid": successor_pid, "uid": uid, "started": " ".join(fields[3:8]),
                          "command_sha256": hashlib.sha256(command.encode()).hexdigest()})
    observer.require(len(found) <= 4, "too many privilege-request children")
    return found


def stop_privilege_child(child):
    def still_owned():
        snapshot = observer.process_snapshot(child["pid"])
        if snapshot is None or snapshot["state"].startswith("Z"):
            return False
        observer.require(snapshot["uid"] == child["uid"] and snapshot["started"] == child["started"]
                         and hashlib.sha256(snapshot["command"].encode()).hexdigest() == child["command_sha256"]
                         and menu.process_path(child["pid"]) == "/usr/bin/osascript", "refusing replaced privilege child")
        return True
    if still_owned():
        os.kill(child["pid"], signal.SIGTERM)
        until = time.monotonic() + 2
        while time.monotonic() < until and still_owned():
            time.sleep(0.1)
        if still_owned():
            os.kill(child["pid"], signal.SIGKILL)
            time.sleep(0.1)
        observer.require(not still_owned(), "privilege child survived cleanup")


def stop_watchdog(context, bindings):
    """Quiesce only this validated real transaction; preserve journal/files."""
    job = f"gui/{bindings['uid']}/dev.slipstream.update-watchdog"
    command = context["command"]
    present = command("pair-cleanup-watchdog-probe", ["/bin/launchctl", "print", job], timeout=3, check=False)
    if present.returncode:
        observer.require(b"could not find service" in (present.stdout + present.stderr).lower(), "watchdog absence unproven")
        return
    journal = context["transaction"].get("journal")
    observer.require(journal is not None, "refusing unbound watchdog cleanup")
    validator = observer.Observation(bindings, "success")
    validator.journal(journal)
    helper, plist = Path(journal["helper"]), Path(journal["launch_agent"])
    observer.require(menu.sha256(helper) == bindings["watchdog_sha256"], "watchdog cleanup hash mismatch")
    info = plistlib.loads(observer.existing._read_bounded_regular_file(plist, 65536))
    wanted_args = [str(helper), "--journal", str(Path(bindings["state_dir"]) / observer.JOURNAL)]
    observer.require(info.get("Label") == "dev.slipstream.update-watchdog"
                     and info.get("ProgramArguments") == wanted_args, "watchdog cleanup plist mismatch")
    pids = re.findall(r"^\s*pid = (\d+)\s*$", present.stdout.decode(), re.M)
    observer.require(len(pids) == 1, "watchdog cleanup PID unavailable")
    pid = int(pids[0])
    snapshot = observer.process_snapshot(pid)
    observer.require(snapshot and snapshot["uid"] == bindings["uid"] and snapshot["command"] == " ".join(wanted_args)
                     and menu.process_path(pid) == str(helper), "watchdog cleanup process mismatch")
    observer.require(observer.process_snapshot(pid) == snapshot, "watchdog identity drift before bootout")
    command("pair-cleanup-watchdog-bootout", ["/bin/launchctl", "bootout", job], timeout=5)
    after = command("pair-cleanup-watchdog-after", ["/bin/launchctl", "print", job], timeout=3, check=False)
    observer.require(after.returncode != 0 and b"could not find service" in (after.stdout + after.stderr).lower(),
                     "watchdog job survived cleanup")
    survivor = observer.process_snapshot(pid)
    observer.require(survivor is None or survivor["state"].startswith("Z"), "watchdog process survived cleanup")


def after_menu(context):
    output = context["output_dir"] / "transaction"
    output.mkdir(mode=0o700)
    report = {"schema_version": 1, "scope": "one_real_public_success_transaction", "status": "blocked",
              "public_pair_qualified": False, "forced_rollback_qualified": False,
              "new_daemon_preinstalled": False, "authorization_dialog_automated": False,
              "discovery_observations": [], "cleanup_errors": [], "privilege_children": []}
    started = time.monotonic()
    deadline = min(started + 300, context["deadline"])
    child = None
    bindings = None
    click_log = None
    context["transaction"]["update_activated"] = False
    ax = [sys.executable, str(menu.ROOT / "scripts/public_update_ax.py"), "--pid", str(context["pid"]),
          "--uid", str(context["uid"]), "--executable", str(menu.TRAY), "--exe-sha256", OLD_TRAY]
    try:
        observer.require(context["old_exe_sha256"] == OLD_TRAY and context["old_daemon_sha256"] == OLD_DAEMON,
                         "actual .23 baseline differs from public pins")
        # The menu was opened by the existing harness. Only read while the real
        # old app performs its normal timed public release discovery.
        discovery_end = min(started + 90, deadline - 90)
        for index in range(24):
            observer.require(time.monotonic() < discovery_end, "exact public .24 offer did not appear within 90 seconds")
            path = output / f"discovery-{index:02}.json"
            context["command"](f"pair-discovery-{index:02}", ax + ["--output", str(path)],
                               timeout=min(30, discovery_end - time.monotonic()), hosted_helper=True)
            result = observer.read_document(path)
            observer.require(result.get("identity", {}).get("started") == context["old_identity"]["started"], "old app process replaced during discovery")
            report["discovery_observations"].append({"elapsed": round(time.monotonic()-started, 3), "update_items": result.get("update_items", [])})
            if offered(result):
                report["exact_public_offer_observed"] = True
                break
            time.sleep(3)
        observer.require(report.get("exact_public_offer_observed") is True, "no enabled exact .24 offer")
        state = Path.home() / "Library/Application Support/dev.slipstream.tray"
        old = observer.process_snapshot(context["pid"])
        observer.require(old is not None, "old app exited before trigger")
        bindings = {"uid": context["uid"], "target": str(menu.APP), "state_dir": str(state),
                    "launch_agents_dir": str(Path.home() / "Library/LaunchAgents"),
                    "current_version": menu.VERSION, "expected_version": NEW_VERSION,
                    "archive_sha256": NEW_ARCHIVE, "old_executable_sha256": OLD_TRAY,
                    "new_executable_sha256": NEW_TRAY,
                    "watchdog_sha256": menu.sha256(menu.APP / "Contents/MacOS/slipstream-update-watchdog"),
                    "initial_pid": context["pid"], "initial_started": context["old_identity"]["started"]}
        observer.save_report(output / "bindings.json", bindings)
        observer.require(not (Path(bindings["launch_agents_dir"]) / "dev.slipstream.update-watchdog.plist").exists(), "preexisting updater LaunchAgent")
        job = f"gui/{bindings['uid']}/dev.slipstream.update-watchdog"
        baseline = context["command"]("pair-watchdog-baseline", ["/bin/launchctl", "print", job], timeout=3, check=False)
        observer.require(baseline.returncode != 0 and b"could not find service" in (baseline.stdout + baseline.stderr).lower(),
                         "preexisting watchdog or absence unproven")
        report["daemon_before_click"] = daemon_sample(context, "pair-before-click")
        observer.require(report["daemon_before_click"].get("owned_fresh") is True
                         and report["daemon_before_click"].get("installed_sha256") == OLD_DAEMON,
                         "exact healthy old daemon is not present before genuine click")

        def click():
            nonlocal child, click_log
            observer.require(time.monotonic() < deadline - 60, "insufficient transaction time")
            click_log = (output / "real-click.log").open("xb")
            context["transaction"]["update_activated"] = True
            child = subprocess.Popen(ax + ["--output", str(output / "real-click.json"), "--press-update",
                                           "--expected-version", NEW_VERSION], cwd=menu.ROOT, env=context["helper_env"],
                                     stdin=subprocess.DEVNULL, stdout=click_log, stderr=click_log)

        seen_pid = None
        def observed(value):
            nonlocal seen_pid
            if value.latest:
                context["transaction"]["journal"] = value.latest.copy()
                pid = value.latest.get("successor_pid")
                if pid and (seen_pid != pid or (value.ack and "daemon_at_observed_ack" not in report)):
                    rows = privilege_children(pid, context["uid"])
                    for row in rows:
                        if row not in report["privilege_children"]:
                            report["privilege_children"].append(row)
                    context["transaction"]["privilege_children"] = report["privilege_children"]
                    seen_pid = pid
            if value.ack and "daemon_at_observed_ack" not in report:
                report["daemon_at_observed_ack"] = daemon_sample(context, "pair-at-ack")
        try:
            observer_timeout = int(deadline - time.monotonic() - 40)
            observer.require(observer_timeout >= 60, "insufficient time for bounded transaction and cleanup")
            report["observer"] = observer.run(bindings, "success", output,
                min(260, observer_timeout), on_ready=click, on_observation=observed)
        finally:
            if child is not None:
                child.wait(timeout=3)
                report["click_exit_code"] = child.returncode
        click_report = observer.read_document(output / "real-click.json")
        report["real_click"] = click_report
        observer.require(child is not None and child.returncode == 0 and click_report.get("status") == "update_pressed"
                         and len(click_report.get("actions", [])) == 1
                         and click_report["actions"][0].get("kind") == "press_update"
                         and click_report["actions"][0].get("ax_error") == 0, "genuine exact update action not proven")
        observer.require(time.monotonic() < deadline - 5, "no terminal verification budget")
        time.sleep(2.5)
        report["daemon_after_ack"] = daemon_sample(context, "pair-after-ack")
        require_new_daemon(report.get("daemon_at_observed_ack", {}), report["daemon_after_ack"])
        observer.require(menu.sha256(menu.BUNDLED_DAEMON) == NEW_DAEMON, "new bundle daemon hash mismatch")
        report.update(status="passed", success_transaction_qualified=True)
    except Exception as error:
        report.update(status="blocked", success_transaction_qualified=False,
                      error_type=type(error).__name__, reason=str(error)[:1024])
    finally:
        if child is not None and child.poll() is None:
            child.terminate()  # Only our direct AX helper, never the product process.
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)
        if click_log is not None:
            click_log.close()
        if bindings is not None:
            try:
                observer.require(time.monotonic() < deadline - 15, "watchdog cleanup budget exhausted; runner teardown required")
                stop_watchdog(context, bindings)
            except Exception as error:
                report["cleanup_errors"].append("watchdog:" + str(error)[:256])
            try:
                # A privilege child can appear after the first successor/ACK
                # sample. Re-read once after quiescing the owned watchdog.
                pid = context["transaction"].get("journal", {}).get("successor_pid")
                if pid:
                    for row in privilege_children(pid, context["uid"]):
                        if row not in report["privilege_children"]:
                            report["privilege_children"].append(row)
            except Exception as error:
                report["cleanup_errors"].append("privilege_resnapshot:" + str(error)[:256])
        context["transaction"]["privilege_children"] = report["privilege_children"]
        for row in report["privilege_children"]:
            try:
                observer.require(time.monotonic() < deadline - 15, "privilege cleanup budget exhausted; runner teardown required")
                stop_privilege_child(row)
            except Exception as error:
                report["cleanup_errors"].append("privilege_child:" + str(error)[:256])
        if report["cleanup_errors"]:
            context["transaction"]["cleanup_unproven"] = True
            report.update(status="blocked", success_transaction_qualified=False)
        if time.monotonic() > deadline:
            report.update(status="blocked", success_transaction_qualified=False, reason="five minute callback budget exceeded")
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        report["remaining_gates"] = ["forced real public rollback", "pair-wide notification/visibility evidence", "new installed daemon attestation"]
        observer.save_report(output / "success-report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = menu.run(args.output_dir, after_menu=after_menu,
                          successor_identity={"tray_sha256": NEW_TRAY, "daemon_sha256": NEW_DAEMON})
    except Exception as error:
        report = {"status": "blocked", "public_pair_qualified": False, "error_type": type(error).__name__, "reason": str(error)[:1024]}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
