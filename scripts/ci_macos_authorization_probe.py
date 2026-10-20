#!/usr/bin/env python3
"""One harmless authorization capability request on a disposable hosted Mac."""
from __future__ import annotations

import argparse
import ctypes as C
import json
import os
from pathlib import Path
import pwd
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time

import public_update_ui_preflight
from public_update_ax import AX

BRANCH = "refs/heads/codex/public-preview30-update-qualification"
SECURITY_AGENT = "/System/Library/CoreServices/SecurityAgent.app/Contents/MacOS/SecurityAgent"
SCRIPT = 'do shell script "/usr/bin/id -u" with administrator privileges with prompt "Slipstream CI authorization capability"'
OUTPUT_LIMIT = 8192


class Refused(RuntimeError):
    pass


class OverallDeadline(Refused):
    pass


def require(ok, reason):
    if not ok:
        raise Refused(reason)


def hosted_guard():
    expected = {"CI": "true", "GITHUB_ACTIONS": "true", "SLIPSTREAM_DISPOSABLE_CI": "1",
                "RUNNER_OS": "macOS", "GITHUB_REPOSITORY": "aiwaki/slipstream", "GITHUB_REF": BRANCH}
    require(sys.platform == "darwin" and all(os.environ.get(k) == v for k, v in expected.items()),
            "hosted_repository_branch_guard")
    uid = os.getuid()
    require(uid > 0 and os.geteuid() == uid and os.stat("/dev/console").st_uid == uid,
            "nonroot_console_guard")
    require(re.fullmatch(r"[0-9a-f]{40}", os.environ.get("GITHUB_SHA", "")) is not None
            and all(re.fullmatch(r"[1-9][0-9]*", os.environ.get(k, "")) is not None
                    for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")), "run_identity_guard")
    return uid


def child_environment():
    return {"HOME": str(Path.home()), "TMPDIR": os.environ["RUNNER_TEMP"],
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8"}


def reserve_output(path):
    root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    require(path.is_absolute() and path.parent == root and root.stat().st_uid == os.getuid(),
            "private_output_location")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    info = os.fstat(fd)
    if not (stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600):
        os.close(fd)
        raise Refused("private_output_identity")
    return os.fdopen(fd, "w", encoding="utf-8")


def executable_path(pid):
    lib = C.CDLL("/usr/lib/libproc.dylib")
    lib.proc_pidpath.argtypes = [C.c_int, C.c_void_p, C.c_uint32]
    lib.proc_pidpath.restype = C.c_int
    value = C.create_string_buffer(4096)
    return os.fsdecode(value.value) if lib.proc_pidpath(pid, value, len(value)) > 0 else None


def process_metadata(pid, executable, uids, env, *, deadline):
    remaining = deadline - time.monotonic()
    require(remaining > 0, "observation_deadline")
    require(executable_path(pid) == executable, "process_executable_mismatch")
    value = subprocess.run(["/bin/ps", "-p", str(pid), "-o", "uid=,lstart=,stat="],
                           capture_output=True, timeout=min(1, remaining), env=env)
    require(len(value.stdout) <= 512 and value.returncode == 0, "process_metadata_unavailable")
    fields = value.stdout.decode("ascii").split()
    require(len(fields) == 7 and fields[0].isdigit() and int(fields[0]) in uids
            and re.fullmatch(r"[A-Za-z+<>NEs]+", fields[-1]) is not None
            and "Z" not in fields[-1] and executable_path(pid) == executable, "process_identity_mismatch")
    return {"pid": pid, "uid": int(fields[0]), "started": " ".join(fields[1:6]), "executable": executable}


def role_tree(client):
    """Only roles/subroles of this process's windows and their descendants."""
    nodes, visited = [], []

    def visit(value, depth, array_allowed=True):
        if not value:
            return
        kind = client.cf.CFGetTypeID(value)
        if kind == client.cf.CFArrayGetTypeID():
            require(array_allowed, "ax_nested_array")
            count = client.cf.CFArrayGetCount(value)
            require(0 <= count <= 32, "ax_array_bound")
            for index in range(count):
                visit(client.cf.CFArrayGetValueAtIndex(value, index), depth, False)
            return
        require(kind == client.ax.AXUIElementGetTypeID(), "ax_element_type")
        if any(client.cf.CFEqual(value, item) for item in visited):
            return
        require(len(nodes) < 32 and depth <= 4, "ax_tree_bound")
        visited.append(value)
        node = {"depth": depth}
        for attribute, key in (("AXRole", "role"), ("AXSubrole", "subrole")):
            error, raw = client.attribute(value, attribute)
            text = client.string(raw) if error == 0 else ""
            require(not text or re.fullmatch(r"AX[A-Za-z0-9_]{1,62}", text) is not None, "ax_role_shape")
            node[key] = text or None
        nodes.append(node)
        error, children = client.attribute(value, "AXChildren")
        if error == 0:
            visit(children, depth + 1)

    error, windows = client.attribute(client.app, "AXWindows")
    require(error == 0, "ax_windows_unavailable")
    visit(windows, 0)
    return nodes


def security_agents(uid, env, deadline):
    remaining = deadline - time.monotonic()
    require(remaining > 0, "observation_deadline")
    found = subprocess.run(["/usr/bin/pgrep", "-x", "SecurityAgent"],
                           capture_output=True, timeout=min(1, remaining), env=env)
    require(len(found.stdout) <= 128 and found.returncode in (0, 1), "security_agent_query")
    pids = found.stdout.split()
    require(len(pids) <= 4 and all(pid.isdigit() and int(pid) > 0 for pid in pids)
            and (found.returncode == 0 or not pids), "security_agent_pid_bound")
    allowed = {uid}
    try:
        allowed.add(pwd.getpwnam("_securityagent").pw_uid)
    except KeyError:
        pass
    result = []
    for raw in pids:
        require(time.monotonic() < deadline, "observation_deadline")
        pid = int(raw)
        identity = process_metadata(pid, SECURITY_AGENT, allowed, env, deadline=deadline)
        require(time.monotonic() < deadline, "observation_deadline")
        client = AX(pid)
        try:
            client.deadline = min(time.monotonic() + 2, deadline)
            item = {"identity": identity, "roles": role_tree(client)}
            require(process_metadata(pid, SECURITY_AGENT, allowed, env, deadline=deadline) == identity,
                    "security_agent_changed")
            result.append(item)
        finally:
            client.close()
    return result


def classify(returncode, stdout, stderr_size, timed_out):
    require(len(stdout) <= OUTPUT_LIMIT and stderr_size <= OUTPUT_LIMIT, "diagnostic_output_bound")
    if timed_out:
        return "timeout"
    return "passed" if returncode == 0 and stdout == b"0\n" else "refused"


def probe(report, uid, output_parent, *, cancel_work_alarm=None):
    started = time.monotonic()
    deadline = started + 25  # Normal work bound; the outer alarm reserves two seconds for reap.
    report["preflight"] = public_update_ui_preflight.run()
    require(report["preflight"].get("status") == "ready_for_owned_app_AX_probe", "ui_preflight_unavailable")
    require(time.monotonic() < deadline, "preflight_deadline")
    env = child_environment()
    child = None
    with tempfile.TemporaryFile(dir=output_parent) as stdout, tempfile.TemporaryFile(dir=output_parent) as stderr:
        try:
            child = subprocess.Popen(["/usr/bin/osascript", "-e", SCRIPT], env=env,
                                     stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
            report["authorization_requested"] = True
            report["owned_pid"] = child.pid
            # A quick successful request may already have exited; its owned wait
            # status still classifies the result, never another process's status.
            if child.poll() is None:
                try:
                    report["owned_process"] = process_metadata(child.pid, "/usr/bin/osascript", {uid}, env,
                                                               deadline=deadline)
                except OverallDeadline:
                    raise
                except Refused:
                    if child.poll() is None:
                        raise
            next_sample = time.monotonic() + 1
            while child.poll() is None and time.monotonic() < deadline:
                require(max(os.fstat(stdout.fileno()).st_size, os.fstat(stderr.fileno()).st_size)
                        <= OUTPUT_LIMIT, "diagnostic_output_bound")
                now = time.monotonic()
                if now >= next_sample and len(report["observations"]) < 3:
                    sample = {"elapsed_seconds": round(now - started, 3)}
                    try:
                        sample["security_agents"] = security_agents(uid, env, deadline)
                    except OverallDeadline:
                        raise
                    except Exception as error:
                        sample["observation_error"] = (str(error) if isinstance(error, Refused)
                                                       else type(error).__name__)
                    report["observations"].append(sample)
                    next_sample = now + 8
                time.sleep(min(0.2, max(0, deadline - time.monotonic())))
            report["timed_out"] = child.poll() is None
        finally:
            # The 28-second work alarm must not interrupt the final bounded reap.
            if cancel_work_alarm is not None:
                cancel_work_alarm()
            if child is not None:
                if child.poll() is None:
                    child.kill()  # Only this direct, unreaped diagnostic child; never a group/system agent.
                    report["owned_child_killed"] = True
                report["returncode"] = child.wait(timeout=2)
            report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        stdout.seek(0)
        raw = stdout.read(OUTPUT_LIMIT + 1)
        report["stdout_is_root_uid"] = raw == b"0\n"
        report["stderr_bytes"] = os.fstat(stderr.fileno()).st_size
        report["status"] = classify(report["returncode"], raw, report["stderr_bytes"], report["timed_out"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    report = {"schema_version": 1, "status": "blocked", "scope": "authorization_capability_only",
              "public_pair_qualified": False, "product_authorization_qualified": False,
              "authorization_requested": False, "owned_child_killed": False, "observations": []}

    def timeout(_signum, _frame):
        raise OverallDeadline("overall_deadline")

    try:
        with reserve_output(args.output) as stream:
            previous = signal.signal(signal.SIGALRM, timeout)
            signal.alarm(28)
            try:
                uid = hosted_guard()
                report.update(uid=uid, run_id=os.environ["GITHUB_RUN_ID"],
                              run_attempt=os.environ["GITHUB_RUN_ATTEMPT"], source_commit=os.environ["GITHUB_SHA"])
                probe(report, uid, args.output.parent, cancel_work_alarm=lambda: signal.alarm(0))
            except Exception as error:
                report.update(status="blocked", reason=str(error) if isinstance(error, Refused) else type(error).__name__)
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, previous)
            payload = json.dumps(report, sort_keys=True) + "\n"
            require(len(payload.encode()) <= 65536, "report_bound")
            stream.write(payload)
    except Exception as error:
        print(json.dumps({"status": "blocked", "reason": str(error) if isinstance(error, Refused)
                          else type(error).__name__}))
        return 2
    print(json.dumps({"status": report["status"], "product_authorization_qualified": False}))
    return 0 if report["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
