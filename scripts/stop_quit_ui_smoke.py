#!/usr/bin/env python3
"""Actual tray menu/admin Stop-Quit qualification, disposable macOS CI only.

Uses the unmodified packaged application. Geph is intentionally disabled: this
qualifies the native UI, root stop, cleanup failure and reopen path, not an
account-backed Geph tunnel. An inert native child exercises real private owned
process cleanup before any listener. No credentials or full accessibility trees
are logged.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

from geph_owned_lifecycle_smoke import ExternalListenerSentinel

ROOT_LABEL = "dev.slipstream.tproxy"
ROOT_TARGET = "system/" + ROOT_LABEL
ROOT_PLIST = Path("/Library/LaunchDaemons/dev.slipstream.tproxy.plist")
INSTALL_DIR = Path("/usr/local/slipstream")
STATUS = Path("/var/run/slipstream.status")
LOCK = "/var/db/dev.slipstream-update/installer.lock"
STOP_LABELS = ["Stop Slipstream and Quit", "Остановить Slipstream и выйти"]
STOP_PROMPT = "Stopping Slipstream background service"
START_PROMPT = "Starting Slipstream background service"
STOP_RESIDUE = tuple(Path(path) for path in (
    "/var/run/slipstream.status", "/var/run/slipstream.status.tmp",
    "/var/run/slipstream-pf.token", "/var/run/slipstream-pf-lo0-skip.json",
    "/var/run/slipstream-semantic.sock", "/var/run/slipstream-browser-probe.sock",
    "/var/run/slipstream-browser-probe-workers",
))


class QualificationError(RuntimeError):
    pass


def run(args, *, input=None, check=True, timeout=30, sensitive=False):
    try:
        result = subprocess.run(args, input=input, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        if sensitive:
            raise QualificationError(f"{Path(args[0]).name} timed out during private fixture operation") from None
        raise error
    if check and result.returncode:
        # Never echo command arguments: fixture authorization uses a random secret.
        detail = "" if sensitive else result.stderr.decode(errors="replace")[-500:]
        raise QualificationError(f"{Path(args[0]).name} failed ({result.returncode}): {detail}")
    return result


def require_disposable():
    expected = {"CI": "true", "GITHUB_ACTIONS": "true", "SLIPSTREAM_DISPOSABLE_CI": "1"}
    if any(os.environ.get(k) != v for k, v in expected.items()):
        raise QualificationError("native Stop-Quit is restricted to disposable GitHub Actions")
    if sys.platform != "darwin" or os.geteuid() == 0:
        raise QualificationError("native Stop-Quit must run as the macOS login user")
    console = run(["/usr/bin/stat", "-f", "%u", "/dev/console"]).stdout.strip()
    if console != str(os.getuid()).encode():
        raise QualificationError("runner is not the GUI console user")


def wait(predicate, message, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if result := predicate():
            return result
        time.sleep(.2)
    raise QualificationError(message)


def apple_string(value):
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def applescript(script, *, sensitive=False, check=True, timeout=15):
    return run(["/usr/bin/osascript", "-"], input=script.encode(),
               sensitive=sensitive, check=check, timeout=timeout).stdout.decode().strip()


# Query the specific app's menu bars instead of assuming menu bar 2. All menu
# interaction belongs to the verified process; no global mouse coordinates.
def menu_action(pid, labels=None):
    label_list = "{" + ",".join(map(apple_string, labels or [])) + "}"
    script = f'''
    tell application "System Events"
      set p to first application process whose unix id is {int(pid)}
      tell p
        set frontmost to true
        repeat with mb in menu bars
          repeat with itemRef in menu bar items of mb
            try
              click itemRef
              delay 0.2
              if exists menu 1 of itemRef then
                set labelsFound to name of every menu item of menu 1 of itemRef
                repeat with wanted in {label_list}
                  if labelsFound contains (contents of wanted) then
                    if not (enabled of menu item (contents of wanted) of menu 1 of itemRef) then return "disabled:" & (contents of wanted)
                    click menu item (contents of wanted) of menu 1 of itemRef
                    return "clicked:" & (contents of wanted)
                  end if
                end repeat
                if {str(not labels).lower()} then
                  if labelsFound contains "Stop Slipstream and Quit" or labelsFound contains "Остановить Slipstream и выйти" then
                    key code 53
                    return labelsFound
                  end if
                end if
              end if
            end try
            key code 53
          end repeat
        end repeat
      end tell
    end tell
    error "Slipstream status menu/action unavailable"
    '''
    response = applescript(script)
    if response.startswith("disabled:"):
        raise QualificationError("native Stop menu item was disabled before click")
    return response


AUTH_WINDOW_ELEMENTS = '''
    set elements to {w} & (entire contents of w)
    set elementLimit to count of elements
    if elementLimit > 256 then set elementLimit to 256
'''
AUTH_PROMPT_COLLECTION = '''
    if r is "AXStaticText" or r is "AXWindow" then
      try
        set valueText to valueText & " " & (value of e as text)
      end try
      try
        set nameText to nameText & " " & (name of e as text)
      end try
      try
        set descriptionText to descriptionText & " " & (description of e as text)
      end try
    end if
'''


def auth_action(prompt, *, cancel=False, username="", password=""):
    # A native Cancel is proven only after finding this operation's prompt.
    # Read static text only, never credentials or secure field values.
    action = '''
        if (count of cancelButtons) is not 1 then error "authorization Cancel unavailable"
        click item 1 of cancelButtons
        return "cancelled"
    ''' if cancel else f'''
        if (count of userFields) is not 1 or (count of secretFields) is not 1 then
          return "unexpected authorization form: user fields=" & (count of userFields) & ", secure fields=" & (count of secretFields) & ", cancel buttons=" & (count of cancelButtons) & ", confirmation buttons=" & (count of confirmButtons)
        end if
        set value of item 1 of userFields to {apple_string(username)}
        set value of item 1 of secretFields to {apple_string(password)}
        if (count of confirmButtons) is not 1 then error "authorization confirmation unavailable"
        click item 1 of confirmButtons
        return "confirmed"
    '''
    script = f'''
    tell application "System Events"
      if not (exists application process "SecurityAgent") then return "absent"
      set agent to application process "SecurityAgent"
      set windowCount to count of windows of agent
      if windowCount is 0 then return "absent"
      if windowCount is not 1 then error "authorization window is ambiguous"
      set frontmost of agent to true
      set w to window 1 of agent
          {AUTH_WINDOW_ELEMENTS}
          if (count of elements) > 256 then error "authorization element inventory is too large"
          set readErrors to 0
          set valueText to ""
          set nameText to ""
          set descriptionText to ""
          set userFields to {{}}
          set secretFields to {{}}
          set cancelButtons to {{}}
          set confirmButtons to {{}}
          repeat with elementIndex from 1 to elementLimit
            set e to item elementIndex of elements
            try
              set r to role of e
              {AUTH_PROMPT_COLLECTION}
              if r is "AXTextField" or r is "AXComboBox" then
                if subrole of e is "AXSecureTextField" then
                  set end of secretFields to e
                else
                  set end of userFields to e
                end if
              end if
              if r is "AXButton" then
                set buttonName to name of e
                if buttonName is "Cancel" or buttonName is "Отмена" then set end of cancelButtons to e
                if buttonName is "OK" or buttonName is "Allow" or buttonName is "ОК" then set end of confirmButtons to e
              end if
            on error
              set readErrors to readErrors + 1
            end try
          end repeat
          if readErrors is not 0 then error "authorization elements unavailable"
          if (valueText contains {apple_string(prompt)}) or (nameText contains {apple_string(prompt)}) then
            {action}
          end if
    end tell
    return "absent"
    '''
    response = applescript(script, sensitive=True)
    if response.startswith("unexpected authorization form:"):
        # Counts only: preserve useful AX diagnostics without reading field values.
        raise QualificationError(response)
    return response


AUTH_PROCESS_NAMES = ("SecurityAgent", "SecurityAgentHelper-arm64", "SecurityAgentHelper-x86_64")


def auth_snapshot(prompt):
    """Diagnostic-only: never click helper UI or return any accessible text."""
    names = "{" + ",".join(map(apple_string, AUTH_PROCESS_NAMES)) + "}"
    script = f'''
    set reportText to ""
    tell application "System Events"
      repeat with expectedName in {names}
        set processName to contents of expectedName
        try
        if exists application process processName then
          set agent to application process processName
          set windowCount to count of windows of agent
          set reportText to reportText & "process=" & processName & "|present=1|windows=" & windowCount & linefeed
          set windowLimit to windowCount
          if windowLimit > 3 then set windowLimit to 3
          repeat with windowIndex from 1 to windowLimit
            set w to window windowIndex of agent
            {AUTH_WINDOW_ELEMENTS}
            set staticCount to 0
            set textCount to 0
            set comboCount to 0
            set secureCount to 0
            set buttonCount to 0
            set cancelCount to 0
            set confirmCount to 0
            set readErrors to 0
            set valueText to ""
            set nameText to ""
            set descriptionText to ""
            repeat with elementIndex from 1 to elementLimit
              set e to item elementIndex of elements
              try
                set r to role of e
                if r is "AXStaticText" then set staticCount to staticCount + 1
                if r is "AXTextField" then set textCount to textCount + 1
                if r is "AXComboBox" then set comboCount to comboCount + 1
                if r is "AXTextField" or r is "AXComboBox" then
                  if subrole of e is "AXSecureTextField" then set secureCount to secureCount + 1
                end if
                if r is "AXButton" then
                  set buttonCount to buttonCount + 1
                  set buttonName to name of e
                  if buttonName is "Cancel" or buttonName is "Отмена" then set cancelCount to cancelCount + 1
                  if buttonName is "OK" or buttonName is "Allow" or buttonName is "ОК" then set confirmCount to confirmCount + 1
                end if
                {AUTH_PROMPT_COLLECTION}
              on error
                set readErrors to readErrors + 1
              end try
            end repeat
            set pv to (valueText contains {apple_string(prompt)}) as integer
            set pn to (nameText contains {apple_string(prompt)}) as integer
            set pd to (descriptionText contains {apple_string(prompt)}) as integer
            set slipstreamText to ((valueText & nameText & descriptionText) contains "Slipstream") as integer
            set reportText to reportText & "process=" & processName & "|window=" & windowIndex & "|elements=" & (count of elements) & "|static=" & staticCount & "|text=" & textCount & "|combo=" & comboCount & "|secure=" & secureCount & "|buttons=" & buttonCount & "|cancel=" & cancelCount & "|confirm=" & confirmCount & "|prompt_value=" & pv & "|prompt_name=" & pn & "|prompt_description=" & pd & "|slipstream=" & slipstreamText & "|read_errors=" & readErrors & linefeed
          end repeat
        else
          set reportText to reportText & "process=" & processName & "|present=0|windows=0" & linefeed
        end if
        on error
          set reportText to reportText & "process=" & processName & "|query_error=1" & linefeed
        end try
      end repeat
    end tell
    return reportText
    '''
    raw = applescript(script, sensitive=True, timeout=10)
    rows = []
    allowed = {"present", "windows", "window", "elements", "static", "text", "combo", "secure", "buttons", "cancel", "confirm",
               "prompt_value", "prompt_name", "prompt_description", "slipstream", "read_errors", "query_error"}
    for line in raw.splitlines()[:15]:
        row = {}
        for item in line.split("|"):
            key, value = item.split("=", 1)
            if key == "process" and value in AUTH_PROCESS_NAMES:
                row[key] = value
            elif key in allowed and value.isdecimal():
                row[key] = int(value)
            else:
                raise QualificationError("unexpected authorization diagnostic shape")
        rows.append(row)
    return rows


def redacted_text(raw, secrets_to_hide=()):
    text = raw.decode(errors="replace") if isinstance(raw, bytes) else str(raw)
    for secret in secrets_to_hide:
        if secret:
            text = text.replace(secret, "[redacted]")
    lines = []
    for line in text.splitlines():
        if re.search(r"(?i)(?:password|secret|token|credentials?|authorization)\s*[:=]|://[^ /:]+:[^ /@]+@|BEGIN .*PRIVATE KEY", line):
            line = "[redacted credential-bearing line]"
        lines.append(line)
    return "\n".join(lines)


def redacted_error_excerpt(raw, secrets_to_hide=()):
    lines = [line[:400] for line in redacted_text(raw, secrets_to_hide).splitlines()
             if re.search(r"(?i)error|fail|cancel|authoriz|service lifecycle|service action|redacted", line)]
    return "\n".join(lines[-8:])[-2000:]


def owned_operation_snapshot(pid, prompt):
    census = run(["/bin/ps", "-axww", "-o", "uid=,pid=,ppid=,command="], check=False)
    if census.returncode or census.stderr.strip() or not census.stdout.strip():
        return {"observation": "unknown"}
    children = scripts = operations = 0
    for line in census.stdout.decode().splitlines():
        fields = line.split(None, 3)
        if len(fields) != 4:
            return {"observation": "unknown"}
        if fields[0] == str(os.getuid()) and fields[2] == str(pid):
            children += 1
            if fields[3].startswith("/usr/bin/osascript "):
                scripts += 1
                operations += int(prompt in fields[3] and "do shell script" in fields[3])
    return {"observation": "known", "children": children, "osascript_children": scripts, "operation_prompt_children": operations}


def failure_snapshot(tray, intent, prompt, secrets_to_hide):
    snapshot = {"prompt": prompt}
    def collect(key, operation):
        try:
            snapshot[key] = operation()
        except Exception as error:
            snapshot[key] = {"observation": "unavailable", "reason": redacted_text(str(error), secrets_to_hide)[:400]}
    collect("intent", lambda: {b"v1 stopping\n": "stopping", b"v1 stopped\n": "stopped"}.get(intent.read_bytes(), "unrecognized") if intent.exists() else "absent")
    if tray:
        collect("tray_alive_owned", tray.alive)
        collect("tray_returncode", lambda: tray.process.poll() if tray.process else None)
        if tray.process:
            collect("owned_operation", lambda: owned_operation_snapshot(tray.process.pid, prompt))
        def log_excerpt():
            size = os.fstat(tray.log.fileno()).st_size
            offset = max(0, size - 16384)
            raw = os.pread(tray.log.fileno(), 16384, offset)
            if offset:
                raw = raw.partition(b"\n")[2]  # never expose a partial first credential
            return redacted_error_excerpt(raw, secrets_to_hide)
        collect("tray_error_excerpt", log_excerpt)
    collect("authorization_ui", lambda: auth_snapshot(prompt))
    return snapshot


def status_observation():
    try:
        status = json.loads(STATUS.read_bytes())
        daemon = status["daemon"]
        pid = daemon["pid"]
        sequence = daemon["heartbeat_seq"]
        if (status.get("schema_version") != 2 or not isinstance(pid, int) or pid <= 1
                or not isinstance(sequence, int) or sequence <= 0
                or daemon.get("state") not in {"active", "dormant"}
                or daemon.get("phase") != "active"
                or time.time() - float(daemon["updated_at"]) > 15):
            return None
        return pid, sequence
    except (OSError, ValueError, KeyError, TypeError):
        return None


def wait_progress(previous=None, timeout=60):
    baseline = previous
    def progressing():
        nonlocal baseline
        observed = status_observation()
        if not observed:
            baseline = None
            return False
        old, baseline = baseline, observed
        if old and old[0] == observed[0] and observed[1] > old[1]:
            # A status file alone cannot witness the root service.
            result = run(["/bin/launchctl", "print", ROOT_TARGET], check=False)
            pids = re.findall(rb"^\s*pid\s*=\s*([0-9]+)\s*$", result.stdout, re.MULTILINE)
            return observed if result.returncode == 0 and len(pids) == 1 and int(pids[0]) == observed[0] else False
        return False
    return wait(progressing, "fresh owned root heartbeat did not advance", timeout)


def continued_root(previous):
    observed = wait_progress(previous)
    if observed[0] != previous[0]:
        raise QualificationError("failed/cancelled stop unexpectedly restarted the root daemon")
    return observed


def routing_residue_clear():
    if any(path.exists() or path.is_symlink() for path in STOP_RESIDUE):
        return False
    for selector in ("-sn", "-sr"):
        result = run(["/usr/bin/sudo", "-n", "/sbin/pfctl", "-a", "com.apple/slipstream", selector], check=False)
        known_warnings = {b"No ALTQ support in kernel", b"ALTQ related functions disabled"}
        if (result.returncode or result.stdout.strip()
                or any(line.strip() not in known_warnings for line in result.stderr.splitlines() if line.strip())):
            return False
    return True


def root_stopped():
    result = run(["/bin/launchctl", "print", ROOT_TARGET], check=False)
    missing = f'Could not find service "{ROOT_LABEL}" in domain for system'.encode()
    if result.returncode == 0 or missing not in result.stderr:
        return False
    disabled = run(["/bin/launchctl", "print-disabled", "system"]).stdout
    pattern = rb'"' + ROOT_LABEL.encode() + rb'"\s*=>\s*(?:true|disabled)\s*,?\s*$'
    if not any(re.search(pattern, line) for line in disabled.splitlines()):
        return False
    listener = run(["/usr/bin/sudo", "-n", "/usr/sbin/lsof", "-nP", "-iTCP:1080", "-sTCP:LISTEN", "-t"], check=False)
    if listener.returncode != 1 or listener.stdout.strip() or listener.stderr.strip():
        return False
    census = run(["/bin/ps", "-axww", "-o", "uid=,pid=,command="], check=False)
    if census.returncode or not census.stdout.strip() or census.stderr.strip():
        return False
    for line in census.stdout.decode().splitlines():
        fields = line.split(None, 2)
        if len(fields) != 3:
            return False
        if fields[0] == "0" and (fields[2] == str(INSTALL_DIR / "slipstreamd") or fields[2].startswith(str(INSTALL_DIR / "slipstreamd") + " ")):
            return False
        if "--pending-navigation-browser-probe" in fields[2].split():
            return False
    return routing_residue_clear()


class NativeHostSnapshot:
    def __init__(self, home, executable):
        self.path = home / "Library/Application Support/Google/Chrome/NativeMessagingHosts/dev.slipstream.semantic.json"
        self.executable = executable
        self.before = None
        if self.path.exists() or self.path.is_symlink():
            metadata = self.path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_size > 65536:
                raise QualificationError("unsafe existing native-host manifest")
            self.before = (self.path.read_bytes(), stat.S_IMODE(metadata.st_mode))

    def restore(self):
        if self.path.exists() or self.path.is_symlink():
            metadata = self.path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_size > 65536:
                raise QualificationError("native-host manifest ownership changed")
            current = self.path.read_bytes()
            if self.before and current == self.before[0]:
                self.path.chmod(self.before[1])
                return
            manifest = json.loads(current)
            if manifest.get("name") != "dev.slipstream.semantic" or manifest.get("path") != str(self.executable):
                raise QualificationError("native-host manifest is not this fixture's registration")
            self.path.unlink()
        if self.before:
            self.path.write_bytes(self.before[0])
            self.path.chmod(self.before[1])


class OwnedPrelistenerFixture:
    """Inert native child at the real ownership boundary; never opens a socket."""
    def __init__(self, config_dir):
        self.directory = config_dir
        self.executable = config_dir / "runtime/geph5-client"
        self.config = config_dir / "geph-active.yaml"
        self.record = config_dir / "geph-owned.json"
        self.process = None

    def start(self):
        require_disposable()
        for directory in (self.directory, self.executable.parent):
            metadata = directory.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
                raise QualificationError("inert owned fixture requires owner-private directories")
        if any(path.exists() or path.is_symlink() for path in (self.executable, self.config, self.record)):
            raise QualificationError("refusing to replace existing owned fixture paths")
        source = b'''#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 3 || strcmp(argv[1], "--config") || access(argv[2], R_OK)) return 64;
    puts("ready"); fflush(stdout);
    for (;;) pause();
}
'''
        run(["/usr/bin/cc", "-x", "c", "-", "-o", str(self.executable)], input=source, timeout=60)
        self.executable.chmod(0o700)
        with self.config.open("xb") as handle:
            handle.write(b"# inert Stop-Quit fixture: no credentials or network\n")
        self.config.chmod(0o600)
        self.process = subprocess.Popen([str(self.executable), "--config", str(self.config)],
                                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            if not selector.select(10) or self.process.stdout.readline().strip() != b"ready":
                raise QualificationError("inert owned process did not become ready")
        if not self.identity():
            raise QualificationError("inert owned process identity unconfirmed")
        listener = run(["/usr/sbin/lsof", "-nP", "-a", "-p", str(self.process.pid), "-i", "-t"], check=False)
        if listener.returncode != 1 or listener.stdout.strip() or listener.stderr.strip():
            raise QualificationError("inert owned process unexpectedly has network sockets")
        record = {"pid": self.process.pid, "uid": os.getuid(), "executable": str(self.executable),
                  "config": str(self.config), "launchd_label": "dev.slipstream.geph"}
        with self.record.open("xb") as handle:
            handle.write((json.dumps(record) + "\n").encode())
        self.record.chmod(0o600)

    def identity(self):
        if not self.process or self.process.poll() is not None:
            return False
        observed = run(["/bin/ps", "-ww", "-p", str(self.process.pid), "-o", "uid=,command="], check=False)
        parts = observed.stdout.decode().strip().split(None, 1)
        return (observed.returncode == 0 and not observed.stderr.strip() and len(parts) == 2
                and parts[0] == str(os.getuid()) and parts[1] == f"{self.executable} --config {self.config}")

    def assert_stopped(self):
        # Waiting reaps this direct child; it does not send a signal.
        if self.process.wait(timeout=10) not in (-signal.SIGTERM, -signal.SIGKILL):
            raise QualificationError("owned fixture did not exit through the real stop signal")
        observed = run(["/bin/ps", "-p", str(self.process.pid), "-o", "uid=,command="], check=False)
        if (observed.returncode != 1 or observed.stdout.strip() or observed.stderr.strip()
                or self.record.exists() or self.record.is_symlink()):
            raise QualificationError("owned fixture absence was not confirmed after Quit")

    def close(self):
        if not self.process:
            return
        if self.process.poll() is None:
            if not self.identity():
                raise QualificationError("refusing cleanup of unowned inert fixture")
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                if not self.identity():
                    raise QualificationError("inert fixture identity changed before cleanup")
                self.process.kill()
                self.process.wait(timeout=5)
        self.process.stdout.close()


def preserved(settings, expected, retained):
    if settings.read_bytes() != expected or retained.read_bytes() != b"retained runtime\n":
        raise QualificationError("Stop/reopen changed settings or retained runtime")


class Tray:
    def __init__(self, executable, log):
        self.executable, self.log, self.process = executable, log, None

    def start(self, *args):
        if self.process and self.process.poll() is None:
            raise QualificationError("tray is already running")
        self.process = subprocess.Popen([str(self.executable), *args], stdin=subprocess.DEVNULL,
                                        stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        wait(lambda: self.process.poll() is None and self.identity(), "tray identity unavailable", 20)
        return self.process.pid

    def identity(self):
        if self.process is None:
            return False
        result = run(["/bin/ps", "-p", str(self.process.pid), "-o", "uid=,command="], check=False)
        parts = result.stdout.decode().strip().split(None, 1)
        return len(parts) == 2 and parts[0] == str(os.getuid()) and (
            parts[1] == str(self.executable) or parts[1].startswith(str(self.executable) + " "))

    def checkpoint(self):
        return os.fstat(self.log.fileno()).st_size

    def error_since(self, offset, text):
        return text.encode() in os.pread(self.log.fileno(), 65536, offset)

    def alive(self):
        return self.process is not None and self.process.poll() is None and self.identity()

    def close(self):
        if self.process and self.process.poll() is None:
            if not self.identity():
                raise QualificationError("refusing cleanup of unowned tray")
            if os.getpgid(self.process.pid) != self.process.pid:
                raise QualificationError("tray cleanup process group changed")
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                if not self.identity():
                    raise QualificationError("tray identity changed before cleanup")
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=10)


@contextmanager
def installer_lock():
    code = '''import fcntl,os,stat,sys
fd=os.open(sys.argv[1],os.O_RDWR|os.O_NOFOLLOW)
m=os.fstat(fd)
assert stat.S_ISREG(m.st_mode) and m.st_uid==0 and stat.S_IMODE(m.st_mode)==0o600
fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
print("locked",flush=True)
sys.stdin.buffer.read()
os.close(fd)
'''
    child = subprocess.Popen(["/usr/bin/sudo", "-n", sys.executable, "-c", code, LOCK],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            if not selector.select(15):
                raise QualificationError("installer lock fixture did not start")
        if child.stdout.readline().strip() != b"locked":
            raise QualificationError("could not establish real installer lock contention")
        yield
    finally:
        child.stdin.close()
        child.wait(timeout=10)


def account_names():
    result = run(["/usr/bin/dscl", ".", "-list", "/Users"], sensitive=True)
    names = result.stdout.decode().splitlines()
    if "root" not in names or any(not name or any(ch.isspace() for ch in name) for name in names):
        raise QualificationError("local account inventory is incomplete")
    return set(names)


@contextmanager
def fixture_admin():
    require_disposable()
    username = "slipstop" + secrets.token_hex(4)
    password = secrets.token_urlsafe(32)
    user_home = Path("/Users") / username
    if username in account_names() or user_home.exists() or user_home.is_symlink():
        raise QualificationError("temporary admin identity is not fresh")
    attempted = False
    try:
        # An unknown command result may already have created the account.
        attempted = True
        run(["/usr/bin/sudo", "-n", "/usr/sbin/sysadminctl", "-addUser", username,
             "-password", password, "-admin"], sensitive=True, timeout=60)
        membership = run(["/usr/sbin/dseditgroup", "-o", "checkmember", "-m", username, "admin"], sensitive=True)
        if username not in account_names() or not membership.stdout.startswith(b"yes "):
            raise QualificationError("temporary administrator creation was not confirmed")
        yield username, password
    finally:
        if attempted:
            if username in account_names():
                run(["/usr/bin/sudo", "-n", "/usr/sbin/sysadminctl", "-deleteUser", username],
                    sensitive=True, timeout=60)
            if username in account_names() or user_home.exists() or user_home.is_symlink():
                raise QualificationError("temporary administrator cleanup was not confirmed")


def run_qualification(bundle, report):
    require_disposable()
    bundle = bundle.resolve(strict=True)
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    if runner_temp not in bundle.parents or bundle.suffix != ".app":
        raise QualificationError("expected the immutable candidate unpacked under RUNNER_TEMP")
    executable = bundle / "Contents/MacOS/slipstream"
    daemon = bundle / "Contents/Resources/slipstreamd/slipstreamd"
    if not executable.is_file() or not daemon.is_file():
        raise QualificationError("packaged executables unavailable")
    if INSTALL_DIR.exists() or ROOT_PLIST.exists():
        raise QualificationError("prior root fixture was not cleaned up")
    if applescript('tell application "System Events" to return UI elements enabled') != "true":
        raise QualificationError("runner Accessibility UI automation is unavailable")
    name = plistlib.loads((bundle / "Contents/Info.plist").read_bytes())["CFBundleName"]
    home = Path.home()
    native_host = NativeHostSnapshot(home, executable)
    config = home / "Library/Application Support/dev.slipstream.tray"
    login = home / "Library/LaunchAgents" / f"{name}.plist"
    if login.exists() or login.is_symlink():
        raise QualificationError("unexpected pre-existing login registration")
    geph_plist = home / "Library/LaunchAgents/dev.slipstream.geph.plist"
    if geph_plist.exists():
        raise QualificationError("unexpected pre-existing owned Geph job")
    cases, cleanup_errors = [], []
    backup = runner_temp / ("stop-ui-user-state-" + secrets.token_hex(6))
    if config.is_symlink() or (config.exists() and config.stat().st_uid != os.getuid()):
        raise QualificationError("refusing unsafe existing user state")
    settings = config / "geph.json"
    preferences = b'{"enabled":"0","exit":"auto"}\n'
    retained = config / "runtime/stop-ui-retained"
    intent = config / "service-lifecycle-v1"
    ownership = config / "geph-owned.json"
    log = tray = sentinel = owned_fixture = None
    redactions = []
    active_prompt = STOP_PROMPT
    config_created = login_created = root_attempted = False
    result = {"result": "fail", "scope": "native menu/admin/root and inert owned-process stop, reopen; Geph tunnel intentionally disabled",
              "commit": os.environ.get("GITHUB_SHA"), "app_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(), "phase": "preparing", "cases": cases}
    def click_stop(pid):
        result["last_menu_action"] = menu_action(pid, STOP_LABELS)
        result["last_menu_item_enabled"] = True
    def observe_auth(prompt, **kwargs):
        response = auth_action(prompt, **kwargs)
        category = response if response in {"absent", "cancelled", "confirmed"} else "unrecognized"
        counts = result.setdefault("authorization_results", {})
        counts[category] = counts.get(category, 0) + 1
        return response
    try:
        if config.exists():
            config.rename(backup)
        config.mkdir(mode=0o700, parents=True)
        config_created = True
        settings.write_bytes(preferences)
        settings.chmod(0o600)
        (config / "runtime").mkdir(mode=0o700)
        retained.write_bytes(b"retained runtime\n")
        login.parent.mkdir(exist_ok=True)
        with login.open("xb") as handle:
            login_created = True
            handle.write(plistlib.dumps({"Label": name, "ProgramArguments": [str(executable)], "RunAtLoad": True}))
        login.chmod(0o600)
        log = tempfile.TemporaryFile()
        tray = Tray(executable, log)
        sentinel = ExternalListenerSentinel()
        with fixture_admin() as (username, password):
            redactions.extend((username, password))
            root_attempted = True
            run(["/usr/bin/sudo", "-n", str(daemon), "--install"], timeout=180)
            initial = wait_progress()
            pid = tray.start()
            def visible_menu():
                try:
                    return menu_action(pid)
                except QualificationError:
                    return False
            wait(visible_menu, "native status menu unavailable", 20)
            result["phase"] = "native_cancel"
            checkpoint = tray.checkpoint()
            click_stop(pid)
            wait(lambda: observe_auth(STOP_PROMPT, cancel=True) == "cancelled", "native Cancel was not observed", 30)
            wait(lambda: intent.exists() and intent.read_bytes() == b"v1 stopping\n", "cancel lost durable stop intent")
            wait(lambda: tray.error_since(checkpoint, "administrator action failed") and "administrator action failed" in menu_action(pid), "cancel phase error not visible")
            if not tray.alive():
                raise QualificationError("tray exited after native cancellation")
            continued_root(initial)
            sentinel.check()
            cases.append({"case": "native_cancel", "result": "pass", "root_continued": True, "ui_error_visible": True})

            def authorize_until(done, prompt=STOP_PROMPT, timeout=90, require_confirmation=False):
                deadline = time.monotonic() + timeout
                confirmed = False
                while time.monotonic() < deadline:
                    response = observe_auth(prompt, username=username, password=password)
                    confirmed |= response == "confirmed"
                    if (confirmed or not require_confirmation) and done():
                        return confirmed
                    time.sleep(.2)
                raise QualificationError("authorized native operation did not reach its expected state")

            with installer_lock():
                result["phase"] = "root_lock_failure"
                before = wait_progress()
                checkpoint = tray.checkpoint()
                click_stop(pid)
                confirmed = authorize_until(lambda: tray.error_since(checkpoint, "administrator action failed") and "administrator action failed" in menu_action(pid), require_confirmation=True)
                # The old error may still be rendered for one status tick. Require
                # the fresh authorization result and a settling poll before proof.
                if not confirmed:
                    raise QualificationError("root failure did not exercise native confirmation")
                time.sleep(2.5)
                if not tray.alive() or intent.read_bytes() != b"v1 stopping\n":
                    raise QualificationError("root failure lost UI or pending intent")
                continued_root(before)
            cases.append({"case": "root_lock_failure", "result": "pass", "native_confirmation": True})

            ownership.write_bytes(b"unreadable cleanup fixture\n")
            ownership.chmod(0)
            result["phase"] = "partial_geph_cleanup_failure"
            checkpoint = tray.checkpoint()
            click_stop(pid)
            authorize_until(lambda: root_stopped() and tray.error_since(checkpoint, "Geph stop unconfirmed") and "Geph stop unconfirmed" in menu_action(pid))
            if not tray.alive() or intent.read_bytes() != b"v1 stopping\n":
                raise QualificationError("partial stop exited or claimed completion")
            preserved(settings, preferences, retained)
            sentinel.check()
            cases.append({"case": "partial_geph_cleanup_failure", "result": "pass", "root_stopped": True, "ui_retained": True})
            ownership.chmod(0o600)
            ownership.unlink()

            owned_fixture = OwnedPrelistenerFixture(config)
            owned_fixture.start()
            result["phase"] = "menu_stop_and_quit"
            if not owned_fixture.identity():
                raise QualificationError("owned pre-listener process disappeared before actual Quit")
            click_stop(pid)
            authorize_until(lambda: tray.process.poll() is not None)
            if tray.process.returncode != 0 or not root_stopped() or intent.read_bytes() != b"v1 stopped\n":
                raise QualificationError("successful menu Quit was not fully confirmed")
            owned_fixture.assert_stopped()
            run(["/usr/bin/sudo", "-n", "/bin/test", "-f", str(INSTALL_DIR / "slipstreamd")])
            args = plistlib.loads(login.read_bytes())["ProgramArguments"]
            if args != [str(executable), "--autostart"]:
                raise QualificationError("legacy enabled login registration was not refreshed")
            preserved(settings, preferences, retained)
            sentinel.check()
            cases.append({"case": "menu_stop_and_quit", "result": "pass", "retained_runtime": True, "legacy_login_refreshed": True})
            cases.append({"case": "owned_prelistener_process_cleanup", "result": "pass", "native_process_absent": True,
                          "external_sentinel_preserved": True, "fixture_opens_network_sockets": False, "geph_account_used": False})

            result["phase"] = "login_keeps_stopped"
            tray.start("--autostart")
            time.sleep(6)
            if not tray.alive() or not root_stopped() or intent.read_bytes() != b"v1 stopped\n":
                raise QualificationError("login launch resumed stopped services")
            tray.close()
            cases.append({"case": "login_keeps_stopped", "result": "pass"})

            result["phase"] = "ordinary_reopen"
            active_prompt = START_PROMPT
            tray.start()
            authorize_until(lambda: not intent.exists(), prompt=START_PROMPT, timeout=150)
            resumed = wait_progress()
            if not tray.alive() or resumed[0] == initial[0]:
                raise QualificationError("ordinary reopen did not establish a new owned daemon")
            preserved(settings, preferences, retained)
            sentinel.check()
            cases.append({"case": "ordinary_reopen", "result": "pass", "fresh_daemon": True, "preferences_preserved": True})
            result["result"] = "pass"
            result["phase"] = "complete"
    except BaseException as error:
        result["result"] = "fail"
        result["failure"] = redacted_text(str(error), redactions)[:1000]
        result["diagnostics"] = failure_snapshot(tray, intent, active_prompt, redactions)
        raise
    finally:
        def restore_user_state():
            if config_created:
                if ownership.exists():
                    ownership.chmod(0o600)
                shutil.rmtree(config)
            if backup.exists():
                backup.rename(config)
        cleanups = [
            ("tray", lambda: tray.close() if tray else None),
            ("owned inert process", lambda: owned_fixture.close() if owned_fixture else None),
            ("root", lambda: run(["/usr/bin/sudo", "-n", str(daemon), "--uninstall"], timeout=180) if root_attempted else None),
            ("sentinel", lambda: sentinel.close() if sentinel else None),
            ("user state", restore_user_state),
            ("login fixture", lambda: login.unlink(missing_ok=True) if login_created else None),
            ("native-host manifest", native_host.restore),
            ("log", lambda: log.close() if log else None),
        ]
        for label, cleanup in cleanups:
            try:
                cleanup()
            except BaseException as error:
                cleanup_errors.append(f"{label}: {error}")
        result["cleanup_errors"] = cleanup_errors
        if cleanup_errors:
            result["result"] = "fail"
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps(result, indent=2) + "\n")
    if cleanup_errors:
        raise QualificationError("native fixture cleanup failed; see report")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-bundle", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        run_qualification(args.app_bundle, args.report)
    except (QualificationError, OSError, subprocess.SubprocessError) as error:
        if not args.report.exists():
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps({"result": "fail", "phase": "preflight", "failure": str(error), "cases": []}, indent=2) + "\n")
        print(f"Stop-Quit qualification failed: {error}", file=sys.stderr)
        return 1
    print(f"Native Stop-Quit qualification passed: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
