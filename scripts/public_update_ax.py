#!/usr/bin/env python3
"""Bounded AX inspection/actions on one hash-bound, owned Slipstream process."""
from __future__ import annotations

import argparse
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time


class Blocked(RuntimeError):
    pass


def update_titles(version: str | None) -> set[str]:
    titles = {"Check for Updates…", "Проверить обновления…", "Updating…", "Обновление…"}
    if version:
        titles.update({f"Install Slipstream {version}…", f"Установить Slipstream {version}…"})
    return titles


def allowed_title(title: str) -> bool:
    return (title in update_titles(None) | {"", "Slipstream"}
            or re.fullmatch(r"(?:Install|Установить) Slipstream 0\.1\.9-preview\.\d+…", title) is not None)


def unique(items: list, description: str):
    if len(items) != 1:
        raise Blocked(f"{description}: expected one element, got {len(items)}")
    return items[0]


def identity(pid: int, uid: int, executable: Path, expected_hash: str) -> dict:
    lib = C.CDLL("/usr/lib/libproc.dylib")
    lib.proc_pidpath.argtypes = [C.c_int, C.c_void_p, C.c_uint32]
    lib.proc_pidpath.restype = C.c_int
    buffer = C.create_string_buffer(4096)
    if lib.proc_pidpath(pid, buffer, len(buffer)) <= 0 or os.fsdecode(buffer.value) != str(executable):
        raise Blocked("process executable path mismatch")
    process = subprocess.run(["/bin/ps", "-ww", "-p", str(pid), "-o", "uid=", "-o", "lstart=", "-o", "stat="],
                             capture_output=True, text=True, timeout=2, check=True)
    fields = process.stdout.split()
    if len(fields) != 7 or fields[0] != str(uid) or "Z" in fields[-1]:
        raise Blocked("process UID/state mismatch")
    before = executable.stat()
    if executable.is_symlink() or not executable.is_file() or before.st_size > 256 * 1024 * 1024:
        raise Blocked("invalid executable file")
    with executable.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    after = executable.stat()
    stable_fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields) or digest != expected_hash:
        raise Blocked("executable changed or SHA256 mismatch")
    return {"pid": pid, "uid": uid, "started": " ".join(fields[1:6]),
            "executable": str(executable), "executable_sha256": digest}


class AX:
    def __init__(self, pid: int):
        self.pid, self.refs, self.nodes = pid, [], []
        self.deadline = time.monotonic() + 20
        self.cf = C.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        self.ax = C.CDLL("/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices")
        ptr = C.c_void_p
        signatures = (
            (self.cf, "CFRelease", [ptr], None), (self.cf, "CFRetain", [ptr], ptr),
            (self.cf, "CFEqual", [ptr, ptr], C.c_ubyte),
            (self.cf, "CFGetTypeID", [ptr], C.c_ulong),
            (self.cf, "CFStringGetTypeID", [], C.c_ulong),
            (self.cf, "CFBooleanGetTypeID", [], C.c_ulong),
            (self.cf, "CFBooleanGetValue", [ptr], C.c_ubyte),
            (self.cf, "CFArrayGetTypeID", [], C.c_ulong),
            (self.cf, "CFArrayGetCount", [ptr], C.c_long),
            (self.cf, "CFArrayGetValueAtIndex", [ptr, C.c_long], ptr),
            (self.cf, "CFStringCreateWithCString", [ptr, C.c_char_p, C.c_uint32], ptr),
            (self.cf, "CFStringGetCString", [ptr, ptr, C.c_long, C.c_uint32], C.c_ubyte),
            (self.ax, "AXIsProcessTrusted", [], C.c_ubyte),
            (self.ax, "AXUIElementGetTypeID", [], C.c_ulong),
            (self.ax, "AXUIElementCreateApplication", [C.c_int], ptr),
            (self.ax, "AXUIElementGetPid", [ptr, C.POINTER(C.c_int)], C.c_int),
            (self.ax, "AXUIElementSetMessagingTimeout", [ptr, C.c_float], C.c_int),
            (self.ax, "AXUIElementCopyAttributeValue", [ptr, ptr, C.POINTER(ptr)], C.c_int),
            (self.ax, "AXUIElementPerformAction", [ptr, ptr], C.c_int),
        )
        for library, name, arguments, result in signatures:
            function = getattr(library, name)
            function.argtypes, function.restype = arguments, result
        if not self.ax.AXIsProcessTrusted():
            raise Blocked("AX is not trusted; no permission requested")
        self.app = self.ax.AXUIElementCreateApplication(pid)
        if not self.app:
            raise Blocked("AX application unavailable")
        self.refs.append(self.app)

    def check(self, element):
        if time.monotonic() > self.deadline:
            raise Blocked("AX 20 second budget exhausted")
        pid = C.c_int()
        if self.ax.AXUIElementGetPid(element, C.byref(pid)) != 0 or pid.value != self.pid:
            raise Blocked("AX element belongs to another process")
        if self.ax.AXUIElementSetMessagingTimeout(element, 0.5) != 0:
            raise Blocked("AX messaging timeout unavailable")

    def attribute(self, element, name):
        self.check(element)
        key = self.cf.CFStringCreateWithCString(None, name.encode(), 0x08000100)
        value = C.c_void_p()
        try:
            error = self.ax.AXUIElementCopyAttributeValue(element, key, C.byref(value))
            if value.value:
                self.refs.append(value.value)
            return error, value.value
        finally:
            self.cf.CFRelease(key)

    def string(self, value):
        if not value or self.cf.CFGetTypeID(value) != self.cf.CFStringGetTypeID():
            return ""
        buffer = C.create_string_buffer(512)
        return buffer.value.decode("utf-8") if self.cf.CFStringGetCString(value, buffer, len(buffer), 0x08000100) else "<overlong>"

    def children(self, element, path, depth):
        error, value = self.attribute(element, "AXChildren")
        if error == 0:
            self.visit_value(value, path + "/AXChildren", depth)
        return error

    def visit_value(self, value, path, depth):
        if not value:
            return
        kind = self.cf.CFGetTypeID(value)
        if kind == self.cf.CFArrayGetTypeID():
            count = self.cf.CFArrayGetCount(value)
            if count > 64:
                raise Blocked("AX child count exceeds 64")
            for index in range(count):
                self.visit_value(self.cf.CFArrayGetValueAtIndex(value, index), f"{path}[{index}]", depth)
        elif kind == self.ax.AXUIElementGetTypeID():
            if any(self.cf.CFEqual(value, node["element"]) for node in self.nodes):
                return
            if len(self.nodes) >= 96:
                raise Blocked("AX node count exceeds 96")
            self.check(value)
            _, role_value = self.attribute(value, "AXRole")
            role = self.string(role_value)
            # Never traverse application windows or unrelated UI controls.
            if role not in {"AXMenuBar", "AXMenuBarItem", "AXMenu", "AXMenuItem"}:
                return
            _, title_value = self.attribute(value, "AXTitle")
            title = self.string(title_value)
            _, enabled_value = self.attribute(value, "AXEnabled")
            enabled = (bool(self.cf.CFBooleanGetValue(enabled_value)) if enabled_value
                       and self.cf.CFGetTypeID(enabled_value) == self.cf.CFBooleanGetTypeID() else None)
            node = {"element": value, "path": path, "role": role,
                    "title": title if allowed_title(title) else "<redacted>", "enabled": enabled}
            self.nodes.append(node)
            if depth < 4:
                node["children_ax_error"] = self.children(value, path, depth + 1)

    def inspect(self):
        self.nodes = []
        roots = []
        for name in ("AXExtrasMenuBar", "AXMenuBar", "AXChildren"):
            error, value = self.attribute(self.app, name)
            roots.append({"attribute": name, "ax_error": error})
            if error == 0:
                self.visit_value(value, name, 0)
        return roots

    def press(self, node):
        self.check(node["element"])
        _, role = self.attribute(node["element"], "AXRole")
        _, title = self.attribute(node["element"], "AXTitle")
        _, enabled = self.attribute(node["element"], "AXEnabled")
        raw_title = self.string(title)
        current_title = raw_title if allowed_title(raw_title) else "<redacted>"
        if self.string(role) != node["role"] or current_title != node["title"]:
            raise Blocked("AX action target changed")
        if not enabled or self.cf.CFGetTypeID(enabled) != self.cf.CFBooleanGetTypeID() or not self.cf.CFBooleanGetValue(enabled):
            raise Blocked("AX action target is not explicitly enabled")
        action = self.cf.CFStringCreateWithCString(None, b"AXPress", 0x08000100)
        try:
            return self.ax.AXUIElementPerformAction(node["element"], action)
        finally:
            self.cf.CFRelease(action)

    def close(self):
        for value in reversed(self.refs):
            self.cf.CFRelease(value)


def run(args, report):
    if not (sys.platform == "darwin" and os.environ.get("CI") == "true"
            and os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_OS") == "macOS"
            and os.environ.get("SLIPSTREAM_DISPOSABLE_CI") == "1"):
        raise Blocked("requires disposable GitHub macOS runner")
    if args.uid != os.getuid() or args.uid == 0 or os.stat("/dev/console").st_uid != args.uid:
        raise Blocked("requires exact nonroot console UID")
    if args.executable != Path("/Applications/Slipstream.app/Contents/MacOS/slipstream") or args.executable.resolve() != args.executable:
        raise Blocked("requires canonical installed Slipstream executable")
    baseline = identity(args.pid, args.uid, args.executable, args.exe_sha256)
    report["identity"] = baseline
    client = AX(args.pid)
    try:
        def recheck():
            if identity(args.pid, args.uid, args.executable, args.exe_sha256) != baseline:
                raise Blocked("process identity changed")

        def inspect():
            recheck()
            report["root_reads"] = client.inspect()
            report["nodes"] = [{key: value for key, value in node.items() if key != "element"} for node in client.nodes]
            report["update_items"] = [node for node in report["nodes"] if node["role"] == "AXMenuItem"
                                      and (node["title"] in update_titles(None)
                                           or node["title"].startswith(("Install Slipstream ", "Установить Slipstream ")))]
            report["owned_menu_present"] = bool(report["update_items"])
            recheck()

        def press(node, kind):
            recheck()
            action = {"kind": kind, "path": node["path"], "title": node["title"], "attempted": True}
            report["actions"].append(action)  # Record intent before the potentially asynchronous action.
            if kind == "press_update":
                report["installation_attempted"] = True
            action["ax_error"] = client.press(node)
            if action["ax_error"] != 0:
                raise Blocked("AXPress failed; no retry")

        inspect()
        if not client.nodes:
            raise Blocked("owned menu roots expose no menu elements")
        if args.open_menu:
            candidates = [node for node in client.nodes if node["role"] == "AXMenuBarItem"
                          and node["path"].startswith("AXExtrasMenuBar") and node["path"].count("/AXChildren") == 1]
            if not candidates:
                candidates = [node for node in client.nodes if node["role"] == "AXMenuBarItem"
                              and node["path"].startswith("AXMenuBar") and node["path"].count("/AXChildren") == 1
                              and node["title"] in {"", "Slipstream"}]
            press(unique(candidates, "owned tray item"), "open_menu")
            time.sleep(0.25)
            inspect()
            if not report["owned_menu_present"]:
                raise Blocked("opened tray does not expose an update menu item")
        if args.press_update:
            exact_titles = {f"Install Slipstream {args.expected_version}…", f"Установить Slipstream {args.expected_version}…"}
            node = unique([node for node in client.nodes if node["role"] == "AXMenuItem" and node["title"] in exact_titles
                           and node["enabled"] is True], "enabled exact-version update item")
            press(node, "press_update")
            # The real app may exit immediately; only the external transaction observer can qualify the update.
        if getattr(args, "press_check", False):
            node = unique([node for node in client.nodes if node["role"] == "AXMenuItem"
                           and node["title"] in {"Check for Updates…", "Проверить обновления…"}
                           and node["enabled"] is True], "enabled ordinary update check")
            press(node, "press_check")
        report["status"] = ("update_pressed" if args.press_update else "check_pressed"
                            if getattr(args, "press_check", False) else "menu_opened" if args.open_menu else "inspected")
    finally:
        client.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--exe-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--open-menu", action="store_true", help="one AXPress on the owned status item; never installs")
    parser.add_argument("--press-update", action="store_true", help="explicitly press the exact-version installation item")
    parser.add_argument("--press-check", action="store_true", help="one ordinary rediscovery after proven cancellation")
    parser.add_argument("--expected-version")
    args = parser.parse_args()
    if args.pid <= 0 or args.uid <= 0 or not re.fullmatch(r"[0-9a-f]{64}", args.exe_sha256):
        parser.error("positive PID/UID and lowercase SHA256 required")
    if args.press_update and not args.expected_version:
        parser.error("--press-update requires --expected-version")
    if args.press_update and args.press_check:
        parser.error("choose exactly one menu action")
    if args.expected_version and not re.fullmatch(r"0\.1\.9-preview\.\d+", args.expected_version):
        parser.error("expected preview version is invalid")
    report = {"schema_version": 1, "status": "blocked", "public_pair_qualified": False,
              "permission_requested": False, "installation_attempted": False, "actions": [], "owned_menu_present": False,
              "run_id": os.environ.get("GITHUB_RUN_ID"), "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
              "source_commit": os.environ.get("GITHUB_SHA")}
    def timeout(_signum, _frame):
        raise Blocked("30 second overall budget exhausted")
    # Reserve the receipt before any action, so an existing output cannot be overwritten after a click.
    with args.output.open("x", encoding="utf-8") as stream:
        signal.signal(signal.SIGALRM, timeout)
        signal.alarm(30)
        try:
            run(args, report)
        except Exception as error:
            report.update(status="blocked", error_type=type(error).__name__, reason=str(error))
        finally:
            signal.alarm(0)
        payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
        stream.write(payload)
        print(payload, end="")
    return 0 if report["status"] in {"inspected", "menu_opened", "update_pressed", "check_pressed"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
