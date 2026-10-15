#!/usr/bin/env python3
"""Read-only hosted macOS UI capability check; never requests permission."""
from __future__ import annotations

import argparse
import ctypes as C
import json
import os
from pathlib import Path
import subprocess
import sys


def run() -> dict:
    report = {"schema_version": 1, "status": "blocked", "public_pair_qualified": False, "ui_actions": 0,
              "permission_requested": False, "installation_attempted": False,
              "scope": "hosted_UI_capability_only"}
    hosted = (sys.platform == "darwin" and os.environ.get("CI") == "true"
              and os.environ.get("GITHUB_ACTIONS") == "true"
              and os.environ.get("SLIPSTREAM_DISPOSABLE_CI") == "1"
              and os.environ.get("RUNNER_OS") == "macOS")
    report["hosted_guard"] = hosted
    if not hosted:
        report["reason"] = "requires_disposable_GitHub_macOS_runner"
        return report
    uid = os.getuid()
    report.update(uid=uid, console_uid=os.stat("/dev/console").st_uid,
                  run_id=os.environ.get("GITHUB_RUN_ID"),
                  run_attempt=os.environ.get("GITHUB_RUN_ATTEMPT"),
                  source_commit=os.environ.get("GITHUB_SHA"))
    if uid == 0 or report["console_uid"] != uid:
        report["reason"] = "not_nonroot_console_user"
        return report
    gui = subprocess.run(["/bin/launchctl", "print", f"gui/{uid}"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
    report["gui_bootstrap_available"] = gui.returncode == 0
    if gui.returncode:
        report["reason"] = "gui_bootstrap_unavailable"
        return report

    cf = C.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    ax = C.CDLL("/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices")
    cg = C.CDLL("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics")
    ptr = C.c_void_p
    signatures = (
        (cf, "CFRelease", [ptr], None),
        (cf, "CFStringCreateWithCString", [ptr, C.c_char_p, C.c_uint32], ptr),
        (cf, "CFDictionaryGetValue", [ptr, ptr], ptr),
        (cf, "CFBooleanGetValue", [ptr], C.c_ubyte),
        (cf, "CFGetTypeID", [ptr], C.c_ulong),
        (cf, "CFBooleanGetTypeID", [], C.c_ulong),
        (cf, "CFArrayGetTypeID", [], C.c_ulong),
        (cf, "CFArrayGetCount", [ptr], C.c_long),
        (cg, "CGSessionCopyCurrentDictionary", [], ptr),
        (ax, "AXIsProcessTrusted", [], C.c_ubyte),
        (ax, "AXUIElementCreateApplication", [C.c_int], ptr),
        (ax, "AXUIElementSetMessagingTimeout", [ptr, C.c_float], C.c_int),
        (ax, "AXUIElementCopyAttributeValue", [ptr, ptr, C.POINTER(ptr)], C.c_int),
    )
    for library, name, arguments, result in signatures:
        function = getattr(library, name)
        function.argtypes, function.restype = arguments, result
    session = cg.CGSessionCopyCurrentDictionary()
    try:
        flags = {}
        # CGSession.h defines CFSTR macros, not exported CFString variables.
        # The doubled S in the on-console value is Apple's actual key spelling.
        for name, raw_key in (("on_console", b"kCGSSessionOnConsoleKey"),
                              ("login_done", b"kCGSessionLoginDoneKey")):
            key = cf.CFStringCreateWithCString(None, raw_key, 0x08000100)
            try:
                value = cf.CFDictionaryGetValue(session, key) if session else None
                flags[name] = (bool(cf.CFBooleanGetValue(value))
                               if value and cf.CFGetTypeID(value) == cf.CFBooleanGetTypeID() else None)
            finally:
                cf.CFRelease(key)
        report["session"] = flags
    finally:
        if session:
            cf.CFRelease(session)
    report["ax_trusted"] = bool(ax.AXIsProcessTrusted())
    if not all(value is True for value in report["session"].values()):
        report["reason"] = "active_console_session_unavailable"
        return report
    if not report["ax_trusted"]:
        report["reason"] = "AX_not_trusted_no_permission_prompt_attempted"
        return report

    found = subprocess.run(["/usr/bin/pgrep", "-x", "-u", str(uid), "SystemUIServer"],
                           capture_output=True, text=True, timeout=3)
    pids = found.stdout.split()
    if found.returncode != 0 or len(pids) != 1 or not pids[0].isdigit():
        report["reason"] = "SystemUIServer_identity_unavailable_or_ambiguous"
        return report
    app = ax.AXUIElementCreateApplication(int(pids[0]))
    if not app:
        report["reason"] = "SystemUIServer_AX_element_unavailable"
        return report
    report["menu_reads"] = []
    try:
        report["ax_timeout_result"] = ax.AXUIElementSetMessagingTimeout(app, 1.0)
        if report["ax_timeout_result"] != 0:
            report["reason"] = "AX_timeout_configuration_failed"
            return report
        # Only these two attributes; no titles, screenshots or global UI tree.
        for attribute in ("AXExtrasMenuBar", "AXMenuBar"):
            key = cf.CFStringCreateWithCString(None, attribute.encode(), 0x08000100)
            value = ptr()
            try:
                error = ax.AXUIElementCopyAttributeValue(app, key, C.byref(value))
                item = {"attribute": attribute, "ax_error": error, "element_present": bool(value.value)}
                if error == 0 and value.value:
                    child_key = cf.CFStringCreateWithCString(None, b"AXChildren", 0x08000100)
                    children = ptr()
                    try:
                        timeout_result = ax.AXUIElementSetMessagingTimeout(value, 1.0)
                        item["children_ax_error"] = (ax.AXUIElementCopyAttributeValue(value, child_key, C.byref(children))
                                                     if timeout_result == 0 else timeout_result)
                        if children.value and cf.CFGetTypeID(children) == cf.CFArrayGetTypeID():
                            item["child_count"] = int(cf.CFArrayGetCount(children))
                    finally:
                        if children.value:
                            cf.CFRelease(children)
                        cf.CFRelease(child_key)
                report["menu_reads"].append(item)
            finally:
                if value.value:
                    cf.CFRelease(value)
                cf.CFRelease(key)
    finally:
        cf.CFRelease(app)
    readable = any(item["ax_error"] == 0 and item.get("children_ax_error") == 0
                   and item.get("child_count", 0) > 0 for item in report["menu_reads"])
    report.update(status="ready_for_owned_app_AX_probe" if readable else "blocked",
                  reason="read_only_AX_menu_query_succeeded" if readable else "AX_menu_read_unavailable")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = run()
    except Exception as error:
        report = {"schema_version": 1, "status": "error", "public_pair_qualified": False, "error_type": type(error).__name__,
                  "ui_actions": 0, "permission_requested": False, "installation_attempted": False}
    report.update(run_id=os.environ.get("GITHUB_RUN_ID"),
                  run_attempt=os.environ.get("GITHUB_RUN_ATTEMPT"),
                  source_commit=os.environ.get("GITHUB_SHA"), ref=os.environ.get("GITHUB_REF"))
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    print(payload, end="")
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(payload)
    return 0 if report["status"] == "ready_for_owned_app_AX_probe" else 2


if __name__ == "__main__":
    raise SystemExit(main())
