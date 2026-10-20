#!/usr/bin/env python3
"""Bounded genuine menu discovery/action for the installed, authenticated OLD tray."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.request

from native_root_update import Refused, document, require
from packaged_update_observer import private_bytes, private_json, same_process


VERSION = "0.1.9-preview.30"
DISCOVERY_URL = "https://api.github.com/repos/aiwaki/slipstream/releases?per_page=10&page=1"
DISCOVERY_HEADERS = {"User-Agent": "Slipstream-Updater/1", "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28"}
DIAGNOSTIC_HEADERS = ("x-ratelimit-remaining", "x-ratelimit-reset", "x-ratelimit-limit",
                      "retry-after", "x-github-request-id", "content-type")
DISCOVERY_BODY_LIMIT = 16384


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def discovery_http_diagnostic(*, opener=None):
    """One later unauthenticated sample, never the original app response."""
    result = {"kind": "after_failure_probe", "original_page_unknown": True, "url": DISCOVERY_URL,
              "authenticated": False, "attempts": 1, "redirects_followed": False,
              "status": None, "headers": {}, "message": None, "body_truncated": False}
    try:
        if opener is None:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        request = urllib.request.Request(DISCOVERY_URL, headers=DISCOVERY_HEADERS, method="GET")
        try:
            response = opener.open(request, timeout=5)
        except urllib.error.HTTPError as error:
            response = error  # HTTP failures, including redirects, remain diagnostic responses.
        with response:
            result["status"] = response.status
            for name in DIAGNOSTIC_HEADERS:
                values = response.headers.get_all(name, [])
                if len(values) == 1:
                    result["headers"][name] = values[0][:256]
            body = response.read(DISCOVERY_BODY_LIMIT + 1)
        result["body_truncated"] = len(body) > DISCOVERY_BODY_LIMIT
        if not result["body_truncated"]:
            try:
                value = json.loads(body)
            except (ValueError, UnicodeError):
                value = None
            if isinstance(value, dict) and isinstance(value.get("message"), str):
                result["message"] = value["message"][:512]
        # A separate response is only corroborating evidence, not a finding
        # about the failed app request, its page, or the cause of arbitrary403.
        result["rate_limit_indicated_by_probe"] = (result["status"] in (403, 429) and (
            result["headers"].get("x-ratelimit-remaining") == "0"
            or "rate limit" in (result["message"] or "").lower()))
    except Exception as error:
        result["error_type"] = type(error).__name__  # No freeform network/env diagnostic.
    return result


def helper_environment(backend):
    # The AX actor needs disposable-runner guards. The product never receives them.
    allowed = ("CI", "GITHUB_ACTIONS", "SLIPSTREAM_DISPOSABLE_CI", "RUNNER_OS",
               "RUNNER_TEMP", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA")
    return {**backend.env, **{key: os.environ[key] for key in allowed if key in os.environ}}


def validate_ax(report, original, executable, old_hash, *, pressed=False):
    identity = report.get("identity", {})
    require(identity == {"pid": original["pid"], "uid": original["uid"], "started": original["started"],
                        "executable": str(executable), "executable_sha256": old_hash},
            "AX report did not bind the original tray")
    require(report.get("status") in ({"update_pressed"} if pressed else {"inspected", "menu_opened"}),
            "owned menu action failed; no retry")
    actions = report.get("actions")
    require(isinstance(actions, list), "AX action evidence missing")
    if pressed:
        require(len(actions) == 1 and actions[0].get("kind") == "press_update"
                and actions[0].get("attempted") is True and actions[0].get("ax_error") == 0
                and actions[0].get("title") in {f"Install Slipstream {VERSION}…", f"Установить Slipstream {VERSION}…"}
                and report.get("installation_attempted") is True, "one exact public update action required")
    else:
        require(report.get("installation_attempted") is False
                and all(action.get("kind") == "open_menu" and action.get("ax_error") == 0 for action in actions),
                "discovery must not install")


def offer_visible(report):
    items = report.get("update_items", [])
    require(isinstance(items, list), "AX update items missing")
    matches = [item for item in items if item.get("title") in
               {f"Install Slipstream {VERSION}…", f"Установить Slipstream {VERSION}…"} and item.get("enabled") is True]
    require(len(matches) <= 1, "ambiguous public update offer")
    return len(matches) == 1


class PublicMenu:
    def __init__(self, backend):
        self.backend = backend
        self.sequence = 0
        self.click_process = self.click_report = None
        self.click_verified = False
        self.handles = []
        self.discovery_diagnosed = False

    def launch(self, *, start=subprocess.Popen):
        backend = self.backend
        executable = backend.target / "Contents/MacOS/slipstream"
        log = (backend.args.output_dir / "normal-old-tray.log").open("xb")
        self.handles.append(log)
        backend.old_launch_attempted = True
        # Ordinary executable, no flags, injected updater environment or adapter.
        child = start([str(executable)], env=backend.env, stdout=log, stderr=subprocess.STDOUT)
        backend.original_process = child
        backend.capture_original(child)
        return child

    def command(self, *, open_menu=False, press=False):
        backend = self.backend
        self.sequence += 1
        output = backend.args.output_dir / f"ax-{self.sequence:02d}.json"
        command = [sys.executable, str(Path(__file__).with_name("public_update_ax.py")),
                   "--pid", str(backend.initiator["pid"]), "--uid", str(backend.uid),
                   "--executable", str(backend.target / "Contents/MacOS/slipstream"),
                   "--exe-sha256", backend.expected["old"]["app_executable_sha256"],
                   "--expected-version", VERSION, "--output", str(output)]
        if open_menu:
            command.append("--open-menu")
        if press:
            command.append("--press-update")
        return command, output

    def validate(self, report, *, pressed=False):
        backend = self.backend
        validate_ax(report, backend.initiator, backend.target / "Contents/MacOS/slipstream",
                    backend.expected["old"]["app_executable_sha256"], pressed=pressed)

    def refuse_logged_discovery_failure(self):
        backend = self.backend
        raw = private_bytes(backend.args.output_dir / "normal-old-tray.log", backend.uid,
                            limit=2 * 1024 * 1024, writing=True)
        if raw is None:
            return
        # Only a complete line emitted by this owned, hash-bound OLD child can
        # trigger the single extra request. Never probe on an ordinary slow load.
        matches = re.findall(rb"(?m)^update discovery unavailable: ([^\r\n]{1,1024})\r?\n", raw)
        if not matches:
            return
        detail = re.fullmatch(rb"preview discovery returned HTTP ([1-5][0-9]{2})(?: [^\r\n]{0,80})?", matches[0])
        failure = {"kind": "normal_app_discovery_failure", "original_page_unknown": True,
                   "http_status": int(detail[1]) if detail else None}
        backend.record("public_discovery_failure", failure)
        if not self.discovery_diagnosed:
            self.discovery_diagnosed = True  # Lost command reply cannot justify a retry.
            try:
                command = [sys.executable, str(Path(__file__).resolve()), "--diagnose-discovery"]
                response = backend.run(command, timeout=10, env=backend.env)
                require(len(response.stdout) <= 8192, "discovery diagnostic exceeded output bound")
                diagnostic = json.loads(response.stdout)
            except Exception as error:
                diagnostic = {"kind": "after_failure_probe", "original_page_unknown": True,
                              "authenticated": False, "attempts": 1, "error_type": type(error).__name__}
            backend.record("public_discovery_http_probe", diagnostic)
        raise Refused("normal OLD public discovery failed; separate unauthenticated diagnostic retained")

    def discover(self, *, clock=time.monotonic, sleep=time.sleep):
        backend = self.backend
        until = min(clock() + 120, backend.deadline - 420)
        first = True
        while clock() < until:
            require(backend.original_process.poll() is None
                    and same_process(backend.initiator, backend.process_snapshot(backend.initiator["pid"])),
                    "original tray exited during public discovery")
            self.refuse_logged_discovery_failure()
            if first:
                saved = private_json(backend.state / "app-update-state-v1.json", backend.uid)
                if saved is None or saved.get("highest_seen_version") is None:
                    sleep(1)
                    continue
                require(saved.get("highest_seen_version") == VERSION, "background discovery selected another version")
                # Opening the status menu is an explicit interaction. The earlier
                # read-only interval observes real background discovery/startup.
                backend.visibility.set_phase("interaction")
            command, output = self.command(open_menu=first)
            first = False
            backend.run(command, timeout=35, check=False, env=helper_environment(backend))
            report = document(output)
            self.validate(report)
            backend.record("public_menu", report)
            if offer_visible(report):
                saved = private_json(backend.state / "app-update-state-v1.json", backend.uid)
                require(saved is not None and set(saved) == {"version", "channel", "last_notified_version", "highest_seen_version"}
                        and saved["version"] == 1 and saved["channel"] == "preview"
                        and saved["highest_seen_version"] == VERSION, "normal app did not persist the public offer")
                backend.record("public_discovery", {"version": VERSION, "menu_report": output.name,
                    "persisted_state": saved, "notification_delivery_qualified": False,
                    "method": "unmodified_normal_app_background_discovery_and_exact_menu_offer"})
                return
            sleep(3)
        raise Refused("normal OLD tray did not offer the published update within the discovery bound")

    def press(self, *, start=subprocess.Popen):
        backend = self.backend
        require(self.click_process is None and not backend.click_attempted, "update click may occur only once")
        require(same_process(backend.initiator, backend.process_snapshot(backend.initiator["pid"])),
                "original tray changed before the update click")
        command, self.click_report = self.command(press=True)
        log = (backend.args.output_dir / "update-click.log").open("xb")
        self.handles.append(log)
        backend.click_attempted = True  # A lost spawn reply is an uncertain action.
        self.click_process = start(command, env=helper_environment(backend), stdout=log, stderr=subprocess.STDOUT)
        backend.record("public_click_started", {"actor_pid": self.click_process.pid,
                                               "original_pid": backend.initiator["pid"], "version": VERSION})

    def check_click(self):
        if self.click_process is None or self.click_verified:
            return
        code = self.click_process.poll()
        if code is None:
            return
        report = document(self.click_report)
        self.backend.record("public_click", report)
        require(code == 0, "actual AX update action failed; pending transaction retained")
        self.validate(report, pressed=True)
        self.click_verified = True

    def finish_click(self):
        require(self.click_process is not None, "real update action missing")
        self.click_process.wait(timeout=5)
        self.check_click()
        require(self.click_verified, "real AXPress completion not observed")

    def close(self):
        for stream in self.handles:
            stream.close()


if __name__ == "__main__":
    if sys.argv[1:] != ["--diagnose-discovery"]:
        raise SystemExit("only the fixed read-only discovery diagnostic is supported")
    print(json.dumps(discovery_http_diagnostic(), sort_keys=True))
