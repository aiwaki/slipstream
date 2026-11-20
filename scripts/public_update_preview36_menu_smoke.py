#!/usr/bin/env python3
"""Bounded genuine menu discovery/action for the installed, authenticated OLD tray."""
from __future__ import annotations

import json
import math
import os
import re
from email.utils import format_datetime, parsedate_to_datetime
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

from native_root_update import Refused, document, require
from packaged_update_observer import private_bytes, private_json, same_process


VERSION = "0.1.9-preview.36"
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


def public_feed_admission(*, opener=None):
    """One prelaunch sample of this runner's anonymous feed, not a reserved quota."""
    started = time.monotonic()
    result = {"kind": "prelaunch_public_feed_admission", "url": DISCOVERY_URL,
              "authenticated": False, "redirects_followed": False, "requests_attempted": 0,
              "started_at_unix": time.time(), "status": None, "headers": {},
              "list_count": None, "body_truncated": False, "message": None,
              "quota": None, "admitted": False, "classification": "external_unknown",
              "future_request_availability_guaranteed": False}
    try:
        if opener is None:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        request = urllib.request.Request(DISCOVERY_URL, headers=DISCOVERY_HEADERS, method="GET")
        result["requests_attempted"] = 1
        try:
            response = opener.open(request, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            result["status"] = response.status
            result["classification"] = "external_unavailable"
            for name in (*DIAGNOSTIC_HEADERS, "date", "age", "cache-control", "etag", "x-cache"):
                values = response.headers.get_all(name, [])
                if len(values) == 1 and isinstance(values[0], str):
                    result["headers"][name] = values[0][:256]
            # Decimal header strings only; no coercion of booleans, floats or
            # malformed/duplicate values. These are observations, not guarantees.
            quota = {}
            for key in ("limit", "remaining", "reset"):
                value = result["headers"].get("x-ratelimit-" + key, "")
                if re.fullmatch(r"0|[1-9][0-9]{0,15}", value) and int(value) <= 2**53 - 1:
                    quota[key] = int(value)
            if (set(quota) == {"limit", "remaining", "reset"} and quota["limit"] > 0
                    and quota["remaining"] <= quota["limit"] and quota["reset"] > 0):
                result["quota"] = quota
            if response.status in (403, 429) and quota.get("remaining") == 0:
                result["classification"] = "external_rate_limited"
            # The OLD updater's per-page cap is 256 KiB; the existing later
            # after-failure diagnostic deliberately retains its smaller 16 KiB cap.
            body = response.read(256 * 1024 + 1)
        result["body_truncated"] = len(body) > 256 * 1024
        if not result["body_truncated"]:
            try:
                value = json.loads(body)
            except (ValueError, UnicodeError):
                value = None
            if type(value) is dict and type(value.get("message")) is str:
                result["message"] = value["message"][:512]
            if type(value) is list:
                result["list_count"] = len(value)
                if (result["status"] == 200 and len(value) <= 10 and all(type(item) is dict for item in value)
                        and result["quota"] is not None and result["quota"]["remaining"] > 0):
                    result.update(admitted=True, classification="ready")
    except Exception as error:
        result["error_type"] = type(error).__name__
    finally:
        result["finished_at_unix"] = time.time()
        result["elapsed_seconds"] = time.monotonic() - started
    return result


def _canonical_http_date(value):
    if type(value) is not str or len(value) > 256:
        return None
    try:
        date = parsedate_to_datetime(value)
        if format_datetime(date, usegmt=True) != value:
            return None
        return int(date.timestamp())
    except (ValueError, TypeError, OverflowError):
        return None


def _sample_clock_valid(sample):
    values = [sample.get(key) for key in ("started_at_unix", "finished_at_unix", "elapsed_seconds")]
    if not all(type(value) in (int, float) and math.isfinite(value) for value in values):
        return False
    start, end, elapsed = values
    return start > 0 and end >= start and 0 <= elapsed <= 10 and abs(end - start - elapsed) <= 1


class _FeedProbeOpener:
    """Retain header multiplicity without altering the original sample report."""
    def __init__(self, opener):
        self.opener = opener
        self.headers = {}

    def open(self, request, **kwargs):
        self.headers = {}
        if self.opener is None:
            self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        try:
            response = self.opener.open(request, **kwargs)
        except urllib.error.HTTPError as error:
            self._record(error)
            raise
        self._record(response)
        return response

    def _record(self, response):
        self.headers = {name: response.headers.get_all(name, []) for name in
                        ("date", "retry-after", "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset")}


class _FeedProbeDeadline(TimeoutError):
    pass


class _FeedDeadlineUnavailable(RuntimeError):
    pass


def _timed_feed_probe(opener, deadline, *, not_after_monotonic=None):
    """Interrupt even a trickling response read; never take over another timer."""
    def refused(error):
        class RefusingOpener:
            def open(self, *_args, **_kwargs):
                raise error
        return public_feed_admission(opener=RefusingOpener()), True

    required = ("SIGALRM", "ITIMER_REAL", "getitimer", "setitimer", "getsignal", "signal")
    if (threading.current_thread() is not threading.main_thread()
            or not all(hasattr(signal, name) for name in required)):
        return refused(_FeedDeadlineUnavailable())
    remaining = deadline - time.monotonic()
    if not math.isfinite(remaining) or remaining <= 0:
        return refused(_FeedProbeDeadline())
    try:
        if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
            return refused(_FeedDeadlineUnavailable())
        previous = signal.getsignal(signal.SIGALRM)
    except (OSError, ValueError):
        return refused(_FeedDeadlineUnavailable())
    expired = False

    def interrupt(_signum, _frame):
        nonlocal expired
        expired = True
        raise _FeedProbeDeadline()

    installed = False
    try:
        signal.signal(signal.SIGALRM, interrupt)
        installed = True
        remaining = deadline - time.monotonic()
        if not math.isfinite(remaining) or remaining <= 0:
            return refused(_FeedProbeDeadline())
        signal.setitimer(signal.ITIMER_REAL, min(10.0, remaining))
        if not_after_monotonic is not None and time.monotonic() > not_after_monotonic:
            return refused(_FeedProbeDeadline())
        report = public_feed_admission(opener=opener)
        return report, expired
    except _FeedProbeDeadline as error:
        return refused(error)
    except (OSError, ValueError):
        return refused(_FeedDeadlineUnavailable())
    finally:
        if installed:
            try:
                signal.setitimer(signal.ITIMER_REAL, 0.0)
            finally:
                signal.signal(signal.SIGALRM, previous)


def _near_reset_target(sample, headers):
    if ("error_type" in sample or sample.get("status") not in (403, 429)
            or sample.get("classification") != "external_rate_limited"
            or not _sample_clock_valid(sample)):
        return None
    quota = sample.get("quota")
    if (type(quota) is not dict or set(quota) != {"limit", "remaining", "reset"}
            or not all(type(value) is int and 0 <= value <= 2**53 - 1 for value in quota.values())
            or quota["limit"] <= 0 or quota["remaining"] != 0 or quota["reset"] <= 0):
        return None
    for name in ("date", "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"):
        values = headers.get(name, [])
        if (len(values) != 1 or type(values[0]) is not str or len(values[0]) > 256
                or sample["headers"].get(name) != values[0]):
            return None
    date = _canonical_http_date(headers["date"][0])
    if (date is None or not sample["started_at_unix"] - 1 <= date <= sample["finished_at_unix"] + 1
            or quota["reset"] <= date):
        return None
    retry_values = headers.get("retry-after", [])
    if len(retry_values) > 1:
        return None
    retry_after = None
    if retry_values:
        value = retry_values[0]
        if type(value) is not str or len(value) > 256 or sample["headers"].get("retry-after") != value:
            return None
        if re.fullmatch(r"0|[1-9][0-9]{0,15}", value):
            retry_after = sample["finished_at_unix"] + int(value)
        else:
            retry_after = _canonical_http_date(value)
            if retry_after is None:
                return None
    target = max(quota["reset"] + 1, retry_after if retry_after is not None else 0)
    return {"date_unix": date, "reset_unix": quota["reset"], "retry_after_unix": retry_after,
            "target_unix": target}


def public_feed_admission_with_reset_wait(*, opener=None):
    """At most two unchanged anonymous probes, separated by one nearby proven reset."""
    started, started_at = time.monotonic(), time.time()
    deadline = started + 75
    recorder = _FeedProbeOpener(opener)
    result = {"kind": "prelaunch_public_feed_admission", "schema_version": 2,
              "policy": "one_near_reset_v1", "authenticated": False, "redirects_followed": False,
              "requests_attempted": 1, "started_at_unix": started_at, "admitted": False,
              "classification": "external_unknown", "future_request_availability_guaranteed": False,
              "samples": [], "reset_wait": None}

    def finish():
        result["finished_at_unix"] = time.time()
        result["elapsed_seconds"] = time.monotonic() - started
        result["requests_attempted"] = len(result["samples"])
        if (not 0 <= result["elapsed_seconds"] <= 75
                or result["finished_at_unix"] < started_at
                or abs(result["finished_at_unix"] - started_at - result["elapsed_seconds"]) > 1
                or not all(_sample_clock_valid(sample) for sample in result["samples"])):
            result.update(admitted=False, classification="external_unknown")
        return result

    first, deadline_refused = _timed_feed_probe(recorder, deadline)
    result["samples"].append(first)
    result.update(admitted=first["admitted"], classification=first["classification"])
    if deadline_refused:
        result.update(admitted=False, classification="external_unknown")
        return finish()
    if first["admitted"] or not _sample_clock_valid(first) or time.monotonic() >= deadline:
        return finish()
    target = _near_reset_target(first, recorder.headers)
    if target is None:
        return finish()
    wait_started, wait_started_at = time.monotonic(), time.time()
    requested = target["target_unix"] - wait_started_at
    if (not 0 < requested <= 60 or wait_started + requested + 10 > deadline
            or wait_started_at < first["finished_at_unix"]
            or abs(wait_started_at - started_at - (wait_started - started)) > 1):
        return finish()
    target_monotonic = wait_started + requested
    wait = {**target, "started_at_unix": wait_started_at, "finished_at_unix": wait_started_at,
            "requested_seconds": requested, "elapsed_seconds": 0, "completed": False,
            "refusal_reason": None}
    result["reset_wait"] = wait
    try:
        time.sleep(max(0, target_monotonic - time.monotonic()))
    except Exception:
        wait["refusal_reason"] = "wait_failed"
    wait_finished, wait_finished_at = time.monotonic(), time.time()
    wait.update(finished_at_unix=wait_finished_at, elapsed_seconds=wait_finished - wait_started)
    if wait["refusal_reason"] is not None:
        return finish()
    if wait_finished < target_monotonic or wait_finished_at < target["target_unix"]:
        wait["refusal_reason"] = "wait_incomplete"
    elif wait_finished - target_monotonic > 2:
        wait["refusal_reason"] = "late_wake"
    elif abs(wait_finished_at - wait_started_at - wait["elapsed_seconds"]) > 1:
        wait["refusal_reason"] = "clock_changed"
    elif wait_finished + 10 > deadline:
        wait["refusal_reason"] = "overall_deadline"
    if wait["refusal_reason"] is not None:
        return finish()
    before_second, before_second_at = time.monotonic(), time.time()
    if before_second + 10 > deadline:
        wait["refusal_reason"] = "overall_deadline"
        return finish()
    if before_second - target_monotonic > 2:
        wait["refusal_reason"] = "late_wake"
        return finish()
    if (before_second < wait_finished or before_second_at < wait_finished_at
            or abs(before_second_at - started_at - (before_second - started)) > 1):
        wait["refusal_reason"] = "clock_changed"
        return finish()
    wait["completed"] = True
    second, deadline_refused = _timed_feed_probe(recorder, deadline,
                                               not_after_monotonic=target_monotonic + 2)
    result["samples"].append(second)
    result.update(admitted=second["admitted"], classification=second["classification"])
    if (deadline_refused
            or not target["target_unix"] <= second["started_at_unix"] <= target["target_unix"] + 3):
        result.update(admitted=False, classification="external_unknown")
    return finish()


def require_public_feed(backend):
    started, started_at = time.monotonic(), time.time()
    try:
        response = backend.run([sys.executable, str(Path(__file__).resolve()), "--prelaunch-public-feed"],
                               timeout=80, env=backend.env)
        require(len(response.stdout) <= 16384, "public feed admission output exceeded bound")
        report = json.loads(response.stdout)
        require(type(report) is dict and report.get("kind") == "prelaunch_public_feed_admission",
                "public feed admission response invalid")
    except Exception as error:
        report = {"kind": "prelaunch_public_feed_admission", "admitted": False,
                  "classification": "external_unknown", "error_type": type(error).__name__,
                  "started_at_unix": started_at, "finished_at_unix": time.time(),
                  "elapsed_seconds": time.monotonic() - started, "requests_attempted": None}
    backend.record("public_feed_admission", report)
    require(report.get("admitted") is True and report.get("classification") == "ready",
            "public feed admission refused; external sample retained; OLD not launched")


def helper_environment(backend):
    # The AX actor needs disposable-runner guards. The product never receives them.
    allowed = ("CI", "GITHUB_ACTIONS", "SLIPSTREAM_DISPOSABLE_CI", "RUNNER_OS",
               "RUNNER_TEMP", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA")
    return {**backend.env, **{key: os.environ[key] for key in allowed if key in os.environ}}


def validate_ax(report, original, executable, old_hash, *, pressed=False, checked=False):
    identity = report.get("identity", {})
    require(identity == {"pid": original["pid"], "uid": original["uid"], "started": original["started"],
                        "executable": str(executable), "executable_sha256": old_hash},
            "AX report did not bind the original tray")
    require(not (pressed and checked), "one menu action required")
    require(report.get("status") in ({"update_pressed"} if pressed else {"check_pressed"} if checked else
                                    {"inspected", "menu_opened", "menu_observed_after_timeout"}),
            "owned menu action failed; no retry")
    actions = report.get("actions")
    require(isinstance(actions, list), "AX action evidence missing")
    if pressed:
        require(len(actions) == 1 and actions[0].get("kind") == "press_update"
                and actions[0].get("attempted") is True and actions[0].get("ax_error") == 0
                and actions[0].get("title") in {f"Install Slipstream {VERSION}…", f"Установить Slipstream {VERSION}…"}
                and report.get("installation_attempted") is True, "one exact public update action required")
    elif checked:
        require(len(actions) == 1 and actions[0].get("kind") == "press_check"
                and actions[0].get("attempted") is True and actions[0].get("ax_error") == 0
                and actions[0].get("title") in {"Check for Updates…", "Проверить обновления…"}
                and report.get("installation_attempted") is False, "one normal update check required")
    elif report.get("status") == "menu_observed_after_timeout":
        require(report.get("installation_attempted") is False and report.get("owned_menu_present") is True
                and len(actions) == 1 and actions[0].get("kind") == "open_menu"
                and actions[0].get("attempted") is True and type(actions[0].get("ax_error")) is int
                and actions[0]["ax_error"] == -25204, "one uncertain menu-open action required")
        proof = actions[0].get("postcondition")
        require(isinstance(proof, dict) and set(proof) == {"post_read", "visible", "visibility_method", "tray_path",
                "menu_path", "item_path", "title", "expected_version"}
                and proof.get("post_read") is True and proof.get("visible") is True
                and isinstance(proof.get("visibility_method"), str) and isinstance(proof.get("title"), str)
                and proof.get("visibility_method") in {"visible_children", "global_hit_test"}
                and proof.get("expected_version") == VERSION
                and proof.get("title") in {f"Install Slipstream {VERSION}…", f"Установить Slipstream {VERSION}…"}
                and all(isinstance(proof.get(key), str) for key in ("tray_path", "menu_path", "item_path")),
                "positive fresh menu visibility proof required")
        require(proof["tray_path"] == actions[0].get("path")
                and re.fullmatch(re.escape(proof["tray_path"]) + r"/AXChildren\[\d+\]", proof["menu_path"]) is not None
                and re.fullmatch(re.escape(proof["menu_path"]) + r"/AXChildren\[\d+\]", proof["item_path"]) is not None,
                "fresh offer must descend from the single opened tray")
        nodes, items = report.get("nodes"), report.get("update_items")
        require(isinstance(nodes, list) and isinstance(items, list), "fresh menu observation missing")
        for key, role in (("tray_path", "AXMenuBarItem"), ("menu_path", "AXMenu"), ("item_path", "AXMenuItem")):
            found = [node for node in nodes if isinstance(node, dict) and node.get("path") == proof[key]]
            require(len(found) == 1 and found[0].get("role") == role, "fresh menu ancestry is ambiguous")
        offered = [item for item in items if isinstance(item, dict) and item.get("title") in
                   {f"Install Slipstream {VERSION}…", f"Установить Slipstream {VERSION}…"} and item.get("enabled") is True]
        require(len(offered) == 1 and offered[0].get("path") == proof["item_path"]
                and offered[0].get("title") == proof["title"] and offered[0] == found[0],
                "fresh enabled exact-version menu offer missing")
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
        self.retry_discovery = False

    def launch(self, *, start=subprocess.Popen):
        backend = self.backend
        executable = backend.target / "Contents/MacOS/slipstream"
        log = (backend.args.output_dir / "normal-old-tray.log").open("xb")
        self.handles.append(log)
        backend.old_launch_attempted = True
        # Ordinary executable, no flags, injected updater environment or adapter.
        # Keep the driver's private-report umask out of the normal app process.
        child = start([str(executable)], env=backend.env, stdout=log, stderr=subprocess.STDOUT,
                      umask=0o022)
        backend.original_process = child
        backend.capture_original(child)
        return child

    def command(self, *, open_menu=False, press=False, check=False):
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
        if check:
            command.append("--press-check")
        return command, output

    def validate(self, report, *, pressed=False, checked=False):
        backend = self.backend
        validate_ax(report, backend.initiator, backend.target / "Contents/MacOS/slipstream",
                    backend.expected["old"]["app_executable_sha256"], pressed=pressed, checked=checked)

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
        rediscovery = self.retry_discovery
        readonly_before_open = rediscovery
        manual_check = False

        def check_enabled(report):
            return any(item.get("title") in {"Check for Updates…", "Проверить обновления…"}
                       and item.get("enabled") is True for item in report.get("update_items", []))

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
            if first and readonly_before_open:
                # Native Cancel proves runtime cleanup, not menu readiness. The
                # app may still be refreshing its offer or awaiting the UI poll.
                command, output = self.command()
                backend.run(command, timeout=35, check=False, env=helper_environment(backend))
                observed = document(output)
                self.validate(observed)
                backend.record("public_menu", observed)
                require(clock() < until, "normal OLD menu readiness exceeded the discovery bound")
                if not (offer_visible(observed) or self.retry_discovery and check_enabled(observed)):
                    sleep(3)
                    continue
            command, output = self.command(open_menu=first)
            first = False
            backend.run(command, timeout=35, check=False, env=helper_environment(backend))
            report = document(output)
            self.validate(report)
            backend.record("public_menu", report)
            if rediscovery:
                require(clock() < until, "normal OLD menu observation exceeded the discovery bound")
            if self.retry_discovery and not offer_visible(report) and check_enabled(report):
                command, output = self.command(check=True)
                backend.run(command, timeout=35, check=False, env=helper_environment(backend))
                checked = document(output)
                self.validate(checked, checked=True)
                backend.record("cancel_retry_discovery", checked)
                self.retry_discovery = False
                manual_check = True
                first = True  # The ordinary Check action closes the menu.
                readonly_before_open = True
                sleep(3)
                continue
            if offer_visible(report):
                saved = private_json(backend.state / "app-update-state-v1.json", backend.uid)
                require(saved is not None and set(saved) == {"version", "channel", "last_notified_version", "highest_seen_version"}
                        and saved["version"] == 1 and saved["channel"] == "preview"
                        and saved["highest_seen_version"] == VERSION, "normal app did not persist the public offer")
                self.retry_discovery = False
                backend.record("public_discovery", {"version": VERSION, "menu_report": output.name,
                    "persisted_state": saved, "notification_delivery_qualified": False,
                    "method": ("unmodified_normal_app_manual_rediscovery_after_cancel" if manual_check else
                               "unmodified_normal_app_automatic_rediscovery_after_cancel" if rediscovery else
                               "unmodified_normal_app_background_discovery_and_exact_menu_offer")})
                return
            sleep(3)
        raise Refused("normal OLD tray did not offer the published update within the discovery bound")

    def press(self, *, start=subprocess.Popen):
        backend = self.backend
        require(self.click_process is None and not backend.click_attempted, "update click may occur only once")
        require(same_process(backend.initiator, backend.process_snapshot(backend.initiator["pid"])),
                "original tray changed before the update click")
        command, self.click_report = self.command(press=True)
        log = (backend.args.output_dir / f"update-click-{self.sequence:02d}.log").open("xb")
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

    def reset_after_cancel(self):
        require(self.backend.cancelled_proof and self.click_verified and self.click_process.poll() == 0,
                "cannot reset an uncertain update click")
        self.click_process = self.click_report = None
        self.click_verified = False
        self.backend.click_attempted = False
        self.retry_discovery = True

    def close(self):
        for stream in self.handles:
            stream.close()


if __name__ == "__main__":
    if sys.argv[1:] == ["--prelaunch-public-feed"]:
        print(json.dumps(public_feed_admission_with_reset_wait(), sort_keys=True))
    elif sys.argv[1:] == ["--diagnose-discovery"]:
        print(json.dumps(discovery_http_diagnostic(), sort_keys=True))
    else:
        raise SystemExit("only the fixed read-only discovery diagnostic is supported")
