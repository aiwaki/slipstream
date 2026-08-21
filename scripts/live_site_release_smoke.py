#!/usr/bin/env python3
"""Run the fixed Safari and Chrome release-site gate on disposable macOS."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse

import chromium_semantic_packaged_smoke as chromium
import live_site_contract
import pf_anchor_smoke as pf
import pf_installed_lifecycle_smoke as lifecycle

SCHEMA_VERSION = 2
SITES = {
    "xpersonatoy.com": {
        "deadline_ms": 20_000,
        "denials": (
            "this connection is not secure",
            "does not support connecting securely over https",
            "cannot establish a secure connection",
        ),
    },
    "app.aikido.dev": {
        "deadline_ms": 30_000,
        "denials": ("err_empty_response", "site can't be reached"),
    },
    "weather.com": {
        "deadline_ms": 25_000,
        "denials": ("this content is no longer available in your area",),
    },
    "capacitorjs.com": {
        "deadline_ms": 25_000,
        "denials": (
            "sorry, you have been blocked",
            "you are unable to access capacitorjs.com",
        ),
    },
}
MIN_DOCUMENT_BYTES = 512
ALLOWED_PROTOCOLS = {"h2", "http/1.1", "h3"}
CHALLENGE_MARKERS = (
    "checking your browser",
    "verify you are human",
    "captcha",
    "just a moment",
    "cf-chl-",
)
TERMINAL_BROWSER_REASONS = live_site_contract.TERMINAL_BROWSER_REASONS


class LiveSiteError(RuntimeError):
    pass


def _require_protected_ci() -> None:
    expected = {
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "SLIPSTREAM_DISPOSABLE_CI": "1",
        "SLIPSTREAM_RELEASE_READINESS": "1",
    }
    missing = [key for key, value in expected.items() if os.environ.get(key) != value]
    if missing or sys.platform != "darwin" or os.geteuid() != 0:
        raise LiveSiteError("live-site gate requires protected disposable macOS CI")


def _positive_readiness(host: str, signals: dict[str, object]) -> bool:
    title = str(signals.get("title") or "").casefold()
    body_text = int(signals.get("body_text_length") or 0)
    main_text = int(signals.get("main_text_length") or 0)
    app_text = int(signals.get("app_text_length") or 0)
    common = (
        signals.get("https") is True
        and signals.get("secure_context") is True
        and signals.get("ready_state") == "complete"
        and signals.get("visible_body") is True
        and signals.get("next_hop_protocol") in ALLOWED_PROTOCOLS
    )
    if host == "xpersonatoy.com":
        return common and "starrtoy" in title and main_text >= 80
    if host == "app.aikido.dev":
        return (
            common
            and "aikido security" in title
            and signals.get("visible_app") is True
            and app_text >= 20
            and signals.get("preloader_visible") is False
        )
    if host == "weather.com":
        return common and "weather" in title and main_text >= 100
    if host == "capacitorjs.com":
        return common and "capacitor" in title and main_text >= 100
    return False


def _classify_document_evidence(
    host: str, document: str, signals: dict[str, object] | None = None
) -> tuple[str, str]:
    if len(document.encode("utf-8")) < MIN_DOCUMENT_BYTES:
        return "terminal_error", "document_too_short"
    lowered = document.casefold()
    if any(marker in lowered for marker in SITES[host]["denials"]):
        if host == "weather.com":
            return "regional_access_denied", "regional_access_denied"
        if host == "capacitorjs.com":
            return "edge_access_denied", "edge_access_denied"
        return "terminal_error", "navigation_denied"
    if any(marker in lowered for marker in CHALLENGE_MARKERS):
        return "challenge_or_auth", "challenge_or_auth"
    if signals is None:
        return "terminal_error", "readiness_signals_invalid"
    try:
        ready = _positive_readiness(host, signals)
    except (TypeError, ValueError):
        return "terminal_error", "readiness_signals_invalid"
    if not ready:
        return "terminal_error", "readiness_timeout"
    return "usable", ""


def _classify_document(
    host: str, document: str, signals: dict[str, object] | None = None
) -> str:
    return _classify_document_evidence(host, document, signals)[0]


def _chrome_command(executable: Path, profile: Path) -> tuple[str, ...]:
    return (
        str(executable),
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-default-apps",
        "--disable-extensions",
        "--disable-features=MediaRouter,OptimizationHints,Translate",
        "--disable-sync",
        "--metrics-recording-only",
        "--no-default-browser-check",
        "--no-first-run",
        "--no-proxy-server",
        "--password-store=basic",
        "--remote-debugging-port=0",
        f"--user-data-dir={profile}",
        "about:blank",
    )


READINESS_EXPRESSION = r"""
(() => {
  const visible = (node) => {
    if (!node) return false;
    const style = getComputedStyle(node);
    const rect = node.getBoundingClientRect();
    return style.display !== 'none' && style.visibility !== 'hidden' &&
      Number(style.opacity || 1) > 0 && rect.width > 0 && rect.height > 0;
  };
  const textLength = (node) => node ? (node.innerText || '').trim().length : 0;
  const navigation = performance.getEntriesByType('navigation')[0];
  const app = document.querySelector('#app');
  const preloader = document.querySelector('#preloader__root');
  return {
    app_text_length: textLength(app),
    body_text_length: textLength(document.body),
    https: location.protocol === 'https:',
    main_text_length: textLength(document.querySelector('main')),
    next_hop_protocol: navigation ? navigation.nextHopProtocol : '',
    preloader_visible: visible(preloader),
    ready_state: document.readyState,
    secure_context: window.isSecureContext === true,
    title: document.title,
    visible_app: visible(app),
    visible_body: visible(document.body)
  };
})()
"""


def _run_chrome(host: str, executable: Path, uid: int, gid: int) -> dict[str, object]:
    executable = executable.resolve(strict=True)
    environment, home = lifecycle._user_environment(uid)
    groups = lifecycle._user_supplementary_groups(uid, gid)
    profile = Path(tempfile.mkdtemp(prefix="slipstream-release-chrome-"))
    output = tempfile.TemporaryFile()
    process: subprocess.Popen | None = None
    process_group: int | None = None
    started = time.monotonic()
    finished = started
    outcome = "terminal_error"
    reason = "browser_start_failed"
    failure_reason = reason
    failure: BaseException | None = None
    try:
        os.chown(profile, uid, gid)
        profile.chmod(0o700)
        process = subprocess.Popen(
            _chrome_command(executable, profile),
            cwd=home,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            user=uid,
            group=gid,
            extra_groups=groups,
        )
        process_group = process.pid
        failure_reason = "devtools_unavailable"
        port = chromium._wait_for_devtools_port(profile, uid, timeout=10)
        failure_reason = "target_unavailable"
        targets = chromium._devtools_json(port, "/json/list")
        pages = [
            item
            for item in targets
            if isinstance(item, dict)
            and item.get("type") == "page"
            and item.get("url") == "about:blank"
        ]
        if len(pages) != 1 or not isinstance(pages[0].get("webSocketDebuggerUrl"), str):
            raise LiveSiteError("Chrome did not expose one clean page")
        debugger = pages[0]["webSocketDebuggerUrl"]
        failure_reason = "navigation_rejected"
        navigation = chromium._devtools_command(
            debugger,
            port,
            "Page.navigate",
            {"url": f"https://{host}/"},
            response_timeout=10,
        )
        if navigation.get("errorText") not in (None, ""):
            raise LiveSiteError("Chrome rejected the HTTPS navigation")
        failure_reason = "browser_observation_failed"
        deadline = started + SITES[host]["deadline_ms"] / 1000
        signals: dict[str, object] = {}
        document = ""
        while time.monotonic() < deadline:
            try:
                evaluated = chromium._devtools_command(
                    debugger,
                    port,
                    "Runtime.evaluate",
                    {
                        "expression": READINESS_EXPRESSION,
                        "returnByValue": True,
                    },
                    response_timeout=2,
                ).get("result")
                value = (
                    evaluated.get("value") if isinstance(evaluated, dict) else None
                )
                if isinstance(value, dict):
                    signals = value
                html = chromium._devtools_command(
                    debugger,
                    port,
                    "Runtime.evaluate",
                    {
                        "expression": "document.documentElement.outerHTML",
                        "returnByValue": True,
                    },
                    response_timeout=2,
                ).get("result")
                value = html.get("value") if isinstance(html, dict) else None
                if isinstance(value, str):
                    document = value
            except chromium.QualificationError:
                # Navigation replaces the execution context. A single CDP
                # evaluation can race that replacement; keep polling inside
                # the existing host deadline instead of treating it as a
                # terminal browser failure.
                time.sleep(0.25)
                continue
            outcome, reason = _classify_document_evidence(host, document, signals)
            # A static app shell reaches readyState=complete before its JS has
            # rendered a useful interface. Keep polling until a fixed positive
            # signal, denial/challenge, or the site deadline.
            if outcome != "terminal_error":
                break
            time.sleep(0.25)
        finished = time.monotonic()
    except BaseException as exc:
        failure = exc
        finished = time.monotonic()
    finally:
        cleanup_failed = False
        if process is not None and process_group is not None:
            try:
                lifecycle._stop_owned_chrome_process_group(
                    process,
                    process_group,
                    uid=uid,
                    gid=gid,
                    supplementary_groups=groups,
                )
            except BaseException:
                cleanup_failed = True
        try:
            output.close()
        except BaseException:
            cleanup_failed = True
        try:
            shutil.rmtree(profile)
        except BaseException:
            cleanup_failed = True
        if cleanup_failed:
            raise LiveSiteError("Chrome cleanup failed") from None
    # Worker teardown is verified but excluded from the navigation deadline.
    elapsed_ms = round((finished - started) * 1000)
    if failure is not None:
        outcome = "terminal_error"
        reason = failure_reason
    return {
        "browser": "chrome",
        "deadline_ms": SITES[host]["deadline_ms"],
        "elapsed_ms": elapsed_ms,
        "outcome": outcome,
        "reason": reason,
        "route": "slipstream_selected",
    }


def _wait_for_safaridriver_ready(driver_url: str, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            lifecycle._assert_safaridriver_ready(driver_url)
            return
        except lifecycle.LifecycleError:
            time.sleep(0.2)
    raise LiveSiteError("SafariDriver did not become ready")


def _decode_safari_readiness_signals(value: object) -> dict[str, object]:
    if not isinstance(value, str):
        raise LiveSiteError("Safari returned invalid readiness signals")
    try:
        signals = json.loads(value)
    except json.JSONDecodeError:
        raise LiveSiteError("Safari returned invalid readiness signals") from None
    if not isinstance(signals, dict):
        raise LiveSiteError("Safari returned invalid readiness signals")
    return signals


def _run_safari(host: str, driver_url: str, uid: int) -> dict[str, object]:
    session_id = None
    safari_pid = None
    document = ""
    outcome = "terminal_error"
    reason = "driver_unavailable"
    failure_reason = reason
    started = time.monotonic()
    finished = started
    failure: BaseException | None = None
    try:
        _wait_for_safaridriver_ready(driver_url)
        failure_reason = "browser_process_conflict"
        lifecycle._assert_no_safari_process(uid, host)
        failure_reason = "session_create_failed"
        created = lifecycle._webdriver_request(
            driver_url,
            "POST",
            "/session",
            {
                "capabilities": {
                    "alwaysMatch": {
                        "browserName": "safari",
                        "pageLoadStrategy": "normal",
                    }
                }
            },
        )
        value = created.get("value")
        session_id = value.get("sessionId") if isinstance(value, dict) else None
        session_id = session_id or created.get("sessionId")
        if not isinstance(session_id, str) or not session_id:
            raise LiveSiteError("SafariDriver did not create a clean session")
        failure_reason = "browser_process_unavailable"
        safari_pid = lifecycle._wait_for_safari_process(uid, host)
        encoded = urllib.parse.quote(session_id, safe="")
        deadline = int(SITES[host]["deadline_ms"])
        absolute_deadline = started + deadline / 1000
        failure_reason = "session_configuration_failed"
        lifecycle._webdriver_request(
            driver_url,
            "POST",
            f"/session/{encoded}/timeouts",
            {"pageLoad": deadline, "script": min(deadline, 10_000)},
        )
        # The protected runner and WebDriver session are both fresh. Deleting
        # cookies while Safari is still on about:blank has no origin and makes
        # SafariDriver reject or stall an otherwise valid clean session.
        failure_reason = "navigation_rejected"
        lifecycle._webdriver_request(
            driver_url,
            "POST",
            f"/session/{encoded}/url",
            {"url": f"https://{host}/"},
            timeout=deadline / 1000 + 5,
        )
        failure_reason = "browser_observation_failed"
        while time.monotonic() < absolute_deadline:
            remaining = max(0.1, absolute_deadline - time.monotonic())
            source = lifecycle._webdriver_request(
                driver_url,
                "GET",
                f"/session/{encoded}/source",
                timeout=min(2.0, remaining),
            ).get("value")
            if not isinstance(source, str):
                failure_reason = "document_invalid"
                raise LiveSiteError("SafariDriver returned a non-text document")
            document = source
            serialized_signals = lifecycle._webdriver_request(
                driver_url,
                "POST",
                f"/session/{encoded}/execute/sync",
                {
                    "script": f"return JSON.stringify({READINESS_EXPRESSION});",
                    "args": [],
                },
                timeout=min(2.0, remaining),
            ).get("value")
            failure_reason = "readiness_signals_invalid"
            signals = _decode_safari_readiness_signals(serialized_signals)
            outcome, reason = _classify_document_evidence(host, document, signals)
            if outcome != "terminal_error":
                break
            time.sleep(min(0.25, max(0.0, absolute_deadline - time.monotonic())))
        finished = time.monotonic()
    except BaseException as exc:
        failure = exc
        finished = time.monotonic()
    finally:
        cleanup: list[BaseException] = []
        if session_id:
            try:
                encoded = urllib.parse.quote(session_id, safe="")
                lifecycle._webdriver_request(
                    driver_url, "DELETE", f"/session/{encoded}", timeout=10
                )
            except BaseException as exc:
                cleanup.append(exc)
        if safari_pid is not None:
            try:
                lifecycle._stop_owned_safari_process(safari_pid, uid, host)
            except BaseException as exc:
                cleanup.append(exc)
        if cleanup:
            raise LiveSiteError("Safari cleanup failed") from (failure or cleanup[0])
    # Session teardown is verified but excluded from the navigation deadline.
    elapsed_ms = round((finished - started) * 1000)
    if failure is not None:
        outcome = "terminal_error"
        reason = failure_reason
    return {
        "browser": "safari",
        "deadline_ms": SITES[host]["deadline_ms"],
        "elapsed_ms": elapsed_ms,
        "outcome": outcome,
        "reason": reason,
        "route": "slipstream_selected",
    }


def _control_route(host: str, route: str) -> str:
    command = [
        "/usr/bin/curl",
        "--location",
        "--silent",
        "--show-error",
        "--connect-timeout",
        "8",
        "--max-time",
        "20",
        "--ignore-content-length",
        "--max-filesize",
        "131072",
        "--range",
        "0-131071",
        "--write-out",
        "\n__SLIPSTREAM_STATUS__:%{http_code}",
    ]
    if route == "owned_geph":
        command.extend(("--socks5-hostname", "127.0.0.1:9954"))
    command.append(f"https://{host}/")
    result = subprocess.run(command, capture_output=True, check=False)
    status_marker = b"\n__SLIPSTREAM_STATUS__:"
    if result.returncode not in (0, 63) or status_marker not in result.stdout:
        return "unavailable"
    body, code_bytes = result.stdout.rsplit(status_marker, 1)
    try:
        code = code_bytes.strip().decode("ascii")
    except UnicodeDecodeError:
        return "unavailable"
    if not code.isdigit() or int(code) == 0:
        return "unavailable"
    lowered = body.decode("utf-8", errors="replace").casefold()
    all_denials = tuple(marker for site in SITES.values() for marker in site["denials"])
    if any(marker in lowered for marker in all_denials):
        return "denial"
    if any(marker in lowered for marker in CHALLENGE_MARKERS) or int(code) in {
        401,
        407,
        429,
    }:
        return "challenge"
    if 200 <= int(code) < 400 and len(body) >= MIN_DOCUMENT_BYTES:
        return "usable"
    return "origin_error"


def run_gate(app_bundle: Path, chrome: Path, driver_url: str) -> tuple[dict, int]:
    failure_stage = "require_protected_ci"
    try:
        _require_protected_ci()
        failure_stage = "pf_runner"
        runner = pf.PfctlRunner()
        failure_stage = "preflight"
        before, uid, gid = lifecycle._preflight(runner)
        failure_stage = "packaged_app_target"
        target = lifecycle.packaged_app_target(app_bundle)
        failure_stage = "system_runner"
        system = lifecycle.SystemRunner(target)
    except BaseException as failure:
        failure_name = type(failure).__name__
        if len(failure_name) > 64 or not failure_name.isidentifier():
            failure_name = "Exception"
        raise LiveSiteError(
            f"live-site execution failed at {failure_stage} ({failure_name})"
        ) from None
    results: list[dict[str, object]] = []
    failure: BaseException | None = None
    try:
        failure_stage = "install"
        system.run(target.install_command)
        failure_stage = "wait_for_active"
        lifecycle._wait_for_status("active", timeout=90)
        failure_stage = "assert_anchor_active"
        lifecycle._assert_anchor_active(runner)
        for host in SITES:
            failure_stage = f"safari:{host}"
            safari = _run_safari(host, driver_url, uid)
            failure_stage = f"chrome:{host}"
            chrome_result = _run_chrome(host, chrome, uid, gid)
            browsers = (safari, chrome_result)
            usable = all(item["outcome"] == "usable" for item in browsers)
            controls = {"direct": "not_needed", "owned_geph": "not_needed"}
            result = "usable" if usable else "terminal_error"
            if not usable:
                failure_stage = f"controls:{host}"
                controls = {
                    "direct": _control_route(host, "direct"),
                    "owned_geph": _control_route(host, "owned_geph"),
                }
                if set(controls.values()) == {"unavailable"}:
                    result = "inconclusive"
            results.append(
                {
                    "browsers": list(browsers),
                    "controls": controls,
                    "host": host,
                    "result": result,
                }
            )
    except BaseException as exc:
        failure = exc
    finally:
        cleanup_failed = False
        try:
            cleanup_failed = bool(lifecycle._fallback_uninstall(system, runner, target))
        except BaseException:
            cleanup_failed = True
        try:
            lifecycle._assert_clean_install_state(runner)
        except BaseException:
            cleanup_failed = True
        try:
            pf._assert_same_snapshot(before, pf._pf_snapshot(runner))
        except BaseException:
            cleanup_failed = True
    if cleanup_failed:
        raise LiveSiteError("live-site cleanup failed") from None
    if failure is not None:
        failure_name = type(failure).__name__
        if len(failure_name) > 64 or not failure_name.isidentifier():
            failure_name = "Exception"
        raise LiveSiteError(
            f"live-site execution failed at {failure_stage} ({failure_name})"
        ) from None
    if any(item["result"] == "terminal_error" for item in results):
        overall = "failed"
    elif any(item["result"] == "inconclusive" for item in results):
        overall = "inconclusive"
    elif len(results) == len(SITES):
        overall = "passed"
    else:
        overall = "failed"
    exit_status = {"passed": 0, "failed": 1, "inconclusive": 2}[overall]
    report = {
        "schema_version": SCHEMA_VERSION,
        "harness": "safari_chrome_live_sites",
        "harness_exit_status": exit_status,
        "result": overall,
        "sites": results,
    }
    return report, exit_status


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-bundle", type=Path, required=True)
    parser.add_argument("--chrome-executable", type=Path, required=True)
    parser.add_argument("--safaridriver-url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report, exit_status = run_gate(
        args.app_bundle, args.chrome_executable, args.safaridriver_url
    )
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return exit_status


if __name__ == "__main__":
    raise SystemExit(main())
