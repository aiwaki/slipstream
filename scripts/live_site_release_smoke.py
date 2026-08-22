#!/usr/bin/env python3
"""Run the fixed Safari and Chrome release-site gate on disposable macOS."""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

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


def _readiness_blocker(host: str, signals: dict[str, object]) -> str | None:
    title = str(signals.get("title") or "").casefold()
    main_text = int(signals.get("main_text_length") or 0)
    app_text = int(signals.get("app_text_length") or 0)
    if signals.get("https") is not True or signals.get("secure_context") is not True:
        return "readiness_context_invalid"
    if signals.get("ready_state") != "complete":
        return "readiness_document_pending"
    if signals.get("visible_body") is not True:
        return "readiness_visibility_missing"
    if signals.get("next_hop_protocol") not in ALLOWED_PROTOCOLS:
        return "readiness_transport_missing"
    if host == "xpersonatoy.com":
        if "starrtoy" not in title:
            return "readiness_title_mismatch"
        return None if main_text >= 80 else "readiness_content_missing"
    if host == "app.aikido.dev":
        if "aikido security" not in title:
            return "readiness_title_mismatch"
        if (
            signals.get("visible_app") is not True
            or signals.get("preloader_visible") is not False
        ):
            return "readiness_visibility_missing"
        return None if app_text >= 20 else "readiness_content_missing"
    if host == "weather.com":
        if "weather" not in title:
            return "readiness_title_mismatch"
        return None if main_text >= 100 else "readiness_content_missing"
    if host == "capacitorjs.com":
        if "capacitor" not in title:
            return "readiness_title_mismatch"
        return None if main_text >= 100 else "readiness_content_missing"
    return "readiness_content_missing"


def _positive_readiness(host: str, signals: dict[str, object]) -> bool:
    return _readiness_blocker(host, signals) is None


def _classify_evidence(
    host: str,
    *,
    document_bytes: int,
    denial_detected: bool,
    challenge_detected: bool,
    signals: dict[str, object] | None = None,
) -> tuple[str, str]:
    if document_bytes < MIN_DOCUMENT_BYTES:
        return "terminal_error", "document_too_short"
    if denial_detected:
        if host == "weather.com":
            return "regional_access_denied", "regional_access_denied"
        if host == "capacitorjs.com":
            return "edge_access_denied", "edge_access_denied"
        return "terminal_error", "navigation_denied"
    if challenge_detected:
        return "challenge_or_auth", "challenge_or_auth"
    if signals is None:
        return "terminal_error", "readiness_signals_invalid"
    try:
        blocker = _readiness_blocker(host, signals)
    except (TypeError, ValueError):
        return "terminal_error", "readiness_signals_invalid"
    if blocker is None:
        return "usable", ""
    return "terminal_error", blocker


def _classify_document_evidence(
    host: str, document: str, signals: dict[str, object] | None = None
) -> tuple[str, str]:
    lowered = document.casefold()
    return _classify_evidence(
        host,
        document_bytes=len(document.encode("utf-8")),
        denial_detected=any(marker in lowered for marker in SITES[host]["denials"]),
        challenge_detected=any(marker in lowered for marker in CHALLENGE_MARKERS),
        signals=signals,
    )


def _classify_chrome_evidence(host: str, evidence: object) -> tuple[str, str]:
    expected = {
        "challenge_detected",
        "denial_detected",
        "document_bytes",
        "signals",
    }
    if not isinstance(evidence, dict) or set(evidence) != expected:
        return "terminal_error", "document_invalid"
    document_bytes = evidence.get("document_bytes")
    denial_detected = evidence.get("denial_detected")
    challenge_detected = evidence.get("challenge_detected")
    signals = evidence.get("signals")
    if (
        isinstance(document_bytes, bool)
        or not isinstance(document_bytes, int)
        or document_bytes < 0
        or not isinstance(denial_detected, bool)
        or not isinstance(challenge_detected, bool)
    ):
        return "terminal_error", "document_invalid"
    return _classify_evidence(
        host,
        document_bytes=document_bytes,
        denial_detected=denial_detected,
        challenge_detected=challenge_detected,
        # Keep the prior classifier ordering: a fixed denial or challenge is
        # still meaningful even if the accompanying readiness object is bad.
        signals=signals if isinstance(signals, dict) else None,
    )


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
  const boundedString = (value, maximum) => String(value || '').slice(0, maximum);
  const textLength = (node) => node ? (node.innerText || '').trim().length : 0;
  const navigation = performance.getEntriesByType('navigation')[0];
  const app = document.querySelector('#app');
  const preloader = document.querySelector('#preloader__root');
  return {
    app_text_length: textLength(app),
    body_text_length: textLength(document.body),
    https: location.protocol === 'https:',
    main_text_length: textLength(document.querySelector('main')),
    next_hop_protocol: navigation ? boundedString(navigation.nextHopProtocol, 32) : '',
    preloader_visible: visible(preloader),
    ready_state: document.readyState,
    secure_context: window.isSecureContext === true,
    title: boundedString(document.title, 512),
    visible_app: visible(app),
    visible_body: visible(document.body)
  };
})()
"""


def _chrome_evidence_expression(host: str) -> str:
    denials = json.dumps(SITES[host]["denials"])
    challenges = json.dumps(CHALLENGE_MARKERS)
    # CDP transport has a strict bounded response size. Inspect the document
    # inside the page and return only fixed booleans, a byte count, and the
    # existing readiness object; raw page content never crosses DevTools.
    return f"""
(() => {{
  const documentSource = document.documentElement.outerHTML;
  const lowered = documentSource.toLowerCase();
  return {{
    challenge_detected: {challenges}.some((marker) => lowered.includes(marker)),
    denial_detected: {denials}.some((marker) => lowered.includes(marker)),
    document_bytes: new TextEncoder().encode(documentSource).length,
    signals: ({READINESS_EXPRESSION})
  }};
}})()
"""


def _run_chrome(host: str, executable: Path, uid: int, gid: int) -> dict[str, object]:
    executable = executable.resolve(strict=True)
    environment, home = lifecycle._user_environment(uid)
    groups = lifecycle._user_supplementary_groups(uid, gid)
    profile = Path(tempfile.mkdtemp(prefix="slipstream-release-chrome-"))
    chrome_stdout_path = profile / "chrome.stdout"
    chrome_stderr_path = profile / "chrome.stderr"
    launcher_stdout_path = profile / "launcher.stdout"
    launcher_stderr_path = profile / "launcher.stderr"
    plist_path = profile / "chrome-launch-agent.plist"
    label = (
        f"{chromium.CHROME_JOB_PREFIX}.live.{os.getpid()}."
        f"{profile.name.rsplit('-', 1)[-1]}"
    )
    launch: chromium.ChromeLaunch | None = None
    browser: chromium.ChromeProcess | None = None
    ownership = chromium.ChromeOwnership(set())
    bootstrap_started = False
    attempt_started = time.monotonic()
    observation_started: float | None = None
    finished = attempt_started
    outcome = "terminal_error"
    reason = "browser_start_failed"
    failure_reason = reason
    failure: BaseException | None = None
    try:
        os.chown(profile, uid, gid)
        profile.chmod(0o700)
        application_bundle = chromium._launchservices_app_bundle(
            executable,
            profile,
            uid,
            gid,
        )
        executable = chromium._launchservices_executable(
            executable,
            application_bundle,
        )
        for path in (
            chrome_stdout_path,
            chrome_stderr_path,
            launcher_stdout_path,
            launcher_stderr_path,
        ):
            chromium._write_owner_private_file(path, b"", uid, gid)
        browser_command = _chrome_command(executable, profile)
        open_command = chromium._launchservices_open_command(
            application_bundle,
            browser_command,
            chrome_stdout_path,
            chrome_stderr_path,
        )
        payload = chromium._launchservices_launch_agent_payload(
            label,
            environment,
            home,
            open_command,
            launcher_stdout_path,
            launcher_stderr_path,
        )
        chromium._write_owner_private_file(
            plist_path,
            plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=True),
            uid,
            gid,
        )
        bootstrap_started = True
        launch = chromium._bootstrap_chrome_launch_agent(uid, label, plist_path)
        browser = chromium._wait_for_owned_chrome_process(
            uid,
            executable,
            profile,
            ownership,
        )
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
        observation_started = time.monotonic()
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
        reason = failure_reason
        deadline = observation_started + SITES[host]["deadline_ms"] / 1000
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                evaluated = chromium._devtools_command(
                    debugger,
                    port,
                    "Runtime.evaluate",
                    {
                        "expression": _chrome_evidence_expression(host),
                        "returnByValue": True,
                    },
                    response_timeout=min(2.0, remaining),
                ).get("result")
                evidence = (
                    evaluated.get("value") if isinstance(evaluated, dict) else None
                )
            except (chromium.QualificationError, TimeoutError):
                # Navigation can replace the execution context and a bounded
                # DevTools request can time out. Neither authorizes a pass;
                # keep polling only inside the unchanged host deadline.
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    time.sleep(min(0.25, remaining))
                continue
            outcome, reason = _classify_chrome_evidence(host, evidence)
            # A static app shell reaches readyState=complete before its JS has
            # rendered a useful interface. Keep polling until a fixed positive
            # signal, a fixed denial, or the site deadline. A challenge remains
            # non-passing but may resolve within the same bounded navigation.
            if outcome in {
                "usable",
                "regional_access_denied",
                "edge_access_denied",
            }:
                break
            time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
        finished = time.monotonic()
    except BaseException as exc:
        failure = exc
        finished = time.monotonic()
    finally:
        cleanup_failed = False
        profile_cleanup_safe = not bootstrap_started
        try:
            if launch is not None:
                chromium._stop_chrome_launch_agent(
                    launch,
                    uid=uid,
                    gid=gid,
                    supplementary_groups=groups,
                    executable=executable,
                    profile=profile,
                    ownership=ownership,
                    post_bootout_settle_time=5.0 if browser is None else 0.0,
                )
                profile_cleanup_safe = True
            elif bootstrap_started:
                partial_errors: list[BaseException] = []
                try:
                    chromium._wait_for_launch_agent_absence(f"gui/{uid}/{label}")
                except BaseException as exc:
                    partial_errors.append(exc)
                try:
                    chromium._stop_owned_chrome_processes(
                        uid,
                        executable,
                        profile,
                        ownership,
                        timeout=10.0,
                        settle_time=5.0,
                    )
                except BaseException as exc:
                    partial_errors.append(exc)
                if partial_errors:
                    raise LiveSiteError(
                        "partial Chrome bootstrap cleanup could not be verified"
                    ) from partial_errors[0]
                profile_cleanup_safe = True
        except BaseException:
            cleanup_failed = True
        if profile_cleanup_safe:
            try:
                chromium._remove_owned_profile(profile)
            except BaseException:
                cleanup_failed = True
        else:
            cleanup_failed = True
        if cleanup_failed:
            raise LiveSiteError("Chrome cleanup failed") from None
    # Worker teardown is verified but excluded from the navigation deadline.
    elapsed_ms = (
        round((finished - observation_started) * 1000)
        if observation_started is not None
        else 0
    )
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


SAFARI_INVALID_READINESS_SIGNALS = "Safari returned invalid readiness signals"


def _decode_safari_readiness_signals(value: object) -> dict[str, object]:
    if not isinstance(value, str):
        raise LiveSiteError(SAFARI_INVALID_READINESS_SIGNALS)
    try:
        signals = json.loads(value)
    except json.JSONDecodeError:
        raise LiveSiteError(SAFARI_INVALID_READINESS_SIGNALS) from None
    if not isinstance(signals, dict):
        raise LiveSiteError(SAFARI_INVALID_READINESS_SIGNALS)
    return signals


def _is_safari_observation_timeout(error: lifecycle.LifecycleError) -> bool:
    return isinstance(error.__cause__, TimeoutError)


def _run_safari(host: str, driver_url: str, uid: int) -> dict[str, object]:
    session_id = None
    safari_pid = None
    document = ""
    outcome = "terminal_error"
    reason = "driver_unavailable"
    failure_reason = reason
    attempt_started = time.monotonic()
    observation_started: float | None = None
    finished = attempt_started
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
                        # The live gate itself must observe incomplete and
                        # challenge documents. "normal" blocks that poll
                        # until load completes; this changes only WebDriver's
                        # return condition, not the fixed observation window
                        # or its strict pass criteria.
                        "pageLoadStrategy": "none",
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
        observation_started = time.monotonic()
        absolute_deadline = observation_started + deadline / 1000
        lifecycle._webdriver_request(
            driver_url,
            "POST",
            f"/session/{encoded}/url",
            {"url": f"https://{host}/"},
            timeout=deadline / 1000 + 5,
        )
        failure_reason = "browser_observation_failed"
        reason = failure_reason
        while time.monotonic() < absolute_deadline:
            # A successful decode may still leave the current document pending.
            # Reset before each later WebDriver request so an HTTP/timeout
            # failure is not mislabeled as a prior serialization failure.
            failure_reason = "browser_observation_failed"
            try:
                remaining = absolute_deadline - time.monotonic()
                if remaining <= 0:
                    break
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
                remaining = absolute_deadline - time.monotonic()
                if remaining <= 0:
                    break
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
            except lifecycle.LifecycleError as exc:
                if not _is_safari_observation_timeout(exc):
                    raise
                remaining = absolute_deadline - time.monotonic()
                if remaining > 0:
                    time.sleep(min(0.25, remaining))
                continue
            failure_reason = "readiness_signals_invalid"
            signals = _decode_safari_readiness_signals(serialized_signals)
            outcome, reason = _classify_document_evidence(host, document, signals)
            if outcome in {
                "usable",
                "regional_access_denied",
                "edge_access_denied",
            }:
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
    elapsed_ms = (
        round((finished - observation_started) * 1000)
        if observation_started is not None
        else 0
    )
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
