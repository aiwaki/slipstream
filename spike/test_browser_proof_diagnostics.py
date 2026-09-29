"""Fail-closed worker diagnostics, with no live network or private URL logging."""
import asyncio
import subprocess
from types import SimpleNamespace

import pytest
import tproxy
import pending_navigation_probe_runtime as runtime_module


@pytest.mark.parametrize('failure,reason', [
    ('type', 'result_type_refused'),
    ('navigation_pending', 'result_outcome_navigation_pending'),
    ('private-url?secret', 'result_outcome_invalid'),
    ('route', 'result_route_refused'),
    ('pid', 'result_backend_changed'),
    ('timeout', 'wait_timeout'),
    ('io', 'wait_io_failed'),
    ('runtime', 'wait_runtime_failed'),
])
def test_worker_refusal_is_specific_and_cleans_capability(monkeypatch, failure, reason):
    records = []
    job = tproxy.route_preflight.RoutePreflightJobV1('a'*32, 'example.com', ('owned_geph',), 1, 8001)
    monkeypatch.setattr(tproxy, '_route_preflight_headless_available', True)
    monkeypatch.setattr(tproxy, '_headless_preflight_breaker_allows', lambda: True)
    monkeypatch.setattr(tproxy, '_owned_geph_confirmation_pid', lambda: 42)
    monkeypatch.setattr(tproxy, '_owned_geph_ready_for_semantic_confirmation', lambda: True)
    matches = iter([True, failure != 'pid'])
    monkeypatch.setattr(tproxy, '_owned_geph_confirmation_pid_matches', lambda _: next(matches))
    monkeypatch.setattr(tproxy, '_route_preflight_browser_capabilities', {})
    monkeypatch.setattr(tproxy, '_route_preflight_browser_claims', {})
    monkeypatch.setattr(tproxy, '_enqueue_route_preflight_root_diagnostic_record', records.append)
    discarded = []
    runtime = SimpleNamespace(enqueue=lambda *a, **k: True, discard=discarded.append)
    monkeypatch.setattr(tproxy, '_get_pending_navigation_probe_runtime', lambda: runtime)

    def notify():
        future = tproxy._route_preflight_browser_capabilities[job.capability].future
        errors = {'timeout': asyncio.TimeoutError, 'io': OSError, 'runtime': RuntimeError}
        if failure in errors:
            future.set_exception(errors[failure]('private-url?secret'))
        else:
            result = tproxy.route_preflight.RoutePreflightResultV1(
                job.capability, job.host, 'system' if failure == 'route' else 'owned_geph',
                failure if failure in ('navigation_pending', 'private-url?secret') else 'usable', 2)
            future.set_result(None if failure == 'type' else result)
        return True

    monkeypatch.setattr(tproxy, '_get_pending_navigation_probe_worker',
                        lambda **k: SimpleNamespace(notify_job_ready=notify, active=lambda: True))
    result = asyncio.run(tproxy._run_admitted_headless_owned_geph_preflight(
        job, None, tproxy.time.monotonic()+5, exact_address='1.1.1.1',
        provenance_already_accepted=True))
    assert result is None
    assert records == [f'>> browser-proof reason={reason}']
    assert discarded == [job.capability]
    assert not tproxy._route_preflight_browser_capabilities


@pytest.mark.parametrize('target', ['helper', 'bundle'])
def test_signature_timeout_identifies_target_without_skipping_validation(tmp_path, target):
    executable = tmp_path/'Slipstream.app'/'Contents'/'MacOS'/'slipstream-browser-probe'
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b'fixture')
    executable.chmod(0o755)
    import os
    identity = runtime_module.ConsoleUserIdentity(os.getuid(), os.getgid(), 'user', '/tmp')
    calls = []
    def codesign(command, **kwargs):
        calls.append(command)
        if ('--deep' in command) == (target == 'bundle'):
            raise subprocess.TimeoutExpired(command, kwargs['timeout'])
        return SimpleNamespace(returncode=0)
    launcher = runtime_module.DirectHeadlessBrowserWorkerLauncher(
        executable=executable, geph_port=9954, identity_probe=lambda: identity,
        codesign_runner=codesign, effective_uid=lambda: 0)
    with pytest.raises(runtime_module.PendingNavigationProbeRuntimeError,
                       match=f'^browser_worker_signature_{target}_timeout$'):
        launcher.launch()
    assert len(calls) == (2 if target == 'bundle' else 1)
