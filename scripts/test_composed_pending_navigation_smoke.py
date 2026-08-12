from pathlib import Path
import os
import tempfile

import pytest

from scripts import composed_pending_navigation_smoke as smoke


def _ci_environment() -> dict[str, str]:
    return {
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "SLIPSTREAM_DISPOSABLE_CI": "1",
    }


def test_disposable_guard_requires_all_three_markers(monkeypatch) -> None:
    monkeypatch.setattr(smoke.os, "environ", _ci_environment())
    smoke.require_disposable_ci()

    monkeypatch.setattr(smoke.os, "environ", {"CI": "true"})
    with pytest.raises(smoke.ComposedQualificationError, match="missing"):
        smoke.require_disposable_ci()


def test_original_navigation_command_is_extension_free_and_targets_public_ip(
    tmp_path: Path,
) -> None:
    command = smoke.original_navigation_command(Path("/tmp/Chrome"), tmp_path)

    assert command[0] == "/tmp/Chrome"
    assert "--disable-extensions" in command
    assert "--disable-quic" in command
    assert "--ignore-certificate-errors" in command
    assert any(smoke.FIXTURE_PUBLIC_IP in value for value in command)
    assert command[-1] == f"https://{smoke.FIXTURE_HOST}/"


def test_qualification_environment_is_exact_and_keeps_the_production_socket(
    monkeypatch,
) -> None:
    monkeypatch.setattr(smoke.os, "environ", _ci_environment())
    with tempfile.TemporaryDirectory() as raw_directory:
        root = Path(raw_directory)
        chrome = root / "Chrome"
        chrome.write_bytes(b"chrome")
        chrome.chmod(0o755)
        fixture = smoke.ComposedHttpsFixture()
        fixture._worker_port = 18443
        fixture._original_port = 19443
        try:
            environment = fixture.qualification_environment(chrome)
        finally:
            fixture.close()

    assert set(environment) == smoke.DISPOSABLE_QUALIFICATION_ENVIRONMENT_KEYS
    assert "SLIPSTREAM_BROWSER_PROBE_SOCKET" not in environment
    assert environment["SLIPSTREAM_BROWSER_PROBE_ORIGIN"] == (
        f"https://{smoke.FIXTURE_HOST}:18443/"
    )
    assert environment[smoke.DAEMON_FIXTURE_PORT_ENV] == "19443"


def test_report_requires_original_worker_original_timing_and_resources() -> None:
    fixture = smoke.ComposedHttpsFixture()
    try:
        fixture._records = [
            {"channel": "original", "path": "/", "count": 1, "elapsed_ms": 100},
            {"channel": "worker", "path": "/", "count": 2, "elapsed_ms": 8_100},
            {"channel": "original", "path": "/", "count": 3, "elapsed_ms": 16_100},
        ]
        fixture._counts.update({"root": 3, "css": 1, "js": 1, "image": 1, "ready": 1})
        fixture._ready.set()

        report = fixture.report()

        assert report["root_channels"] == ["original", "worker", "original"]
        assert report["ready_callbacks"] == 1
        fixture._records[1]["elapsed_ms"] = 7_000
        with pytest.raises(
            smoke.ComposedQualificationError,
            match="observation windows",
        ):
            fixture.report()
    finally:
        fixture.close()


@pytest.mark.parametrize(
    ("value", "expected"),
    (("01:02", 62.0), ("01:02:03", 3723.0), ("00:00.50", 0.5)),
)
def test_cpu_time_parser(value: str, expected: float) -> None:
    assert smoke._cpu_seconds(value) == expected


def test_worker_diagnostics_is_bounded_to_owned_metadata(
    monkeypatch,
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    launch = runtime / "dev.slipstream.browser-probe.0123456789abcdef"
    launch.mkdir(mode=0o700)
    for name in ("worker.plist", "worker.stdout.log", "worker.stderr.log"):
        (launch / name).write_bytes(b"private")
    profile = tmp_path / ("slipstream-browser-probe-" + "a" * 32)
    profile.mkdir()
    monkeypatch.setattr(smoke, "PRODUCTION_WORKER_RUNTIME", runtime)
    monkeypatch.setattr(smoke, "_worker_processes", lambda _uid: (123,))
    monkeypatch.setattr(smoke, "_worker_profiles", lambda: (profile,))

    diagnostic = smoke.worker_diagnostics(os.getuid())

    assert diagnostic["processes"] == (123,)
    assert diagnostic["profiles"] == (profile.name,)
    assert diagnostic["runtime"] == ({
        "name": launch.name,
        "owner": os.getuid(),
        "mode": "0700",
        "entries": (
            "worker.plist",
            "worker.stderr.log",
            "worker.stdout.log",
        ),
    },)
