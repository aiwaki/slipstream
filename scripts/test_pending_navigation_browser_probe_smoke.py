import tempfile
from pathlib import Path
import subprocess
from unittest import mock

import pytest

from scripts import pending_navigation_browser_probe_smoke as smoke


def test_worker_failure_diagnostic_reports_only_static_worker_category() -> None:
    worker = subprocess.CompletedProcess(
        ("slipstream",),
        17,
        stdout="ignored",
        stderr="slipstream browser probe failed: claimed_job_invalid\n",
    )

    assert smoke._worker_failure_diagnostic(worker) == (
        "exit=17; detail=slipstream browser probe failed: claimed_job_invalid"
    )


def test_worker_failure_diagnostic_redacts_unstructured_output() -> None:
    worker = subprocess.CompletedProcess(
        ("slipstream",),
        17,
        stdout="ignored",
        stderr="first line\n" + "x" * 800,
    )

    diagnostic = smoke._worker_failure_diagnostic(worker)

    assert diagnostic == "exit=17; detail=<redacted>"
    assert "\n" not in diagnostic
    assert len(diagnostic) <= smoke.WORKER_DIAGNOSTIC_MAX_CHARS + 32


def test_profile_residue_matches_only_exact_worker_nonce() -> None:
    with tempfile.TemporaryDirectory() as raw_directory:
        root = Path(raw_directory)
        expected = root / ("slipstream-browser-probe-" + "a" * 32)
        expected.mkdir()
        (root / "slipstream-browser-probe-smoke-fixture").mkdir()
        (root / ("slipstream-browser-probe-" + "g" * 32)).mkdir()
        (root / ("slipstream-browser-probe-" + "b" * 31)).mkdir()

        assert smoke._profile_residue(root) == {expected}


def _snapshot(
    *,
    front="ASN:0x0-0x1001:",
    windows=(),
    registered=False,
    dock=False,
    gui=(),
    headless=(),
):
    return smoke.VisibilitySnapshot(
        frontmost_asn=front,
        slipstream_window_ids=frozenset(windows),
        slipstream_launch_services=registered,
        slipstream_dock_visible=dock,
        gui_chrome_pids=frozenset(gui),
        headless_shell_pids=frozenset(headless),
    )


def test_launch_services_parser_distinguishes_uielement_from_dock_app() -> None:
    listing = '''1) "Slipstream" ASN:0x0-0x1001:
    bundleID="org.slipstream.slipstream"
    bundle path="/Applications/Slipstream.app"
    pid = 123 type="UIElement" flavor=3
'''
    assert smoke._slipstream_launch_services_state(listing) == (True, False)


@pytest.mark.parametrize(
    ("samples", "events", "message"),
    (
        ([_snapshot(windows={17})], [], "CoreGraphics window"),
        ([_snapshot(front="ASN:0x0-0x2002:")], [], "frontmost"),
        ([_snapshot(dock=True)], [], "Dock"),
        ([_snapshot(registered=True)], [], "LaunchServices"),
        ([_snapshot(gui={42})], [], "GUI Chrome"),
        ([_snapshot()], ["PostShowProcess Slipstream"], "LaunchServices"),
    ),
)
def test_visibility_monitor_fails_closed(samples, events, message) -> None:
    with mock.patch.object(smoke, "_visibility_snapshot", return_value=_snapshot()):
        monitor = smoke.VisibilityMonitor()
    monitor.samples.extend(samples)
    monitor.events = events
    with pytest.raises(smoke.QualificationError, match=message):
        monitor.assert_invisible(_snapshot())


def test_packaged_smoke_does_not_claim_visibility_by_constant() -> None:
    source = Path(smoke.__file__).read_text(encoding="utf-8")
    assert '"visible_window": False' not in source
    assert "CGWindowListCopyWindowInfo" in source
    assert 'LSAPPINFO, "listen", "+all"' in source
    assert "PendingNavigationBrowserWorkerLauncher" not in source
