import hashlib
import tempfile
from pathlib import Path
import subprocess
from unittest import mock

import pytest

from scripts import pending_navigation_browser_probe_smoke as smoke

EXPECTED_SHELL = Path("/private/runtime/chrome-headless-shell")


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


def test_pinned_executable_identity_requires_manifest_digest_and_stability() -> None:
    with tempfile.TemporaryDirectory() as raw_directory:
        root = Path(raw_directory)
        executable = root / "chrome-headless-shell"
        executable.write_bytes(b"pinned-shell")
        digest = hashlib.sha256(b"pinned-shell").hexdigest()
        (root / "manifest.json").write_text(
            '{"executable_sha256":"' + digest + '"}',
            encoding="utf-8",
        )

        identity = smoke._pinned_executable_identity(executable)
        smoke._assert_pinned_executable_unchanged(identity)

        executable.write_bytes(b"replaced-shell")
        with pytest.raises(smoke.QualificationError, match="digest changed"):
            smoke._assert_pinned_executable_unchanged(identity)


def _snapshot(
    *,
    front="ASN:0x0-0x1001:",
    windows=(),
    registered=False,
    dock=False,
    gui=(),
    headless=(),
    roots=(),
    entries=(),
):
    return smoke.VisibilitySnapshot(
        frontmost_asn=front,
        slipstream_window_ids=frozenset(windows),
        slipstream_launch_services=registered,
        slipstream_dock_visible=dock,
        gui_chrome_pids=frozenset(gui),
        headless_shell_pids=frozenset(headless),
        headless_shell_root_pids=frozenset(roots),
        launch_services_entries=tuple(entries),
    )


def test_launch_services_parser_distinguishes_uielement_from_dock_app() -> None:
    listing = '''1) "Slipstream" ASN:0x0-0x1001:
    bundleID="org.slipstream.slipstream"
    bundle path="/Applications/Slipstream.app"
    pid = 123 type="UIElement" flavor=3
'''
    assert smoke._slipstream_launch_services_state(listing) == (True, False)
    assert smoke._slipstream_launch_services_entries(listing) == (
        smoke.LaunchServicesEntry(
            pid=123,
            executable_path=None,
            application_type="UIElement",
            dock_visible=False,
        ),
    )


def test_browser_process_snapshot_attributes_only_process_group_root() -> None:
    listing = """731  44 731 /private/runtime/chrome-headless-shell --headless=new
732 731 731 /private/runtime/chrome-headless-shell --type=renderer
733  44 733 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
"""

    assert smoke._browser_process_snapshot(listing) == (
        frozenset({733}),
        frozenset({731, 732}),
        frozenset({731}),
    )


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
        monitor = smoke.VisibilityMonitor(EXPECTED_SHELL)
    monitor.samples.extend(samples)
    monitor.events = events
    with pytest.raises(smoke.QualificationError, match=message):
        monitor.assert_invisible(_snapshot())


def _launch_event(
    name: str,
    *,
    pid: int = 731,
    include_path: bool = True,
    include_marker: bool = True,
) -> str:
    fields = [
        '"ApplicationType"="UIElement"',
        '"LSASN"=ASN:0x0-0x731731:',
        f'"pid"={pid}',
    ]
    if include_path:
        fields.append(f'"CFBundleExecutablePath"="{EXPECTED_SHELL}"')
    affected = (
        'affectedASN="chrome-headless-shell" ASN:0x0-0x731731:'
        if include_marker
        else "affectedASN=ASN:0x0-0x731731:"
    )
    return (
        f"Notification: {name} time=now dataRef={{ "
        + ", ".join(fields)
        + f" }} {affected}"
    )


def test_visibility_monitor_allows_only_complete_owned_hidden_ls_lifecycle() -> None:
    entry = smoke.LaunchServicesEntry(
        pid=731,
        executable_path=str(EXPECTED_SHELL),
        application_type="UIElement",
        dock_visible=False,
    )
    with mock.patch.object(smoke, "_visibility_snapshot", return_value=_snapshot()):
        monitor = smoke.VisibilityMonitor(EXPECTED_SHELL)
    monitor.samples.extend(
        [
            _snapshot(
                registered=True,
                headless={731},
                roots={731},
                entries={entry},
            ),
            _snapshot(),
        ]
    )
    monitor.events = [
        _launch_event("kLSNotifyApplicationCreation"),
        _launch_event("kLSNotifyApplicationTypeChanged", include_path=False),
        _launch_event("kLSNotifyApplicationDeath"),
    ]

    assert monitor.assert_invisible(_snapshot()) == 3


def test_hidden_launch_services_contract_accepts_quoted_lsasn_value() -> None:
    events = [
        _launch_event("kLSNotifyApplicationCreation"),
        _launch_event("kLSNotifyApplicationTypeChanged", include_path=False),
        _launch_event("kLSNotifyApplicationDeath"),
    ]
    events = [
        event.replace(
            '"LSASN"=ASN:0x0-0x731731:',
            '"LSASN" = "ASN:0x0-0x731731:"',
        )
        for event in events
    ]

    assert smoke._assert_hidden_launch_services_events(
        events,
        expected_shell=EXPECTED_SHELL,
        observed_root_pids=frozenset({731}),
    ) == 3


def test_hidden_launch_services_contract_accepts_only_unique_asn_fallback() -> None:
    events = [
        _launch_event("kLSNotifyApplicationCreation").replace('"LSASN"=', ""),
        _launch_event(
            "kLSNotifyApplicationTypeChanged", include_path=False
        ).replace('"LSASN"=', ""),
        _launch_event("kLSNotifyApplicationDeath").replace('"LSASN"=', ""),
    ]

    assert smoke._assert_hidden_launch_services_events(
        events,
        expected_shell=EXPECTED_SHELL,
        observed_root_pids=frozenset({731}),
    ) == 3


def test_hidden_launch_services_contract_rejects_ambiguous_asn_fallback() -> None:
    event = _launch_event("kLSNotifyApplicationCreation").replace(
        '"LSASN"=ASN:0x0-0x731731:',
        'sourceASN=ASN:0x0-0x999999:',
    )

    with pytest.raises(
        smoke.QualificationError,
        match="omitted or ambiguously encoded",
    ):
        smoke._assert_hidden_launch_services_events(
            [event],
            expected_shell=EXPECTED_SHELL,
            observed_root_pids=frozenset({731}),
        )


def test_hidden_launch_services_contract_accepts_unknown_single_asn_wrapper() -> None:
    events = [
        _launch_event("kLSNotifyApplicationCreation"),
        _launch_event("kLSNotifyApplicationTypeChanged", include_path=False),
        _launch_event("kLSNotifyApplicationDeath"),
    ]
    events = [
        event.replace(
            '"LSASN"=ASN:0x0-0x731731:',
            '"LSASN"=<canonical ASN:0x0-0x731731:>',
        )
        for event in events
    ]

    assert smoke._assert_hidden_launch_services_events(
        events,
        expected_shell=EXPECTED_SHELL,
        observed_root_pids=frozenset({731}),
    ) == 3


def test_hidden_launch_services_contract_rejects_missing_anchor_asn() -> None:
    event = (
        _launch_event("kLSNotifyApplicationCreation")
        .replace(
            '"LSASN"=ASN:0x0-0x731731:',
            '"LSASN"=<missing>',
        )
        .replace(" ASN:0x0-0x731731:", "")
    )

    with pytest.raises(
        smoke.QualificationError,
        match=r"canonical_asn_count=0, explicit_lsasn_token=True",
    ):
        smoke._assert_hidden_launch_services_events(
            [event],
            expected_shell=EXPECTED_SHELL,
            observed_root_pids=frozenset({731}),
        )


def test_hidden_launch_services_contract_rejects_unknown_ambiguous_wrapper() -> None:
    event = _launch_event("kLSNotifyApplicationCreation").replace(
        '"LSASN"=ASN:0x0-0x731731:',
        '"LSASN"=<canonical ASN:0x0-0x731731: source ASN:0x0-0x999999:>',
    )

    with pytest.raises(
        smoke.QualificationError,
        match=r"canonical_asn_count=2, explicit_lsasn_token=True",
    ):
        smoke._assert_hidden_launch_services_events(
            [event],
            expected_shell=EXPECTED_SHELL,
            observed_root_pids=frozenset({731}),
        )


@pytest.mark.parametrize(
    ("events", "message"),
    (
        (
            [
                _launch_event("kLSNotifyApplicationCreation"),
                _launch_event(
                    "PostShowProcess",
                    include_path=False,
                    include_marker=False,
                ),
                _launch_event("kLSNotifyApplicationDeath"),
            ],
            "visible LaunchServices",
        ),
        (
            [
                _launch_event("kLSNotifyApplicationCreation"),
                _launch_event("kLSNotifyApplicationDeath", pid=999),
            ],
            "unowned process",
        ),
        (
            [_launch_event("kLSNotifyApplicationCreation")],
            "fully exit",
        ),
        (
            [
                _launch_event("kLSNotifyApplicationCreation"),
                _launch_event(
                    "kLSNotifySomethingNew",
                    include_path=False,
                    include_marker=False,
                ),
                _launch_event("kLSNotifyApplicationDeath"),
            ],
            "unexpected LaunchServices",
        ),
    ),
)
def test_hidden_launch_services_event_contract_fails_closed(events, message) -> None:
    with pytest.raises(smoke.QualificationError, match=message):
        smoke._assert_hidden_launch_services_events(
            events,
            expected_shell=EXPECTED_SHELL,
            observed_root_pids=frozenset({731}),
        )


def test_hidden_launch_services_event_contract_rejects_listener_blindness() -> None:
    with pytest.raises(smoke.QualificationError, match="no owned lifecycle"):
        smoke._assert_hidden_launch_services_events(
            [],
            expected_shell=EXPECTED_SHELL,
            observed_root_pids=frozenset({731}),
        )


@pytest.mark.parametrize("event_name", smoke.FORBIDDEN_LAUNCH_SERVICES_EVENTS)
def test_every_visible_launch_services_event_is_rejected(event_name) -> None:
    events = [
        _launch_event("kLSNotifyApplicationCreation"),
        _launch_event(
            event_name,
            include_path=False,
            include_marker=False,
        ),
        _launch_event("kLSNotifyApplicationDeath"),
    ]

    with pytest.raises(smoke.QualificationError, match="visible LaunchServices"):
        smoke._assert_hidden_launch_services_events(
            events,
            expected_shell=EXPECTED_SHELL,
            observed_root_pids=frozenset({731}),
        )


def test_visibility_monitor_rejects_wrong_shell_path_and_lingering_entry() -> None:
    wrong_entry = smoke.LaunchServicesEntry(
        pid=731,
        executable_path="/tmp/chrome-headless-shell",
        application_type="UIElement",
        dock_visible=False,
    )
    with mock.patch.object(smoke, "_visibility_snapshot", return_value=_snapshot()):
        monitor = smoke.VisibilityMonitor(EXPECTED_SHELL)
    monitor.samples.append(
        _snapshot(
            registered=True,
            headless={731},
            roots={731},
            entries={wrong_entry},
        )
    )
    with pytest.raises(smoke.QualificationError, match="non-pinned"):
        monitor.assert_invisible(_snapshot())

    with pytest.raises(smoke.QualificationError, match="left a LaunchServices"):
        monitor.assert_invisible(
            _snapshot(registered=True, roots={731}, entries={wrong_entry})
        )


def test_packaged_smoke_does_not_claim_visibility_by_constant() -> None:
    source = Path(smoke.__file__).read_text(encoding="utf-8")
    assert '"visible_window": False' not in source
    assert "CGWindowListCopyWindowInfo" in source
    assert 'LSAPPINFO, "listen", "+all"' in source
    assert "PendingNavigationBrowserWorkerLauncher" not in source


def test_packaged_smoke_launches_only_the_non_gui_auxiliary_helper() -> None:
    source = Path(smoke.__file__).read_text(encoding="utf-8")

    assert smoke.PACKAGED_BROWSER_WORKER_RELATIVE == Path(
        "Contents/MacOS/slipstream-browser-probe"
    )
    assert '"Contents" / "MacOS" / "slipstream"' not in source
