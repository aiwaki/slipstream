import io
import json
import os
from pathlib import Path
import tempfile
import time
from unittest import mock

import pytest

from scripts import macos_update_notification_smoke as smoke


SOURCE = "1" * 40
DIGEST = "2" * 64
NONCE = "3" * 64


def _identity(root: Path) -> smoke.CandidateIdentity:
    app = root / "Slipstream.app"
    executable = app / "Contents/MacOS/slipstream"
    executable.parent.mkdir(parents=True, exist_ok=True)
    executable.write_bytes(b"exact packaged executable")
    return smoke.CandidateIdentity(
        app_bundle=app,
        executable=executable,
        app_tree_sha256="4" * 64,
        executable_sha256=smoke._sha256(executable),
        manifest_sha256="5" * 64,
        candidate_id=f"release-candidate-{SOURCE}",
    )


def _template(root: Path, *, now: int = 10_000) -> dict:
    home = root / "home"
    home.mkdir(exist_ok=True)
    return smoke.build_capability_template(
        _identity(root),
        uid=501,
        gid=20,
        home=home,
        nonce=NONCE,
        issued_at_unix_ms=now,
    )


def _hook(outcome: str, **extra) -> dict:
    value = {
        "schema_version": smoke.SCHEMA_VERSION,
        "outcome": outcome,
        "identity": smoke.BUNDLE_IDENTIFIER,
        "capability_sha256": DIGEST,
    }
    if outcome != "terminal":
        value["permission_status"] = "allowed"
    value.update(extra)
    return value


def _snapshot(*, maximum=0, count=0):
    return smoke.NotificationRecordSnapshot(maximum, count)


def _visibility(*, front="ASN:0x0-0x100:", windows=(), entries=()):
    return smoke.VisibilitySnapshot(
        frontmost_asn=front,
        window_ids=frozenset(windows),
        launch_services_entries=tuple(entries),
    )


def test_capability_binds_exact_candidate_user_deadline_and_nonce() -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        template = _template(root)

        assert smoke.validate_capability_template(
            template, now_unix_ms=10_001
        ) == template
        capability = json.loads(
            smoke.finalize_root_capability(
                template, pid=733, now_unix_ms=10_001
            )
        )

    assert capability["expected_pid"] == 733
    assert capability["expected_uid"] == 501
    assert capability["candidate_id"] == f"release-candidate-{SOURCE}"
    assert capability["nonce"] == NONCE
    assert capability["deadline_unix_ms"] == (
        capability["issued_at_unix_ms"] + smoke.CAPABILITY_MAX_LIFETIME_MS
    )
    assert capability["bundle_identifier"] == smoke.BUNDLE_IDENTIFIER


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ({"purpose": "other"}, "purpose"),
        ({"nonce": "0" * 63}, "nonce"),
        ({"candidate_id": "release-candidate-main"}, "candidate ID"),
        ({"candidate_id": f"release-candidate-{'1' * 41}"}, "candidate ID"),
        ({"executable_sha256": "z" * 64}, "digest"),
        ({"expected_uid": 0}, "user identity"),
        ({"bundle_identifier": "com.apple.Finder"}, "bundle identity"),
        ({"unexpected": True}, "fields"),
    ),
)
def test_capability_rejects_spoofed_or_broadened_authority(
    mutation, message
) -> None:
    with tempfile.TemporaryDirectory() as raw:
        value = _template(Path(raw))
        value.update(mutation)
        with pytest.raises(smoke.NotificationQualificationError, match=message):
            smoke.validate_capability_template(value, now_unix_ms=10_001)


def test_capability_rejects_expired_or_overlong_deadline() -> None:
    with tempfile.TemporaryDirectory() as raw:
        value = _template(Path(raw))
        with pytest.raises(
            smoke.NotificationQualificationError, match="deadline"
        ):
            smoke.validate_capability_template(
                value, now_unix_ms=value["deadline_unix_ms"]
            )

        value = _template(Path(raw), now=20_000)
        value["deadline_unix_ms"] += 1
        with pytest.raises(
            smoke.NotificationQualificationError, match="deadline"
        ):
            smoke.validate_capability_template(value, now_unix_ms=20_001)


def test_bounded_json_rejects_oversized_capability() -> None:
    with pytest.raises(
        smoke.NotificationQualificationError, match="size limit"
    ):
        smoke._read_bounded_json(
            io.BytesIO(b"{" + b"x" * smoke.CAPABILITY_MAX_BYTES + b"}"),
            label="fixture",
        )


@pytest.mark.parametrize("permission", ("allowed", "suppressed", "unknown"))
def test_hook_result_accepts_only_fixed_non_content_outcomes(permission: str) -> None:
    value = _hook("submitted", permission_status=permission)
    parsed = smoke.parse_hook_result(
        json.dumps(value), capability_sha256=DIGEST
    )
    assert parsed["outcome"] == "submitted"
    assert set(parsed) == {
        "schema_version",
        "outcome",
        "identity",
        "capability_sha256",
        "permission_status",
    }


def test_hook_result_accepts_bounded_terminal_category() -> None:
    parsed = smoke.parse_hook_result(
        json.dumps(_hook("terminal", reason="native_submission_failed")),
        capability_sha256=DIGEST,
    )
    assert parsed["reason"] == "native_submission_failed"


@pytest.mark.parametrize("reason", sorted(smoke.TERMINAL_REASONS))
def test_validated_rust_terminal_reason_survives_failure_report(reason) -> None:
    hook_result = _hook("terminal", reason=reason)
    with pytest.raises(smoke.NotificationQualificationError) as raised:
        smoke.classify_os_observation(
            hook_result=hook_result,
            before=_snapshot(maximum=17, count=4),
            after=_snapshot(maximum=17, count=4),
        )

    assert raised.value.failure_code == reason
    assert smoke._failure_report(raised.value) == {
        "schema_version": smoke.SCHEMA_VERSION,
        "outcome": "terminal",
        "failure_code": reason,
    }


def test_failure_report_is_whitelisted_bounded_and_content_free() -> None:
    secret = "cookie=session-secret path=/private/user/url"
    report = smoke._failure_report(RuntimeError(secret))
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )

    assert report == {
        "schema_version": smoke.SCHEMA_VERSION,
        "outcome": "terminal",
        "failure_code": smoke.INTERNAL_FAILURE_CODE,
    }
    assert len(encoded) <= smoke.FAILURE_REPORT_MAX_BYTES
    assert secret.encode("utf-8") not in encoded
    with pytest.raises(ValueError, match="not whitelisted"):
        smoke.NotificationQualificationError(
            "raw detail", failure_code="raw_backend_error"
        )


@pytest.mark.parametrize(
    "mutation",
    (
        {"identity": "com.apple.Finder"},
        {"capability_sha256": "9" * 64},
        {"outcome": "visible"},
        {"body": "sensitive content"},
        {"reason": "raw backend error"},
    ),
)
def test_hook_result_rejects_wrong_identity_binding_or_raw_content(
    mutation,
) -> None:
    value = _hook("submitted")
    value.update(mutation)
    with pytest.raises(smoke.NotificationQualificationError):
        smoke.parse_hook_result(json.dumps(value), capability_sha256=DIGEST)


def test_os_observation_proves_exact_attributed_submission() -> None:
    assert (
        smoke.classify_os_observation(
            hook_result=_hook("submitted"),
            before=_snapshot(maximum=17, count=4),
            after=_snapshot(maximum=18, count=5),
        )
        == "submitted"
    )


def test_os_observation_allows_permission_suppression_without_display_claim() -> None:
    assert (
        smoke.classify_os_observation(
            hook_result=_hook("submitted", permission_status="suppressed"),
            before=_snapshot(maximum=17, count=4),
            after=_snapshot(maximum=17, count=4),
        )
        == "permission_suppressed"
    )


@pytest.mark.parametrize(
    ("outcome", "after", "message"),
    (
        ("submitted", _snapshot(maximum=17, count=4), "exactly one"),
        ("terminal", _snapshot(maximum=17, count=4), "terminal"),
        ("submitted", _snapshot(maximum=19, count=6), "changed unexpectedly"),
    ),
)
def test_os_observation_fails_closed_on_mismatch(outcome, after, message) -> None:
    result = _hook(outcome)
    if outcome == "terminal":
        result["reason"] = "native_submission_failed"
    with pytest.raises(smoke.NotificationQualificationError, match=message):
        smoke.classify_os_observation(
            hook_result=result,
            before=_snapshot(maximum=17, count=4),
            after=after,
        )


def test_unknown_or_allowed_permission_without_os_record_fails_closed() -> None:
    for permission in ("unknown", "allowed"):
        with pytest.raises(
            smoke.NotificationQualificationError, match="exactly one"
        ):
            smoke.classify_os_observation(
                hook_result=_hook(
                    "submitted", permission_status=permission
                ),
                before=_snapshot(maximum=17, count=4),
                after=_snapshot(maximum=17, count=4),
            )


def test_visibility_monitor_rejects_window_dock_activation_and_residue() -> None:
    entry = smoke.LaunchServicesEntry(
        pid=733,
        executable_path="/Applications/Slipstream.app/Contents/MacOS/slipstream",
        application_type="Foreground",
        dock_visible=True,
    )
    with mock.patch.object(smoke, "_visibility_snapshot", return_value=_visibility()):
        monitor = smoke.VisibilityMonitor(
            app_bundle=Path("/Applications/Slipstream.app"),
            executable=Path(
                "/Applications/Slipstream.app/Contents/MacOS/slipstream"
            ),
        )
    monitor.set_pid(733)
    monitor.samples = [_visibility(windows={17}, entries={entry})]
    with pytest.raises(smoke.NotificationQualificationError, match="window"):
        monitor.assert_invisible(_visibility())

    monitor.samples = [_visibility(entries={entry})]
    with pytest.raises(smoke.NotificationQualificationError, match="Dock"):
        monitor.assert_invisible(_visibility())

    monitor.samples = [_visibility(front="ASN:0x0-0x200:")]
    with pytest.raises(smoke.NotificationQualificationError, match="frontmost"):
        monitor.assert_invisible(_visibility())

    monitor.samples = [_visibility()]
    with pytest.raises(smoke.NotificationQualificationError, match="leaked"):
        monitor.assert_invisible(_visibility(entries={entry}))


def test_visibility_monitor_rejects_post_show_event() -> None:
    with mock.patch.object(smoke, "_visibility_snapshot", return_value=_visibility()):
        monitor = smoke.VisibilityMonitor(
            app_bundle=Path("/Applications/Slipstream.app"),
            executable=Path(
                "/Applications/Slipstream.app/Contents/MacOS/slipstream"
            ),
        )
    monitor.set_pid(733)
    monitor.samples = [_visibility()]
    monitor.events = [
        'Notification: kLSNotifyShowRequest "pid"=733 PostShowProcess'
    ]
    with pytest.raises(smoke.NotificationQualificationError, match="activation"):
        monitor.assert_invisible(_visibility())


def test_visibility_monitor_rejects_spaced_foreground_event() -> None:
    with mock.patch.object(smoke, "_visibility_snapshot", return_value=_visibility()):
        monitor = smoke.VisibilityMonitor(
            app_bundle=Path("/Applications/Slipstream.app"),
            executable=Path(
                "/Applications/Slipstream.app/Contents/MacOS/slipstream"
            ),
        )
    monitor.set_pid(733)
    monitor.samples = [_visibility()]
    monitor.events = [
        'Notification: birth "PID" = 733 '
        '"ApplicationType" = "Foreground"'
    ]
    with pytest.raises(smoke.NotificationQualificationError, match="foreground"):
        monitor.assert_invisible(_visibility())


def test_hidden_foreground_launch_services_entry_is_still_dock_capable() -> None:
    app = Path("/private/candidate/Slipstream.app")
    executable = app / "Contents/MacOS/slipstream"
    listing = f'''\n  1) "Slipstream" ASN:0x0-0x733:
      bundleID="{smoke.BUNDLE_IDENTIFIER}"
      executable path = "{executable}"
      "ApplicationType" = "Foreground"
      hidden=true
      pid=733
'''

    entries = smoke._launch_services_entries(
        listing,
        app_bundle=app,
        executable=executable,
        pid=733,
    )

    assert len(entries) == 1
    assert entries[0].application_type == "Foreground"
    assert entries[0].dock_visible is True


def test_visibility_monitor_accepts_hidden_no_window_lifecycle() -> None:
    with mock.patch.object(smoke, "_visibility_snapshot", return_value=_visibility()):
        monitor = smoke.VisibilityMonitor(
            app_bundle=Path("/Applications/Slipstream.app"),
            executable=Path(
                "/Applications/Slipstream.app/Contents/MacOS/slipstream"
            ),
        )
    monitor.set_pid(733)
    monitor.samples = [_visibility(), _visibility()]
    monitor.events = [
        'Notification: kLSNotifyApplicationBirth "pid"=733 '
        '"ApplicationType"="UIElement"',
        'Notification: kLSNotifyApplicationDeath "pid"=733',
    ]

    evidence = monitor.assert_invisible(_visibility())

    assert evidence == {
        "sample_count": 2,
        "launch_services_event_count": 2,
        "window_count": 0,
        "dock_visible": False,
        "frontmost_unchanged": True,
    }


def test_candidate_validation_binds_manifest_and_tree_before_bundle() -> None:
    manifest = {
        "source": {"commit": SOURCE, "repository": "aiwaki/slipstream"},
        "version": "0.1.9-preview.23",
        "target": "aarch64-apple-darwin",
        "app_tree_sha256": "4" * 64,
    }
    verified = {
        "candidate_id": f"release-candidate-{SOURCE}",
        "manifest_sha256": "5" * 64,
    }
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        identity = _identity(root)
        candidate = root / "candidate"
        candidate.mkdir()
        with (
            mock.patch.object(
                smoke.release_candidate, "_read_object", return_value=manifest
            ),
            mock.patch.object(
                smoke.release_candidate,
                "validate_manifest",
                return_value=verified,
            ) as validate,
            mock.patch.object(
                smoke,
                "_validate_packaged_bundle",
                return_value=(identity.executable, {}),
            ),
        ):
            result = smoke._validated_candidate_identity(
                candidate_dir=candidate,
                app_bundle=identity.app_bundle,
                repository="aiwaki/slipstream",
                source_commit=SOURCE,
                candidate_run_id=77,
                candidate_run_attempt=2,
            )

    assert result.candidate_id == f"release-candidate-{SOURCE}"
    assert validate.call_args.kwargs["expected_workflow_run_id"] == 77
    assert validate.call_args.kwargs["expected_workflow_run_attempt"] == 2
    assert validate.call_args.kwargs["app_tree"] == identity.app_bundle
    assert validate.call_args.kwargs["repository"] == "aiwaki/slipstream"


def test_candidate_validation_rejects_a_different_repository() -> None:
    manifest = {
        "source": {"commit": SOURCE, "repository": "attacker/slipstream"},
    }
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        with mock.patch.object(
            smoke.release_candidate, "_read_object", return_value=manifest
        ):
            with pytest.raises(
                smoke.NotificationQualificationError,
                match="repository and SHA",
            ):
                smoke._validated_candidate_identity(
                    candidate_dir=root / "candidate",
                    app_bundle=root / "Slipstream.app",
                    repository="aiwaki/slipstream",
                    source_commit=SOURCE,
                    candidate_run_id=77,
                    candidate_run_attempt=2,
                )


def test_disposable_ci_guard_requires_all_three_markers() -> None:
    with (
        mock.patch.object(smoke.sys, "platform", "darwin"),
        mock.patch.dict(os.environ, {}, clear=True),
        pytest.raises(
            smoke.NotificationQualificationError, match="disposable"
        ),
    ):
        smoke._require_disposable_macos_ci()

    with (
        mock.patch.object(smoke.sys, "platform", "darwin"),
        mock.patch.dict(
            os.environ,
            {
                "CI": "true",
                "GITHUB_ACTIONS": "true",
                "SLIPSTREAM_DISPOSABLE_CI": "1",
            },
            clear=True,
        ),
    ):
        smoke._require_disposable_macos_ci()


def test_launch_services_registration_is_exact_and_reversible() -> None:
    app = Path("/private/candidate/Slipstream.app")
    with mock.patch.object(smoke.subprocess, "run") as run:
        run.return_value.returncode = 0
        smoke._set_launch_services_registration(app, register=True)
        smoke._set_launch_services_registration(app, register=False)

    assert run.call_args_list[0].args[0] == (smoke.LSREGISTER, "-f", str(app))
    assert run.call_args_list[1].args[0] == (smoke.LSREGISTER, "-u", str(app))


def test_packaged_bundle_rejects_symlink_and_oversized_metadata() -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        identity = _identity(root)
        info = identity.app_bundle / "Contents/Info.plist"
        info.write_bytes(
            smoke.plistlib.dumps(
                {
                    "CFBundleIdentifier": smoke.BUNDLE_IDENTIFIER,
                    "CFBundleExecutable": smoke.BUNDLE_EXECUTABLE,
                    "LSUIElement": True,
                }
            )
        )
        identity.executable.chmod(0o755)
        alias = root / "Alias.app"
        alias.symlink_to(identity.app_bundle, target_is_directory=True)

        with pytest.raises(
            smoke.NotificationQualificationError, match="bundle is unsafe"
        ):
            smoke._validate_packaged_bundle(alias)

        info.write_bytes(b"x" * (smoke.INFO_PLIST_MAX_BYTES + 1))
        with pytest.raises(
            smoke.NotificationQualificationError, match="metadata is unsafe"
        ):
            smoke._validate_packaged_bundle(identity.app_bundle)


def test_failed_hook_is_reaped_even_when_root_phase_cannot_be_signalled() -> None:
    process = mock.Mock()
    process.poll.return_value = None
    process.kill.side_effect = PermissionError
    process.communicate.return_value = (b"", b"")

    smoke._reap_hook_after_failure(process)

    process.kill.assert_called_once_with()
    process.communicate.assert_called_once_with(
        timeout=(smoke.CAPABILITY_MAX_LIFETIME_MS / 1_000) + 5
    )


def test_failed_hook_cleanup_fails_closed_if_process_survives() -> None:
    process = mock.Mock()
    process.poll.return_value = None
    process.kill.side_effect = PermissionError
    process.communicate.side_effect = smoke.subprocess.TimeoutExpired(
        "hook", 35
    )

    with pytest.raises(
        smoke.NotificationQualificationError, match="survived"
    ):
        smoke._reap_hook_after_failure(process)


def test_cli_atomically_writes_safe_failure_report_before_nonzero_exit(
    capsys,
) -> None:
    secret = "sensitive notification backend output"
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        output = root / "reports" / "notification.json"
        argv = [
            str(smoke.__file__),
            "--candidate-dir",
            str(root / "candidate"),
            "--app-bundle",
            str(root / "Slipstream.app"),
            "--repository",
            "aiwaki/slipstream",
            "--source-commit",
            SOURCE,
            "--candidate-run-id",
            "77",
            "--candidate-run-attempt",
            "2",
            "--output",
            str(output),
        ]
        failure = smoke.NotificationQualificationError(
            secret, failure_code="native_submission_failed"
        )
        with (
            mock.patch.object(smoke.sys, "argv", argv),
            mock.patch.object(smoke, "run_gate", side_effect=failure),
        ):
            status = smoke._main()

        report = json.loads(output.read_text(encoding="utf-8"))
        report_size = output.stat().st_size
        leftovers = list(output.parent.glob(f".{output.name}.*"))

    captured = capsys.readouterr()
    assert status == 1
    assert report == {
        "schema_version": smoke.SCHEMA_VERSION,
        "outcome": "terminal",
        "failure_code": "native_submission_failed",
    }
    assert report_size <= smoke.FAILURE_REPORT_MAX_BYTES
    assert leftovers == []
    assert secret not in captured.err
    assert json.loads(captured.err) == report


def test_ci_always_uploads_native_notification_failure_report() -> None:
    root = Path(smoke.__file__).resolve().parents[1]
    workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    job = workflow.split(
        "  packaged-update-notification-qualification:\n", 1
    )[1].split("\n  packaged-app-lifecycle-heavy:\n", 1)[0]
    upload = job.split(
        "      - name: Upload native notification qualification report\n", 1
    )[1].split("\n      - ", 1)[0]

    assert "        if: always()\n" in upload
    assert "update-notification-qualification.json" in upload
    assert "          if-no-files-found: error\n" in upload


def test_report_contract_never_claims_visible_delivery_or_contains_content() -> None:
    source = Path(smoke.__file__).read_text(encoding="utf-8")
    assert '"visible_display_claimed": False' in source
    assert "CGWindowListCopyWindowInfo" in source
    assert '(LSAPPINFO, "listen", "+all"' in source
    assert "USERNOTED_DB_RELATIVE" in source
    assert "Notification Center" not in source
    assert "fixed non-user" not in source.lower() or "body" not in source
