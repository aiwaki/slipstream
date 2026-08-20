import io
import hashlib
import json
import os
from pathlib import Path
import sqlite3
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
    reason = extra.pop(
        "reason",
        "native_submission_failed" if outcome == "terminal" else "",
    )
    capability = "" if reason == "capability_invalid" else DIGEST
    terminal_permission = {
        "capability_invalid": "unknown",
        "identity_unavailable": "unknown",
        "permission_unavailable": "unknown",
        "authorization_failed": "not_determined",
        "native_submission_failed": "allowed",
        "delivery_unobserved": "allowed",
        "cleanup_unconfirmed": "allowed",
    }
    permission = (
        terminal_permission[reason]
        if outcome == "terminal"
        else {
            "submitted": "allowed",
            "permission_suppressed": "denied",
        }[outcome]
    )
    delivered = outcome == "submitted" or reason == "cleanup_unconfirmed"
    value = {
        "schema_version": smoke.HOOK_SCHEMA_VERSION,
        "outcome": outcome,
        "identity": smoke.BUNDLE_IDENTIFIER,
        "capability_sha256": capability,
        "request_identifier_sha256": (
            smoke._request_identifier_sha256(capability) if capability else ""
        ),
        "permission_status": permission,
        "delivered": delivered,
        "removed": outcome == "submitted",
        "reason": reason,
    }
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


def _create_notification_database(path: Path, *, valid: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        if valid:
            connection.execute(
                "CREATE TABLE app (app_id INTEGER PRIMARY KEY, identifier TEXT)"
            )
            connection.execute(
                "CREATE TABLE record (rec_id INTEGER PRIMARY KEY, app_id INTEGER)"
            )
            connection.execute(
                "INSERT INTO app (app_id, identifier) VALUES (?, ?)",
                (1, smoke.BUNDLE_IDENTIFIER),
            )
            connection.execute(
                "INSERT INTO record (rec_id, app_id) VALUES (?, ?)",
                (7, 1),
            )
        else:
            connection.execute("CREATE TABLE app (identifier TEXT)")
            connection.execute("CREATE TABLE record (rec_id INTEGER)")


def _producer_payloads(*, producer_attempt=1, qualification_attempt=2):
    manifest = {
        "source": {
            "repository": "aiwaki/slipstream",
            "commit": SOURCE,
        },
        "builder": {
            "workflow": smoke.release_candidate.BUILD_WORKFLOW,
            "run_id": 77,
            "run_attempt": producer_attempt,
        },
    }
    run = {
        "id": 77,
        "run_attempt": qualification_attempt,
        "head_sha": SOURCE,
        "head_branch": "main",
        "event": "push",
        "path": smoke.release_candidate.BUILD_WORKFLOW,
        "status": "in_progress",
        "conclusion": None,
        "repository": {"id": 91, "full_name": "aiwaki/slipstream"},
        "head_repository": {"id": 91, "full_name": "aiwaki/slipstream"},
    }
    jobs = {
        "total_count": 1,
        "jobs": [
            {
                "id": 101,
                "name": "assemble-release-candidate",
                "run_id": 77,
                "run_attempt": producer_attempt,
                "head_sha": SOURCE,
                "status": "completed",
                "conclusion": "success",
                "started_at": "2026-08-20T00:00:00Z",
                "completed_at": "2026-08-20T00:05:00Z",
            }
        ],
    }
    artifacts = {
        "total_count": 1,
        "artifacts": [
            {
                "id": 201,
                "name": f"release-candidate-{SOURCE}",
                "size_in_bytes": 123456,
                "expired": False,
                "digest": f"sha256:{'6' * 64}",
                "created_at": "2026-08-20T00:04:00Z",
                "workflow_run": {
                    "id": 77,
                    "head_sha": SOURCE,
                    "head_branch": "main",
                    "repository_id": 91,
                    "head_repository_id": 91,
                },
            }
        ],
    }
    return manifest, run, jobs, artifacts


def _write_producer_evidence(root: Path, payloads) -> dict:
    manifest, run, jobs, artifacts = payloads
    candidate = root / "candidate"
    candidate.mkdir()
    (candidate / smoke.release_candidate.MANIFEST_NAME).write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    paths = {}
    for name, payload in (("run", run), ("jobs", jobs), ("artifacts", artifacts)):
        path = root / f"{name}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        paths[name] = path
    return {
        "candidate_dir": candidate,
        "repository": "aiwaki/slipstream",
        "source_commit": SOURCE,
        "candidate_run_id": 77,
        "candidate_run_attempt": manifest["builder"]["run_attempt"],
        "qualification_run_attempt": run["run_attempt"],
        "run_metadata_path": paths["run"],
        "jobs_path": paths["jobs"],
        "artifacts_path": paths["artifacts"],
    }


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


@pytest.mark.parametrize("permission", ("allowed", "provisional"))
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
        "request_identifier_sha256",
        "permission_status",
        "delivered",
        "removed",
        "reason",
    }


@pytest.mark.parametrize(
    "permission", ("denied", "notification_center_disabled")
)
def test_hook_result_accepts_only_exact_suppressed_states(permission: str) -> None:
    value = _hook("permission_suppressed", permission_status=permission)
    parsed = smoke.parse_hook_result(
        json.dumps(value), capability_sha256=DIGEST
    )
    assert parsed["outcome"] == "permission_suppressed"
    assert parsed["delivered"] is False
    assert parsed["removed"] is False


def test_hook_result_accepts_bounded_terminal_category() -> None:
    parsed = smoke.parse_hook_result(
        json.dumps(_hook("terminal", reason="native_submission_failed")),
        capability_sha256=DIGEST,
    )
    assert parsed["reason"] == "native_submission_failed"


def test_runtime_bundle_identity_failure_remains_exact_terminal_reason() -> None:
    parsed = smoke.parse_hook_result(
        json.dumps(_hook("terminal", reason="identity_unavailable")),
        capability_sha256=DIGEST,
    )
    with pytest.raises(smoke.NotificationQualificationError) as raised:
        smoke.classify_os_observation(hook_result=parsed)
    assert raised.value.failure_code == "identity_unavailable"


@pytest.mark.parametrize(
    ("reason", "mutation"),
    (
        ("authorization_failed", {"permission_status": "unknown"}),
        ("delivery_unobserved", {"delivered": True}),
        ("cleanup_unconfirmed", {"delivered": False}),
        ("identity_unavailable", {"permission_status": "allowed"}),
    ),
)
def test_terminal_hook_state_is_exact_and_fail_closed(reason, mutation) -> None:
    value = _hook("terminal", reason=reason)
    value.update(mutation)
    with pytest.raises(
        smoke.NotificationQualificationError, match="state is inconsistent"
    ):
        smoke.parse_hook_result(json.dumps(value), capability_sha256=DIGEST)


def test_capability_invalid_is_the_only_unbound_hook_outcome() -> None:
    invalid = _hook("terminal", reason="capability_invalid")
    parsed = smoke.parse_hook_result(
        json.dumps(invalid), capability_sha256=DIGEST
    )
    assert parsed["capability_sha256"] == ""
    assert parsed["request_identifier_sha256"] == ""

    invalid["capability_sha256"] = DIGEST
    invalid["request_identifier_sha256"] = smoke._request_identifier_sha256(
        DIGEST
    )
    with pytest.raises(
        smoke.NotificationQualificationError, match="inconsistent"
    ):
        smoke.parse_hook_result(json.dumps(invalid), capability_sha256=DIGEST)


def test_request_identifier_digest_is_exact_and_capability_bound() -> None:
    expected = hashlib.sha256(
        f"{smoke.REQUEST_IDENTIFIER_PREFIX}{DIGEST}".encode("ascii")
    ).hexdigest()
    assert smoke._request_identifier_sha256(DIGEST) == expected


@pytest.mark.parametrize("reason", sorted(smoke.TERMINAL_REASONS))
def test_validated_rust_terminal_reason_survives_failure_report(reason) -> None:
    hook_result = _hook("terminal", reason=reason)
    with pytest.raises(smoke.NotificationQualificationError) as raised:
        smoke.classify_os_observation(hook_result=hook_result)

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
        {"request_identifier_sha256": "9" * 64},
        {"outcome": "visible"},
        {"body": "sensitive content"},
        {"reason": "raw backend error"},
        {"delivered": 1},
        {"removed": False},
        {"schema_version": True},
    ),
)
def test_hook_result_rejects_wrong_identity_binding_or_raw_content(
    mutation,
) -> None:
    value = _hook("submitted")
    value.update(mutation)
    with pytest.raises(smoke.NotificationQualificationError):
        smoke.parse_hook_result(json.dumps(value), capability_sha256=DIGEST)


def test_supported_hook_delivery_and_cleanup_are_authoritative() -> None:
    assert (
        smoke.classify_os_observation(
            hook_result=_hook("submitted"),
        )
        == "submitted"
    )


@pytest.mark.parametrize(
    "permission", ("denied", "notification_center_disabled")
)
def test_permission_suppression_never_satisfies_release_delivery(
    permission,
) -> None:
    with pytest.raises(smoke.NotificationQualificationError) as raised:
        smoke.classify_os_observation(
            hook_result=_hook(
                "permission_suppressed", permission_status=permission
            ),
        )
    assert raised.value.failure_code == "permission_suppressed"


def test_terminal_hook_fails_before_private_store_diagnostics() -> None:
    with pytest.raises(smoke.NotificationQualificationError, match="terminal"):
        smoke.classify_os_observation(
            hook_result=_hook(
                "terminal", reason="native_submission_failed"
            ),
        )


@pytest.mark.parametrize(
    "permission", ("not_determined", "unknown")
)
def test_unresolved_permission_cannot_be_nonterminal(permission) -> None:
    value = _hook("submitted", permission_status=permission)
    with pytest.raises(
        smoke.NotificationQualificationError, match="proof is incomplete"
    ):
        smoke.parse_hook_result(json.dumps(value), capability_sha256=DIGEST)


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


@pytest.mark.parametrize("qualification_attempt", (1, 2))
def test_qualification_accepts_only_authenticated_candidate_attempt(
    qualification_attempt,
) -> None:
    with tempfile.TemporaryDirectory() as raw:
        kwargs = _write_producer_evidence(
            Path(raw),
            _producer_payloads(
                producer_attempt=1,
                qualification_attempt=qualification_attempt,
            ),
        )
        evidence = smoke.validate_candidate_producer_evidence(**kwargs)

    assert evidence == smoke.CandidateProducerEvidence(
        run_id=77,
        run_attempt=1,
        assemble_job_id=101,
        artifact_id=201,
        artifact_digest=f"sha256:{'6' * 64}",
    )


@pytest.mark.parametrize(
    "case",
    (
        "wrong_producer_attempt",
        "wrong_qualification_attempt",
        "wrong_manifest_repository",
        "wrong_run_repository",
        "wrong_run_sha",
        "wrong_job_attempt",
        "failed_job",
        "expired_artifact",
        "wrong_artifact_repository",
        "wrong_artifact_sha",
        "artifact_outside_job",
        "duplicate_artifact",
    ),
)
def test_candidate_producer_evidence_rejects_wrong_provenance(case) -> None:
    payloads = _producer_payloads(producer_attempt=1, qualification_attempt=2)
    manifest, run, jobs, artifacts = payloads
    if case == "wrong_manifest_repository":
        manifest["source"]["repository"] = "attacker/slipstream"
    elif case == "wrong_run_repository":
        run["repository"]["full_name"] = "attacker/slipstream"
    elif case == "wrong_run_sha":
        run["head_sha"] = "9" * 40
    elif case == "wrong_job_attempt":
        jobs["jobs"][0]["run_attempt"] = 2
    elif case == "failed_job":
        jobs["jobs"][0]["conclusion"] = "failure"
    elif case == "expired_artifact":
        artifacts["artifacts"][0]["expired"] = True
    elif case == "wrong_artifact_repository":
        artifacts["artifacts"][0]["workflow_run"]["repository_id"] = 92
    elif case == "wrong_artifact_sha":
        artifacts["artifacts"][0]["workflow_run"]["head_sha"] = "9" * 40
    elif case == "artifact_outside_job":
        artifacts["artifacts"][0]["created_at"] = "2026-08-20T00:06:00Z"
    elif case == "duplicate_artifact":
        artifacts["artifacts"].append(dict(artifacts["artifacts"][0]))
        artifacts["total_count"] = 2

    with tempfile.TemporaryDirectory() as raw:
        kwargs = _write_producer_evidence(Path(raw), payloads)
        if case == "wrong_producer_attempt":
            kwargs["candidate_run_attempt"] = 2
        elif case == "wrong_qualification_attempt":
            kwargs["qualification_run_attempt"] = 1
        with pytest.raises(smoke.NotificationQualificationError) as raised:
            smoke.validate_candidate_producer_evidence(**kwargs)

    assert raised.value.failure_code == "candidate_producer_invalid"


def test_candidate_producer_evidence_rejects_duplicate_json_fields() -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        kwargs = _write_producer_evidence(root, _producer_payloads())
        kwargs["run_metadata_path"].write_text(
            '{"id":77,"id":77}', encoding="utf-8"
        )
        with pytest.raises(smoke.NotificationQualificationError) as raised:
            smoke.validate_candidate_producer_evidence(**kwargs)

    assert raised.value.failure_code == "candidate_producer_invalid"


@pytest.mark.parametrize("condition", ("symlink", "oversized"))
def test_candidate_producer_evidence_files_are_bounded_and_nofollow(
    condition,
) -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        kwargs = _write_producer_evidence(root, _producer_payloads())
        run_path = kwargs["run_metadata_path"]
        if condition == "symlink":
            alias = root / "run-alias.json"
            alias.symlink_to(run_path)
            kwargs["run_metadata_path"] = alias
        else:
            run_path.write_bytes(b"x" * (smoke.PRODUCER_EVIDENCE_MAX_BYTES + 1))
        with pytest.raises(smoke.NotificationQualificationError) as raised:
            smoke.validate_candidate_producer_evidence(**kwargs)

    assert raised.value.failure_code == "candidate_producer_invalid"


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


def test_sonoma_notification_store_uses_exact_darwin_user_directory() -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        darwin_user = root / "darwin-user"
        darwin_user.mkdir()
        result = mock.Mock(
            returncode=0,
            stdout=f"{darwin_user}\n",
            stderr="",
        )
        with (
            mock.patch.object(
                smoke.platform,
                "mac_ver",
                return_value=("14.8.7", (), ""),
            ),
            mock.patch.object(
                smoke.subprocess, "run", return_value=result
            ) as run,
        ):
            database = smoke._notification_database_path(root / "home")

    assert database == (
        darwin_user.resolve() / smoke.LEGACY_USERNOTED_DB_RELATIVE
    )
    assert run.call_args.args[0] == (smoke.GETCONF, "DARWIN_USER_DIR")
    assert run.call_args.kwargs["timeout"] == 5


def test_sequoia_notification_store_uses_group_container() -> None:
    home = Path("/Users/runner")
    with (
        mock.patch.object(
            smoke.platform,
            "mac_ver",
            return_value=("15.1.0", (), ""),
        ),
        mock.patch.object(smoke.subprocess, "run") as run,
    ):
        database = smoke._notification_database_path(home)

    assert database == home / smoke.MODERN_USERNOTED_DB_RELATIVE
    run.assert_not_called()


def test_notification_store_snapshot_preflights_schema_and_identity() -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        database = root / "db2/db"
        _create_notification_database(database)
        with mock.patch.object(
            smoke, "_notification_database_path", return_value=database
        ):
            snapshot = smoke._notification_record_snapshot(root)

    assert snapshot == smoke.NotificationRecordSnapshot(7, 1)


@pytest.mark.parametrize("condition", ("absent", "symlink", "wrong_owner"))
def test_unusable_notification_store_is_explicitly_unavailable(condition) -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        database = root / "db2/db"
        if condition == "symlink":
            real = root / "real.db"
            _create_notification_database(real)
            database.parent.mkdir(parents=True)
            database.symlink_to(real)
        elif condition == "wrong_owner":
            _create_notification_database(database)
        with mock.patch.object(
            smoke, "_notification_database_path", return_value=database
        ):
            if condition == "wrong_owner":
                real_uid = os.getuid()
                with mock.patch.object(
                    smoke.os, "getuid", return_value=real_uid + 1
                ):
                    snapshot, diagnostic = (
                        smoke._optional_notification_record_snapshot(root)
                    )
            else:
                snapshot, diagnostic = (
                    smoke._optional_notification_record_snapshot(root)
                )

    assert snapshot is None
    assert diagnostic == {
        "status": "unavailable",
        "failure_code": "os_observation_unavailable",
    }


def test_invalid_notification_store_schema_is_not_treated_as_zero_records() -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        database = root / "db2/db"
        _create_notification_database(database, valid=False)
        with mock.patch.object(
            smoke, "_notification_database_path", return_value=database
        ):
            snapshot, diagnostic = smoke._optional_notification_record_snapshot(
                root
            )

    assert snapshot is None
    assert diagnostic["failure_code"] == "os_observation_unavailable"


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
            "--qualification-run-attempt",
            "3",
            "--candidate-run-metadata",
            str(root / "run.json"),
            "--candidate-run-jobs",
            str(root / "jobs.json"),
            "--candidate-run-artifacts",
            str(root / "artifacts.json"),
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
    assert (
        "Slipstream-update-notification-qualified-${{ github.sha }}-"
        "${{ github.run_attempt }}"
    ) in upload


def test_ci_authenticates_producer_attempt_independently_from_rerun() -> None:
    root = Path(smoke.__file__).resolve().parents[1]
    workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    job = workflow.split(
        "  packaged-update-notification-qualification:\n", 1
    )[1].split("\n  packaged-app-lifecycle-heavy:\n", 1)[0]

    assert "Authenticate the exact candidate producer attempt" in job
    assert "smoke._candidate_producer_attempt" in job
    assert "actions/runs/$GITHUB_RUN_ID\"" in job
    assert (
        "actions/runs/$GITHUB_RUN_ID/attempts/$candidate_attempt/jobs?per_page=100"
        in job
    )
    assert "actions/runs/$GITHUB_RUN_ID/artifacts?per_page=100" in job
    assert 'test "$evidence_size" -le 4194304' in job
    assert (
        '--candidate-run-attempt '
        '"${{ steps.candidate-producer.outputs.run_attempt }}"'
        in job
    )
    assert '--qualification-run-attempt "$GITHUB_RUN_ATTEMPT"' in job
    assert '--candidate-run-metadata "$RUNNER_TEMP/' in job
    assert '--candidate-run-jobs "$RUNNER_TEMP/' in job
    assert '--candidate-run-artifacts "$RUNNER_TEMP/' in job


def test_ci_qualifies_and_cleans_exact_applications_candidate() -> None:
    root = Path(smoke.__file__).resolve().parents[1]
    workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    job = workflow.split(
        "  packaged-update-notification-qualification:\n", 1
    )[1].split("\n  packaged-app-lifecycle-heavy:\n", 1)[0]

    assert 'installed_app="/Applications/Slipstream.app"' in job
    assert '[ -e "$installed_app" ] || [ -L "$installed_app" ]' in job
    assert "trap cleanup_installed_app EXIT INT TERM" in job
    assert "/usr/bin/ditto --rsrc --extattr --acl" in job
    assert job.count("deterministic_tree_sha256") == 2
    assert 'test "$source_tree" = "$installed_tree"' in job
    assert 'test "$source_executable_sha256" = ' in job
    assert '/usr/bin/codesign --verify --deep --strict "$installed_app"' in job
    assert '--app-bundle "$installed_app"' in job
    assert '/bin/rm -rf -- "$installed_app"' in job
    assert '"$lsregister" -u "$installed_app"' in job
    assert 'if ! "$lsregister" -dump >"$lsregister_dump"' in job
    assert "LaunchServices cleanup could not be verified" in job
    assert "lsregister_deadline=$((SECONDS + 5))" in job
    assert "/bin/sleep 0.1" in job
    cleanup_exit = job.index('exit "$cleanup_status"')
    original_exit = job.index('exit "$original_status"')
    assert cleanup_exit < original_exit


def test_report_contract_never_claims_visible_delivery_or_contains_content() -> None:
    source = Path(smoke.__file__).read_text(encoding="utf-8")
    assert '"visible_display_claimed": False' in source
    assert "CGWindowListCopyWindowInfo" in source
    assert '(LSAPPINFO, "listen", "+all"' in source
    assert "USERNOTED_DB_RELATIVE" in source
    assert '(GETCONF, "DARWIN_USER_DIR")' in source
    assert "mode=ro&nofollow=1" in source
    assert '"delivered": hook_result["delivered"]' in source
    assert '"removed": hook_result["removed"]' in source
    assert "Notification Center" not in source
    assert "fixed non-user" not in source.lower() or "body" not in source
