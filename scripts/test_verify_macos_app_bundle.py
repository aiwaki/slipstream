from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import plistlib
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import verify_macos_app_bundle as verifier


class VerifyMacosAppBundleTests(unittest.TestCase):
    @staticmethod
    def _write_executable(path: Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        path.chmod(0o755)

    def _daemon_trees(
        self,
        root: Path,
        *,
        safe_symlink: bool = False,
    ) -> tuple[Path, Path, Path]:
        fresh = root / "fresh"
        staged = root / "staged"
        bundled = root / "bundled"
        fresh.mkdir()
        self._write_executable(fresh / "slipstreamd", b"frozen-daemon\n")
        (fresh / "runtime.dat").write_bytes(b"runtime-resource\n")
        if safe_symlink:
            (fresh / "runtime.link").symlink_to("runtime.dat")

        shutil.copytree(fresh, staged, symlinks=True)
        # Tauri materializes a safe in-tree PyInstaller symlink in the bundle.
        shutil.copytree(fresh, bundled, symlinks=False)
        return fresh, staged, bundled

    def _console_browser_fixture(self, root: Path) -> Path:
        app = root / "Slipstream.app"
        self._write_executable(app / "Contents/MacOS/slipstream-browser-probe", b"worker")
        chromium_dir = app / "Contents/Resources/chromium-headless-shell"
        self._write_executable(chromium_dir / "chrome-headless-shell", b"chromium")
        (chromium_dir / "icudtl.dat").write_bytes(b"browser-data")
        (chromium_dir / "icudtl.dat").chmod(0o644)
        return app

    def test_console_browser_rejects_owner_only_execution_before_root_install(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            app = self._console_browser_fixture(Path(temporary))
            chromium = app / "Contents/Resources/chromium-headless-shell/chrome-headless-shell"
            chromium.chmod(0o744)
            # This is the old false green: the builder can execute its own file.
            self.assertTrue(os.access(chromium, os.X_OK))
            with self.assertRaisesRegex(verifier.VerificationError, "after root installation"):
                verifier.verify_console_browser_access(app)

    def test_console_browser_accepts_portable_executables_and_readable_resources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            app = self._console_browser_fixture(Path(temporary))
            verifier.verify_console_browser_access(app)

    def test_console_browser_rejects_private_directory_or_resource(self) -> None:
        for relative, mode in (
            ("Contents/Resources", 0o700),
            ("Contents/Resources/chromium-headless-shell/icudtl.dat", 0o600),
            ("Contents/MacOS/slipstream-browser-probe", 0o744),
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                app = self._console_browser_fixture(Path(temporary))
                (app / relative).chmod(mode)
                with self.assertRaisesRegex(verifier.VerificationError, "after root installation"):
                    verifier.verify_console_browser_access(app)

    def test_installed_browser_rechecks_actual_access_despite_matching_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            app = self._console_browser_fixture(Path(temporary))
            built_report = {"tree_sha256": verifier.deterministic_tree_sha256(app)}
            chromium = app / "Contents/Resources/chromium-headless-shell/chrome-headless-shell"
            real_access = os.access
            with mock.patch.object(
                verifier.os, "access",
                side_effect=lambda path, mode: False if path == chromium else real_access(path, mode),
            ), mock.patch.object(verifier, "verify_install_attestation") as attestation:
                with self.assertRaisesRegex(verifier.VerificationError, "after root installation"):
                    verifier.verify_installed_app(
                        built_report=built_report,
                        installed_app=app,
                        attestation_path=Path(temporary) / "attestation.json",
                        launchd_plist=Path(temporary) / "launchd.plist",
                        status_path=Path(temporary) / "status.json",
                    )
                attestation.assert_not_called()

    @staticmethod
    def _rewrite_attestation(path: Path, evidence: dict) -> None:
        path.write_text(json.dumps(evidence), encoding="utf-8")
        path.chmod(verifier.INSTALL_ATTESTATION_MODE)

    def _install_attestation_fixture(self, root: Path) -> dict[str, object]:
        installed = root / "installed-slipstreamd"
        installed.write_bytes(b"installed-daemon\n")
        installed.chmod(verifier.INSTALLED_DAEMON_MODE)
        digest = hashlib.sha256(installed.read_bytes()).hexdigest()

        attestation = root / "install-attestation.json"
        witness = Path(f"{attestation}.daemon")
        os.link(installed, witness)
        witness_stat = witness.lstat()
        expected_uid = os.getuid()
        evidence = {
            "schema_version": verifier.INSTALL_ATTESTATION_SCHEMA,
            "source_sha256": digest,
            "daemon": {
                "path": str(verifier.INSTALLED_DAEMON),
                "sha256": digest,
                # expected_uid relaxes only the fixture-owned evidence/witness;
                # the attested privileged runtime must remain root-owned.
                "uid": 0,
                "gid": 0,
                "mode": verifier.INSTALLED_DAEMON_MODE,
            },
            "witness": {
                "path": str(witness),
                "dev": witness_stat.st_dev,
                "ino": witness_stat.st_ino,
                "size": witness_stat.st_size,
                "mtime": witness_stat.st_mtime_ns // 1_000_000_000,
                "mtime_nsec": witness_stat.st_mtime_ns % 1_000_000_000,
            },
            "launchd": {
                "label": verifier.LAUNCHD_LABEL,
                "pid": 4242,
            },
            "listener": {
                "host": verifier.LISTENER_HOSTS[0],
                "hosts": verifier.LISTENER_HOSTS,
                "port": verifier.LISTENER_PORT,
            },
            "state": "active",
            "pf_active": True,
        }
        self._rewrite_attestation(attestation, evidence)

        launchd_plist = root / "dev.slipstream.tproxy.plist"
        with launchd_plist.open("wb") as handle:
            plistlib.dump(
                {
                    "Label": verifier.LAUNCHD_LABEL,
                    "ProgramArguments": [
                        str(verifier.INSTALLED_DAEMON),
                        "--port",
                        str(verifier.LISTENER_PORT),
                    ],
                    "RunAtLoad": True,
                    "KeepAlive": True,
                    "WorkingDirectory": str(verifier.LAUNCHD_WORKING_DIRECTORY),
                    "StandardOutPath": "/dev/null",
                    "StandardErrorPath": "/dev/null",
                    "EnvironmentVariables": {
                        "PATH": verifier.LAUNCHD_PATH,
                        "PYTHONUNBUFFERED": "1",
                        "SLIPSTREAM_PENDING_NAVIGATION_BROWSER_WORKER": str(
                            verifier.INSTALLED_BROWSER_WORKER
                        ),
                    },
                    "SoftResourceLimits": {"NumberOfFiles": 16384},
                    "HardResourceLimits": {"NumberOfFiles": 16384},
                },
                handle,
            )
        return {
            "installed": installed,
            "digest": digest,
            "attestation": attestation,
            "witness": witness,
            "evidence": evidence,
            "launchd_plist": launchd_plist,
            "expected_uid": expected_uid,
        }

    def _status_fixture(
        self,
        root: Path,
        *,
        now: float = 1_000.0,
        pid: int = 4242,
        state: str = "active",
        phase: str = "active",
        pf_applied: bool | None = None,
        pf_enabled: bool = True,
    ) -> Path:
        status_path = root / "slipstream.status"
        active = state == "active"
        status_path.write_text(
            json.dumps(
                {
                    "schema_version": verifier.STATUS_SCHEMA,
                    "daemon": {
                        "pid": pid,
                        "state": state,
                        "phase": phase,
                        "updated_at": now,
                        "heartbeat_at": "1970-01-01T00:16:40.000Z",
                        "heartbeat_seq": 7,
                    },
                    "environment": {
                        "pf": {
                            "applied": active if pf_applied is None else pf_applied,
                            "enabled": pf_enabled,
                            "rules_loaded": active,
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        status_path.chmod(verifier.STATUS_MODE)
        os.utime(status_path, (now, now))
        return status_path

    @staticmethod
    def _launchctl_payload(*, pid: int = 4242, program: str | None = None) -> str:
        daemon = str(verifier.INSTALLED_DAEMON) if program is None else program
        return f"""system/{verifier.LAUNCHD_LABEL} = {{
    state = running
    program = {daemon}
    arguments = {{
        {daemon}
        --port
        {verifier.LISTENER_PORT}
    }}
    working directory = {verifier.LAUNCHD_WORKING_DIRECTORY}
    pid = {pid}
    job state = running
}}
"""

    def test_build_chain_accepts_materialized_safe_in_tree_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fresh, staged, bundled = self._daemon_trees(
                Path(temporary),
                safe_symlink=True,
            )

            report = verifier.verify_build_chain(
                fresh_daemon=fresh / "slipstreamd",
                staged_daemon=staged / "slipstreamd",
                bundled_daemon=bundled / "slipstreamd",
            )

            self.assertTrue((fresh / "runtime.link").is_symlink())
            self.assertTrue((staged / "runtime.link").is_symlink())
            self.assertFalse((bundled / "runtime.link").is_symlink())
            self.assertEqual(set(report["copies"].values()), {report["sha256"]})
            self.assertEqual(
                report["materialized_tree_sha256"],
                report["bundled_tree_sha256"],
            )

    def test_materialization_uses_private_snapshot_after_source_symlink_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fresh, _staged, _bundled = self._daemon_trees(root, safe_symlink=True)
            expected = root / "expected"
            shutil.copytree(fresh, expected, symlinks=False)
            expected_digest = verifier.deterministic_tree_sha256(expected)
            external = root / "external.dat"
            external.write_bytes(b"must-not-be-followed\n")
            original_copytree = shutil.copytree
            copied_snapshot = False

            def copytree_with_swap(
                source: Path,
                destination: Path,
                *args: object,
                **kwargs: object,
            ) -> Path:
                nonlocal copied_snapshot
                result = original_copytree(source, destination, *args, **kwargs)
                if Path(source) == fresh and kwargs.get("symlinks") is True:
                    copied_snapshot = True
                    link = fresh / "runtime.link"
                    link.unlink()
                    link.symlink_to(external)
                return result

            with mock.patch.object(
                verifier.shutil,
                "copytree",
                side_effect=copytree_with_swap,
            ):
                actual_digest = verifier.materialized_tree_sha256(fresh)

            self.assertTrue(copied_snapshot)
            self.assertEqual(actual_digest, expected_digest)

    def test_build_chain_rejects_executable_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fresh, staged, bundled = self._daemon_trees(Path(temporary))
            self._write_executable(bundled / "slipstreamd", b"different-daemon\n")

            with self.assertRaisesRegex(
                verifier.VerificationError,
                "frozen daemon SHA-256 mismatch",
            ):
                verifier.verify_build_chain(
                    fresh_daemon=fresh / "slipstreamd",
                    staged_daemon=staged / "slipstreamd",
                    bundled_daemon=bundled / "slipstreamd",
                )

    def test_build_chain_rejects_bundled_tree_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fresh, staged, bundled = self._daemon_trees(Path(temporary))
            (bundled / "runtime.dat").write_bytes(b"different-resource\n")

            with self.assertRaisesRegex(
                verifier.VerificationError,
                "bundled daemon tree differs",
            ):
                verifier.verify_build_chain(
                    fresh_daemon=fresh / "slipstreamd",
                    staged_daemon=staged / "slipstreamd",
                    bundled_daemon=bundled / "slipstreamd",
                )

    def test_file_hash_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "daemon"
            target.write_bytes(b"daemon\n")
            alias = root / "daemon-link"
            alias.symlink_to(target.name)

            with self.assertRaisesRegex(
                verifier.VerificationError,
                "cannot open regular file safely",
            ):
                verifier.file_sha256(alias)

    def test_build_chain_precedes_any_bundle_execution(self) -> None:
        events: list[str] = []

        with mock.patch.object(
            verifier,
            "verify_build_chain",
            side_effect=lambda **_kwargs: events.append("build-chain")
            or {"sha256": "hash"},
        ), mock.patch.object(
            verifier,
            "verify_app_bundle",
            side_effect=lambda *_args, **_kwargs: events.append("artifact")
            or {"tree_sha256": "tree", "critical_sha256": {"daemon": "hash"}},
        ), contextlib.redirect_stdout(io.StringIO()):
            result = verifier.main(
                [
                    "--app-bundle",
                    "/tmp/Slipstream.app",
                    "--fresh-daemon",
                    "/tmp/fresh/slipstreamd",
                    "--staged-daemon",
                    "/tmp/staged/slipstreamd",
                ]
            )

        self.assertEqual(result, 0)
        self.assertEqual(events, ["build-chain", "artifact"])

    def test_main_rejects_build_chain_artifact_daemon_hash_mismatch(self) -> None:
        with mock.patch.object(
            verifier,
            "verify_build_chain",
            return_value={"sha256": "a" * 64},
        ), mock.patch.object(
            verifier,
            "verify_app_bundle",
            return_value={
                "tree_sha256": "tree",
                "critical_sha256": {"daemon": "b" * 64},
            },
        ), self.assertRaisesRegex(
            verifier.VerificationError,
            "build-chain daemon differs",
        ):
            verifier.main(
                [
                    "--app-bundle",
                    "/tmp/Slipstream.app",
                    "--fresh-daemon",
                    "/tmp/fresh/slipstreamd",
                    "--staged-daemon",
                    "/tmp/staged/slipstreamd",
                ]
            )

    def test_bundle_rejects_missing_or_mismatched_build_version(self) -> None:
        for name, bundle_version in (("missing", None), ("mismatched", "old-version")):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                app = Path(temporary) / "Slipstream.app"
                contents = app / "Contents"
                contents.mkdir(parents=True)
                plist = {
                    "CFBundleIdentifier": verifier.BUNDLE_IDENTIFIER,
                    "CFBundleExecutable": verifier.APP_EXECUTABLE,
                    "CFBundleShortVersionString": "test-version",
                    "LSUIElement": True,
                }
                if bundle_version is not None:
                    plist["CFBundleVersion"] = bundle_version
                with (contents / "Info.plist").open("wb") as handle:
                    plistlib.dump(plist, handle)

                with self.assertRaisesRegex(
                    verifier.VerificationError,
                    "bundle build version does not match",
                ):
                    verifier.verify_app_bundle(
                        app,
                        expected_version="test-version",
                        architecture="arm64",
                    )

    def test_bundle_signature_precedes_daemon_classification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            app = Path(temporary) / "Slipstream.app"
            contents = app / "Contents"
            (contents / "Resources/chromium-headless-shell").mkdir(parents=True)
            with (contents / "Info.plist").open("wb") as handle:
                plistlib.dump(
                    {
                        "CFBundleIdentifier": verifier.BUNDLE_IDENTIFIER,
                        "CFBundleExecutable": verifier.APP_EXECUTABLE,
                        "CFBundleShortVersionString": "test-version",
                        "CFBundleVersion": "test-version",
                        "LSUIElement": True,
                    },
                    handle,
                )
            (contents / "Resources/chromium-headless-shell/manifest.json").write_text(
                "{}",
                encoding="utf-8",
            )
            events: list[str] = []

            def command(arguments: list[str] | tuple[str, ...], **_kwargs: object) -> str:
                self.assertEqual(arguments[1], "--classify-host")
                events.append("classification")
                host = arguments[2]
                if host == "www.youtube.com":
                    return json.dumps(
                        {
                            "host": host,
                            "route_class": "local_bypass",
                            "service_group": "youtube_video",
                            "strategy_set": "fake_only",
                        }
                    )
                return json.dumps(
                    {
                        "host": host,
                        "route_class": "direct_first",
                        "service_group": "youtube_video",
                        "strategy_set": "direct_first",
                    }
                )

            with mock.patch.object(
                verifier,
                "verify_codesign",
                side_effect=lambda *_args, **_kwargs: events.append("signature")
                or {"valid": True},
            ), mock.patch.object(verifier, "verify_architecture"), mock.patch.object(
                verifier,
                "verify_non_gui_helper",
            ), mock.patch.object(
                verifier,
                "verify_console_browser_access",
                side_effect=lambda *_args: events.append("console-access"),
            ), mock.patch.object(verifier, "regular_file"), mock.patch.object(
                verifier,
                "file_sha256",
                return_value="a" * 64,
            ), mock.patch.object(
                verifier,
                "deterministic_tree_sha256",
                return_value="b" * 64,
            ), mock.patch.object(
                verifier,
                "run_checked",
                side_effect=command,
            ):
                verifier.verify_app_bundle(
                    app,
                    expected_version="test-version",
                    architecture="arm64",
                )

            self.assertEqual(events[0], "signature")
            self.assertEqual(events[1], "console-access")
            self.assertEqual(events.count("classification"), 2)

    def test_schema3_attestation_witness_and_launchd_plist_are_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._install_attestation_fixture(Path(temporary))

            report = verifier.verify_install_attestation(
                attestation_path=fixture["attestation"],
                launchd_plist=fixture["launchd_plist"],
                expected_daemon_sha256=fixture["digest"],
                expected_uid=os.getuid(),
            )

            self.assertEqual(report["schema_version"], 3)
            self.assertEqual(report["daemon_sha256"], fixture["digest"])
            self.assertEqual(report["witness"], "valid")

    def test_install_attestation_rejects_missing_or_loosely_typed_contract_fields(self) -> None:
        cases = (
            (
                "missing gid",
                lambda evidence: evidence["daemon"].pop("gid"),
                "installed daemon gid must be an integer",
            ),
            (
                "boolean pid",
                lambda evidence: evidence["launchd"].__setitem__("pid", True),
                "attested PID must be an integer",
            ),
            (
                "numeric pf boolean",
                lambda evidence: evidence.__setitem__("pf_active", 1),
                "attested PF state must be a boolean",
            ),
            (
                "floating mode",
                lambda evidence: evidence["daemon"].__setitem__("mode", 448.0),
                "installed daemon mode must be an integer",
            ),
            (
                "floating port",
                lambda evidence: evidence["listener"].__setitem__("port", 1080.0),
                "listener port must be an integer",
            ),
        )
        for name, mutate, expected_error in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                fixture = self._install_attestation_fixture(Path(temporary))
                evidence = fixture["evidence"]
                mutate(evidence)
                self._rewrite_attestation(fixture["attestation"], evidence)
                with self.assertRaisesRegex(verifier.VerificationError, expected_error):
                    verifier.verify_install_attestation(
                        attestation_path=fixture["attestation"],
                        launchd_plist=fixture["launchd_plist"],
                        expected_daemon_sha256=fixture["digest"],
                        expected_uid=os.getuid(),
                    )

    def test_install_attestation_rejects_nonproduction_launchd_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._install_attestation_fixture(Path(temporary))
            plist = plistlib.loads(fixture["launchd_plist"].read_bytes())
            plist["ProgramArguments"].append("--unexpected")
            with fixture["launchd_plist"].open("wb") as handle:
                plistlib.dump(plist, handle)

            with self.assertRaisesRegex(
                verifier.VerificationError,
                "exact frozen production arguments",
            ):
                verifier.verify_install_attestation(
                    attestation_path=fixture["attestation"],
                    launchd_plist=fixture["launchd_plist"],
                    expected_daemon_sha256=fixture["digest"],
                    expected_uid=os.getuid(),
                )

    def test_install_attestation_rejects_launchd_semantic_overrides(self) -> None:
        cases = (
            (
                "Program override",
                lambda plist: plist.__setitem__("Program", "/tmp/evil"),
                "exact production key set",
            ),
            (
                "QueueDirectories trigger",
                lambda plist: plist.__setitem__("QueueDirectories", ["/tmp/evil"]),
                "exact production key set",
            ),
            (
                "resource limit override",
                lambda plist: plist["HardResourceLimits"].__setitem__("CPU", 1),
                "HardResourceLimits does not use the exact production key set",
            ),
        )
        for name, mutate, expected_error in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                fixture = self._install_attestation_fixture(Path(temporary))
                plist = plistlib.loads(fixture["launchd_plist"].read_bytes())
                mutate(plist)
                with fixture["launchd_plist"].open("wb") as handle:
                    plistlib.dump(plist, handle)

                with self.assertRaisesRegex(verifier.VerificationError, expected_error):
                    verifier.verify_install_attestation(
                        attestation_path=fixture["attestation"],
                        launchd_plist=fixture["launchd_plist"],
                        expected_daemon_sha256=fixture["digest"],
                        expected_uid=os.getuid(),
                    )

    def test_status_v2_binds_fresh_heartbeat_to_attested_pid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            status_path = self._status_fixture(Path(temporary))
            report = verifier.verify_status_v2(
                status_path=status_path,
                expected_pid=4242,
                expected_uid=os.getuid(),
                now=1_000.0,
            )

            self.assertEqual(report["pid"], 4242)
            self.assertEqual(report["state"], "active")
            self.assertEqual(report["phase"], "active")
            self.assertEqual(report["heartbeat_seq"], 7)

    def test_status_v2_accepts_independent_production_state_and_phase(self) -> None:
        cases = (("dormant", "active"), ("active", "active"))
        for state, phase in cases:
            with self.subTest(state=state, phase=phase), tempfile.TemporaryDirectory() as temporary:
                status_path = self._status_fixture(Path(temporary), state=state, phase=phase)
                report = verifier.verify_status_v2(
                    status_path=status_path,
                    expected_pid=4242,
                    expected_uid=os.getuid(),
                    now=1_000.0,
                )
                self.assertEqual(report["state"], state)
                self.assertEqual(report["phase"], phase)

    def test_status_v2_rejects_invalid_phase_or_nonoperational_active_pf(self) -> None:
        cases = (
            ("invalid phase", {"phase": "dormant"}, "phase is invalid"),
            ("unstable phase", {"phase": "recovering"}, "not in its stable phase"),
            ("PF not applied", {"pf_applied": False}, "has not applied PF"),
            ("PF disabled", {"pf_enabled": False}, "reports PF disabled"),
        )
        for name, kwargs, expected_error in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                status_path = self._status_fixture(Path(temporary), **kwargs)
                with self.assertRaisesRegex(verifier.VerificationError, expected_error):
                    verifier.verify_status_v2(
                        status_path=status_path,
                        expected_pid=4242,
                        expected_uid=os.getuid(),
                        now=1_000.0,
                    )

    def test_status_v2_rejects_stale_or_wrong_pid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            status_path = self._status_fixture(root)
            with self.assertRaisesRegex(verifier.VerificationError, "attested launchd PID"):
                verifier.verify_status_v2(
                    status_path=status_path,
                    expected_pid=9999,
                    expected_uid=os.getuid(),
                    now=1_000.0,
                )
            with self.assertRaisesRegex(verifier.VerificationError, "heartbeat file is stale"):
                verifier.verify_status_v2(
                    status_path=status_path,
                    expected_pid=4242,
                    expected_uid=os.getuid(),
                    now=1_000.0 + verifier.STATUS_STALE_AFTER_SECS + 0.1,
                )

    def test_launchctl_print_binds_program_arguments_and_pid(self) -> None:
        report = verifier.parse_launchctl_print(
            self._launchctl_payload(),
            expected_pid=4242,
        )
        self.assertEqual(report["program"], str(verifier.INSTALLED_DAEMON))
        self.assertEqual(report["pid"], 4242)
        with self.assertRaisesRegex(verifier.VerificationError, "wrong daemon program"):
            verifier.parse_launchctl_print(
                self._launchctl_payload(program="/tmp/not-slipstreamd"),
                expected_pid=4242,
            )

    def test_launchctl_accepts_only_exact_managed_proxy_flag(self) -> None:
        payload = self._launchctl_payload().replace(
            f"        {verifier.LISTENER_PORT}\n",
            f"        {verifier.LISTENER_PORT}\n        --managed-https-proxy\n",
        )
        report = verifier.parse_launchctl_print(payload, expected_pid=4242)
        self.assertEqual(report["arguments"][-1], "--managed-https-proxy")
        with self.assertRaises(verifier.VerificationError):
            verifier.parse_launchctl_print(
                payload.replace("--managed-https-proxy", "--other-proxy"),
                expected_pid=4242,
            )

    def test_launchctl_print_rejects_truncated_or_ambiguous_snapshot(self) -> None:
        payload = self._launchctl_payload()
        truncated = payload.rstrip().removesuffix("}")
        with self.assertRaisesRegex(verifier.VerificationError, "incomplete service block"):
            verifier.parse_launchctl_print(truncated, expected_pid=4242)

        daemon = str(verifier.INSTALLED_DAEMON)
        ambiguous = payload.replace(
            f"    program = {daemon}\n",
            f"    program = {daemon}\n    program = /tmp/evil\n",
            1,
        )
        with self.assertRaisesRegex(verifier.VerificationError, "exactly one program"):
            verifier.parse_launchctl_print(ambiguous, expected_pid=4242)

    def test_install_attestation_rejects_stale_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._install_attestation_fixture(Path(temporary))
            evidence = fixture["evidence"]
            evidence["source_sha256"] = "0" * 64
            self._rewrite_attestation(fixture["attestation"], evidence)

            with self.assertRaisesRegex(
                verifier.VerificationError,
                "stale attested source hash",
            ):
                verifier.verify_install_attestation(
                    attestation_path=fixture["attestation"],
                    launchd_plist=fixture["launchd_plist"],
                    expected_daemon_sha256=fixture["digest"],
                    expected_uid=os.getuid(),
                )

    def test_install_attestation_rejects_symlinked_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._install_attestation_fixture(Path(temporary))
            attestation = fixture["attestation"]
            actual = attestation.with_name("actual-attestation.json")
            attestation.rename(actual)
            attestation.symlink_to(actual.name)

            with self.assertRaisesRegex(
                verifier.VerificationError,
                "install attestation is not a regular file",
            ):
                verifier.verify_install_attestation(
                    attestation_path=attestation,
                    launchd_plist=fixture["launchd_plist"],
                    expected_daemon_sha256=fixture["digest"],
                    expected_uid=os.getuid(),
                )

    def test_install_attestation_rejects_broken_witness(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._install_attestation_fixture(Path(temporary))
            fixture["installed"].unlink()

            with self.assertRaisesRegex(
                verifier.VerificationError,
                "attestation witness is no longer hard-linked",
            ):
                verifier.verify_install_attestation(
                    attestation_path=fixture["attestation"],
                    launchd_plist=fixture["launchd_plist"],
                    expected_daemon_sha256=fixture["digest"],
                    expected_uid=os.getuid(),
                )


if __name__ == "__main__":
    unittest.main()
