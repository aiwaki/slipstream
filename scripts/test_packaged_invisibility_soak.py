from __future__ import annotations

import json
import unittest
import inspect
import io
import shlex
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import packaged_invisibility_soak as soak

ROOT = Path(__file__).resolve().parents[1]


def _unified_log_filter_banner() -> str:
    return (
        'Filtering the log data using "composedMessage CONTAINS[c] '
        '"PostShowProcess" AND (composedMessage CONTAINS[c] '
        '"slipstream" OR composedMessage CONTAINS[c] '
        '"chrome-headless" OR composedMessage CONTAINS[c] '
        '"chromium")"'
    )


class FakeClock:
    def __init__(self) -> None:
        self.value = 100.0

    def monotonic(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class PackagedInvisibilitySoakTests(unittest.TestCase):
    def test_unified_log_filter_banner_handshake_precedes_measurement(self) -> None:
        pipe = io.StringIO(_unified_log_filter_banner() + "\n")
        process = SimpleNamespace(stdout=pipe, poll=lambda: None)
        with mock.patch.object(
            soak.select,
            "select",
            return_value=([pipe], [], []),
        ):
            banner = soak._wait_for_unified_log_filter_banner(process)

        self.assertEqual(banner, _unified_log_filter_banner() + "\n")

    def test_unified_log_filter_banner_handshake_times_out_closed(self) -> None:
        pipe = io.StringIO("")
        process = SimpleNamespace(stdout=pipe, poll=lambda: None)
        with (
            mock.patch.object(
                soak.select,
                "select",
                return_value=([], [], []),
            ),
            self.assertRaisesRegex(
                soak.SoakError,
                "unified-log filter banner timed out",
            ),
        ):
            soak._wait_for_unified_log_filter_banner(process)

    def test_unified_log_filter_banner_handshake_rejects_early_exit(self) -> None:
        process = SimpleNamespace(stdout=io.StringIO(""), poll=lambda: 1)

        with self.assertRaisesRegex(
            soak.SoakError,
            "unified-log sampler exited before its filter banner",
        ):
            soak._wait_for_unified_log_filter_banner(process)

    def test_unified_log_sampler_is_polled_inside_measured_window(self) -> None:
        source = inspect.getsource(soak.run_soak)
        sample = source.index("def sample()")
        sampler_poll = source.index("unified_log.poll()", sample)
        measured = source.index("_sample_window(", sample)

        self.assertLess(sampler_poll, measured)

    def test_all_samplers_are_polled_at_measured_window_boundary(self) -> None:
        source = inspect.getsource(soak.run_soak)
        measured = source.index(
            "measured_seconds, samples, max_sample_gap = _sample_window("
        )
        cleanup = source.index("except BaseException as exc:", measured)
        boundary = source[measured:cleanup]

        self.assertIn("tray.poll()", boundary)
        self.assertIn("listener.poll()", boundary)
        self.assertIn("unified_log.poll()", boundary)

    def test_unified_log_filter_banner_is_not_a_visibility_event(self) -> None:
        self.assertEqual(
            soak._count_unified_log_post_show_events(_unified_log_filter_banner()),
            0,
        )

    def test_unified_log_structured_post_show_event_still_fails(self) -> None:
        event = json.dumps(
            {
                "eventMessage": (
                    "Notification: kLSNotifyShowRequest Slipstream "
                    "PostShowProcess"
                )
            }
        )

        output = _unified_log_filter_banner() + "\n" + event

        self.assertEqual(soak._count_unified_log_post_show_events(output), 1)

    def test_unified_log_counts_every_structured_post_show_event(self) -> None:
        event = json.dumps(
            {"eventMessage": "Slipstream PostShowProcess"}
        )
        output = "\n".join((_unified_log_filter_banner(), event, event))

        self.assertEqual(soak._count_unified_log_post_show_events(output), 2)

    def test_unified_log_missing_filter_banner_is_fail_closed(self) -> None:
        event = json.dumps(
            {"eventMessage": "Slipstream PostShowProcess"}
        )

        with self.assertRaisesRegex(
            soak.SoakError,
            "unified-log filter banner is missing",
        ):
            soak._count_unified_log_post_show_events(event)

    def test_unified_log_duplicate_filter_banner_is_fail_closed(self) -> None:
        banner = _unified_log_filter_banner()

        with self.assertRaisesRegex(
            soak.SoakError,
            "unified-log filter banner is invalid",
        ):
            soak._count_unified_log_post_show_events(banner + "\n" + banner)

    def test_unified_log_unexpected_output_is_fail_closed(self) -> None:
        with self.assertRaisesRegex(
            soak.SoakError,
            "unified-log sampler emitted malformed NDJSON",
        ):
            soak._count_unified_log_post_show_events("unexpected output")

    def test_unified_log_unrelated_structured_event_is_fail_closed(self) -> None:
        event = json.dumps({"eventMessage": "unrelated diagnostic"})
        output = _unified_log_filter_banner() + "\n" + event

        with self.assertRaisesRegex(
            soak.SoakError,
            "unified-log predicate emitted an unrelated event",
        ):
            soak._count_unified_log_post_show_events(output)

    def test_system_cleanup_residue_uses_only_symbolic_names(self) -> None:
        def fake_lexists(path: str) -> bool:
            return path == "/var/run/slipstream.status"

        command_results = [
            SimpleNamespace(returncode=0, stdout="", stderr=""),
            SimpleNamespace(returncode=0, stdout="nat residue\n", stderr=""),
            SimpleNamespace(returncode=0, stdout="", stderr=""),
            SimpleNamespace(returncode=1, stdout="", stderr=""),
        ]
        with (
            mock.patch.object(soak.os.path, "lexists", side_effect=fake_lexists),
            mock.patch.object(
                soak.subprocess,
                "run",
                side_effect=command_results,
            ),
        ):
            residues = soak._system_cleanup_residues()

        self.assertEqual(
            residues,
            ("daemon_status", "launchd_job", "pf_nat_anchor"),
        )
        self.assertNotIn("/", "".join(residues))

    def test_system_cleanup_probe_failure_is_fail_closed(self) -> None:
        command_results = [
            SimpleNamespace(
                returncode=113,
                stdout="",
                stderr="Could not find service in domain for system",
            ),
            SimpleNamespace(returncode=1, stdout="", stderr="probe failed"),
        ]
        with (
            mock.patch.object(soak.os.path, "lexists", return_value=False),
            mock.patch.object(
                soak.subprocess,
                "run",
                side_effect=command_results,
            ),
            self.assertRaisesRegex(
                soak.SoakError,
                r"^cleanup probe failed: pf_nat_anchor$",
            ),
        ):
            soak._system_cleanup_residues()

    def test_cleanup_always_uses_the_root_owned_installed_daemon(self) -> None:
        with (
            mock.patch.object(soak, "_run_checked") as run_checked,
            mock.patch.object(
                soak,
                "_wait_for_system_cleanup_absence",
                return_value=(),
            ),
        ):
            soak._cleanup_installed_candidate()

        run_checked.assert_called_once_with(
            ("/usr/bin/sudo", str(soak.INSTALLED_DAEMON), "--uninstall")
        )

    def test_cleanup_does_not_mask_residue_with_a_second_uninstall(self) -> None:
        with (
            mock.patch.object(soak, "_run_checked") as run_checked,
            mock.patch.object(
                soak,
                "_wait_for_system_cleanup_absence",
                return_value=("daemon_status",),
            ) as wait_absent,
            self.assertRaisesRegex(
                soak.SoakError,
                r"^product cleanup residue: daemon_status$",
            ),
        ):
            soak._cleanup_installed_candidate()

        run_checked.assert_called_once()
        wait_absent.assert_called_once()

    def test_unexpected_launchctl_failure_is_not_absence(self) -> None:
        with (
            mock.patch.object(soak.os.path, "lexists", return_value=False),
            mock.patch.object(
                soak.subprocess,
                "run",
                return_value=SimpleNamespace(
                    returncode=1,
                    stdout="",
                    stderr="permission denied",
                ),
            ),
            self.assertRaisesRegex(
                soak.SoakError,
                r"^cleanup probe failed: launchd_job$",
            ),
        ):
            soak._system_cleanup_residues()

    def test_launchctl_113_without_exact_absence_phrase_fails_closed(self) -> None:
        with (
            mock.patch.object(soak.os.path, "lexists", return_value=False),
            mock.patch.object(
                soak.subprocess,
                "run",
                return_value=SimpleNamespace(
                    returncode=113,
                    stdout="",
                    stderr="unrelated launchctl failure",
                ),
            ),
            self.assertRaisesRegex(
                soak.CleanupError,
                r"^cleanup probe failed: launchd_job$",
            ),
        ):
            soak._system_cleanup_residues()

    def test_cleanup_fails_with_only_bounded_symbolic_residue(self) -> None:
        with (
            mock.patch.object(soak, "_run_checked"),
            mock.patch.object(
                soak,
                "_wait_for_system_cleanup_absence",
                return_value=("daemon_status",),
            ),
            self.assertRaisesRegex(
                soak.SoakError,
                r"^product cleanup residue: daemon_status$",
            ),
        ):
            soak._cleanup_installed_candidate()

    def test_listener_probe_covers_ipv4_and_ipv6_and_rejects_stderr(self) -> None:
        command_results = [
            SimpleNamespace(
                returncode=113,
                stdout="",
                stderr="Could not find service in domain for system",
            ),
            SimpleNamespace(returncode=0, stdout="", stderr=""),
            SimpleNamespace(returncode=0, stdout="", stderr=""),
            SimpleNamespace(returncode=1, stdout="", stderr="invalid selector"),
        ]
        with (
            mock.patch.object(soak.os.path, "lexists", return_value=False),
            mock.patch.object(
                soak.subprocess,
                "run",
                side_effect=command_results,
            ) as run,
            self.assertRaisesRegex(
                soak.CleanupError,
                r"^cleanup probe failed: daemon_listener$",
            ),
        ):
            soak._system_cleanup_residues()

        listener_command = run.call_args_list[-1].args[0]
        self.assertIn("-iTCP:1080", listener_command)
        self.assertNotIn("-iTCP@127.0.0.1:1080", listener_command)

    def test_run_soak_cleanup_does_not_probe_inaccessible_installed_child(
        self,
    ) -> None:
        commands: list[tuple[str, ...]] = []

        def run_checked(command: tuple[str, ...], timeout: float = 120.0) -> None:
            del timeout
            commands.append(command)
            if command[-1] == "--install":
                raise soak.SoakError("stop after entering protected body")

        def guarded_exists(path: Path) -> bool:
            if path == soak.INSTALLED_DAEMON:
                raise PermissionError(str(path))
            return False

        with tempfile.TemporaryDirectory() as temporary:
            app = Path(temporary) / "Slipstream.app"
            app.mkdir()
            resolved_app = app.resolve()
            with (
                mock.patch.object(soak, "_require_protected_ci"),
                mock.patch.object(Path, "is_file", autospec=True, return_value=True),
                mock.patch.object(
                    Path,
                    "exists",
                    autospec=True,
                    side_effect=guarded_exists,
                ),
                mock.patch.object(
                    soak.visibility,
                    "_frontmost_asn",
                    return_value="baseline",
                ),
                mock.patch.object(
                    soak.visibility,
                    "_browser_processes",
                    return_value=(set(), set()),
                ),
                mock.patch.object(soak, "_profiles", return_value=set()),
                mock.patch.object(soak, "_launch_agents", return_value=set()),
                mock.patch.object(soak, "_run_checked", side_effect=run_checked),
                mock.patch.object(
                    soak,
                    "_wait_for_system_cleanup_absence",
                    return_value=(),
                ),
            ):
                report, status = soak.run_soak(app, 1)

        candidate_daemon = (
            resolved_app
            / "Contents"
            / "Resources"
            / "slipstreamd"
            / "slipstreamd"
        )
        self.assertEqual(
            commands,
            [
                ("/usr/bin/sudo", str(candidate_daemon), "--install"),
                (
                    "/usr/bin/sudo",
                    str(soak.INSTALLED_DAEMON),
                    "--uninstall",
                ),
            ],
        )
        self.assertEqual(status, 1)
        self.assertEqual(report["cleanup_failures"], [])

    def test_run_soak_report_preserves_allowlisted_cleanup_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            app = Path(temporary) / "Slipstream.app"
            app.mkdir()
            with (
                mock.patch.object(soak, "_require_protected_ci"),
                mock.patch.object(Path, "is_file", autospec=True, return_value=True),
                mock.patch.object(
                    soak.visibility,
                    "_frontmost_asn",
                    return_value="baseline",
                ),
                mock.patch.object(
                    soak.visibility,
                    "_browser_processes",
                    return_value=(set(), set()),
                ),
                mock.patch.object(soak, "_profiles", return_value=set()),
                mock.patch.object(soak, "_launch_agents", return_value=set()),
                mock.patch.object(
                    soak,
                    "_run_checked",
                    side_effect=soak.SoakError(
                        "stop after entering protected body"
                    ),
                ),
                mock.patch.object(
                    soak,
                    "_cleanup_installed_candidate",
                    side_effect=soak.CleanupError(
                        "residue", ("daemon_status",)
                    ),
                ),
            ):
                report, status = soak.run_soak(app, 1)

        self.assertEqual(status, 1)
        self.assertEqual(
            report["cleanup_failures"],
            ["residue:daemon_status"],
        )
        self.assertLessEqual(
            set(report["cleanup_failures"]),
            soak.CLEANUP_REPORT_SYMBOLS,
        )

    def test_workflow_post_soak_cleanup_manifest_matches_harness(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "release-readiness.yml"
        ).read_text(encoding="utf-8")
        diagnostic_step, remainder = workflow.split(
            "- name: Preserve bounded invisibility-soak diagnostics for this attempt",
            1,
        )
        del diagnostic_step
        diagnostic_block, remainder = remainder.split(
            "- name: Verify the soak left no product-owned system path",
            1,
        )
        cleanup_block, _next_step = remainder.split(
            "- name: Bind qualification and measured readiness to one workflow attempt",
            1,
        )
        actual_paths = []
        for line in cleanup_block.splitlines():
            stripped = line.strip()
            if not stripped.startswith("assert_absent_path "):
                continue
            tokens = shlex.split(stripped)
            self.assertEqual(len(tokens), 3)
            actual_paths.append((tokens[2], tokens[1]))

        self.assertIn("if: always()", diagnostic_block)
        self.assertIn("if: always()", cleanup_block)
        self.assertEqual(tuple(actual_paths), soak.SYSTEM_CLEANUP_PATHS)
        self.assertIn('test -e "$1" || test -L "$1"', cleanup_block)
        self.assertIn("Could not find service", cleanup_block)
        self.assertEqual(
            [
                line.strip()
                for line in cleanup_block.splitlines()
                if line.strip().startswith("assert_empty_anchor ")
            ],
            [
                "assert_empty_anchor -sn pf_nat_anchor",
                "assert_empty_anchor -sr pf_filter_anchor",
            ],
        )
        self.assertIn("-iTCP:1080", cleanup_block)
        self.assertNotIn("-iTCP@127.0.0.1:1080", cleanup_block)
        self.assertIn("test ! -s \"$listener_stderr\"", cleanup_block)

    def test_cleanup_absence_must_be_stable_across_samples(self) -> None:
        clock = FakeClock()
        observations = iter([(), ("daemon_status",), (), (), ()])
        with mock.patch.object(
            soak,
            "_system_cleanup_residues",
            side_effect=lambda: next(observations),
        ):
            result = soak._wait_for_system_cleanup_absence(
                timeout=10,
                stable_samples=3,
                monotonic=clock.monotonic,
                sleep=clock.sleep,
            )

        self.assertEqual(result, ())
        self.assertAlmostEqual(clock.value, 100.8)

    def test_cleanup_absence_reports_last_exact_residue_at_deadline(self) -> None:
        clock = FakeClock()
        with mock.patch.object(
            soak,
            "_system_cleanup_residues",
            return_value=("pf_nat_anchor",),
        ):
            result = soak._wait_for_system_cleanup_absence(
                timeout=0.4,
                stable_samples=3,
                monotonic=clock.monotonic,
                sleep=clock.sleep,
            )

        self.assertEqual(result, ("pf_nat_anchor",))

    def test_unified_log_observation_starts_after_launch_sampling(self) -> None:
        source = inspect.getsource(soak.run_soak)
        startup = source.index("startup_deadline =")
        first_status = source.index("first_status = _wait_status()", startup)
        unified_log = source.index("unified_log = subprocess.Popen", startup)
        measured = source.index("_sample_window(", startup)
        self.assertLess(startup, first_status)
        self.assertLess(first_status, unified_log)
        self.assertLess(unified_log, measured)

    def test_profile_residue_uses_the_effective_macos_temp_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / ("slipstream-browser-probe-" + "a" * 32)
            profile.mkdir()
            with (
                mock.patch.object(soak.tempfile, "gettempdir", return_value=temporary),
                mock.patch.dict(soak.os.environ, {"TMPDIR": temporary}),
            ):
                self.assertIn(str(profile.resolve()), soak._profiles())

    def test_sample_window_measures_full_1800_seconds_after_readiness(self) -> None:
        clock = FakeClock()
        observed: list[float] = []
        measured, samples, max_gap = soak._sample_window(
            1800,
            lambda: observed.append(clock.monotonic()),
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )
        self.assertEqual(measured, 1800)
        self.assertEqual(samples, 3600)
        self.assertEqual(max_gap, 0.5)
        self.assertEqual(observed[0], 100.0)
        self.assertEqual(observed[-1], 1899.5)

    def test_live_heartbeat_rejects_stale_status_after_daemon_crash(self) -> None:
        with self.assertRaisesRegex(soak.SoakError, "became stale"):
            soak._validate_live_heartbeat(
                {
                    "state": "active",
                    "pid": 42,
                    "heartbeat_seq": 8,
                    "updated_at": 100.0,
                },
                expected_pid=42,
                previous_seq=8,
                last_change_monotonic=10.0,
                now_wall=106.0,
                now_monotonic=16.0,
            )

    def test_live_heartbeat_must_keep_advancing(self) -> None:
        with self.assertRaisesRegex(soak.SoakError, "stopped advancing"):
            soak._validate_live_heartbeat(
                {
                    "state": "active",
                    "pid": 42,
                    "heartbeat_seq": 8,
                    "updated_at": 105.0,
                },
                expected_pid=42,
                previous_seq=8,
                last_change_monotonic=10.0,
                now_wall=106.0,
                now_monotonic=16.0,
            )

    def test_live_heartbeat_accepts_owned_progress(self) -> None:
        seq, changed = soak._validate_live_heartbeat(
            {
                "state": "active",
                "pid": 42,
                "heartbeat_seq": 9,
                "updated_at": 105.5,
            },
            expected_pid=42,
            previous_seq=8,
            last_change_monotonic=10.0,
            now_wall=106.0,
            now_monotonic=16.0,
        )
        self.assertEqual(seq, 9)
        self.assertEqual(changed, 16.0)


if __name__ == "__main__":
    unittest.main()
