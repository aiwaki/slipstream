from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
import os
import subprocess
import tempfile
import unittest

from scripts import composed_pending_navigation_smoke as smoke


def _ci_environment() -> dict[str, str]:
    return {
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "SLIPSTREAM_DISPOSABLE_CI": "1",
    }


class _IdleClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.oversleep = 0.0
        self.sleeps = []
        self.on_sleep = lambda _seconds: None

    def wall(self) -> float:
        return 1_800_000_000.0 + self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds + (self.oversleep if seconds == 3.0 else 0.0)
        self.on_sleep(seconds)


def _idle_status(clock: _IdleClock) -> dict:
    health = datetime.fromtimestamp(clock.wall(), timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "schema_version": 2,
        "daemon": {"pid": 42, "state": "active", "phase": "active",
                   "updated_at": clock.wall(), "heartbeat_at": health, "health_updated_at": health},
        "recovery": {"state": "idle", "count": 0},
        # Completion is sufficient; failed external probes must not block this CPU measurement.
        "canaries": {"running": False, "total": 3, "ok": 0, "next_due_in": 30},
    }


@contextmanager
def _idle_fixture():
    clock = _IdleClock()
    with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
        values = {
            "_assert_broker_socket": mock.Mock(),
            "_worker_profiles": mock.Mock(return_value=()),
            "_worker_processes": mock.Mock(return_value=()),
            "_daemon_process_identity": mock.Mock(return_value=(42, "Tue Oct 20 12:00:00 2026")),
            "_daemon_cpu_seconds": mock.Mock(side_effect=(10.0, 10.5)),
        }
        for name, value in values.items():
            stack.enter_context(mock.patch.object(smoke, name, value))
        runtime = Path(directory) / "runtime"
        stack.enter_context(mock.patch.object(smoke, "PRODUCTION_WORKER_RUNTIME", runtime))
        stack.enter_context(mock.patch.object(smoke.os, "environ", _ci_environment()))
        stack.enter_context(mock.patch.object(smoke.time, "monotonic", side_effect=lambda: clock.now))
        stack.enter_context(mock.patch.object(smoke.time, "time", side_effect=clock.wall))
        stack.enter_context(mock.patch.object(smoke.time, "sleep", side_effect=clock.sleep))
        stack.enter_context(mock.patch.object(smoke.subprocess, "run",
            side_effect=AssertionError("native execution is forbidden in idle fixtures")))
        yield SimpleNamespace(clock=clock, runtime=runtime, **values)


class ComposedPendingNavigationSmokeTests(unittest.TestCase):
    def test_disposable_guard_requires_all_three_markers(self) -> None:
        with mock.patch.object(smoke.os, "environ", _ci_environment()):
            smoke.require_disposable_ci()

        with mock.patch.object(smoke.os, "environ", {"CI": "true"}):
            with self.assertRaisesRegex(smoke.ComposedQualificationError, "missing"):
                smoke.require_disposable_ci()

    def test_original_navigation_command_is_extension_free_and_targets_public_ip(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            command = smoke.original_navigation_command(
                Path("/tmp/Chrome"),
                Path(raw_directory),
            )

        self.assertEqual(command[0], "/tmp/Chrome")
        self.assertIn("--disable-extensions", command)
        self.assertIn("--disable-quic", command)
        self.assertIn("--ignore-certificate-errors", command)
        self.assertTrue(any(smoke.FIXTURE_PUBLIC_IP in value for value in command))
        self.assertEqual(command[-1], f"https://{smoke.FIXTURE_HOST}/")

    def test_qualification_environment_is_exact_and_keeps_production_socket(
        self,
    ) -> None:
        with mock.patch.object(smoke.os, "environ", _ci_environment()):
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

        self.assertEqual(
            set(environment),
            smoke.DISPOSABLE_QUALIFICATION_ENVIRONMENT_KEYS,
        )
        self.assertNotIn("SLIPSTREAM_BROWSER_PROBE_SOCKET", environment)
        self.assertEqual(
            environment["SLIPSTREAM_BROWSER_PROBE_ORIGIN"],
            f"https://{smoke.FIXTURE_HOST}:18443/",
        )
        self.assertEqual(environment[smoke.DAEMON_FIXTURE_PORT_ENV], "19443")

    def test_report_requires_original_worker_original_timing_and_resources(
        self,
    ) -> None:
        fixture = smoke.ComposedHttpsFixture()
        try:
            fixture._records = [
                {"channel": "original", "path": "/", "count": 1, "elapsed_ms": 100},
                {"channel": "worker", "path": "/", "count": 2, "elapsed_ms": 8_100},
                {
                    "channel": "original",
                    "path": "/",
                    "count": 3,
                    "elapsed_ms": 16_100,
                },
            ]
            fixture._counts.update(
                {"root": 3, "css": 1, "js": 1, "image": 1, "ready": 1}
            )
            fixture._ready.set()

            report = fixture.report()

            self.assertEqual(
                report["root_channels"],
                ["original", "worker", "original"],
            )
            self.assertEqual(report["ready_callbacks"], 1)
            fixture._records[1]["elapsed_ms"] = 7_000
            with self.assertRaisesRegex(
                smoke.ComposedQualificationError,
                "observation windows",
            ):
                fixture.report()
        finally:
            fixture.close()

    def test_cpu_time_parser(self) -> None:
        for value, expected in (
            ("01:02", 62.0),
            ("01:02:03", 3723.0),
            ("00:00.50", 0.5),
        ):
            with self.subTest(value=value):
                self.assertEqual(smoke._cpu_seconds(value), expected)

    def test_cpu_time_parser_rejects_negative_nonfinite_and_overflow(self) -> None:
        for value in ("00:nan", "inf:00", "00:-1", "1e308:00"):
            with self.subTest(value=value), self.assertRaises(smoke.ComposedQualificationError):
                smoke._cpu_seconds(value)

    def test_daemon_process_birth_uses_exact_pid_and_no_argv(self) -> None:
        completed = subprocess.CompletedProcess((), 0, " 42 Tue Oct 20 12:00:00 2026\n", "")
        with mock.patch.object(smoke.subprocess, "run", return_value=completed) as query:
            self.assertEqual(smoke._daemon_process_identity(42), (42, "Tue Oct 20 12:00:00 2026"))
            self.assertEqual(query.call_args.args[0], ("/bin/ps", "-p", "42", "-o", "pid=,lstart="))
            for raw in ("", "43 Tue Oct 20 12:00:00 2026\n", completed.stdout * 2):
                completed.stdout = raw
                with self.assertRaisesRegex(smoke.ComposedQualificationError, "PID/birth"):
                    smoke._daemon_process_identity(42)

    def test_idle_process_queries_share_the_remaining_settle_deadline(self) -> None:
        for function, stdout in ((smoke._daemon_process_identity, "42 Tue Oct 20 12:00:00 2026\n"),
                                 (smoke._worker_processes, "")):
            with self.subTest(function=function.__name__):
                completed = subprocess.CompletedProcess((), 0, stdout, "")
                with (mock.patch.object(smoke.time, "monotonic", return_value=119.75) as clock,
                      mock.patch.object(smoke.subprocess, "run", return_value=completed) as query):
                    function(42, deadline=120)
                    self.assertEqual(query.call_args.kwargs["timeout"], 0.25)
                    clock.return_value = 120
                    with self.assertRaisesRegex(smoke.ComposedQualificationError, "timed out"):
                        function(42, deadline=120)
                    self.assertEqual(query.call_count, 1)

    def test_idle_waits_for_first_completed_batch_then_samples_cpu_once(self) -> None:
        with _idle_fixture() as fixture:
            reads = 0
            def read_status():
                nonlocal reads
                reads += 1
                status = _idle_status(fixture.clock)
                if reads <= 3:
                    self.assertEqual(fixture._daemon_cpu_seconds.call_count, 0)
                if reads == 1:
                    status["canaries"]["total"] = 0
                elif reads == 2:
                    status["canaries"]["running"] = True
                return status
            report = smoke.assert_worker_idle(os.getuid(), 42, read_status=read_status)
            self.assertEqual(fixture.clock.sleeps, [0.5, 0.5, 3.0])
            self.assertEqual(fixture._daemon_cpu_seconds.call_count, 2)
            self.assertEqual(fixture._assert_broker_socket.call_count, 4)
            self.assertEqual(report["settle_ms"], 1000)
            self.assertEqual(report["observation_ms"], 3000)
            self.assertEqual(report["daemon_cpu_before_seconds"], 10.0)
            self.assertEqual(report["daemon_cpu_after_seconds"], 10.5)
            self.assertEqual(report["daemon_cpu_delta_ms"], 500)

    def test_idle_waits_for_broker_created_after_first_active_status(self) -> None:
        with _idle_fixture() as fixture:
            missing = smoke.ComposedQualificationError("broker not created yet")
            missing.__cause__ = FileNotFoundError()
            fixture._assert_broker_socket.side_effect = (missing, None, None)
            report = smoke.assert_worker_idle(os.getuid(), 42, read_status=lambda: _idle_status(fixture.clock))
            self.assertEqual(fixture.clock.sleeps, [0.5, 3.0])
            self.assertEqual(fixture._worker_processes.call_count, 3)
            self.assertEqual(report["settle_ms"], 500)

    def test_idle_missing_broker_does_not_hide_worker_or_unsafe_socket(self) -> None:
        for cause in (None, PermissionError(), FileNotFoundError()):
            with self.subTest(cause=cause), _idle_fixture() as fixture:
                error = smoke.ComposedQualificationError("unsafe or absent broker")
                error.__cause__ = cause
                fixture._assert_broker_socket.side_effect = error
                if isinstance(cause, FileNotFoundError):
                    fixture._worker_processes.return_value = (123,)
                with self.assertRaises(smoke.ComposedQualificationError):
                    smoke.assert_worker_idle(os.getuid(), 42, read_status=lambda: _idle_status(fixture.clock))
                self.assertEqual(fixture.clock.sleeps, [])
                self.assertEqual(fixture._daemon_cpu_seconds.call_count, 0)

    def test_idle_broker_cannot_disappear_after_it_was_observed(self) -> None:
        with _idle_fixture() as fixture:
            missing = smoke.ComposedQualificationError("broker disappeared")
            missing.__cause__ = FileNotFoundError()
            fixture._assert_broker_socket.side_effect = (None, missing)
            def read_status():
                status = _idle_status(fixture.clock)
                status["canaries"]["running"] = True
                return status
            with self.assertRaisesRegex(smoke.ComposedQualificationError, "broker disappeared"):
                smoke.assert_worker_idle(os.getuid(), 42, read_status=read_status)
            self.assertEqual(fixture.clock.sleeps, [0.5])
            self.assertEqual(fixture._daemon_cpu_seconds.call_count, 0)

    def test_idle_ages_cached_next_due_in_instead_of_using_new_heartbeat(self) -> None:
        with _idle_fixture() as fixture:
            cached = _idle_status(fixture.clock)
            cached["daemon"]["health_updated_at"] = datetime.fromtimestamp(
                fixture.clock.wall() - 10, timezone.utc).isoformat()
            cached["canaries"]["next_due_in"] = 12
            def read_status():
                return cached if fixture.clock.now == 0 else _idle_status(fixture.clock)
            report = smoke.assert_worker_idle(os.getuid(), 42, read_status=read_status)
            self.assertEqual(fixture.clock.sleeps, [0.5, 3.0])
            self.assertEqual(report["settle_ms"], 500)

    def test_idle_missing_stale_or_incomplete_status_times_out_without_cpu_sample(self) -> None:
        for kind in ("missing", "schema", "health_missing", "health_stale", "health_future", "running"):
            with self.subTest(kind=kind), _idle_fixture() as fixture:
                def read_status():
                    status = _idle_status(fixture.clock)
                    if kind == "missing":
                        return None
                    if kind == "schema":
                        status["schema_version"] = 1
                    elif kind == "health_missing":
                        status["daemon"].pop("health_updated_at")
                    elif kind in ("health_stale", "health_future"):
                        offset = -16 if kind == "health_stale" else 1
                        status["daemon"]["health_updated_at"] = datetime.fromtimestamp(
                            fixture.clock.wall() + offset, timezone.utc).isoformat()
                    elif kind == "running":
                        status["canaries"]["running"] = True
                    return status
                with self.assertRaisesRegex(smoke.ComposedQualificationError, "timed out") as raised:
                    smoke.assert_worker_idle(os.getuid(), 42, read_status=read_status)
                self.assertEqual(fixture.clock.now, 120.0)
                self.assertEqual(fixture._daemon_cpu_seconds.call_count, 0)
                self.assertIsNone(raised.exception.idle_evidence["observation_ms"])

    def test_idle_does_not_admit_readiness_at_expired_deadline(self) -> None:
        with _idle_fixture() as fixture:
            def read_status():
                status = _idle_status(fixture.clock)
                status["canaries"]["running"] = fixture.clock.now < 120
                return status
            with self.assertRaisesRegex(smoke.ComposedQualificationError, "timed out"):
                smoke.assert_worker_idle(os.getuid(), 42, read_status=read_status)
            self.assertEqual(fixture._daemon_cpu_seconds.call_count, 0)

    def test_idle_missing_or_untyped_recovery_count_never_qualifies(self) -> None:
        for count in (None, False, -1, "0", 0.0):
            with self.subTest(count=count), _idle_fixture() as fixture:
                def read_status():
                    status = _idle_status(fixture.clock)
                    if count is None:
                        status["recovery"].pop("count")
                    else:
                        status["recovery"]["count"] = count
                    return status
                with self.assertRaisesRegex(smoke.ComposedQualificationError, "timed out") as raised:
                    smoke.assert_worker_idle(os.getuid(), 42, read_status=read_status)
                self.assertEqual(fixture._daemon_cpu_seconds.call_count, 0)
                self.assertEqual(raised.exception.idle_evidence["startup_readiness"]["reason"],
                                 "invalid_recovery_count")

    def test_idle_nonidle_status_and_pid_or_recovery_changes_fail_without_waiting(self) -> None:
        for field, value in (("pid", 43), ("state", "dormant"), ("phase", "recovering"), ("recovery", "rearmed")):
            with self.subTest(field=field), _idle_fixture() as fixture:
                status = _idle_status(fixture.clock)
                if field == "recovery":
                    status["recovery"]["state"] = value
                else:
                    status["daemon"][field] = value
                with self.assertRaises(smoke.ComposedQualificationError):
                    smoke.assert_worker_idle(os.getuid(), 42, read_status=lambda: status)
                self.assertEqual(fixture.clock.sleeps, [])
                self.assertEqual(fixture._daemon_cpu_seconds.call_count, 0)
        with _idle_fixture() as fixture:
            status = _idle_status(fixture.clock)
            status["daemon"]["pid"] = 43
            status.pop("canaries")
            with self.assertRaisesRegex(smoke.ComposedQualificationError, "PID changed"):
                smoke.assert_worker_idle(os.getuid(), 42, read_status=lambda: status)
        with _idle_fixture() as fixture:
            def read_status():
                status = _idle_status(fixture.clock)
                status["canaries"]["running"] = fixture.clock.now == 0
                status["recovery"]["count"] = int(fixture.clock.now > 0)
                return status
            with self.assertRaisesRegex(smoke.ComposedQualificationError, "recovery changed"):
                smoke.assert_worker_idle(os.getuid(), 42, read_status=read_status)
            self.assertEqual(fixture._daemon_cpu_seconds.call_count, 0)

    def test_idle_rejects_birth_change_before_and_after_single_sample(self) -> None:
        for after_sample in (False, True):
            with self.subTest(after_sample=after_sample), _idle_fixture() as fixture:
                original = fixture._daemon_process_identity.return_value
                fixture._daemon_process_identity.side_effect = (
                    [original] * (2 if after_sample else 1) + [(42, "Tue Oct 20 12:00:01 2026")]
                )
                with self.assertRaisesRegex(smoke.ComposedQualificationError, "PID/birth changed") as raised:
                    smoke.assert_worker_idle(os.getuid(), 42, read_status=lambda: _idle_status(fixture.clock))
                self.assertEqual(fixture._daemon_cpu_seconds.call_count, 2 if after_sample else 0)
                if after_sample:
                    self.assertEqual(raised.exception.idle_evidence["observation_ms"], 3000)
                    self.assertEqual(raised.exception.idle_evidence["daemon_cpu_after_seconds"], 10.5)

    def test_idle_cpu_failure_records_original_counters_and_never_retries(self) -> None:
        for after in (11.01, 9.0, float("nan"), float("inf")):
            with self.subTest(after=after), _idle_fixture() as fixture:
                fixture._daemon_cpu_seconds.side_effect = (10.0, after)
                fixture.clock.oversleep = 0.25
                with self.assertRaises(smoke.ComposedQualificationError) as raised:
                    smoke.assert_worker_idle(os.getuid(), 42, read_status=lambda: _idle_status(fixture.clock))
                evidence = raised.exception.idle_evidence
                self.assertEqual(evidence["observation_ms"], 3250)
                self.assertEqual(evidence["daemon_cpu_before_seconds"], 10.0)
                self.assertIsNotNone(evidence["daemon_cpu_after_seconds"])
                self.assertEqual(fixture._daemon_cpu_seconds.call_count, 2)
                self.assertEqual(fixture.clock.sleeps, [3.0])
                self.assertIn("idle_evidence=", str(raised.exception))

    def test_idle_nonfinite_initial_counter_never_starts_sample_sleep(self) -> None:
        with _idle_fixture() as fixture:
            fixture._daemon_cpu_seconds.side_effect = (float("nan"),)
            with self.assertRaisesRegex(smoke.ComposedQualificationError, "invalid daemon CPU") as raised:
                smoke.assert_worker_idle(os.getuid(), 42, read_status=lambda: _idle_status(fixture.clock))
            self.assertEqual(fixture.clock.sleeps, [])
            self.assertEqual(raised.exception.idle_evidence["daemon_cpu_before_seconds"], "nan")
            self.assertEqual(raised.exception.idle_evidence["observation_ms"], 0)

    def test_idle_reports_actual_elapsed_and_keeps_one_second_cpu_limit(self) -> None:
        with _idle_fixture() as fixture:
            fixture.clock.oversleep = 0.75
            fixture._daemon_cpu_seconds.side_effect = (10.0, 11.0)
            report = smoke.assert_worker_idle(os.getuid(), 42, read_status=lambda: _idle_status(fixture.clock))
            self.assertEqual(report["observation_ms"], 3750)
            self.assertEqual(report["daemon_cpu_delta_ms"], 1000)

    def test_idle_oversleep_cannot_outlive_original_canary_window(self) -> None:
        with _idle_fixture() as fixture:
            fixture.clock.oversleep = 1.25
            def read_status():
                status = _idle_status(fixture.clock)
                status["canaries"]["next_due_in"] = 4
                return status
            with self.assertRaisesRegex(smoke.ComposedQualificationError, "quiet window elapsed") as raised:
                smoke.assert_worker_idle(os.getuid(), 42, read_status=read_status)
            self.assertEqual(raised.exception.idle_evidence["observation_ms"], 4250)
            self.assertEqual(fixture._daemon_cpu_seconds.call_count, 2)

    def test_worker_residue_or_socket_loss_fails_during_settle_and_after_sample(self) -> None:
        for after_sample in (False, True):
            for kind in ("process", "profile", "runtime", "socket"):
                with self.subTest(after_sample=after_sample, kind=kind), _idle_fixture() as fixture:
                    def appear(_seconds):
                        if kind == "process":
                            fixture._worker_processes.return_value = (123,)
                        elif kind == "profile":
                            fixture._worker_profiles.return_value = (Path("/inert/profile"),)
                        elif kind == "runtime":
                            fixture.runtime.mkdir()
                            (fixture.runtime / "residue").write_bytes(b"inert")
                        else:
                            fixture._assert_broker_socket.side_effect = smoke.ComposedQualificationError("socket lost")
                    fixture.clock.on_sleep = appear
                    def read_status():
                        status = _idle_status(fixture.clock)
                        status["canaries"]["running"] = not after_sample
                        return status
                    with self.assertRaises(smoke.ComposedQualificationError) as raised:
                        smoke.assert_worker_idle(os.getuid(), 42, read_status=read_status)
                    self.assertEqual(fixture._daemon_cpu_seconds.call_count, 2 if after_sample else 0)
                    if after_sample:
                        self.assertEqual(raised.exception.idle_evidence["observation_ms"], 3000)

    def test_idle_post_sample_status_must_remain_fresh_active_and_between_canaries(self) -> None:
        for kind in ("missing", "stale", "pid", "recovering", "running", "recovery_count"):
            with self.subTest(kind=kind), _idle_fixture() as fixture:
                def read_status():
                    status = _idle_status(fixture.clock)
                    if fixture.clock.now == 0:
                        return status
                    if kind == "missing":
                        return None
                    if kind == "stale":
                        status["daemon"]["health_updated_at"] = "2020-01-01T00:00:00Z"
                    elif kind == "pid":
                        status["daemon"]["pid"] = 43
                    elif kind == "recovering":
                        status["daemon"]["phase"] = "recovering"
                    elif kind == "running":
                        status["canaries"]["running"] = True
                    else:
                        status["recovery"]["count"] = 1
                    return status
                with self.assertRaises(smoke.ComposedQualificationError):
                    smoke.assert_worker_idle(os.getuid(), 42, read_status=read_status)
                self.assertEqual(fixture._daemon_cpu_seconds.call_count, 2)
                self.assertEqual(fixture.clock.sleeps, [3.0])

    def test_worker_diagnostics_is_bounded_to_owned_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            root = Path(raw_directory)
            runtime = root / "runtime"
            runtime.mkdir(mode=0o700)
            launch = runtime / "dev.slipstream.browser-probe.0123456789abcdef"
            launch.mkdir(mode=0o700)
            for name in ("worker.plist", "worker.stdout.log", "worker.stderr.log"):
                (launch / name).write_bytes(b"private")
            profile = root / ("slipstream-browser-probe-" + "a" * 32)
            profile.mkdir()
            with (
                mock.patch.object(smoke, "PRODUCTION_WORKER_RUNTIME", runtime),
                mock.patch.object(smoke, "_worker_processes", return_value=(123,)),
                mock.patch.object(smoke, "_worker_profiles", return_value=(profile,)),
            ):
                diagnostic = smoke.worker_diagnostics(os.getuid())

        self.assertEqual(diagnostic["processes"], (123,))
        self.assertEqual(diagnostic["profiles"], (profile.name,))
        self.assertEqual(
            diagnostic["runtime"],
            ({
                "name": launch.name,
                "owner": os.getuid(),
                "mode": "0700",
                "entries": (
                    "worker.plist",
                    "worker.stderr.log",
                    "worker.stdout.log",
                ),
            },),
        )

    def test_active_worker_requires_one_matching_loaded_launchagent(self) -> None:
        uid = os.getuid()
        label = "dev.slipstream.browser-probe.0123456789abcdef"
        diagnostic = {
            "processes": (4242,),
            "profiles": ("slipstream-browser-probe-" + "a" * 32,),
            "runtime": ({
                "name": label,
                "owner": uid,
                "mode": "0700",
                "entries": (
                    "worker.plist",
                    "worker.stderr.log",
                    "worker.stdout.log",
                ),
            },),
        }
        profile = Path("/var/folders/test/slipstream-browser-probe-" + "a" * 32)
        completed = subprocess.CompletedProcess((), 0, "pid = 4242\n", "")
        with (
            mock.patch.object(smoke.os, "environ", _ci_environment()),
            mock.patch.object(smoke, "worker_diagnostics", return_value=diagnostic),
            mock.patch.object(
                smoke,
                "_active_worker_chrome_profiles",
                return_value=(profile,),
            ),
            mock.patch.object(smoke.subprocess, "run", return_value=completed),
        ):
            self.assertEqual(
                smoke.assert_worker_active(uid, timeout=0.1),
                (
                    {
                        "worker_processes": 1,
                        "worker_profiles": 1,
                        "worker_runtime_directories": 1,
                        "launchagent": "loaded",
                    },
                    (profile,),
                ),
            )

            diagnostic["processes"] = (4243,)
            with self.assertRaisesRegex(
                smoke.ComposedQualificationError,
                "not provably active",
            ):
                smoke.assert_worker_active(uid, timeout=0.01)

    def test_live_worker_profile_comes_from_exact_owned_chrome_argument(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            root = Path(raw_directory)
            profile = root / ("slipstream-browser-probe-" + "b" * 32)
            profile.mkdir(mode=0o700)
            completed = subprocess.CompletedProcess(
                (),
                0,
                f"{os.getuid()} /tmp/Chrome --user-data-dir={profile} --headless\n"
                f"{os.getuid()} /tmp/Chrome --user-data-dir=/tmp/unowned --headless\n",
                "",
            )
            with mock.patch.object(smoke.subprocess, "run", return_value=completed):
                observed = smoke._active_worker_chrome_profiles(os.getuid())

            self.assertEqual(observed, (profile,))


if __name__ == "__main__":
    unittest.main()
