from contextlib import ExitStack
import io
import json
import os
import plistlib
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import geph_installed_route_smoke as smoke


class _Origin:
    def __init__(self):
        self.value = {"connections": 0, "requests": 0}
        self.alias = SimpleNamespace(address=smoke.pf.IPV6_LOOPBACK_TEST_DESTINATION)
        self.certificate = Path("/fixture/certificate.pem")
        self.closed = False

    def counts(self):
        return dict(self.value)

    def visit(self):
        self.value = {k: v + 1 for k, v in self.value.items()}
        return {"route": "system", "bytes": len(smoke.SYSTEM_BODY), "status": 200, "source": self.alias.address}

    def start(self):
        pass

    def close(self):
        self.closed = True


class InstalledGephRouteSmokeTests(unittest.TestCase):
    def _run_fixture(self, fail_probe=None, cleanup_failure=False):
        stack = ExitStack()
        self.addCleanup(stack.close)
        root = stack.enter_context(tempfile.TemporaryDirectory())
        home = Path(root)
        origin = _Origin()
        events = []
        settings = mock.Mock(original=b'{"enabled":"1"}')
        settings.disable.side_effect = lambda: events.append("disable")
        settings.restore.side_effect = lambda: events.append("restore")
        backend = mock.Mock(mutated=False, state="verified")
        def stop():
            backend.mutated = True
            events.append("stop")
        backend.stop.side_effect = stop
        backend.start.side_effect = lambda: events.append("start")
        probe_number = 0
        def probe(*_args, **_kwargs):
            nonlocal probe_number
            probe_number += 1
            events.append(f"probe{probe_number}")
            if probe_number == fail_probe:
                raise smoke.RouteQualificationError("injected observed failure")
            if cleanup_failure and probe_number == 7:
                raise smoke.RouteQualificationError("restoration payload missing")
            if probe_number in (2, 3, 4):
                return {"route": "closed", "error": "SSLEOFError"}
            if probe_number == 6:
                return origin.visit()
            return {"route": "owned", "bytes": 4096, "status": 200}
        env = {"CI": "true", "GITHUB_ACTIONS": "true", "SLIPSTREAM_DISPOSABLE_CI": "1"}
        stack.enter_context(mock.patch.dict(smoke.os.environ, env, clear=True))
        for obj, name, value in (
            (smoke.sys, "platform", "darwin"),
            (smoke.os, "geteuid", mock.Mock(return_value=0)),
            (smoke, "SettingsSnapshot", mock.Mock(return_value=settings)),
            (smoke, "OwnedBackend", mock.Mock(return_value=backend)),
            (smoke, "SystemOrigin", mock.Mock(return_value=origin)),
            (smoke, "_status", mock.Mock(return_value={"daemon": {"pid": 91, "updated_at": 1}})),
            (smoke, "_wait_backend", mock.Mock()),
            (smoke, "_private_bytes", mock.Mock(return_value=settings.original)),
            (smoke, "client_probe", mock.Mock(side_effect=lambda *_: origin.visit())),
            (smoke, "_probe", mock.Mock(side_effect=probe)),
            (smoke.geph, "_assert_owned_geph", mock.Mock()),
            (smoke.geph, "_wait_for_payload", mock.Mock()),
        ):
            stack.enter_context(mock.patch.object(obj, name, value))
        return SimpleNamespace(home=home, origin=origin, events=events, settings=settings, backend=backend)

    def test_enabled_recovery_precedes_disabled_control_and_exact_restore(self):
        fixture = self._run_fixture()
        result = smoke.run_qualification(os.getuid(), os.getgid(), fixture.home, lambda: {})
        self.assertEqual(result["result"], "pass")
        self.assertEqual(fixture.events, [
            "probe1", "stop", "probe2", "probe3", "probe4", "start", "probe5",
            "stop", "disable", "probe6", "restore", "start", "probe7",
        ])
        self.assertEqual(result["system_counts"], {"connections": 2, "requests": 2})
        self.assertEqual(result["restored_probe"]["route"], "owned")
        self.assertTrue(fixture.origin.closed)

    def test_failed_root_control_keeps_route_source_and_counts(self):
        fixture = self._run_fixture()
        control = {"route": "closed", "error": "SSLEOFError", "source": fixture.origin.alias.address}
        with mock.patch.object(smoke, "client_probe", return_value=control):
            with self.assertRaises(smoke.RouteQualificationError) as caught:
                smoke.run_qualification(os.getuid(), os.getgid(), fixture.home, lambda: {})
        receipt = json.loads(str(caught.exception))
        self.assertEqual(receipt["stage"], "local-origin")
        self.assertEqual(receipt["root_control"], {**control, "system_counts": {"connections": 0, "requests": 0}})
        fixture.backend.stop.assert_not_called()
        self.assertTrue(fixture.origin.closed)

    def test_root_control_rejects_wrong_default_source_even_with_payload(self):
        fixture = self._run_fixture()
        def wrong_source(*_args):
            return {**fixture.origin.visit(), "source": "::1"}
        with mock.patch.object(smoke, "client_probe", side_effect=wrong_source):
            with self.assertRaises(smoke.RouteQualificationError) as caught:
                smoke.run_qualification(os.getuid(), os.getgid(), fixture.home, lambda: {})
        receipt = json.loads(str(caught.exception))
        self.assertIn("unexpected source", receipt["failure"]["reason"])
        self.assertEqual(receipt["root_control"]["system_counts"]["connections"], 1)
        fixture.backend.stop.assert_not_called()

    def test_client_bind_is_explicit_only_for_captured_requests(self):
        context = mock.Mock()
        context.wrap_socket.side_effect = smoke.ssl.SSLEOFError
        raw = mock.MagicMock()
        raw.__enter__.return_value.getsockname.return_value = ("::1", 12345, 0, 0)
        with mock.patch.object(smoke.ssl, "create_default_context", return_value=context), mock.patch.object(smoke.socket, "create_connection", return_value=raw) as connect:
            self.assertEqual(smoke.client_probe("fixture", Path("cert"), source_address="::1")["source"], "::1")
            connect.assert_called_once_with(("fixture", 443), timeout=15, source_address=("::1", 0))
            connect.reset_mock()
            smoke.client_probe("fixture", Path("cert"))
            connect.assert_called_once_with(("fixture", 443), timeout=15)

    def test_captured_receipt_requires_the_distinct_client_source(self):
        origin = _Origin()
        for source in (None, origin.alias.address):
            completed = SimpleNamespace(returncode=0, stdout=json.dumps({"route": "owned", "source": source}))
            with self.subTest(source=source), mock.patch.object(smoke.subprocess, "run", return_value=completed):
                with self.assertRaisesRegex(smoke.RouteQualificationError, "distinct fixture source"):
                    smoke._probe(origin, 501, 20)
        completed.stdout = json.dumps({"route": "closed", "source": "::1"})
        with mock.patch.object(smoke.subprocess, "run", return_value=completed):
            self.assertEqual(smoke._probe(origin, 501, 20)["route"], "closed")

    def test_failure_after_bootout_restores_settings_backend_and_origin(self):
        fixture = self._run_fixture(fail_probe=2)
        with self.assertRaises(smoke.RouteQualificationError) as caught:
            smoke.run_qualification(os.getuid(), os.getgid(), fixture.home, lambda: {})
        receipt = json.loads(str(caught.exception))
        self.assertEqual(receipt["stage"], "enabled-outage")
        self.assertEqual(receipt["result"], "fail")
        fixture.settings.restore.assert_called_once()
        fixture.backend.start.assert_called_once()
        self.assertTrue(fixture.origin.closed)
        self.assertNotIn("enabled", str(receipt.get("failure")))

    def test_cleanup_payload_failure_cannot_return_pass(self):
        fixture = self._run_fixture(cleanup_failure=True)
        with self.assertRaises(smoke.RouteQualificationError) as caught:
            smoke.run_qualification(os.getuid(), os.getgid(), fixture.home, lambda: {})
        receipt = json.loads(str(caught.exception))
        self.assertEqual(receipt["result"], "fail")
        self.assertEqual(receipt["cleanup_errors"][0]["type"], "RouteQualificationError")
        self.assertTrue(fixture.origin.closed)

    def test_zero_payload_alone_does_not_hide_system_connection(self):
        origin = _Origin()
        baseline = origin.counts()
        origin.value["connections"] = 1
        with self.assertRaises(smoke.RouteQualificationError):
            smoke._expect({"route": "closed"}, "closed", origin, baseline)

    def test_private_settings_exact_restore_and_external_mutation_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            original = b'{ "exit": "auto", "enabled": "1" }\n'
            path.write_bytes(original)
            path.chmod(0o600)
            snapshot = smoke.SettingsSnapshot(path, os.getuid(), os.getgid())
            snapshot.disable()
            self.assertEqual(json.loads(path.read_bytes())["enabled"], "0")
            snapshot.restore()
            self.assertEqual(path.read_bytes(), original)
            path.write_bytes(b'{"enabled":"1","exit":"different"}')
            with self.assertRaisesRegex(smoke.RouteQualificationError, "outside"):
                snapshot.disable()
            self.assertIn(b"different", path.read_bytes())

    def test_private_settings_reject_symlink_permissions_and_disabled_intent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            path.write_text('{"enabled":"1"}')
            path.chmod(0o644)
            with self.assertRaisesRegex(smoke.RouteQualificationError, "private"):
                smoke.SettingsSnapshot(path, os.getuid(), os.getgid())
            path.chmod(0o600)
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                smoke.SettingsSnapshot(link, os.getuid(), os.getgid())
            path.write_text('{"enabled":"0"}')
            with self.assertRaisesRegex(smoke.RouteQualificationError, "explicitly enabled"):
                smoke.SettingsSnapshot(path, os.getuid(), os.getgid())

    def test_status_requires_same_fresh_daemon_and_no_smart_dns(self):
        status = {"schema_version": 2, "daemon": {"pid": 5, "state": "active", "updated_at": 100}, "backends": {"local_engine": {"state": "ready"}}, "environment": {"dns": {"state": "configured"}, "pf": {"state": "ready", "applied": True, "enabled": True, "rules_loaded": True}}}
        with mock.patch.object(smoke.time, "time", return_value=101):
            self.assertEqual(smoke._status(lambda: status, 5), status)
            with self.assertRaises(smoke.RouteQualificationError):
                smoke._status(lambda: status, 6)
            status["environment"]["dns"]["state"] = "xbox_dns"
            with self.assertRaisesRegex(smoke.RouteQualificationError, "without Smart DNS"):
                smoke._status(lambda: status, 5)

    def test_status_rejects_inactive_capture_even_with_fresh_daemon(self):
        status = {"schema_version": 2, "daemon": {"pid": 5, "state": "active", "updated_at": 100}, "backends": {"local_engine": {"state": "paused"}}, "environment": {"dns": {"state": "configured"}}}
        with mock.patch.object(smoke.time, "time", return_value=101):
            with self.assertRaisesRegex(smoke.RouteQualificationError, "packet capture"):
                smoke._status(lambda: status, 5)

    def test_backend_transition_requires_advancing_status(self):
        statuses = [
            {"daemon": {"updated_at": 100}, "backends": {"geph": {"state": "down", "owned": False}}},
            {"daemon": {"updated_at": 101}, "backends": {"geph": {"state": "down", "owned": False}}},
        ]
        with mock.patch.object(smoke, "_status", side_effect=statuses) as read, mock.patch.object(smoke.time, "sleep") as sleep:
            smoke._wait_backend(lambda: {}, 5, False, updated_after=100)
        self.assertEqual(read.call_count, 2)
        sleep.assert_called_once_with(0.5)

    def test_recovery_waits_for_captured_payload_through_natural_cooldown(self):
        origin = _Origin()
        closed = {"route": "closed", "error": "SSLEOFError"}
        ready = {"route": "owned", "bytes": 2048, "status": 200}
        with mock.patch.object(smoke, "_status"), mock.patch.object(smoke, "_probe", side_effect=(closed, closed, ready)), mock.patch.object(smoke.time, "sleep") as sleep:
            result = smoke._wait_owned_payload(origin, 501, 20, lambda: {}, 42, origin.counts())
        self.assertEqual(result["closed_before_payload"], 2)
        self.assertEqual(sleep.call_count, 2)

    def test_recovery_rejects_system_route_even_during_cooldown(self):
        origin = _Origin()
        with mock.patch.object(smoke, "_status"), mock.patch.object(smoke, "_probe", return_value={"route": "system"}):
            with self.assertRaisesRegex(smoke.RouteQualificationError, "route invariant"):
                smoke._wait_owned_payload(origin, 501, 20, lambda: {}, 42, origin.counts())

    def test_recovery_is_bounded_and_does_not_accept_timeout_as_closed(self):
        origin = _Origin()
        with mock.patch.object(smoke, "_status"), mock.patch.object(smoke, "_probe", side_effect=TimeoutError):
            with self.assertRaises(TimeoutError):
                smoke._wait_owned_payload(origin, 501, 20, lambda: {}, 42, origin.counts())
        with mock.patch.object(smoke.time, "monotonic", side_effect=(0, 91)):
            with self.assertRaisesRegex(smoke.RouteQualificationError, "did not recover"):
                smoke._wait_owned_payload(origin, 501, 20, lambda: {}, 42, origin.counts())

    def test_recovery_probe_uses_remaining_budget_and_rejects_late_payload(self):
        origin = _Origin()
        with mock.patch.object(smoke, "_status"), mock.patch.object(smoke, "_probe", return_value={"route": "owned"}) as probe, mock.patch.object(smoke.time, "monotonic", side_effect=(0, 89, 89, 91)):
            with self.assertRaisesRegex(smoke.RouteQualificationError, "did not recover"):
                smoke._wait_owned_payload(origin, 501, 20, lambda: {}, 42, origin.counts())
        probe.assert_called_once_with(origin, 501, 20, timeout=1)

    def test_origin_cleanup_does_not_shutdown_a_thread_that_never_started(self):
        with tempfile.TemporaryDirectory() as directory:
            origin = smoke.SystemOrigin.__new__(smoke.SystemOrigin)
            origin.directory = Path(directory) / "fixture"
            origin.directory.mkdir()
            origin.server = mock.Mock()
            origin.thread = mock.Mock()
            origin.thread.is_alive.return_value = False
            origin.thread.ident = None
            origin.alias = mock.Mock()
            origin.isolation = mock.Mock()
            origin.close()
            origin.server.shutdown.assert_not_called()
            origin.thread.join.assert_not_called()
            origin.server.server_close.assert_called_once()
            origin.alias.cleanup.assert_called_once()
            origin.isolation.close.assert_called_once()
            self.assertFalse(origin.directory.exists())

    def test_backend_revalidates_exact_process_before_bootout(self):
        paths = smoke.geph.geph_paths(Path("/fixture"))
        state = SimpleNamespace(pid=42)
        payload = plistlib.dumps({"Label": smoke.geph.GEPH_LABEL, "ProgramArguments": [str(paths.launcher)]})
        with mock.patch.object(smoke, "_private_bytes", return_value=payload), mock.patch.object(smoke.geph, "_wait_for_owned_geph", return_value=state), mock.patch.object(smoke.geph, "_assert_owned_geph", side_effect=smoke.geph.QualificationError("identity changed")) as validate, mock.patch.object(smoke.geph, "_bootout_owned_geph") as bootout:
            backend = smoke.OwnedBackend(paths, 501)
            with self.assertRaises(smoke.geph.QualificationError):
                backend.stop()
        validate.assert_called_once_with(paths, 501, state)
        bootout.assert_not_called()
        self.assertFalse(backend.mutated)

    def test_backend_changed_launch_authority_prevents_bootstrap(self):
        paths = smoke.geph.geph_paths(Path("/fixture"))
        payload = plistlib.dumps({"Label": smoke.geph.GEPH_LABEL, "ProgramArguments": [str(paths.launcher)]})
        with mock.patch.object(smoke, "_private_bytes", side_effect=(payload, b"changed")), mock.patch.object(smoke.geph, "_wait_for_owned_geph", return_value=SimpleNamespace(pid=42)), mock.patch.object(smoke.geph, "_run") as run:
            backend = smoke.OwnedBackend(paths, 501)
            with self.assertRaisesRegex(smoke.RouteQualificationError, "LaunchAgent changed"):
                backend.start()
        run.assert_not_called()

    def test_unknown_launchctl_error_is_not_absence(self):
        backend = smoke.OwnedBackend.__new__(smoke.OwnedBackend)
        backend.uid = 501
        result = SimpleNamespace(returncode=1, stdout="", stderr="Permission denied")
        with mock.patch.object(smoke.geph, "_run", return_value=result):
            with self.assertRaisesRegex(smoke.RouteQualificationError, "cannot prove"):
                backend.present()
        result.stderr = "Could not find service dev.slipstream.geph"
        with mock.patch.object(smoke.geph, "_run", return_value=result):
            self.assertFalse(backend.present())

    def test_client_reads_full_body_and_rejects_truncation_and_forbidden(self):
        class TLS:
            def __init__(self, wire):
                self.wire = wire
            def __enter__(self):
                return self
            def __exit__(self, *_):
                pass
            def getsockname(self):
                return ("::1", 12345, 0, 0)
            def sendall(self, _):
                pass
            def makefile(self, *_):
                return io.BytesIO(self.wire)
        for status, declared, body, succeeds in (
            (200, 64, b"a" * 64, True),
            (200, 128, b"a" * 64, False),
            (403, 64, b"a" * 64, False),
        ):
            tls = TLS(f"HTTP/1.1 {status} Status\r\nContent-Length: {declared}\r\n\r\n".encode() + body)
            context = mock.Mock()
            context.wrap_socket.return_value = tls
            with self.subTest(status=status, declared=declared), mock.patch.object(smoke.ssl, "create_default_context", return_value=context), mock.patch.object(smoke.socket, "create_connection", return_value=tls):
                if succeeds:
                    result = smoke.client_probe("::1", Path("fixture.pem"))
                    self.assertEqual(result["bytes"], 64)
                    context.load_verify_locations.assert_called_once_with(cafile=Path("fixture.pem"))
                else:
                    with self.assertRaises(smoke.RouteQualificationError):
                        smoke.client_probe("::1", Path("fixture.pem"))

    def test_client_timeout_is_not_a_successful_blocked_request(self):
        with mock.patch.object(smoke.ssl, "create_default_context"), mock.patch.object(smoke.socket, "create_connection", side_effect=TimeoutError):
            with self.assertRaises(TimeoutError):
                smoke.client_probe("::1", Path("fixture.pem"))


if __name__ == "__main__":
    unittest.main()
