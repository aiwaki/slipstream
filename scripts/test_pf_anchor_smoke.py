from __future__ import annotations

import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest import mock

import pf_anchor_smoke


class PfAnchorSmokeTests(unittest.TestCase):
    def test_unprivileged_client_closes_root_pf_descriptor_before_setuid(self) -> None:
        calls = []
        listener = mock.Mock()
        client = mock.MagicMock()
        client.__enter__.return_value.recv.return_value = pf_anchor_smoke.MARKER
        with mock.patch.object(
            pf_anchor_smoke.os,
            "close",
            side_effect=lambda descriptor: calls.append(("close", descriptor)),
        ), mock.patch.object(
            pf_anchor_smoke.os,
            "setgroups",
            side_effect=lambda groups: calls.append(("groups", groups)),
        ), mock.patch.object(
            pf_anchor_smoke.os,
            "setgid",
            side_effect=lambda gid: calls.append(("gid", gid)),
        ), mock.patch.object(
            pf_anchor_smoke.os,
            "setuid",
            side_effect=lambda uid: calls.append(("uid", uid)),
        ), mock.patch.object(
            pf_anchor_smoke.socket,
            "create_connection",
            return_value=client,
        ):
            result = pf_anchor_smoke._run_unprivileged_test_client(
                listener=listener,
                target_port=18443,
                uid=501,
                gid=20,
                destination=pf_anchor_smoke.TEST_DESTINATION,
                inherited_descriptors=(71,),
            )

        self.assertEqual(result, 0)
        self.assertEqual(
            calls,
            [("close", 71), ("groups", []), ("gid", 20), ("uid", 501)],
        )
        listener.close.assert_called_once_with()

    def test_sentinel_isolation_is_exact_source_and_destination_on_both_ports(self):
        for port in (443, 18443):
            isolation = pf_anchor_smoke.SentinelPfIsolation(port)
            before = SimpleNamespace(enabled=True, nat_rules='rdr-anchor "com.apple/*" all', filter_rules='anchor "com.apple/*" all')
            commands = []
            def run(*args):
                commands.append(args)
                if args[0] == "-f":
                    address = pf_anchor_smoke.IPV6_LOOPBACK_TEST_DESTINATION
                    self.assertEqual(Path(args[1]).read_text(), f"no rdr on lo0 inet6 proto tcp from {address}/128 to {address}/128 port {port}\n")
                return ""
            with self.subTest(port=port), tempfile.TemporaryDirectory() as directory, mock.patch.object(isolation, "snapshot", side_effect=(("", ""), ("no rdr", ""), ("", ""))), mock.patch.object(isolation, "production_snapshot", return_value=("production-nat", "production-filter")), mock.patch.object(pf_anchor_smoke, "_pf_snapshot", return_value=before), mock.patch.object(pf_anchor_smoke, "_assert_same_snapshot"), mock.patch.object(isolation, "_run", side_effect=run):
                isolation.install(pf_anchor_smoke.IPV6_LOOPBACK_TEST_DESTINATION, Path(directory))
                isolation.close()
            self.assertEqual([x[0] for x in commands], ["-f", "-F", "-F"])
        with self.assertRaisesRegex(pf_anchor_smoke.SmokeError, "unscoped"):
            isolation._run("-F", "all")

    def test_sentinel_isolation_refuses_collision_destination_and_invalid_port(self):
        isolation = pf_anchor_smoke.SentinelPfIsolation()
        with mock.patch.object(isolation, "snapshot", return_value=("foreign", "")):
            with self.assertRaisesRegex(pf_anchor_smoke.SmokeError, "occupied"):
                isolation.install(pf_anchor_smoke.IPV6_LOOPBACK_TEST_DESTINATION, Path("/unused"))
        self.assertFalse(isolation.attempted)
        with self.assertRaisesRegex(pf_anchor_smoke.SmokeError, "destination"):
            isolation.install("::1", Path("/unused"))
        for port in (0, 80, -1, 65536, True, "443"):
            with self.subTest(port=port), self.assertRaises(pf_anchor_smoke.SmokeError):
                pf_anchor_smoke.SentinelPfIsolation(port)

    def test_console_source_bind_is_forwarded_after_dropping_privileges(self):
        client = mock.MagicMock()
        client.__enter__.return_value.recv.return_value = pf_anchor_smoke.MARKER
        client.__enter__.return_value.getsockname.return_value = ("::1", 12000, 0, 0)
        with mock.patch.object(pf_anchor_smoke.os, "close"), mock.patch.object(pf_anchor_smoke.os, "setgroups"), mock.patch.object(pf_anchor_smoke.os, "setgid"), mock.patch.object(pf_anchor_smoke.os, "setuid"), mock.patch.object(pf_anchor_smoke.socket, "create_connection", return_value=client) as connect:
            result = pf_anchor_smoke._run_unprivileged_test_client(listener=mock.Mock(), target_port=18443, uid=501, gid=20, destination=pf_anchor_smoke.IPV6_LOOPBACK_TEST_DESTINATION, inherited_descriptors=(71, 72), source_address="::1")
        self.assertEqual(result, 0)
        connect.assert_called_once_with((pf_anchor_smoke.IPV6_LOOPBACK_TEST_DESTINATION, 18443), timeout=4, source_address=("::1", 0))

    def test_redirect_checks_natlook_before_forwarding_and_waits_for_child(self):
        for valid in (True, False):
            listener = mock.Mock()
            connection = mock.MagicMock()
            listener.accept.return_value = (connection, ("::1", 12000, 0, 0))
            address = pf_anchor_smoke.IPV6_LOOPBACK_TEST_DESTINATION
            original = (address, 18443 if valid else 18444)
            forward = mock.Mock(return_value=pf_anchor_smoke.MARKER)
            with self.subTest(valid=valid), mock.patch.object(pf_anchor_smoke.os, "fork", return_value=42), mock.patch.object(pf_anchor_smoke.os, "waitpid", return_value=(42, 0)) as wait:
                kwargs = dict(probe="fixture", listener=listener, target_port=18443, uid=501, gid=20, destination=address, source_address="::1", original_destination_lookup=lambda _: original, expected_original_destination=(address, 18443), forward_payload=forward)
                if valid:
                    pf_anchor_smoke._probe_redirect(**kwargs)
                    forward.assert_called_once()
                    connection.sendall.assert_called_once_with(pf_anchor_smoke.MARKER)
                else:
                    with self.assertRaisesRegex(pf_anchor_smoke.SmokeError, "wrong original destination"):
                        pf_anchor_smoke._probe_redirect(**kwargs)
                    forward.assert_not_called()
                listener.close.assert_called_once()
                wait.assert_called_once_with(42, 0)

    def _route_fixture_mocks(self, wrong_source=False, wrong_natlook=False, cleanup_fails=False):
        from contextlib import ExitStack
        stack = ExitStack()
        self.addCleanup(stack.close)
        address = pf_anchor_smoke.IPV6_LOOPBACK_TEST_DESTINATION
        isolation = mock.Mock(before="global", production=("production", "filter"))
        isolation.snapshot.return_value = ("no rdr", "")
        isolation.production_snapshot.return_value = isolation.production
        if cleanup_fails:
            isolation.close.side_effect = pf_anchor_smoke.SmokeError("cleanup")
        sentinel = mock.Mock()
        sentinel.fileno.return_value = 72
        sentinel.accept.return_value = (mock.MagicMock(), (address, 12000, 0, 0))
        capture = mock.Mock()
        client = mock.MagicMock()
        client.__enter__.return_value.getsockname.return_value = ("::1" if wrong_source else address, 12000, 0, 0)
        client.__enter__.return_value.makefile.return_value.__enter__.return_value.read.return_value = pf_anchor_smoke.MARKER
        lookup = mock.Mock(return_value=(address, 18444 if wrong_natlook else 18443))
        def redirect(**kwargs):
            self.assertEqual(kwargs["source_address"], "::1")
            self.assertEqual(kwargs["inherited_descriptors"], (71, 72))
            connection = mock.Mock()
            connection.getpeername.return_value = ("::1", 13000, 0, 0)
            original = kwargs["original_destination_lookup"](connection)
            if original != kwargs["expected_original_destination"]:
                raise pf_anchor_smoke.SmokeError("wrong original")
            self.assertEqual(kwargs["forward_payload"](), pf_anchor_smoke.MARKER)
            capture.close()
        stack.enter_context(mock.patch.object(pf_anchor_smoke, "SentinelPfIsolation", return_value=isolation))
        stack.enter_context(mock.patch.object(pf_anchor_smoke, "_open_listener", side_effect=(sentinel, capture)))
        connect = stack.enter_context(mock.patch.object(pf_anchor_smoke.socket, "create_connection", return_value=client))
        stack.enter_context(mock.patch.object(pf_anchor_smoke, "_pf_snapshot", return_value="global"))
        stack.enter_context(mock.patch.object(pf_anchor_smoke, "_probe_redirect", side_effect=redirect))
        args = dict(target_port=18443, proxy_port=19443, uid=501, gid=20, destination=address, natlook_descriptor=71, original_destination_lookup=lookup)
        return args, isolation, sentinel, capture, connect

    def test_native_fixture_requires_root_direct_capture_natlook_and_root_forward(self):
        args, isolation, sentinel, capture, connect = self._route_fixture_mocks()
        result = pf_anchor_smoke._probe_route_fixture(**args)
        self.assertEqual(result["result"], "pass")
        self.assertEqual(result["sentinel_connections"], 2)
        self.assertEqual([c["phase"] for c in result["root_controls"]], ["direct", "forwarded"])
        self.assertEqual(result["captured"]["source"], "::1")
        self.assertEqual(connect.call_count, 2)
        for call in connect.call_args_list:
            self.assertNotIn("source_address", call.kwargs)
        sentinel.close.assert_called_once()
        capture.close.assert_called_once()
        isolation.close.assert_called_once()

    def test_native_fixture_reports_source_natlook_and_cleanup_failures(self):
        for field in ("wrong_source", "wrong_natlook", "cleanup_fails"):
            with self.subTest(field=field):
                args, isolation, sentinel, capture, _ = self._route_fixture_mocks(**{field: True})
                with self.assertRaises(pf_anchor_smoke.SmokeError) as caught:
                    pf_anchor_smoke._probe_route_fixture(**args)
                result = json.loads(str(caught.exception).split(": ", 1)[1])
                self.assertEqual(result["result"], "fail")
                if field == "wrong_source":
                    self.assertEqual(result["root_controls"][0]["source"], "::1")
                    self.assertEqual(result["sentinel_connections"], 0)
                if field == "wrong_natlook":
                    self.assertEqual(result["captured"]["original"][1], 18444)
                    self.assertEqual(result["sentinel_connections"], 1)
                isolation.close.assert_called_once()
                sentinel.close.assert_called_once()

    def test_ipv6_loopback_fixture_installs_and_restores_exact_alias(self) -> None:
        state = {"installed": False}
        calls: list[tuple[str, ...]] = []

        def run(*command: str):
            calls.append(command)
            if command in {
                (str(pf_anchor_smoke.IFCONFIG), "-a"),
                (str(pf_anchor_smoke.IFCONFIG), "lo0"),
            }:
                alias = (
                    "inet6 2001:db8:5354:5354::1 prefixlen 128\n"
                    if state["installed"]
                    else ""
                )
                return SimpleNamespace(
                    returncode=0,
                    stdout="inet6 ::1 prefixlen 128\n" + alias,
                    stderr="",
                )
            if command == (
                str(pf_anchor_smoke.ROUTE),
                "-n",
                "get",
                "-inet6",
                pf_anchor_smoke.IPV6_LOOPBACK_TEST_DESTINATION,
            ):
                return SimpleNamespace(
                    returncode=0,
                    stdout="interface: lo0\n" if state["installed"] else "",
                    stderr="" if state["installed"] else "not in table",
                )
            if command[-1] == "alias":
                state["installed"] = True
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if command[-1] == "-alias":
                state["installed"] = False
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            raise AssertionError(command)

        fixture = pf_anchor_smoke.IPv6LoopbackAliasFixture()
        with mock.patch.object(fixture, "_run", side_effect=run):
            self.assertEqual(
                fixture.install(),
                pf_anchor_smoke.IPV6_LOOPBACK_TEST_DESTINATION,
            )
            fixture.cleanup()

        self.assertFalse(state["installed"])
        self.assertIn(
            (
                str(pf_anchor_smoke.IFCONFIG),
                "lo0",
                "inet6",
                pf_anchor_smoke.IPV6_LOOPBACK_TEST_DESTINATION,
                "prefixlen",
                "128",
                "alias",
            ),
            calls,
        )
        self.assertIn(
            (
                str(pf_anchor_smoke.IFCONFIG),
                "lo0",
                "inet6",
                pf_anchor_smoke.IPV6_LOOPBACK_TEST_DESTINATION,
                "-alias",
            ),
            calls,
        )

    def test_ipv6_loopback_fixture_refuses_address_collision(self) -> None:
        fixture = pf_anchor_smoke.IPv6LoopbackAliasFixture()
        collision = SimpleNamespace(
            returncode=0,
            stdout=(
                "inet6 2001:db8:5354:5354::1 prefixlen 128\n"
            ),
            stderr="",
        )
        with mock.patch.object(fixture, "_run", return_value=collision) as run:
            with self.assertRaisesRegex(
                pf_anchor_smoke.SmokeError,
                "pre-existing IPv6 fixture address",
            ):
                fixture.install()

        run.assert_called_once_with(str(pf_anchor_smoke.IFCONFIG), "-a")

    def test_ipv6_loopback_fixture_refuses_preexisting_lo0_route(self) -> None:
        fixture = pf_anchor_smoke.IPv6LoopbackAliasFixture()
        results = (
            SimpleNamespace(returncode=0, stdout="inet6 ::1 prefixlen 128\n", stderr=""),
            SimpleNamespace(returncode=0, stdout="inet6 ::1 prefixlen 128\n", stderr=""),
            SimpleNamespace(returncode=0, stdout="interface: lo0\n", stderr=""),
        )
        with mock.patch.object(fixture, "_run", side_effect=results):
            with self.assertRaisesRegex(
                pf_anchor_smoke.SmokeError,
                "pre-existing lo0 route",
            ):
                fixture.install()

    def test_ipv6_loopback_fixture_cleans_partial_failed_add(self) -> None:
        fixture = pf_anchor_smoke.IPv6LoopbackAliasFixture()
        state = {"installed": False}

        def run(*command: str):
            if command[0] == str(pf_anchor_smoke.ROUTE):
                return SimpleNamespace(
                    returncode=0,
                    stdout="interface: lo0\n" if state["installed"] else "",
                    stderr="" if state["installed"] else "not in table",
                )
            if command[-1] == "alias":
                state["installed"] = True
                return SimpleNamespace(returncode=1, stdout="", stderr="partial add")
            if command[-1] == "-alias":
                state["installed"] = False
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            alias = (
                "inet6 2001:db8:5354:5354::1 prefixlen 128\n"
                if state["installed"]
                else ""
            )
            return SimpleNamespace(
                returncode=0,
                stdout="inet6 ::1 prefixlen 128\n" + alias,
                stderr="",
            )

        with mock.patch.object(fixture, "_run", side_effect=run):
            with self.assertRaisesRegex(pf_anchor_smoke.SmokeError, "partial add"):
                fixture.install()
            fixture.cleanup()

        self.assertFalse(state["installed"])

    def test_ipv6_loopback_fixture_reconciles_add_verification_exception(self) -> None:
        fixture = pf_anchor_smoke.IPv6LoopbackAliasFixture()
        state = {"installed": False, "verification_failed": False}

        def run(*command: str):
            if command[0] == str(pf_anchor_smoke.ROUTE):
                return SimpleNamespace(
                    returncode=0,
                    stdout="interface: lo0\n" if state["installed"] else "",
                    stderr="" if state["installed"] else "not in table",
                )
            if command[-1] == "alias":
                state["installed"] = True
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if command[-1] == "-alias":
                state["installed"] = False
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if (
                command == (str(pf_anchor_smoke.IFCONFIG), "lo0")
                and state["installed"]
                and not state["verification_failed"]
            ):
                state["verification_failed"] = True
                raise pf_anchor_smoke.SmokeError("verification command failed")
            alias = (
                "inet6 2001:db8:5354:5354::1 prefixlen 128\n"
                if state["installed"]
                else ""
            )
            return SimpleNamespace(
                returncode=0,
                stdout="inet6 ::1 prefixlen 128\n" + alias,
                stderr="",
            )

        with mock.patch.object(fixture, "_run", side_effect=run):
            with self.assertRaisesRegex(
                pf_anchor_smoke.SmokeError,
                "verification command failed",
            ):
                fixture.install()
            fixture.cleanup()

        self.assertFalse(state["installed"])

    def test_ipv6_loopback_fixture_reports_cleanup_leak(self) -> None:
        fixture = pf_anchor_smoke.IPv6LoopbackAliasFixture()
        state = {"installed": False}

        def run(*command: str):
            if command[0] == str(pf_anchor_smoke.ROUTE):
                return SimpleNamespace(
                    returncode=0,
                    stdout="interface: lo0\n" if state["installed"] else "",
                    stderr="" if state["installed"] else "not in table",
                )
            if command[-1] == "alias":
                state["installed"] = True
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if command[-1] == "-alias":
                return SimpleNamespace(returncode=1, stdout="", stderr="delete failed")
            alias = (
                "inet6 2001:db8:5354:5354::1 prefixlen 128\n"
                if state["installed"]
                else ""
            )
            return SimpleNamespace(
                returncode=0,
                stdout="inet6 ::1 prefixlen 128\n" + alias,
                stderr="",
            )

        with mock.patch.object(fixture, "_run", side_effect=run):
            fixture.install()
            with self.assertRaisesRegex(
                pf_anchor_smoke.SmokeError,
                "owned IPv6 fixture address remains assigned",
            ):
                fixture.cleanup()

    def test_natlook_descriptor_is_an_integer_and_closed_exactly_once(self) -> None:
        tproxy = SimpleNamespace(_pf_fd=None)
        with mock.patch.object(
            pf_anchor_smoke.os,
            "open",
            return_value=71,
        ) as open_descriptor, mock.patch.object(
            pf_anchor_smoke.os,
            "close",
        ) as close_descriptor:
            descriptor = pf_anchor_smoke._open_tproxy_pf_natlook(tproxy)
            self.assertEqual(descriptor, 71)
            self.assertEqual(tproxy._pf_fd, 71)
            pf_anchor_smoke._close_tproxy_pf_natlook(tproxy, descriptor)

        open_descriptor.assert_called_once_with("/dev/pf", pf_anchor_smoke.os.O_RDWR)
        close_descriptor.assert_called_once_with(71)
        self.assertIsNone(tproxy._pf_fd)

    def test_natlook_descriptor_refuses_to_replace_an_existing_handle(self) -> None:
        tproxy = SimpleNamespace(_pf_fd=70)
        with mock.patch.object(pf_anchor_smoke.os, "open") as open_descriptor:
            with self.assertRaisesRegex(
                pf_anchor_smoke.SmokeError,
                "already open",
            ):
                pf_anchor_smoke._open_tproxy_pf_natlook(tproxy)

        open_descriptor.assert_not_called()

    def test_redirect_rules_never_target_https(self) -> None:
        rules = pf_anchor_smoke.build_redirect_rules(
            target_port=18443,
            proxy_port=19443,
        )

        self.assertIn("port 18443", rules)
        self.assertIn("port 19443", rules)
        self.assertIn("to ! 127.0.0.0/8", rules)
        self.assertIn("rdr on lo0 inet6 proto tcp", rules)
        self.assertIn("to ! ::1/128", rules)
        self.assertIn("route-to (lo0 ::1) inet6", rules)
        self.assertIn("reply-to (lo0 ::1) inet6", rules)
        self.assertIn("pass out quick on ! lo0 route-to", rules)
        self.assertIn("pass in quick on lo0 reply-to", rules)
        self.assertNotIn("proto udp", rules)
        self.assertNotIn("port 443 ", rules)

    def test_redirect_rules_reject_tcp_443(self) -> None:
        with self.assertRaisesRegex(pf_anchor_smoke.SmokeError, "never intercept"):
            pf_anchor_smoke.build_redirect_rules(target_port=443, proxy_port=19443)

    def test_pfctl_guard_accepts_only_scoped_mutations(self) -> None:
        for command in (
            ("/sbin/pfctl", "-s", "info"),
            ("/sbin/pfctl", "-s", "states"),
            ("/sbin/pfctl", "-s", "References"),
            ("/sbin/pfctl", "-v", "-s", "Interfaces"),
            ("pfctl", "-sn"),
            ("pfctl", "-sr"),
            ("pfctl", "-E"),
            ("pfctl", "-X", "1234"),
            ("pfctl", "-a", pf_anchor_smoke.SLIPSTREAM_ANCHOR, "-f", "/tmp/rules"),
            ("pfctl", "-a", pf_anchor_smoke.SENTINEL_ANCHOR, "-F", "rules"),
            ("pfctl", "-a", pf_anchor_smoke.SENTINEL_ANCHOR, "-F", "nat"),
        ):
            pf_anchor_smoke.validate_pfctl_args(command)

    def test_pfctl_guard_rejects_global_or_external_mutations(self) -> None:
        commands = (
            ("pfctl", "-d"),
            ("pfctl", "-F", "states"),
            ("pfctl", "-a", pf_anchor_smoke.SLIPSTREAM_ANCHOR, "-F", "states"),
            ("pfctl", "-a", pf_anchor_smoke.SLIPSTREAM_ANCHOR, "-F", "all"),
            ("pfctl", "-a", pf_anchor_smoke.SLIPSTREAM_ANCHOR, "-F", "rules", "-e"),
            ("pfctl", "-f", "/etc/pf.conf"),
            ("pfctl", "-a", "com.vendor/external", "-F", "all"),
            ("rm", "-rf", "/"),
        )
        for command in commands:
            with self.subTest(command=command):
                with self.assertRaises(pf_anchor_smoke.SmokeError):
                    pf_anchor_smoke.validate_pfctl_args(command)

    def test_audit_log_redacts_pf_enable_token(self) -> None:
        command = ("/sbin/pfctl", "-X", "sensitive-token")

        rendered = pf_anchor_smoke.PfctlRunner.display(command)

        self.assertNotIn("sensitive-token", rendered)
        self.assertIn("<redacted-token>", rendered)

    def test_snapshot_comparison_detects_global_changes(self) -> None:
        before = pf_anchor_smoke.PfSnapshot(False, "nat", "filter", True)
        after = pf_anchor_smoke.PfSnapshot(False, "changed", "filter", True)

        with self.assertRaisesRegex(pf_anchor_smoke.SmokeError, "global NAT"):
            pf_anchor_smoke._assert_same_snapshot(before, after)

    def test_snapshot_comparison_detects_loopback_skip_changes(self) -> None:
        before = pf_anchor_smoke.PfSnapshot(False, "nat", "filter", True)
        after = pf_anchor_smoke.PfSnapshot(False, "nat", "filter", False)

        with self.assertRaisesRegex(pf_anchor_smoke.SmokeError, "lo0 skip"):
            pf_anchor_smoke._assert_same_snapshot(before, after)

    def test_failed_loopback_restore_never_releases_pf_token(self) -> None:
        calls = []

        class Tproxy:
            @staticmethod
            def _restore_pf_loopback_skip():
                calls.append("restore")
                return False

            @staticmethod
            def _pf_release_enable_token():
                calls.append("release")
                return None

        self.assertFalse(
            pf_anchor_smoke._restore_loopback_before_token_release(
                Tproxy(),
                object(),
            )
        )
        self.assertEqual(calls, ["restore"])

    def test_dry_run_is_non_privileged_and_explicit(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            result = pf_anchor_smoke.main(["--dry-run"])

        self.assertEqual(result, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["result"], "dry-run")
        self.assertFalse(report["intercepts_tcp_443"])
        self.assertIn("pfctl -d", report["forbidden_operations"])


if __name__ == "__main__":
    unittest.main()
