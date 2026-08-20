from __future__ import annotations

import io
import json
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
