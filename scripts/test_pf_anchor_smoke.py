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

    def test_ipv6_test_destination_uses_active_link_local_route(self) -> None:
        inactive = SimpleNamespace(
            returncode=0,
            stdout="inet6 fe80::7%en7 prefixlen 64\nstatus: inactive\n",
        )
        active = SimpleNamespace(
            returncode=0,
            stdout="inet6 fe80::8%en8 prefixlen 64\nstatus: active\n",
        )
        with mock.patch.object(
            pf_anchor_smoke.socket,
            "if_nameindex",
            return_value=((1, "lo0"), (7, "en7"), (8, "en8")),
        ), mock.patch.object(
            pf_anchor_smoke.subprocess,
            "run",
            side_effect=(inactive, active),
        ) as run:
            destination = pf_anchor_smoke._scoped_ipv6_test_destination()

        self.assertEqual(destination, "fe80::8%en8")
        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [
                (str(pf_anchor_smoke.IFCONFIG), "en7"),
                (str(pf_anchor_smoke.IFCONFIG), "en8"),
            ],
        )

    def test_ipv6_test_destination_fails_closed_without_active_route(self) -> None:
        unavailable = SimpleNamespace(returncode=1, stdout="")
        with mock.patch.object(
            pf_anchor_smoke.socket,
            "if_nameindex",
            return_value=((1, "lo0"), (7, "en7")),
        ), mock.patch.object(
            pf_anchor_smoke.subprocess,
            "run",
            return_value=unavailable,
        ), self.assertRaisesRegex(
            pf_anchor_smoke.SmokeError,
            "no active non-loopback IPv6 link-local address",
        ):
            pf_anchor_smoke._scoped_ipv6_test_destination()

    def test_ipv6_test_destination_ignores_unassigned_or_wrong_scope_addresses(self) -> None:
        active = SimpleNamespace(
            returncode=0,
            stdout=(
                "inet6 2001:db8::8%en8 prefixlen 64\n"
                "inet6 fe80::9%en9 prefixlen 64\n"
                "inet6 fe80::8%en8 prefixlen 64\n"
                "status: active\n"
            ),
        )
        with mock.patch.object(
            pf_anchor_smoke.socket,
            "if_nameindex",
            return_value=((8, "en8"),),
        ), mock.patch.object(
            pf_anchor_smoke.subprocess,
            "run",
            return_value=active,
        ):
            destination = pf_anchor_smoke._scoped_ipv6_test_destination()

        self.assertEqual(destination, "fe80::8%en8")

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
