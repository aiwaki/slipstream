import json
import logging
import ssl
from collections import OrderedDict

import tproxy
from tproxy import _doh_request, _doh_ssl_context


def test_doh_ssl_context_verifies_resolver_certificate():
    ctx = _doh_ssl_context()

    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_doh_request_percent_encodes_host():
    req = _doh_request("good.example\r\nX-Bad: yes", "dns.google")
    first_line = req.split(b"\r\n", 1)[0]

    assert first_line == (
        b"GET /dns-query?name=good.example%0D%0AX-Bad%3A+yes&type=A HTTP/1.1"
    )
    assert b"\r\nX-Bad:" not in req


def test_telegram_proxy_suggests_only_after_repeated_direct_failures(monkeypatch):
    clock = {"now": 1_000.0}
    monkeypatch.setattr(tproxy.time, "time", lambda: clock["now"])
    tproxy._tg_direct_failures.clear()
    tproxy._tg_proxy_suggest_until = 0.0

    tproxy.note_telegram_direct_failure("connect failed")
    tproxy.note_telegram_direct_failure("connect failed")

    assert clock["now"] >= tproxy._tg_proxy_suggest_until

    tproxy.note_telegram_direct_failure("connect failed")

    assert clock["now"] < tproxy._tg_proxy_suggest_until


def test_telegram_direct_success_clears_failure_window():
    tproxy._tg_direct_failures.clear()
    tproxy._tg_proxy_suggest_until = 0.0

    tproxy.note_telegram_direct_failure("connect failed")
    tproxy.note_telegram_direct_success()

    assert list(tproxy._tg_direct_failures) == []


def test_telegram_proxy_acceptance_clears_current_suggestion_once(monkeypatch, tmp_path):
    ack = tmp_path / "accepted"
    ack.write_text("1\n")
    monkeypatch.setattr(tproxy, "TGWS_ACCEPTED_PATH", str(ack))
    tproxy._tg_proxy_ack_seen = 0.0
    tproxy._tg_direct_failures.clear()
    tproxy._tg_direct_failures.append(100.0)
    tproxy._tg_proxy_suggest_until = 200.0

    assert tproxy.consume_telegram_proxy_acceptance()
    assert list(tproxy._tg_direct_failures) == []
    assert tproxy._tg_proxy_suggest_until == 0.0

    tproxy._tg_direct_failures.append(300.0)
    tproxy._tg_proxy_suggest_until = 400.0

    assert not tproxy.consume_telegram_proxy_acceptance()
    assert list(tproxy._tg_direct_failures) == [300.0]
    assert tproxy._tg_proxy_suggest_until == 400.0


def test_tgws_status_reports_ready_duration(monkeypatch):
    clock = {"now": 10_000.0}
    monkeypatch.setattr(tproxy.time, "time", lambda: clock["now"])

    tproxy.set_tgws_state("starting")
    tproxy.set_tgws_state("ready")
    clock["now"] = 10_007.0

    assert tproxy.tgws_status(clock["now"]) == {
        "telegram_proxy": "ready",
        "telegram_proxy_port": tproxy.TGWS_PORT,
        "telegram_proxy_error": "",
        "telegram_proxy_ready_for": 7,
    }


def test_tgws_status_reports_error_without_ready_duration():
    tproxy.set_tgws_state("error", "boom")

    assert tproxy.tgws_status(10_000.0) == {
        "telegram_proxy": "error",
        "telegram_proxy_port": tproxy.TGWS_PORT,
        "telegram_proxy_error": "boom",
        "telegram_proxy_ready_for": 0,
    }


def test_frozen_daemon_running_from_install_dir():
    assert tproxy.running_from_install_dir(
        file_path="/usr/local/slipstream/_internal/tproxy.py",
        executable="/usr/local/slipstream/slipstreamd",
        frozen=True,
    )


def test_repo_script_is_not_running_from_install_dir():
    assert not tproxy.running_from_install_dir(
        file_path="/Users/example/slipstream/spike/tproxy.py",
        executable="/usr/bin/python3",
        frozen=False,
    )


def test_scapy_mac_noise_filter_only_drops_broadcast_warning():
    filt = tproxy._ScapyMacNoiseFilter()
    noisy = logging.LogRecord(
        "scapy.runtime", logging.WARNING, __file__, 1,
        "MAC address to reach destination not found. Using broadcast.",
        (), None,
    )
    useful = logging.LogRecord(
        "scapy.runtime", logging.WARNING, __file__, 1,
        "other warning",
        (), None,
    )

    assert not filt.filter(noisy)
    assert filt.filter(useful)


def test_default_route_info_tracks_interface_and_gateway(monkeypatch):
    class Result:
        stdout = """
           route to: default
        destination: default
            gateway: 192.168.1.1
          interface: en0
        """

    monkeypatch.setattr(tproxy, "_run", lambda *args: Result())

    assert tproxy.default_route_info() == ("en0", "192.168.1.1")
    assert tproxy.default_iface() == "en0"
    assert tproxy.route_signature(("en0", "192.168.1.1")) == "en0|192.168.1.1"


def test_routing_diagnostics_status_reports_route_pf_and_strategy():
    tproxy._strat_cache.clear()
    tproxy._strat_cache["example.com"] = "split64+fake"
    tproxy.note_routing_decision("local", "split64+fake", now=1234.0)

    status = tproxy.routing_diagnostics_status(
        route_info=("en0", "192.168.1.1"),
        pf_state="active",
    )

    assert status["route"] == "en0|192.168.1.1"
    assert status["route_iface"] == "en0"
    assert status["route_gateway"] == "192.168.1.1"
    assert status["pf"] == "active"
    assert status["route_mode_last"] == "local"
    assert status["strategy_last"] == "split64+fake"
    assert status["strategy_last_at"] == 1234.0
    assert status["strategy_known_hosts"] == 1
    assert "example.com" not in status.values()


def test_write_status_includes_route_diagnostics(monkeypatch, tmp_path):
    status_path = tmp_path / "slipstream.status"
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(status_path))
    tproxy._strat_cache.clear()
    tproxy._strat_cache["example.com"] = "split64+fake"
    tproxy.note_routing_decision("geph", "socks5", now=1234.0)

    tproxy.write_status(
        "active",
        "en0",
        "en0",
        route_info=("en0", "192.168.1.1"),
        pf_state="active",
    )

    status = json.loads(status_path.read_text())
    assert status["route"] == "en0|192.168.1.1"
    assert status["route_iface"] == "en0"
    assert status["route_gateway"] == "192.168.1.1"
    assert status["pf"] == "active"
    assert status["route_mode_last"] == "geph"
    assert status["strategy_last"] == "socks5"
    assert status["strategy_last_at"] == 1234.0


def test_reset_network_runtime_state_clears_transient_route_state(monkeypatch):
    calls = []
    monkeypatch.setattr(tproxy, "_pf_applied", True)
    monkeypatch.setattr(tproxy, "_run", lambda *args: calls.append(args))
    tproxy._dead["blocked.example"] = 999.0
    tproxy._tg_direct_failures.clear()
    tproxy._tg_direct_failures.append(10.0)
    tproxy._tg_proxy_suggest_until = 999.0
    tproxy.note_routing_decision("local", "split64+fake", now=1234.0)
    with tproxy._doh_lock:
        tproxy._doh_cache["blocked.example"] = (["203.0.113.10"], 999.0)

    tproxy.reset_network_runtime_state("test")

    assert tproxy._dead == {}
    assert list(tproxy._tg_direct_failures) == []
    assert tproxy._tg_proxy_suggest_until == 0.0
    status = tproxy.routing_diagnostics_status()
    assert status["route_mode_last"] == ""
    assert status["strategy_last"] == ""
    assert status["strategy_last_at"] == 0.0
    with tproxy._doh_lock:
        assert tproxy._doh_cache == {}
    assert calls == []


def test_run_network_canary_resolves_via_doh_then_checks_tcp():
    class Sock:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    sockets = []

    def connector(addr, timeout):
        sock = Sock()
        sockets.append((addr, timeout, sock))
        return sock

    checks = []

    def throughput_checker(sock, host, timeout):
        checks.append((sock, host, timeout))
        return True, "512 bytes in 0.25s (2048 B/s)"

    ok, detail = tproxy.run_network_canary(
        host="gateway.discord.gg",
        timeout=1.25,
        resolver=lambda host: ["203.0.113.10"],
        connector=connector,
        throughput_checker=throughput_checker,
    )

    assert ok
    assert detail == "203.0.113.10: 512 bytes in 0.25s (2048 B/s)"
    assert sockets[0][0] == ("203.0.113.10", 443)
    assert sockets[0][1] == 1.25
    assert sockets[0][2].closed
    assert checks == [(sockets[0][2], "gateway.discord.gg", 1.25)]


def test_run_network_canary_falls_back_to_system_dns_after_doh_timeout():
    class Sock:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    sockets = []

    def resolver(host):
        raise TimeoutError("timed out")

    def connector(addr, timeout):
        sock = Sock()
        sockets.append((addr, timeout, sock))
        return sock

    ok, detail = tproxy.run_network_canary(
        host="gateway.discord.gg",
        timeout=1.25,
        resolver=resolver,
        fallback_resolver=lambda host: ["203.0.113.10"],
        connector=connector,
        throughput_checker=lambda sock, host, timeout: (
            True,
            "512 bytes in 0.25s (2048 B/s)",
        ),
    )

    assert ok
    assert detail == (
        "203.0.113.10: 512 bytes in 0.25s (2048 B/s) "
        "(system DNS fallback after resolve error: timed out)"
    )
    assert sockets[0][0] == ("203.0.113.10", 443)
    assert sockets[0][2].closed


def test_check_canary_throughput_reads_https_response():
    class TLS:
        def __init__(self):
            self.sent = b""
            self.closed = False
            self.chunks = [b"x" * 128]

        def sendall(self, data):
            self.sent += data

        def recv(self, count):
            if self.chunks:
                return self.chunks.pop(0)[:count]
            return b""

        def close(self):
            self.closed = True

    tls = TLS()
    calls = []
    ticks = iter([10.0, 10.25])

    def tls_wrapper(sock, host, timeout):
        calls.append((sock, host, timeout))
        return tls

    probe = object()
    ok, detail = tproxy.check_canary_throughput(
        probe,
        "gateway.discord.gg",
        1.25,
        read_bytes=128,
        min_bps=128.0,
        path="/health",
        tls_wrapper=tls_wrapper,
        clock=lambda: next(ticks),
    )

    assert ok
    assert detail == "128 bytes in 0.25s (512 B/s)"
    assert b"GET /health HTTP/1.1" in tls.sent
    assert b"Host: gateway.discord.gg" in tls.sent
    assert calls == [(probe, "gateway.discord.gg", 1.25)]
    assert tls.closed


def test_run_network_canary_reports_throughput_failure():
    class Sock:
        def close(self):
            pass

    ok, detail = tproxy.run_network_canary(
        host="gateway.discord.gg",
        timeout=1.25,
        resolver=lambda host: ["203.0.113.10"],
        connector=lambda addr, timeout: Sock(),
        throughput_checker=lambda sock, host, timeout: (
            False,
            "throughput 5 B/s below 128 B/s",
        ),
    )

    assert not ok
    assert detail == "203.0.113.10: throughput 5 B/s below 128 B/s"


def test_run_network_canary_reports_resolve_failure():
    ok, detail = tproxy.run_network_canary(
        resolver=lambda host: [],
        connector=lambda addr, timeout: None,
    )

    assert not ok
    assert detail == "resolve returned no A records"


def test_periodic_canary_runs_only_when_due_and_active():
    assert tproxy.should_run_periodic_canary(
        now=400.0,
        last_run=100.0,
        interval=300.0,
    )
    assert not tproxy.should_run_periodic_canary(
        now=399.0,
        last_run=100.0,
        interval=300.0,
    )
    assert not tproxy.should_run_periodic_canary(
        now=400.0,
        last_run=100.0,
        interval=300.0,
        vpn=True,
    )
    assert not tproxy.should_run_periodic_canary(
        now=400.0,
        last_run=100.0,
        interval=300.0,
        recheck_reason="route change",
    )
    assert not tproxy.should_run_periodic_canary(
        now=400.0,
        last_run=0.0,
        interval=0.0,
    )


def test_pf_rules_force_quic_to_tcp_fallback():
    assert "block return quick inet proto udp from any to any port 443" in tproxy.PF_RULES
    assert "slipstream_quic_block" not in tproxy.PF_RULES


def test_voice_flow_observe_caps_count_and_keeps_recent_flow():
    flows = OrderedDict()
    key = ("10.0.0.2", 50000, "203.0.113.10", 50001)

    for index in range(tproxy.VOICE_CUTOFF):
        should_prime, count = tproxy.observe_voice_flow(flows, key, now=float(index))
        assert should_prime
        assert count == index

    should_prime, count = tproxy.observe_voice_flow(flows, key, now=99.0)

    assert not should_prime
    assert count == tproxy.VOICE_CUTOFF
    assert flows[key] == (tproxy.VOICE_CUTOFF, 99.0)


def test_voice_flow_prune_expires_idle_entries():
    flows = OrderedDict([
        ("old", (1, 0.0)),
        ("fresh", (1, 200.0)),
    ])

    tproxy.prune_voice_flows(flows, now=400.0, idle_ttl=250.0)

    assert list(flows) == ["fresh"]


def test_voice_flow_prune_evicts_lru_overflow_without_full_clear():
    flows = OrderedDict([
        ("oldest", (1, 100.0)),
        ("middle", (1, 101.0)),
        ("newest", (1, 102.0)),
    ])

    tproxy.prune_voice_flows(flows, now=110.0, max_flows=2, idle_ttl=999.0)

    assert list(flows) == ["middle", "newest"]


def test_rotating_log_writer_keeps_bounded_archives(tmp_path):
    log = tmp_path / "slipstream.log"
    writer = tproxy.RotatingLogWriter(str(log), max_bytes=10, backups=2)

    writer.write("123456789\n")
    writer.write("abcdefghi\n")
    writer.write("XYZ\n")
    writer.flush()

    assert log.read_text() == "XYZ\n"
    assert (tmp_path / "slipstream.log.1").read_text() == "abcdefghi\n"
    assert (tmp_path / "slipstream.log.2").read_text() == "123456789\n"
    assert not (tmp_path / "slipstream.log.3").exists()
    assert log.stat().st_mode & 0o777 == 0o640


def test_rotating_log_writer_rotates_oversized_existing_log(tmp_path):
    log = tmp_path / "slipstream.log"
    log.write_text("already too large\n")

    writer = tproxy.RotatingLogWriter(str(log), max_bytes=10, backups=2)
    writer.write("fresh\n")
    writer.flush()

    assert log.read_text() == "fresh\n"
    assert (tmp_path / "slipstream.log.1").read_text() == "already too large\n"


def test_remove_obsolete_newsyslog_config(monkeypatch, tmp_path):
    conf = tmp_path / "dev.slipstream.tproxy.conf"
    conf.write_text("obsolete\n")
    monkeypatch.setattr(tproxy, "OBSOLETE_NEWSYSLOG_CONFIG_PATH", str(conf))

    tproxy.remove_obsolete_newsyslog_config()
    tproxy.remove_obsolete_newsyslog_config()

    assert not conf.exists()
