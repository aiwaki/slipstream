import ssl
import logging
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


def test_reset_network_runtime_state_clears_transient_route_state(monkeypatch):
    calls = []
    monkeypatch.setattr(tproxy, "_pf_applied", True)
    monkeypatch.setattr(tproxy, "_run", lambda *args: calls.append(args))
    tproxy._dead["blocked.example"] = 999.0
    tproxy._tg_direct_failures.clear()
    tproxy._tg_direct_failures.append(10.0)
    tproxy._tg_proxy_suggest_until = 999.0
    tproxy._quic_block_ips.clear()
    tproxy._quic_block_ips["203.0.113.10"] = 1.0
    with tproxy._doh_lock:
        tproxy._doh_cache["blocked.example"] = (["203.0.113.10"], 999.0)

    tproxy.reset_network_runtime_state("test")

    assert tproxy._dead == {}
    assert list(tproxy._tg_direct_failures) == []
    assert tproxy._tg_proxy_suggest_until == 0.0
    assert tproxy._quic_block_ips == {}
    with tproxy._doh_lock:
        assert tproxy._doh_cache == {}
    assert calls == [
        ("pfctl", "-t", tproxy.QUIC_BLOCK_TABLE, "-T", "flush")
    ]


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

    ok, detail = tproxy.run_network_canary(
        host="gateway.discord.gg",
        timeout=1.25,
        resolver=lambda host: ["203.0.113.10"],
        connector=connector,
    )

    assert ok
    assert detail == "203.0.113.10"
    assert sockets[0][0] == ("203.0.113.10", 443)
    assert sockets[0][1] == 1.25
    assert sockets[0][2].closed


def test_run_network_canary_reports_resolve_failure():
    ok, detail = tproxy.run_network_canary(
        resolver=lambda host: [],
        connector=lambda addr, timeout: None,
    )

    assert not ok
    assert detail == "resolve returned no A records"


def test_pf_rules_scope_quic_block_to_table():
    assert f"table <{tproxy.QUIC_BLOCK_TABLE}> persist" in tproxy.PF_RULES
    assert f"to <{tproxy.QUIC_BLOCK_TABLE}> port 443" in tproxy.PF_RULES
    assert "proto udp from any to any port 443" not in tproxy.PF_RULES


def test_note_quic_block_ips_filters_and_evicts_lru(monkeypatch):
    calls = []
    monkeypatch.setattr(tproxy, "_pf_applied", True)
    monkeypatch.setattr(tproxy, "_run", lambda *args: calls.append(args))
    tproxy._quic_block_ips.clear()

    tproxy.note_quic_block_ips([
        "93.184.216.34",
        "10.0.0.1",
        "149.154.160.1",
        "1.1.1.1",
        "8.8.8.8",
    ], max_ips=2)

    assert list(tproxy._quic_block_ips) == ["1.1.1.1", "8.8.8.8"]
    assert calls == [
        ("pfctl", "-t", tproxy.QUIC_BLOCK_TABLE, "-T", "replace",
         "1.1.1.1", "8.8.8.8")
    ]


def test_sync_quic_block_table_replaces_loaded_table(monkeypatch):
    calls = []
    monkeypatch.setattr(tproxy, "_run", lambda *args: calls.append(args))
    tproxy._quic_block_ips.clear()
    tproxy._quic_block_ips["93.184.216.34"] = 1.0
    tproxy._quic_block_ips["1.1.1.1"] = 2.0

    tproxy.sync_quic_block_table()

    assert calls == [
        ("pfctl", "-t", tproxy.QUIC_BLOCK_TABLE, "-T", "replace",
         "93.184.216.34", "1.1.1.1")
    ]


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
