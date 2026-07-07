import asyncio
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


def test_default_iface_tracks_interface(monkeypatch):
    class Result:
        stdout = """
           route to: default
        destination: default
            gateway: 192.168.1.1
          interface: en0
        """

    monkeypatch.setattr(tproxy, "_run", lambda *args: Result())

    assert tproxy.default_iface() == "en0"


def test_write_status_includes_core_runtime_state(monkeypatch, tmp_path):
    status_path = tmp_path / "slipstream.status"
    monkeypatch.setattr(tproxy, "STATUS_PATH", str(status_path))
    tproxy._strat_cache.clear()
    tproxy._strat_cache["example.com"] = "split64+fake"
    tproxy._dead.clear()
    tproxy._dead["blocked.example"] = 999.0
    monkeypatch.setattr(tproxy, "_geph_up", True)

    tproxy.write_status("active", "en0", "en0")

    status = json.loads(status_path.read_text())
    assert status["state"] == "active"
    assert status["iface"] == "en0"
    assert status["voice"] == "en0"
    assert status["hosts_learned"] == 1
    assert status["dead"] == 1
    assert status["geph"] == "up"
    assert status["telegram_proxy"] in {"ready", "starting", "error"}
    assert "route" not in status
    assert "canary" not in status


def test_pf_rules_leave_quic_unblocked():
    assert "table <slipstream_quic_block> persist" in tproxy.PF_RULES
    assert "proto udp" not in tproxy.PF_RULES
    assert "block return quick inet proto udp from any to any port 443" not in tproxy.PF_RULES


def test_youtube_video_hosts_ignore_stale_non_fake_strategy_cache():
    host = "rr2---sn-ntq7yner.googlevideo.com"
    tproxy._strat_cache.clear()
    tproxy._strat_cache[host] = "split64"

    try:
        names = [s["name"] for s in tproxy.strategy_order(host)]

        assert names == ["split64+fake", "split16+fake", "fake5"]
    finally:
        tproxy._strat_cache.clear()


def test_discord_hosts_use_fake_only_local_bypass_strategy():
    host = "gateway.discord.gg"
    tproxy._strat_cache.clear()
    tproxy._strat_cache[host] = "split64"

    try:
        names = [s["name"] for s in tproxy.strategy_order(host)]

        assert names == ["split64+fake", "split16+fake", "fake5"]
    finally:
        tproxy._strat_cache.clear()


def test_discord_hosts_do_not_route_via_geph():
    assert not tproxy.geph_route("updates.discord.com")
    assert not tproxy.geph_route("gateway.discord.gg")
    assert not tproxy.geph_route("discord.com")


def test_local_bypass_hosts_ignore_stale_auto_geph_cache():
    tproxy._auto_geph.clear()
    tproxy._auto_geph["updates.discord.com"] = tproxy.time.time() + 3600
    tproxy._auto_geph["rr2---sn-ntq7yner.googlevideo.com"] = tproxy.time.time() + 3600

    try:
        assert not tproxy.geph_route("updates.discord.com")
        assert not tproxy.geph_route("rr2---sn-ntq7yner.googlevideo.com")
    finally:
        tproxy._auto_geph.clear()


def test_local_bypass_resolution_uses_system_dns_when_doh_is_empty(monkeypatch):
    async def empty_doh(host):
        return []

    async def system(host):
        return ["162.159.136.232", "162.159.138.232"]

    monkeypatch.setattr(tproxy, "doh_resolve_async", empty_doh)
    monkeypatch.setattr(tproxy, "system_resolve_async", system)

    ips = asyncio.run(tproxy.resolve_connection_ips("updates.discord.com", "162.159.136.232"))

    assert ips == ["162.159.136.232", "162.159.138.232"]
    assert tproxy.ip_attempt_limit("updates.discord.com") == 4


def test_local_bypass_resolution_keeps_system_dns_even_when_doh_has_results(monkeypatch):
    async def doh(host):
        return ["162.159.128.233"]

    async def system(host):
        return ["162.159.136.232", "162.159.138.232"]

    monkeypatch.setattr(tproxy, "doh_resolve_async", doh)
    monkeypatch.setattr(tproxy, "system_resolve_async", system)

    ips = asyncio.run(tproxy.resolve_connection_ips("gateway.discord.gg", "162.159.136.232"))

    assert ips == ["162.159.128.233", "162.159.136.232", "162.159.138.232"]


def test_fake_injector_uses_discord_decoy_without_changing_video_poison(monkeypatch):
    calls = []
    monkeypatch.setattr(tproxy, "inject_fake_decoy", lambda *args: calls.append("decoy"))
    monkeypatch.setattr(tproxy, "inject_fake_poison", lambda *args: calls.append("poison"))

    tproxy.inject_fake_for_host("gateway.discord.gg", "127.0.0.1", 50000, "203.0.113.10", 443)
    tproxy.inject_fake_for_host("rr2---sn-ntq7yner.googlevideo.com", "127.0.0.1", 50001, "203.0.113.11", 443)

    assert calls == ["decoy", "poison"]


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
