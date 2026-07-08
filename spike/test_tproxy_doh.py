import asyncio
import base64
import json
import logging
import re
import ssl
import sys
from types import SimpleNamespace
from collections import OrderedDict, deque

import pytest
import tproxy
from tproxy import _doh_request, _doh_ssl_context


@pytest.fixture(autouse=True)
def reset_smart_dns_state():
    dns_cache = dict(tproxy._system_dns_cache)
    smart_ok = dict(tproxy._smart_dns_ok_until)
    smart_failure = dict(tproxy._smart_dns_last_failure)
    auto_fail = {host: list(values) for host, values in tproxy._auto_fail.items()}
    auto_geph = dict(tproxy._auto_geph)
    auto_confirming = dict(tproxy._auto_geph_confirming)
    auto_last_probe = dict(tproxy._auto_geph_last_probe)
    auto_last_status = dict(tproxy._auto_geph_last_status)
    strat_scores = OrderedDict(
        (host, {name: dict(value) for name, value in per_host.items()})
        for host, per_host in tproxy._strat_scores.items()
    )
    canary_health = {key: dict(value) for key, value in tproxy._canary_health.items()}
    canary_windows = {
        key: deque(value) for key, value in tproxy._canary_failure_windows.items()
    }
    try:
        tproxy._system_dns_cache.update({
            "ts": 0.0,
            "status": None,
            "resolution_ts": 0.0,
            "resolution_checks": None,
        })
        tproxy._smart_dns_ok_until.clear()
        tproxy._smart_dns_last_failure.update({"host": "", "reason": "", "ts": 0.0})
        tproxy._auto_fail.clear()
        tproxy._auto_geph.clear()
        tproxy._auto_geph_confirming.clear()
        tproxy._auto_geph_last_probe.clear()
        tproxy._auto_geph_last_status.update({
            "state": "idle",
            "host": "",
            "reason": "",
            "ts": 0.0,
            "bytes": 0,
        })
        tproxy._strat_scores.clear()
        tproxy._canary_health.clear()
        tproxy._canary_failure_windows.clear()
        yield
    finally:
        tproxy._system_dns_cache.clear()
        tproxy._system_dns_cache.update(dns_cache)
        tproxy._smart_dns_ok_until.clear()
        tproxy._smart_dns_ok_until.update(smart_ok)
        tproxy._smart_dns_last_failure.clear()
        tproxy._smart_dns_last_failure.update(smart_failure)
        tproxy._auto_fail.clear()
        tproxy._auto_fail.update(auto_fail)
        tproxy._auto_geph.clear()
        tproxy._auto_geph.update(auto_geph)
        tproxy._auto_geph_confirming.clear()
        tproxy._auto_geph_confirming.update(auto_confirming)
        tproxy._auto_geph_last_probe.clear()
        tproxy._auto_geph_last_probe.update(auto_last_probe)
        tproxy._auto_geph_last_status.clear()
        tproxy._auto_geph_last_status.update(auto_last_status)
        tproxy._strat_scores.clear()
        tproxy._strat_scores.update(strat_scores)
        tproxy._canary_health.clear()
        tproxy._canary_health.update(canary_health)
        tproxy._canary_failure_windows.clear()
        tproxy._canary_failure_windows.update(canary_windows)


def test_doh_ssl_context_verifies_resolver_certificate():
    ctx = _doh_ssl_context()

    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_local_payload_ssl_context_prefers_certifi(monkeypatch):
    calls = []
    fake_certifi = SimpleNamespace(where=lambda: "/tmp/fake-ca.pem")

    monkeypatch.setitem(sys.modules, "certifi", fake_certifi)
    monkeypatch.setattr(
        tproxy.ssl,
        "create_default_context",
        lambda **kwargs: calls.append(kwargs) or object(),
    )

    tproxy._local_payload_ssl_context()

    assert calls == [{"cafile": "/tmp/fake-ca.pem"}]


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


def test_copy_file_resilient_skips_identical_and_replaces_changed_file(tmp_path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.write_text("one")
    dst.write_text("one")
    dst.chmod(0o600)

    assert tproxy._copy_file_resilient(str(src), str(dst), mode=0o644) == "unchanged"
    assert dst.read_text() == "one"
    assert dst.stat().st_mode & 0o777 == 0o644

    src.write_text("two")

    assert tproxy._copy_file_resilient(str(src), str(dst), mode=0o600) == "copied"
    assert dst.read_text() == "two"
    assert dst.stat().st_mode & 0o777 == 0o600


def test_replace_tree_resilient_replaces_tree_without_stale_files(tmp_path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    dst.mkdir()
    (src / "fresh.txt").write_text("fresh")
    (dst / "stale.txt").write_text("stale")

    assert tproxy._replace_tree_resilient(str(src), str(dst)) == "replaced"
    assert (dst / "fresh.txt").read_text() == "fresh"
    assert not (dst / "stale.txt").exists()


def test_replace_tree_resilient_keeps_existing_tree_when_copy_fails(tmp_path, monkeypatch):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    dst.mkdir()
    (src / "fresh.txt").write_text("fresh")
    (dst / "current.txt").write_text("current")

    def fail_copytree(_src, _dst):
        raise OSError("copy failed")

    monkeypatch.setattr(tproxy.shutil, "copytree", fail_copytree)

    with pytest.raises(OSError):
        tproxy._replace_tree_resilient(str(src), str(dst), attempts=1)

    assert (dst / "current.txt").read_text() == "current"
    assert not (dst / "fresh.txt").exists()


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

    def fake_run(*args):
        if args == ("scutil", "--proxy"):
            return type("Result", (), {"returncode": 0, "stdout": "HTTPEnable : 0\n", "stderr": ""})()
        if args == ("scutil", "--dns"):
            return type("Result", (), {
                "returncode": 0,
                "stdout": "nameserver[0] : 111.88.96.50\nnameserver[1] : 111.88.96.51\n",
                "stderr": "",
            })()
        return type("Result", (), {"returncode": 1, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(tproxy, "_run", fake_run)
    monkeypatch.setattr(tproxy, "system_resolve", lambda host: ["142.250.186.46"])
    tproxy._strat_cache.clear()
    tproxy._strat_cache["example.com"] = "split64+fake"
    tproxy._dead.clear()
    tproxy._dead["blocked.example"] = 999.0
    tproxy._system_dns_cache.update({
        "ts": 0.0,
        "status": None,
        "resolution_ts": 0.0,
        "resolution_checks": None,
    })
    monkeypatch.setattr(tproxy, "_geph_up", True)

    tproxy.write_status("active", "en0", "en0")

    status = json.loads(status_path.read_text())
    assert status["state"] == "active"
    assert status["iface"] == "en0"
    assert status["voice"] == "en0"
    assert status["hosts_learned"] == 1
    assert status["dead"] == 1
    assert status["geph"] == "up"
    assert status["auto_geo_exit"]["enabled"] is True
    assert status["auto_geo_exit"]["learned"] == 0
    assert status["auto_geo_exit"]["pending"] == 0
    assert status["telegram_proxy"] in {"ready", "starting", "error"}
    assert status["route_health"]["discord"]["last_route_class"] == tproxy.ROUTE_LOCAL_BYPASS
    assert status["system_proxy"] == {"state": "off", "kind": ""}
    assert status["system_dns"]["state"] == "xbox_dns"
    assert status["system_dns"]["providers"] == "xbox_dns"
    assert status["system_dns"]["servers"] == ["111.88.96.50", "111.88.96.51"]
    assert status["system_dns"]["managed_by_slipstream"] is False
    assert status["system_dns"]["resolution_checks"]["state"] == "ok"
    assert status["smart_dns"] == {
        "state": "available",
        "providers": "xbox_dns",
        "enabled_groups": [],
        "last_failure_host": "",
        "last_failure_reason": "",
        "last_failure_at": 0.0,
        "managed_by_slipstream": False,
    }
    assert status["pf_state"] == {"applied": False, "enabled": False, "rules_loaded": False}
    assert status["geph_detail"]["port"] == 0
    assert "canaries" in status


def test_pf_state_snapshot_reports_enabled_and_loaded_rules(monkeypatch):
    def fake_run(*args):
        if args == ("pfctl", "-s", "info"):
            return type("Result", (), {
                "returncode": 0,
                "stdout": "Status: Enabled\n",
                "stderr": "",
            })()
        if args == ("pfctl", "-sn"):
            return type("Result", (), {
                "returncode": 0,
                "stdout": "rdr pass on en0 inet proto tcp to any port 443 -> 127.0.0.1 port 1080\n",
                "stderr": "",
            })()
        raise AssertionError(args)

    monkeypatch.setattr(tproxy, "_run", fake_run)
    monkeypatch.setattr(tproxy, "_pf_applied", True)

    assert tproxy.pf_state_snapshot(1080) == {
        "applied": True,
        "enabled": True,
        "rules_loaded": True,
    }


def test_route_policy_classifies_service_groups():
    assert tproxy.route_policy("updates.discord.com") == {
        "host": "updates.discord.com",
        "route_class": tproxy.ROUTE_LOCAL_BYPASS,
        "service_group": tproxy.SERVICE_DISCORD,
        "strategy_set": tproxy.STRATEGY_FAKE_ONLY,
    }
    assert tproxy.route_policy("status.discordstatus.com") == {
        "host": "status.discordstatus.com",
        "route_class": tproxy.ROUTE_LOCAL_BYPASS,
        "service_group": tproxy.SERVICE_DISCORD,
        "strategy_set": tproxy.STRATEGY_FAKE_ONLY,
    }
    assert tproxy.route_policy("rr2---sn-ntq7yner.googlevideo.com")["service_group"] == (
        tproxy.SERVICE_YOUTUBE
    )
    assert tproxy.route_policy("youtu.be")["service_group"] == tproxy.SERVICE_YOUTUBE
    assert tproxy.route_policy("yt3.ggpht.com")["service_group"] == tproxy.SERVICE_YOUTUBE
    assert tproxy.route_policy("billing.openai.com")["route_class"] == tproxy.ROUTE_GEO_EXIT
    assert tproxy.route_policy("claude.ai")["service_group"] == tproxy.SERVICE_ANTHROPIC
    assert tproxy.route_policy("t.me")["service_group"] == tproxy.SERVICE_TELEGRAM
    assert tproxy.route_policy("store.steampowered.com") == {
        "host": "store.steampowered.com",
        "route_class": tproxy.ROUTE_GEO_EXIT,
        "service_group": tproxy.SERVICE_STEAM_STORE,
        "strategy_set": tproxy.STRATEGY_GEPH,
    }
    assert tproxy.route_policy("cdn.fastly.steamstatic.com")["service_group"] == (
        tproxy.SERVICE_STEAM_STORE
    )
    assert tproxy.route_policy("steamcdn-a.akamaihd.net")["service_group"] == (
        tproxy.SERVICE_STEAM_STORE
    )
    assert tproxy.route_policy("cmp1-fra1.steamserver.net")["route_class"] == (
        tproxy.ROUTE_UNKNOWN
    )


def test_local_payload_canary_request_supports_discord_gateway_websocket():
    spec = {"payload_probe": "websocket_upgrade"}
    req = tproxy._local_payload_canary_request(
        "gateway.discord.gg",
        spec,
    )
    req2 = tproxy._local_payload_canary_request("gateway.discord.gg", spec)

    assert req.startswith(b"GET /?v=10&encoding=json HTTP/1.1\r\n")
    assert b"Host: gateway.discord.gg\r\n" in req
    assert b"Upgrade: websocket\r\n" in req
    assert b"Sec-WebSocket-Version: 13\r\n" in req
    key = re.search(rb"Sec-WebSocket-Key: ([^\r]+)", req).group(1)
    key2 = re.search(rb"Sec-WebSocket-Key: ([^\r]+)", req2).group(1)
    decoded = base64.b64decode(key)
    decoded2 = base64.b64decode(key2)
    assert len(decoded) == 16
    assert len(decoded2) == 16
    assert decoded != b"the sample nonce"
    assert key2 != key


def test_local_payload_canary_request_supports_specific_http_path():
    req = tproxy._local_payload_canary_request(
        "cdn.discordapp.com",
        {"payload_path": "/embed/avatars/0.png"},
    )

    assert req.startswith(b"HEAD /embed/avatars/0.png HTTP/1.1\r\n")
    assert b"Host: cdn.discordapp.com\r\n" in req


def test_discord_api_canary_uses_gateway_api_path():
    spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "discord_api")
    req = tproxy._local_payload_canary_request(spec["host"], spec)

    assert spec["payload_path"] == "/api/v10/gateway"
    assert req.startswith(b"HEAD /api/v10/gateway HTTP/1.1\r\n")
    assert b"Host: discord.com\r\n" in req


def test_youtube_web_canary_uses_generate_204_path():
    spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "youtube_web")
    req = tproxy._local_payload_canary_request(spec["host"], spec)

    assert spec["payload_path"] == "/generate_204"
    assert req.startswith(b"HEAD /generate_204 HTTP/1.1\r\n")
    assert b"Host: www.youtube.com\r\n" in req


def test_quic_version_negotiation_probe_packet_is_padded_initial():
    pkt = tproxy._quic_version_negotiation_probe_packet(
        dcid=b"12345678",
        scid=b"abcdefgh",
    )

    assert len(pkt) == tproxy.QUIC_MIN_INITIAL_SIZE
    assert pkt[:5] == b"\xc0" + tproxy.QUIC_UNSUPPORTED_VERSION
    assert pkt[5] == 8
    assert pkt[6:14] == b"12345678"
    assert pkt[14] == 8
    assert pkt[15:23] == b"abcdefgh"


def test_quic_version_negotiation_response_detection():
    assert tproxy._is_quic_version_negotiation_response(b"\xc0\x00\x00\x00\x00rest")

    assert not tproxy._is_quic_version_negotiation_response(b"\xc0\x00\x00\x00\x01rest")
    assert not tproxy._is_quic_version_negotiation_response(b"\x40\x00\x00\x00\x00rest")


def test_discord_cdn_canary_stays_local_bypass_and_fake_only():
    spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "discord_cdn")

    assert tproxy.route_policy(spec["host"]) == {
        "host": "cdn.discordapp.com",
        "route_class": tproxy.ROUTE_LOCAL_BYPASS,
        "service_group": tproxy.SERVICE_DISCORD,
        "strategy_set": tproxy.STRATEGY_FAKE_ONLY,
    }
    assert not tproxy.geph_route(spec["host"])
    assert [s["name"] for s in tproxy.strategy_order(spec["host"])] == [
        "split64+fake",
        "split16+fake",
        "fake5",
    ]


def test_discord_api_canary_stays_local_bypass_and_fake_only():
    spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "discord_api")

    assert tproxy.route_policy(spec["host"]) == {
        "host": "discord.com",
        "route_class": tproxy.ROUTE_LOCAL_BYPASS,
        "service_group": tproxy.SERVICE_DISCORD,
        "strategy_set": tproxy.STRATEGY_FAKE_ONLY,
    }
    assert not tproxy.geph_route(spec["host"])
    assert [s["name"] for s in tproxy.strategy_order(spec["host"])] == [
        "split64+fake",
        "split16+fake",
        "fake5",
    ]


def test_youtube_redirector_canary_stays_local_bypass_and_fake_only():
    spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "youtube_video")
    host = spec["fallback_host"]

    assert tproxy.route_policy(host) == {
        "host": "redirector.googlevideo.com",
        "route_class": tproxy.ROUTE_LOCAL_BYPASS,
        "service_group": tproxy.SERVICE_YOUTUBE,
        "strategy_set": tproxy.STRATEGY_FAKE_ONLY,
    }
    assert not tproxy.geph_route(host)
    assert [s["name"] for s in tproxy.strategy_order(host)] == [
        "split64+fake",
        "split16+fake",
        "fake5",
    ]


def test_youtube_web_canary_stays_local_bypass_and_fake_only():
    spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "youtube_web")

    assert spec["soft"] is True
    assert tproxy.route_policy(spec["host"]) == {
        "host": "www.youtube.com",
        "route_class": tproxy.ROUTE_LOCAL_BYPASS,
        "service_group": tproxy.SERVICE_YOUTUBE,
        "strategy_set": tproxy.STRATEGY_FAKE_ONLY,
    }
    assert not tproxy.geph_route(spec["host"])
    assert [s["name"] for s in tproxy.strategy_order(spec["host"])] == [
        "split64+fake",
        "split16+fake",
        "fake5",
    ]


def test_system_proxy_status_from_scutil_reports_kind_without_mutating():
    raw = """
HTTPEnable : 1
HTTPSEnable : 1
SOCKSEnable : 0
ProxyAutoConfigEnable : 1
"""

    assert tproxy.system_proxy_status_from_scutil(raw) == {
        "state": "active",
        "kind": "http,https,pac",
    }
    assert tproxy.system_proxy_status_from_scutil("HTTPEnable : 0\n") == {
        "state": "off",
        "kind": "",
    }


def test_system_dns_status_detects_xbox_dns_without_mutating():
    raw = """
DNS configuration

resolver #1
  nameserver[0] : 111.88.96.50
  nameserver[1] : 111.88.96.51

DNS configuration (for scoped queries)
resolver #1
  nameserver[0] : 111.88.96.50
"""

    assert tproxy.system_dns_status_from_scutil(raw) == {
        "state": "xbox_dns",
        "providers": "xbox_dns",
        "servers": ["111.88.96.50", "111.88.96.51"],
        "managed_by_slipstream": False,
    }
    assert tproxy.system_dns_status_from_scutil("nameserver[0] : 1.1.1.1\n") == {
        "state": "configured",
        "providers": "",
        "servers": ["1.1.1.1"],
        "managed_by_slipstream": False,
    }


def test_system_dns_resolution_checks_flag_null_private_and_stub_answers():
    answers = {
        "updates.discord.com": ["0.0.0.0"],
        "gateway.discord.gg": ["10.0.0.42"],
        "www.youtube.com": ["142.250.186.46"],
        "redirector.googlevideo.com": ["87.228.47.11"],
    }

    status = tproxy.system_dns_resolution_checks(lambda host: answers.get(host, []))
    checks = {item["host"]: item for item in status["checks"]}

    assert status["state"] == "suspicious"
    assert checks["updates.discord.com"]["state"] == "suspicious"
    assert checks["gateway.discord.gg"]["suspicious_ips"] == ["10.0.0.42"]
    assert checks["www.youtube.com"]["state"] == "ok"
    assert checks["redirector.googlevideo.com"]["suspicious_ips"] == ["87.228.47.11"]


def test_system_dns_resolution_checks_report_unknown_without_mutating():
    status = tproxy.system_dns_resolution_checks(lambda host: [])

    assert status["state"] == "unknown"
    assert all(item["state"] == "unknown" for item in status["checks"])


def test_current_system_dns_status_is_cached(monkeypatch):
    calls = []
    resolves = []

    def fake_run(*args):
        calls.append(args)
        return type("Result", (), {
            "returncode": 0,
            "stdout": "nameserver[0] : 111.88.96.50\n",
            "stderr": "",
        })()

    def fake_resolve(host):
        resolves.append(host)
        return ["142.250.186.46"]

    original = dict(tproxy._system_dns_cache)
    try:
        tproxy._system_dns_cache.update({
            "ts": 0.0,
            "status": None,
            "resolution_ts": 0.0,
            "resolution_checks": None,
        })
        monkeypatch.setattr(tproxy, "_run", fake_run)
        monkeypatch.setattr(tproxy, "system_resolve", fake_resolve)

        first = tproxy.current_system_dns_status(now=100.0)
        second = tproxy.current_system_dns_status(now=110.0)

        assert first["state"] == "xbox_dns"
        assert first["resolution_checks"]["state"] == "ok"
        assert second["state"] == "xbox_dns"
        assert calls == [("scutil", "--dns")]
        assert resolves == [host for host, _group in tproxy.DNS_DIAGNOSTIC_HOSTS]
    finally:
        tproxy._system_dns_cache.clear()
        tproxy._system_dns_cache.update(original)


def test_smart_dns_route_gate_requires_geo_exit_and_fresh_canary(monkeypatch):
    monkeypatch.setattr(
        tproxy,
        "current_system_dns_status",
        lambda now=None: {
            "state": "xbox_dns",
            "providers": "xbox_dns",
            "servers": ["111.88.96.50"],
            "managed_by_slipstream": False,
        },
    )
    tproxy._smart_dns_ok_until[tproxy.SERVICE_OPENAI] = 200.0

    assert tproxy.smart_dns_route_enabled("chatgpt.com", now=100.0)
    assert not tproxy.smart_dns_route_enabled("chatgpt.com", now=201.0)
    assert not tproxy.smart_dns_route_enabled("gateway.discord.gg", now=100.0)
    assert not tproxy.smart_dns_route_enabled("rr2---sn-ntq7yner.googlevideo.com", now=100.0)
    tproxy._smart_dns_ok_until[tproxy.SERVICE_STEAM_STORE] = 200.0
    assert not tproxy.smart_dns_route_enabled("store.steampowered.com", now=100.0)


def test_canary_scheduler_runs_on_forced_and_periodic_triggers(monkeypatch):
    calls = []
    tproxy._canary_state.update({
        "running": False,
        "last_run": 0.0,
        "last_started": 0.0,
        "next_due": 0.0,
        "last_reason": "",
        "total": 0,
        "ok": 0,
        "degraded": 0,
    })
    monkeypatch.setattr(tproxy, "CANARY_INTERVAL", 10.0)
    monkeypatch.setattr(tproxy, "CANARY_JITTER", 1.0)

    assert tproxy.start_canaries_if_due("startup", force=True, now=100.0, runner=calls.append)
    assert calls == ["startup"]
    assert not tproxy._canary_state["running"]
    assert tproxy._canary_state["next_due"] == 110.0

    assert not tproxy.start_canaries_if_due("periodic", now=105.0, runner=calls.append)
    assert tproxy.start_canaries_if_due("periodic", now=111.0, runner=calls.append)
    assert calls == ["startup", "periodic"]


def test_local_bypass_canary_failure_decays_only_local_strategy_cache(monkeypatch):
    async def no_ips(host, fallback_ip):
        return []

    monkeypatch.setattr(tproxy, "resolve_connection_ips", no_ips)
    tproxy._strat_cache.clear()
    tproxy._strat_cache["updates.discord.com"] = "split64+fake"
    tproxy._strat_cache["billing.openai.com"] = "split64+fake"

    try:
        spec = {"group": tproxy.SERVICE_DISCORD, "host": "updates.discord.com"}
        assert not asyncio.run(tproxy._run_local_bypass_canary(spec))

        assert "updates.discord.com" not in tproxy._strat_cache
        assert tproxy._strat_cache["billing.openai.com"] == "split64+fake"
        health = tproxy.route_health_snapshot()[tproxy.SERVICE_DISCORD]
        assert health["state"] == tproxy.HEALTH_DEGRADED
        assert health["last_failure"] == "dns failed"
    finally:
        tproxy._strat_cache.clear()


def test_local_bypass_canary_requires_payload_success(monkeypatch):
    host = "updates.discord.com"
    original = dict(tproxy._route_health[tproxy.SERVICE_DISCORD])
    original_window = list(tproxy._route_failure_windows[tproxy.SERVICE_DISCORD])
    payload_calls = []

    class DummyWriter:
        def close(self):
            pass

    async def ips(_host, _fallback_ip):
        return ["203.0.113.10"]

    async def connected(ip, port, head, body, sni, strat):
        return object(), DummyWriter(), b"\x16\x03\x03"

    async def payload(ip, sni, strat, spec):
        payload_calls.append((ip, sni, strat["name"], spec["name"]))
        return tproxy.LOCAL_PAYLOAD_CANARY_MIN_BYTES

    try:
        tproxy._route_failure_windows[tproxy.SERVICE_DISCORD].clear()
        tproxy._strat_cache.clear()
        monkeypatch.setattr(tproxy, "resolve_connection_ips", ips)
        monkeypatch.setattr(
            tproxy,
            "strategy_order",
            lambda _host: [tproxy.STRAT_BY_NAME["split64+fake"]],
        )
        monkeypatch.setattr(tproxy, "dial_strategy", connected)
        monkeypatch.setattr(tproxy, "_run_local_payload_probe", payload)

        spec = {"name": "discord_update", "group": tproxy.SERVICE_DISCORD, "host": host}
        assert asyncio.run(tproxy._run_local_bypass_canary(spec))

        assert payload_calls == [("203.0.113.10", host, "split64+fake", "discord_update")]
        assert tproxy._strat_cache[host] == "split64+fake"
        health = tproxy.route_health_snapshot()[tproxy.SERVICE_DISCORD]
        assert health["state"] == tproxy.HEALTH_OK
        assert health["last_failure"] == ""
        assert health["last_host"] == host
    finally:
        tproxy._strat_cache.clear()
        tproxy._route_health[tproxy.SERVICE_DISCORD] = original
        q = tproxy._route_failure_windows[tproxy.SERVICE_DISCORD]
        q.clear()
        q.extend(original_window)


def test_local_bypass_canary_payload_failure_warns_before_degraded(monkeypatch):
    host = "updates.discord.com"
    original = dict(tproxy._route_health[tproxy.SERVICE_DISCORD])
    original_window = list(tproxy._route_failure_windows[tproxy.SERVICE_DISCORD])

    class DummyWriter:
        def close(self):
            pass

    async def ips(_host, _fallback_ip):
        return ["203.0.113.10"]

    async def connected(ip, port, head, body, sni, strat):
        return object(), DummyWriter(), b"\x16\x03\x03"

    async def no_payload(ip, sni, strat, spec):
        return 0

    try:
        tproxy._route_failure_windows[tproxy.SERVICE_DISCORD].clear()
        tproxy.route_health_event(
            tproxy.SERVICE_DISCORD,
            tproxy.ROUTE_LOCAL_BYPASS,
            host,
            ok=True,
            now=100.0,
        )
        tproxy._strat_cache.clear()
        tproxy._strat_cache[host] = "split64+fake"
        tproxy._strat_cache["billing.openai.com"] = "split64+fake"
        monkeypatch.setattr(tproxy, "resolve_connection_ips", ips)
        monkeypatch.setattr(
            tproxy,
            "strategy_order",
            lambda _host: [tproxy.STRAT_BY_NAME["split64+fake"]],
        )
        monkeypatch.setattr(tproxy, "dial_strategy", connected)
        monkeypatch.setattr(tproxy, "_run_local_payload_probe", no_payload)

        spec = {"name": "discord_update", "group": tproxy.SERVICE_DISCORD, "host": host}
        assert asyncio.run(tproxy._run_local_bypass_canary(spec)) == "warning"

        assert host not in tproxy._strat_cache
        assert tproxy._strat_cache["billing.openai.com"] == "split64+fake"
        health = tproxy.route_health_snapshot()[tproxy.SERVICE_DISCORD]
        assert health["state"] == tproxy.HEALTH_OK
        assert health["last_failure"] == ""
        assert health["last_warning"] == "payload probe failed"

        for _ in range(max(0, tproxy.LOCAL_PAYLOAD_DEGRADE_AFTER - 2)):
            assert asyncio.run(tproxy._run_local_bypass_canary(spec)) == "warning"
        assert not asyncio.run(tproxy._run_local_bypass_canary(spec))
        health = tproxy.route_health_snapshot()[tproxy.SERVICE_DISCORD]
        assert health["state"] == tproxy.HEALTH_DEGRADED
        assert health["last_failure"] == "payload probe failed"
    finally:
        tproxy._strat_cache.clear()
        tproxy._route_health[tproxy.SERVICE_DISCORD] = original
        q = tproxy._route_failure_windows[tproxy.SERVICE_DISCORD]
        q.clear()
        q.extend(original_window)


def test_canary_health_keeps_endpoint_failure_visible_after_sibling_ok():
    original = dict(tproxy._route_health[tproxy.SERVICE_DISCORD])
    original_window = list(tproxy._route_failure_windows[tproxy.SERVICE_DISCORD])
    gateway = next(item for item in tproxy.CANARY_SPECS if item["name"] == "discord_gateway")
    cdn = next(item for item in tproxy.CANARY_SPECS if item["name"] == "discord_cdn")
    now = tproxy.time.time()

    try:
        tproxy._route_failure_windows[tproxy.SERVICE_DISCORD].clear()
        tproxy.canary_health_event(
            gateway,
            tproxy.ROUTE_LOCAL_BYPASS,
            "gateway.discord.gg",
            ok=False,
            reason="websocket upgrade failed",
            now=now,
        )
        tproxy.canary_health_event(
            cdn,
            tproxy.ROUTE_LOCAL_BYPASS,
            "cdn.discordapp.com",
            ok=True,
            now=now + 10.0,
        )

        checks = tproxy.canary_status_snapshot()["checks"]
        assert checks["discord_gateway"]["state"] == tproxy.HEALTH_DEGRADED
        assert checks["discord_gateway"]["last_failure"] == "websocket upgrade failed"
        assert checks["discord_cdn"]["state"] == tproxy.HEALTH_OK

        health = tproxy.route_health_snapshot(now=now + 10.0)[tproxy.SERVICE_DISCORD]
        assert health["state"] == tproxy.HEALTH_DEGRADED
        assert health["last_host"] == "gateway.discord.gg"
        assert health["last_failure"] == "websocket upgrade failed"
        assert health["failures_5m"] == 1
    finally:
        tproxy._route_health[tproxy.SERVICE_DISCORD] = original
        q = tproxy._route_failure_windows[tproxy.SERVICE_DISCORD]
        q.clear()
        q.extend(original_window)


def test_canary_status_keeps_legacy_summary_fields_with_check_details():
    spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "discord_update")
    original = dict(tproxy._route_health[tproxy.SERVICE_DISCORD])
    original_window = list(tproxy._route_failure_windows[tproxy.SERVICE_DISCORD])

    try:
        tproxy.canary_health_event(
            spec,
            tproxy.ROUTE_LOCAL_BYPASS,
            "updates.discord.com",
            ok=True,
            now=tproxy.time.time(),
        )

        snapshot = tproxy.canary_status_snapshot()

        for key in ("running", "last_run", "total", "ok", "degraded", "warnings", "unknown"):
            assert key in snapshot
        assert snapshot["checks"]["discord_update"]["group"] == tproxy.SERVICE_DISCORD
        assert snapshot["checks"]["discord_update"]["last_host"] == "updates.discord.com"
    finally:
        tproxy._route_health[tproxy.SERVICE_DISCORD] = original
        q = tproxy._route_failure_windows[tproxy.SERVICE_DISCORD]
        q.clear()
        q.extend(original_window)


def test_youtube_canary_prefers_observed_video_host_then_redirector_fallback():
    spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "youtube_video")
    tproxy._strat_cache.clear()

    try:
        assert tproxy._canary_host(spec) == "redirector.googlevideo.com"

        tproxy._strat_cache["www.youtube.com"] = "fake5"
        assert tproxy._canary_host(spec) == "redirector.googlevideo.com"

        tproxy._strat_cache["rr2---sn-ntq7yner.googlevideo.com"] = "fake5"

        assert tproxy._canary_host(spec) == "rr2---sn-ntq7yner.googlevideo.com"
    finally:
        tproxy._strat_cache.clear()


def test_youtube_web_canary_failure_is_warning_only(monkeypatch):
    spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "youtube_web")
    original = dict(tproxy._route_health[tproxy.SERVICE_YOUTUBE])
    original_window = deque(tproxy._route_failure_windows[tproxy.SERVICE_YOUTUBE])

    async def fake_resolve(host, fallback_ip):
        return ["203.0.113.10"]

    async def fake_dial(ip, port, head, body, host, strat):
        return None

    try:
        monkeypatch.setattr(tproxy, "resolve_connection_ips", fake_resolve)
        monkeypatch.setattr(tproxy, "dial_strategy", fake_dial)

        assert asyncio.run(tproxy._run_local_bypass_canary(spec)) == "warning"

        check = tproxy.canary_health_snapshot()["youtube_web"]
        assert check["state"] == tproxy.HEALTH_UNKNOWN
        assert check["last_warning"] == "strategy probe failed"
        assert check["failures_5m"] == 0
        health = tproxy.route_health_snapshot()[tproxy.SERVICE_YOUTUBE]
        assert health["state"] != tproxy.HEALTH_DEGRADED
    finally:
        tproxy._route_health[tproxy.SERVICE_YOUTUBE] = original
        q = tproxy._route_failure_windows[tproxy.SERVICE_YOUTUBE]
        q.clear()
        q.extend(original_window)


def test_youtube_canary_uses_quic_transport_probe(monkeypatch):
    spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "youtube_video")
    original = dict(tproxy._route_health[tproxy.SERVICE_YOUTUBE])
    original_window = deque(tproxy._route_failure_windows[tproxy.SERVICE_YOUTUBE])
    tproxy._strat_cache.clear()
    calls = []

    async def fake_resolve(host, fallback_ip):
        calls.append(("resolve", host, fallback_ip))
        return ["203.0.113.10"]

    async def fake_quic(ips):
        calls.append(("quic", tuple(ips)))
        return True

    async def unexpected_dial_strategy(*args, **kwargs):
        raise AssertionError("YouTube canary should not use the TCP strategy probe")

    monkeypatch.setattr(tproxy, "resolve_connection_ips", fake_resolve)
    monkeypatch.setattr(tproxy, "_run_quic_version_negotiation_probe", fake_quic)
    monkeypatch.setattr(tproxy, "dial_strategy", unexpected_dial_strategy)

    try:
        assert asyncio.run(tproxy._run_local_bypass_canary(spec)) is True

        assert calls == [
            ("resolve", "redirector.googlevideo.com", None),
            ("quic", ("203.0.113.10",)),
        ]
        health = tproxy.route_health_snapshot()[tproxy.SERVICE_YOUTUBE]
        assert health["state"] == tproxy.HEALTH_OK
        assert health["last_host"] == "redirector.googlevideo.com"
    finally:
        tproxy._strat_cache.clear()
        tproxy._route_health[tproxy.SERVICE_YOUTUBE] = original
        q = tproxy._route_failure_windows[tproxy.SERVICE_YOUTUBE]
        q.clear()
        q.extend(original_window)


def test_geo_exit_canary_failure_does_not_promote_to_local_bypass(monkeypatch):
    monkeypatch.setattr(tproxy, "smart_dns_available", lambda: False)
    monkeypatch.setattr(tproxy, "_geph_up", False)

    spec = {"group": tproxy.SERVICE_OPENAI, "host": "billing.openai.com"}
    assert not asyncio.run(tproxy._run_geo_exit_canary(spec))

    assert tproxy.geph_route("billing.openai.com")
    health = tproxy.route_health_snapshot()[tproxy.SERVICE_OPENAI]
    assert health["state"] == tproxy.HEALTH_BLOCKED
    assert health["last_route_class"] == tproxy.ROUTE_GEO_EXIT


def test_geo_exit_canary_success_clears_stale_geph_failure(monkeypatch):
    original = dict(tproxy._route_health[tproxy.SERVICE_OPENAI])
    original_failure = dict(tproxy._geph_last_failure)

    class DummyWriter:
        def close(self):
            pass

    async def connected(host, port, first_flight):
        return object(), DummyWriter()

    try:
        monkeypatch.setattr(tproxy, "smart_dns_available", lambda: False)
        monkeypatch.setattr(tproxy, "_geph_up", True)
        monkeypatch.setattr(tproxy, "dial_via_geph", connected)
        tproxy._geph_last_failure.update({
            "host": "chatgpt.com",
            "reason": "tunnel down",
            "ts": 100.0,
        })

        spec = {"group": tproxy.SERVICE_OPENAI, "host": "chatgpt.com"}
        assert asyncio.run(tproxy._run_geo_exit_canary(spec))

        assert tproxy._geph_last_failure == {"host": "", "reason": "", "ts": 0.0}
    finally:
        tproxy._route_health[tproxy.SERVICE_OPENAI] = original
        tproxy._geph_last_failure.update(original_failure)


def test_geo_exit_canary_uses_smart_dns_before_geph(monkeypatch):
    original = dict(tproxy._route_health[tproxy.SERVICE_OPENAI])

    class DummyWriter:
        def close(self):
            pass

    async def system_ips(host):
        assert host == "chatgpt.com"
        return ["203.0.113.10"]

    async def smart_probe(ip, port, first_flight, probe_timeout=3.0):
        assert (ip, port) == ("203.0.113.10", 443)
        return object(), DummyWriter(), b"\x16\x03\x03"

    async def geph_should_not_run(host, port, first_flight):
        raise AssertionError("Geph should not run after Smart DNS succeeds")

    try:
        monkeypatch.setattr(
            tproxy,
            "current_system_dns_status",
            lambda now=None: {
                "state": "xbox_dns",
                "providers": "xbox_dns",
                "servers": ["111.88.96.50"],
                "managed_by_slipstream": False,
            },
        )
        monkeypatch.setattr(tproxy, "system_resolve_async", system_ips)
        monkeypatch.setattr(tproxy, "dial_and_probe", smart_probe)
        monkeypatch.setattr(tproxy, "dial_via_geph", geph_should_not_run)
        monkeypatch.setattr(tproxy, "_geph_up", False)

        spec = {"group": tproxy.SERVICE_OPENAI, "host": "chatgpt.com"}
        assert asyncio.run(tproxy._run_geo_exit_canary(spec))

        assert tproxy._smart_dns_ok_until[tproxy.SERVICE_OPENAI] > 0
        health = tproxy.route_health_snapshot()[tproxy.SERVICE_OPENAI]
        assert health["state"] == tproxy.HEALTH_OK
        assert health["last_backend"] == tproxy.GEO_BACKEND_SMART_DNS
    finally:
        tproxy._route_health[tproxy.SERVICE_OPENAI] = original


def test_geo_exit_canary_falls_back_to_geph_when_smart_dns_fails(monkeypatch):
    original = dict(tproxy._route_health[tproxy.SERVICE_OPENAI])

    class DummyWriter:
        def close(self):
            pass

    async def system_ips(host):
        return ["203.0.113.10"]

    async def smart_probe(ip, port, first_flight, probe_timeout=3.0):
        return None

    async def geph_connect(host, port, first_flight):
        return object(), DummyWriter()

    try:
        monkeypatch.setattr(
            tproxy,
            "current_system_dns_status",
            lambda now=None: {
                "state": "xbox_dns",
                "providers": "xbox_dns",
                "servers": ["111.88.96.50"],
                "managed_by_slipstream": False,
            },
        )
        monkeypatch.setattr(tproxy, "system_resolve_async", system_ips)
        monkeypatch.setattr(tproxy, "dial_and_probe", smart_probe)
        monkeypatch.setattr(tproxy, "dial_via_geph", geph_connect)
        monkeypatch.setattr(tproxy, "_geph_up", True)

        spec = {"group": tproxy.SERVICE_OPENAI, "host": "chatgpt.com"}
        assert asyncio.run(tproxy._run_geo_exit_canary(spec))

        assert tproxy.SERVICE_OPENAI not in tproxy._smart_dns_ok_until
        assert tproxy._smart_dns_last_failure["host"] == "chatgpt.com"
        health = tproxy.route_health_snapshot()[tproxy.SERVICE_OPENAI]
        assert health["state"] == tproxy.HEALTH_OK
        assert health["last_backend"] == tproxy.GEO_BACKEND_GEPH
    finally:
        tproxy._route_health[tproxy.SERVICE_OPENAI] = original


def test_steam_store_canary_skips_smart_dns_and_uses_geph(monkeypatch):
    original = dict(tproxy._route_health[tproxy.SERVICE_STEAM_STORE])

    class DummyWriter:
        def close(self):
            pass

    async def smart_should_not_run(spec):
        raise AssertionError("Steam Store should not use Smart DNS")

    async def geph_connect(host, port, first_flight):
        assert host == "store.steampowered.com"
        assert port == 443
        return object(), DummyWriter()

    try:
        monkeypatch.setattr(tproxy, "smart_dns_available", lambda: True)
        monkeypatch.setattr(tproxy, "_run_smart_dns_geo_canary", smart_should_not_run)
        monkeypatch.setattr(tproxy, "dial_via_geph", geph_connect)
        monkeypatch.setattr(tproxy, "_geph_up", True)

        spec = next(item for item in tproxy.CANARY_SPECS if item["name"] == "steam_store")
        assert asyncio.run(tproxy._run_geo_exit_canary(spec))

        health = tproxy.route_health_snapshot()[tproxy.SERVICE_STEAM_STORE]
        assert health["state"] == tproxy.HEALTH_OK
        assert health["last_backend"] == tproxy.GEO_BACKEND_GEPH
    finally:
        tproxy._route_health[tproxy.SERVICE_STEAM_STORE] = original


def test_secondary_geo_exit_canary_failure_does_not_override_core_ok():
    original = dict(tproxy._route_health[tproxy.SERVICE_OPENAI])
    original_window = list(tproxy._route_failure_windows[tproxy.SERVICE_OPENAI])

    try:
        tproxy._route_failure_windows[tproxy.SERVICE_OPENAI].clear()
        tproxy.route_health_event(
            tproxy.SERVICE_OPENAI,
            tproxy.ROUTE_GEO_EXIT,
            "chatgpt.com",
            ok=True,
            now=100.0,
        )
        tproxy.route_health_event(
            tproxy.SERVICE_OPENAI,
            tproxy.ROUTE_GEO_EXIT,
            "billing.openai.com",
            ok=False,
            reason="SOCKS connect failed",
            soft=True,
            now=110.0,
        )

        health = tproxy.route_health_snapshot(now=110.0)[tproxy.SERVICE_OPENAI]
        assert health["state"] == tproxy.HEALTH_OK
        assert health["last_failure"] == ""
        assert health["last_warning"] == "SOCKS connect failed"
        assert health["last_warning_host"] == "billing.openai.com"
        assert health["failures_5m"] == 0
        assert health["last_host"] == "chatgpt.com"

        tproxy.route_health_event(
            tproxy.SERVICE_OPENAI,
            tproxy.ROUTE_GEO_EXIT,
            "chatgpt.com",
            ok=False,
            reason="SOCKS connect failed",
            now=115.0,
        )
        health = tproxy.route_health_snapshot(now=115.0)[tproxy.SERVICE_OPENAI]
        assert health["state"] == tproxy.HEALTH_DEGRADED
        assert health["last_failure"] == "SOCKS connect failed"

        health = tproxy.route_health_snapshot(now=500.0)[tproxy.SERVICE_OPENAI]
        assert health["state"] == tproxy.HEALTH_UNKNOWN
        assert health["last_failure"] == ""
        assert health["failures_5m"] == 0

        tproxy.route_health_event(
            tproxy.SERVICE_OPENAI,
            tproxy.ROUTE_GEO_EXIT,
            "chatgpt.com",
            ok=False,
            reason="tunnel down",
            state=tproxy.HEALTH_BLOCKED,
            now=120.0,
        )
        health = tproxy.route_health_snapshot(now=120.0)[tproxy.SERVICE_OPENAI]
        assert health["state"] == tproxy.HEALTH_BLOCKED
        assert health["last_failure"] == "tunnel down"
    finally:
        tproxy._route_health[tproxy.SERVICE_OPENAI] = original
        q = tproxy._route_failure_windows[tproxy.SERVICE_OPENAI]
        q.clear()
        q.extend(original_window)


def test_canary_health_secondary_geo_warning_does_not_override_core_ok():
    original = dict(tproxy._route_health[tproxy.SERVICE_OPENAI])
    original_window = list(tproxy._route_failure_windows[tproxy.SERVICE_OPENAI])
    core = next(item for item in tproxy.CANARY_SPECS if item["name"] == "openai_core")
    billing = next(item for item in tproxy.CANARY_SPECS if item["name"] == "openai_billing")
    now = tproxy.time.time()

    try:
        tproxy._route_failure_windows[tproxy.SERVICE_OPENAI].clear()
        tproxy.canary_health_event(
            core,
            tproxy.ROUTE_GEO_EXIT,
            "chatgpt.com",
            ok=True,
            backend=tproxy.GEO_BACKEND_GEPH,
            now=now,
        )
        tproxy.canary_health_event(
            billing,
            tproxy.ROUTE_GEO_EXIT,
            "billing.openai.com",
            ok=False,
            reason="SOCKS connect failed",
            soft=True,
            now=now + 10.0,
        )

        checks = tproxy.canary_health_snapshot(now=now + 10.0)
        assert checks["openai_core"]["state"] == tproxy.HEALTH_OK
        assert checks["openai_billing"]["state"] == tproxy.HEALTH_UNKNOWN
        assert checks["openai_billing"]["last_warning"] == "SOCKS connect failed"

        health = tproxy.route_health_snapshot(now=now + 10.0)[tproxy.SERVICE_OPENAI]
        assert health["state"] == tproxy.HEALTH_OK
        assert health["last_host"] == "chatgpt.com"
        assert health["last_failure"] == ""
        assert health["last_warning"] == "SOCKS connect failed"
        assert health["last_warning_host"] == "billing.openai.com"
    finally:
        tproxy._route_health[tproxy.SERVICE_OPENAI] = original
        q = tproxy._route_failure_windows[tproxy.SERVICE_OPENAI]
        q.clear()
        q.extend(original_window)


def test_soft_geo_exit_canary_counts_warning_not_degraded(monkeypatch):
    original = dict(tproxy._route_health[tproxy.SERVICE_OPENAI])
    original_window = list(tproxy._route_failure_windows[tproxy.SERVICE_OPENAI])
    original_state = dict(tproxy._canary_state)

    async def no_connect(host, port, first_flight):
        return None

    try:
        monkeypatch.setattr(tproxy, "smart_dns_available", lambda: False)
        tproxy._route_health[tproxy.SERVICE_OPENAI] = tproxy._route_health_default(
            tproxy.SERVICE_OPENAI,
            tproxy.ROUTE_GEO_EXIT,
        )
        tproxy._route_failure_windows[tproxy.SERVICE_OPENAI].clear()
        monkeypatch.setattr(tproxy, "_geph_up", True)
        monkeypatch.setattr(tproxy, "dial_via_geph", no_connect)
        monkeypatch.setattr(tproxy, "CANARY_SPECS", (
            {
                "name": "openai_billing",
                "group": tproxy.SERVICE_OPENAI,
                "host": "billing.openai.com",
                "soft": True,
            },
        ))

        ok, degraded = asyncio.run(tproxy.run_route_canaries("test"))

        assert (ok, degraded) == (0, 0)
        assert tproxy._canary_state["degraded"] == 0
        assert tproxy._canary_state["warnings"] == 1
        assert tproxy.canary_status_snapshot()["warnings"] == 1
        health = tproxy.route_health_snapshot()[tproxy.SERVICE_OPENAI]
        assert health["state"] == tproxy.HEALTH_UNKNOWN
        assert health["last_warning"] == "SOCKS connect failed"
        assert health["failures_5m"] == 0
    finally:
        tproxy._canary_state.clear()
        tproxy._canary_state.update(original_state)
        tproxy._route_health[tproxy.SERVICE_OPENAI] = original
        q = tproxy._route_failure_windows[tproxy.SERVICE_OPENAI]
        q.clear()
        q.extend(original_window)


def test_runtime_geo_exit_failures_require_repeated_signal():
    original = dict(tproxy._route_health[tproxy.SERVICE_OPENAI])
    original_window = list(tproxy._route_failure_windows[tproxy.SERVICE_OPENAI])

    try:
        tproxy._route_failure_windows[tproxy.SERVICE_OPENAI].clear()
        tproxy.route_health_event(
            tproxy.SERVICE_OPENAI,
            tproxy.ROUTE_GEO_EXIT,
            "chatgpt.com",
            ok=True,
            now=100.0,
        )

        for i, now in enumerate((110.0, 120.0), start=1):
            tproxy.route_health_event(
                tproxy.SERVICE_OPENAI,
                tproxy.ROUTE_GEO_EXIT,
                "persistent.oaistatic.com",
                ok=False,
                reason="remote closed without response",
                degrade_after=tproxy.GEO_EXIT_RUNTIME_DEGRADE_AFTER,
                now=now,
            )
            health = tproxy.route_health_snapshot(now=now)[tproxy.SERVICE_OPENAI]
            assert health["state"] == tproxy.HEALTH_OK
            assert health["last_failure"] == ""
            assert health["last_warning"] == "remote closed without response"
            assert health["last_warning_host"] == "persistent.oaistatic.com"
            assert health["failures_5m"] == i
            assert health["last_host"] == "chatgpt.com"

        tproxy.route_health_event(
            tproxy.SERVICE_OPENAI,
            tproxy.ROUTE_GEO_EXIT,
            "persistent.oaistatic.com",
            ok=False,
            reason="remote closed without response",
            degrade_after=tproxy.GEO_EXIT_RUNTIME_DEGRADE_AFTER,
            now=130.0,
        )
        health = tproxy.route_health_snapshot(now=130.0)[tproxy.SERVICE_OPENAI]
        assert health["state"] == tproxy.HEALTH_DEGRADED
        assert health["last_failure"] == "remote closed without response"
        assert health["failures_5m"] == tproxy.GEO_EXIT_RUNTIME_DEGRADE_AFTER
        assert health["last_host"] == "persistent.oaistatic.com"
    finally:
        tproxy._route_health[tproxy.SERVICE_OPENAI] = original
        q = tproxy._route_failure_windows[tproxy.SERVICE_OPENAI]
        q.clear()
        q.extend(original_window)


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


def test_local_strategy_score_demotes_failed_cached_fake_strategy():
    host = "gateway.discord.gg"
    tproxy._strat_cache.clear()
    tproxy._strat_cache[host] = "split64+fake"

    try:
        tproxy._record_strategy_result(host, "split64+fake", False, now=100.0)
        names = [s["name"] for s in tproxy.strategy_order(host)]

        assert names == ["split16+fake", "fake5", "split64+fake"]
    finally:
        tproxy._strat_cache.clear()
        tproxy._strat_scores.clear()


def test_local_strategy_score_keeps_successful_cached_fake_strategy_first():
    host = "gateway.discord.gg"
    tproxy._strat_cache.clear()
    tproxy._strat_cache[host] = "split64+fake"

    try:
        tproxy._record_strategy_result(host, "split64+fake", True, now=100.0)
        names = [s["name"] for s in tproxy.strategy_order(host)]

        assert names == ["split64+fake", "split16+fake", "fake5"]
    finally:
        tproxy._strat_cache.clear()
        tproxy._strat_scores.clear()


def test_clear_route_strategy_cache_removes_strategy_scores():
    host = "gateway.discord.gg"
    tproxy._strat_cache.clear()
    tproxy._strat_cache[host] = "split64+fake"
    tproxy._record_strategy_result(host, "split64+fake", False, now=100.0)

    try:
        assert tproxy.clear_route_strategy_cache(host=host) == 1

        assert host not in tproxy._strat_cache
        assert host not in tproxy._strat_scores
    finally:
        tproxy._strat_cache.clear()
        tproxy._strat_scores.clear()


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
    assert not tproxy.geph_route("status.discordstatus.com")
    assert not tproxy.geph_route("cdn.discordapp.com")
    assert not tproxy.geph_route("discord-activities.com")


def test_geph_route_failure_log_is_rate_limited(capsys):
    tproxy._geph_fail_log.clear()

    try:
        tproxy.log_geph_route_failure("billing.openai.com", "SOCKS connect failed", now=10.0)
        tproxy.log_geph_route_failure("billing.openai.com", "SOCKS connect failed", now=20.0)
        tproxy.log_geph_route_failure(
            "billing.openai.com", "remote closed without response", now=30.0
        )
        tproxy.log_geph_route_failure("billing.openai.com", "SOCKS connect failed", now=71.0)

        err = capsys.readouterr().err
        assert err.count("billing.openai.com") == 3
        assert "SOCKS connect failed" in err
        assert "remote closed without response" in err
    finally:
        tproxy._geph_fail_log.clear()


def test_local_bypass_hosts_ignore_stale_auto_geph_cache():
    tproxy._auto_geph.clear()
    tproxy._auto_geph["updates.discord.com"] = tproxy.time.time() + 3600
    tproxy._auto_geph["rr2---sn-ntq7yner.googlevideo.com"] = tproxy.time.time() + 3600

    try:
        assert not tproxy.geph_route("updates.discord.com")
        assert not tproxy.geph_route("rr2---sn-ntq7yner.googlevideo.com")
    finally:
        tproxy._auto_geph.clear()


def test_auto_geph_candidate_allows_only_unknown_hosts():
    assert tproxy._auto_geph_candidate_allowed("payments.example.com")

    assert not tproxy._auto_geph_candidate_allowed("updates.discord.com")
    assert not tproxy._auto_geph_candidate_allowed("rr2---sn-ntq7yner.googlevideo.com")
    assert not tproxy._auto_geph_candidate_allowed("t.me")
    assert not tproxy._auto_geph_candidate_allowed("vk.com")
    assert not tproxy._auto_geph_candidate_allowed("chatgpt.com")
    assert not tproxy._auto_geph_candidate_allowed("kubernetes.io")


def test_auto_geph_learns_exact_host_after_local_stalls_and_geph_payload(monkeypatch):
    saves = []

    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_payload_probe", lambda host: 128)
    monkeypatch.setattr(tproxy, "save_auto_geph", lambda: saves.append(True))

    for idx in range(tproxy.AUTO_GEPH_STORM - 1):
        tproxy.note_local_result(
            "payments.example.com",
            down_bytes=100,
            duration=tproxy.AUTO_GEPH_HANG + 1,
            now=100.0 + idx,
            confirmation_runner=tproxy._confirm_auto_geph,
        )
        assert not tproxy.geph_route("payments.example.com")

    tproxy.note_local_result(
        "payments.example.com",
        down_bytes=100,
        duration=tproxy.AUTO_GEPH_HANG + 1,
        now=120.0,
        confirmation_runner=tproxy._confirm_auto_geph,
    )

    assert tproxy.geph_route("payments.example.com")
    assert not tproxy.geph_route("example.com")
    assert saves
    snap = tproxy.auto_geo_exit_status_snapshot()
    assert snap["last_state"] == "learned"
    assert snap["last_host"] == "payments.example.com"
    assert snap["last_bytes"] == 128


def test_auto_geph_requires_geph_payload_proof(monkeypatch):
    monkeypatch.setattr(tproxy, "_geph_up", True)
    monkeypatch.setattr(tproxy, "_geph_payload_probe", lambda host: 0)
    monkeypatch.setattr(tproxy, "save_auto_geph", lambda: None)

    for idx in range(tproxy.AUTO_GEPH_STORM):
        tproxy.note_local_result(
            "payments.example.com",
            down_bytes=100,
            duration=tproxy.AUTO_GEPH_HANG + 1,
            now=100.0 + idx,
            confirmation_runner=tproxy._confirm_auto_geph,
        )

    assert not tproxy.geph_route("payments.example.com")
    snap = tproxy.auto_geo_exit_status_snapshot()
    assert snap["last_state"] == "rejected"
    assert snap["last_reason"] == "geph payload probe failed"


def test_auto_geph_network_wide_guard_blocks_learning(monkeypatch):
    calls = []
    monkeypatch.setattr(tproxy, "_geph_up", True)

    cutoff_base = 100.0
    for idx in range(tproxy.AUTO_GEPH_NET_BAD):
        tproxy._auto_fail[f"noisy-{idx}.example.com"] = [cutoff_base, cutoff_base + 1]

    for idx in range(tproxy.AUTO_GEPH_STORM):
        tproxy.note_local_result(
            "payments.example.com",
            down_bytes=100,
            duration=tproxy.AUTO_GEPH_HANG + 1,
            now=cutoff_base + 2 + idx,
            confirmation_runner=lambda host: calls.append(host),
        )

    assert calls == []
    assert not tproxy.geph_route("payments.example.com")


def test_auto_geph_prunes_expired_learned_hosts(monkeypatch):
    saves = []
    tproxy._auto_geph["old.example.com"] = 100.0
    tproxy._auto_geph["fresh.example.com"] = 300.0
    monkeypatch.setattr(tproxy, "save_auto_geph", lambda: saves.append(True))

    snap = tproxy.auto_geo_exit_status_snapshot(now=200.0)

    assert "old.example.com" not in tproxy._auto_geph
    assert "fresh.example.com" in tproxy._auto_geph
    assert snap["learned"] == 1
    assert saves


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


def test_voice_bpf_includes_discord_setup_and_primary_ranges():
    bpf = tproxy._voice_bpf("10.0.0.2")

    assert "dst portrange 19294-19344" in bpf
    assert "dst portrange 50000-65535" in bpf
    assert "(dst portrange 19294-19344 or dst portrange 50000-65535)" in bpf


def test_voice_payload_gate_preserves_existing_primary_range():
    assert tproxy.should_prime_voice_payload(50000, b"unclassified")
    assert tproxy.should_prime_voice_payload(65535, b"")


def test_voice_payload_gate_requires_known_setup_payload_on_setup_range():
    assert tproxy.should_prime_voice_payload(19294, tproxy._fake_stun())
    assert tproxy.should_prime_voice_payload(19344, b"\x80\x78" + (b"\x00" * 10))

    assert not tproxy.should_prime_voice_payload(19294, b"unclassified")
    assert not tproxy.should_prime_voice_payload(19345, tproxy._fake_stun())


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


def test_rotating_log_writer_can_prefix_timestamps(tmp_path):
    log = tmp_path / "slipstream.log"
    writer = tproxy.RotatingLogWriter(
        str(log),
        max_bytes=1024,
        backups=1,
        timestamp=True,
        clock=lambda: 1783512000.0,
    )

    writer.write("alpha")
    writer.write("\n")
    writer.write("beta")
    writer.write(" continued\n")
    writer.flush()

    lines = log.read_text().splitlines()
    assert len(lines) == 2
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4} alpha$", lines[0])
    assert re.match(
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4} beta continued$",
        lines[1],
    )


def test_active_console_gid_uses_console_user_group(monkeypatch):
    class Stat:
        st_uid = 501

    class User:
        pw_gid = 20

    monkeypatch.setattr(tproxy.os, "stat", lambda path: Stat())
    monkeypatch.setattr(tproxy.pwd, "getpwuid", lambda uid: User())

    assert tproxy.active_console_gid() == 20


def test_active_console_gid_falls_back_to_root_group(monkeypatch):
    class Stat:
        st_uid = 0

    monkeypatch.setattr(tproxy.os, "stat", lambda path: Stat())

    assert tproxy.active_console_gid() == 0


def test_remove_obsolete_newsyslog_config(monkeypatch, tmp_path):
    conf = tmp_path / "dev.slipstream.tproxy.conf"
    conf.write_text("obsolete\n")
    monkeypatch.setattr(tproxy, "OBSOLETE_NEWSYSLOG_CONFIG_PATH", str(conf))

    tproxy.remove_obsolete_newsyslog_config()
    tproxy.remove_obsolete_newsyslog_config()

    assert not conf.exists()
