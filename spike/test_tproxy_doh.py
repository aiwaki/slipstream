import ssl
import logging

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
