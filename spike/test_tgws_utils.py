import sys
import ssl
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "vendor" / "tg-ws-proxy"))

from proxy import utils


def test_log_limited_summarizes_suppressed_messages(monkeypatch):
    calls = []
    clock = {"now": 100.0}
    monkeypatch.setattr(utils.time, "monotonic", lambda: clock["now"])
    utils._LIMITED_LOG_EVENTS.clear()

    def log_method(message, *args):
        calls.append(message % args if args else message)

    utils.log_limited(log_method, "noise", "failed: %s", "first", interval=10.0)
    clock["now"] = 101.0
    utils.log_limited(log_method, "noise", "failed: %s", "second", interval=10.0)
    clock["now"] = 111.0
    utils.log_limited(log_method, "noise", "failed: %s", "third", interval=10.0)

    assert calls == [
        "failed: first",
        "failed: third (suppressed 1 similar messages)",
    ]


def test_upstream_tls_contexts_verify_chains_and_default_hostname():
    # Fronting needs a distinct HTTP hostname; it must still authenticate the
    # certificate chain, as the updated upstream does for both TLS contexts.
    ordinary = utils.create_ssl_context()
    fronted = utils.create_ssl_context(check_hostname=False)
    assert ordinary.check_hostname and not fronted.check_hostname
    assert ordinary.verify_mode == fronted.verify_mode == ssl.CERT_REQUIRED
    assert ordinary.get_ca_certs() and fronted.get_ca_certs()
