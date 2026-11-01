import sys
import ssl
from pathlib import Path

import pytest


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


@pytest.mark.parametrize("check_hostname", [True, False])
def test_frozen_tls_uses_bundle_ca_without_source_tree_fallback(tmp_path, monkeypatch, check_hostname):
    ca_bytes = Path(utils.certifi.where()).read_bytes()
    bundled_ca = tmp_path / "certifi" / "cacert.pem"
    bundled_ca.parent.mkdir()
    bundled_ca.write_bytes(ca_bytes)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)

    def source_tree_ca_is_unavailable():
        raise AssertionError("frozen daemon must use its bundled CA file")

    monkeypatch.setattr(utils.certifi, "where", source_tree_ca_is_unavailable)
    context = utils.create_ssl_context(check_hostname=check_hostname)
    assert context.check_hostname is check_hostname
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.get_ca_certs()


def test_frozen_tls_missing_bundle_ca_fails_instead_of_using_host_roots(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    with pytest.raises(FileNotFoundError):
        utils.create_ssl_context()
