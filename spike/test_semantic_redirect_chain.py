"""Bounded whole-page Geph confirmation; no network or routing mutations."""
import gzip
from collections import deque

import pytest
import tproxy


def reply(status, body=b"", extra=b""):
    return (f"HTTP/1.1 {status} Test\r\nContent-Length: {len(body)}\r\n".encode()
            + extra + b"\r\n" + body, False, False)


def redirect(location, status=302, body=b""):
    return reply(status, body, b"Location: " + location.encode() + b"\r\n")


def test_three_redirects_reach_full_large_compressed_document(monkeypatch):
    body = b"<html>" + b"x" * 413000 + b"</html>"
    responses = deque([
        redirect("https://example.com/", 301),
        redirect("https://example.com/locale/forecast?from=root"),
        redirect("/locale/city/today", 301, b"redirect body is not success"),
        reply(200, gzip.compress(body), b"Content-Encoding: gzip\r\n"),
    ])
    calls = []
    def probe(host, deadline, target="/"):
        calls.append((host, deadline, target))
        return responses.popleft()
    monkeypatch.setattr(tproxy, "_semantic_geph_root_response", probe)
    monkeypatch.setattr(tproxy.time, "monotonic", lambda: 0.0)
    assert tproxy._semantic_geph_payload_probe("www.example.com", timeout=6) == len(body)
    assert calls == [("www.example.com", 3.0, "/"), ("example.com", 6.0, "/"),
                     ("example.com", 6.0, "/locale/forecast?from=root"),
                     ("example.com", 6.0, "/locale/city/today")]
    assert not responses


@pytest.mark.parametrize("location", [
    "https://outside.example/path", "http://example.com/path", "//example.com/path",
    "https://user@example.com/path", "https://example.com:444/path", "/path#fragment",
    "relative/path", "/path with spaces", "/\\outside.example/", "/" + "x" * 2049,
])
def test_redirect_rejects_unbounded_or_ambiguous_target(location):
    assert tproxy._semantic_geph_redirect_target("example.com", redirect(location)[0]) is None


def test_duplicate_location_refused():
    data = reply(302, extra=b"Location: /a\r\nLocation: /b\r\n")[0]
    assert tproxy._semantic_geph_redirect_target("example.com", data) is None


@pytest.mark.parametrize("loop", [False, True])
def test_redirect_loop_or_fourth_hop_cannot_be_payload(monkeypatch, loop):
    calls = []
    def probe(host, deadline, target="/"):
        calls.append(target)
        return redirect("/" if loop else "/hop" + str(len(calls)), body=b"not payload")
    monkeypatch.setattr(tproxy, "_semantic_geph_root_response", probe)
    assert tproxy._semantic_geph_payload_probe("example.com") == 0
    assert len(calls) == (1 if loop else 4)


def test_redirect_does_not_extend_deadline(monkeypatch):
    now = [0.0]
    calls = []
    def probe(host, deadline, target="/"):
        calls.append(target)
        now[0] = 6.0
        return redirect("/next")
    monkeypatch.setattr(tproxy.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(tproxy, "_semantic_geph_root_response", probe)
    assert tproxy._semantic_geph_payload_probe("example.com", timeout=6) == 0
    assert calls == ["/"]


def test_decode_budget_is_geph_only_and_still_bounded():
    body = b"x" * 413000
    data, closed, truncated = reply(200, gzip.compress(body), b"Content-Encoding: gzip\r\n")
    assert tproxy._semantic_plain_response_observation(data).root_boundary.value == "decode_inconclusive"
    assert tproxy._semantic_geph_root_response_observation(data).payload_bytes == len(body)
    huge = reply(200, gzip.compress(b"x" * (tproxy.SEMANTIC_GEPH_DECODE_MAX_BYTES + 1)),
                 b"Content-Encoding: gzip\r\n")[0]
    assert tproxy._semantic_geph_root_response_observation(huge).root_boundary.value == "decode_inconclusive"


def test_request_keeps_server_path_out_of_host_and_uses_no_cookie():
    request = tproxy._semantic_geph_probe_request("example.com", request_target="/locale/today?q=1")
    assert request.startswith(b"GET /locale/today?q=1 HTTP/1.1\r\n")
    assert b"Host: example.com\r\n" in request
    assert b"Cookie:" not in request and b"Referer:" not in request
