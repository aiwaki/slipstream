from types import SimpleNamespace

import install_guard


def _answer(ip):
    return (2, 1, 6, "", (ip, 443))


def test_resolve_candidates_is_bounded_ordered_and_ipv4_only():
    answers = {
        "one.example": [_answer("203.0.113.10"), _answer("203.0.113.10")],
        "two.example": [_answer("203.0.113.20")],
    }

    def resolver(host, *_args, **_kwargs):
        return answers[host]

    candidates = install_guard.resolve_candidates(
        (("one.example", "/one"), ("two.example", "/two")),
        resolver=resolver,
        max_candidates=2,
    )

    assert candidates == (
        install_guard.BaselineCandidate("one.example", "203.0.113.10", "/one"),
        install_guard.BaselineCandidate("two.example", "203.0.113.20", "/two"),
    )


def test_probe_https_requires_verified_http_payload():
    class Socket:
        def __init__(self, response):
            self.response = response
            self.request = b""

        def settimeout(self, _timeout):
            pass

        def sendall(self, request):
            self.request = request

        def recv(self, _size):
            response, self.response = self.response, b""
            return response

        def close(self):
            pass

    tls = Socket(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
    raw = Socket(b"")
    context = SimpleNamespace(
        wrap_socket=lambda supplied, server_hostname: (
            tls
            if supplied is raw and server_hostname == "example.com"
            else None
        )
    )
    candidate = install_guard.BaselineCandidate(
        "example.com", "203.0.113.10", "/health"
    )

    result = install_guard.probe_https(
        candidate,
        socket_factory=lambda address, timeout: (
            raw if address == (candidate.ip, 443) and timeout == 2.5 else None
        ),
        context_factory=lambda: context,
    )

    assert result.ok
    assert result.status_code == 403
    assert b"GET /health HTTP/1.1" in tls.request
    assert b"Host: example.com" in tls.request


def test_probe_https_rejects_tls_without_http_payload():
    class Socket:
        def settimeout(self, _timeout):
            pass

        def sendall(self, _request):
            pass

        def recv(self, _size):
            return b"not-http\r\n"

        def close(self):
            pass

    raw = Socket()
    tls = Socket()
    candidate = install_guard.BaselineCandidate(
        "example.com", "203.0.113.10", "/"
    )

    result = install_guard.probe_https(
        candidate,
        socket_factory=lambda *_args, **_kwargs: raw,
        context_factory=lambda: SimpleNamespace(
            wrap_socket=lambda *_args, **_kwargs: tls
        ),
    )

    assert not result.ok
    assert result.reason == "no_http_response"


def test_probe_https_rejects_control_characters_before_opening_a_socket():
    candidate = install_guard.BaselineCandidate(
        "example.com", "203.0.113.10", "/\r\nInjected: true"
    )

    result = install_guard.probe_https(
        candidate,
        socket_factory=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("invalid input must not open a socket")
        ),
    )

    assert not result.ok
    assert result.reason == "invalid_candidate"


def test_post_arm_reuses_only_candidates_proven_before_arm():
    candidates = (
        install_guard.BaselineCandidate("one.example", "203.0.113.10", "/"),
        install_guard.BaselineCandidate("two.example", "203.0.113.20", "/"),
    )
    preflight_calls = []

    def preflight(candidate):
        preflight_calls.append(candidate)
        return install_guard.ProbeResult(candidate == candidates[1], "fixture")

    result = install_guard.qualify_before_arm(
        preflight,
        resolver=lambda host, *_args, **_kwargs: [
            _answer("203.0.113.10" if host == "one.example" else "203.0.113.20")
        ],
        targets=(("one.example", "/"), ("two.example", "/")),
    )
    postflight_calls = []
    postflight = install_guard.qualify_after_arm(
        result.candidates,
        lambda candidate: (
            postflight_calls.append(candidate)
            or install_guard.ProbeResult(True, "ok")
        ),
    )

    assert result.ok
    assert result.candidates == (candidates[1],)
    assert postflight.ok
    assert postflight_calls == [candidates[1]]
