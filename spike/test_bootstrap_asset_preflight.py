import json
import pickle

import pytest

from bootstrap_asset_preflight import (
    DEFAULT_RANGE_END,
    MAX_ASSET_URL_LENGTH,
    MAX_CRITICAL_ASSETS,
    EphemeralBootstrapAsset,
    RangeProbeEvidence,
    RangeProbeOutcome,
    classify_range_response,
    extract_critical_bootstrap_assets,
    inspect_range_response,
)


def _response(body, *, status="200 OK", headers=()):
    return (
        f"HTTP/1.1 {status}\r\n".encode()
        + b"Content-Type: text/html; charset=utf-8\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"\r\n".join(header.encode() for header in headers)
        + (b"\r\n" if headers else b"")
        + b"\r\n"
        + body
    )


def _assets(html, *, root="https://app.example/", **kwargs):
    return extract_critical_bootstrap_assets(
        root,
        _response(html.encode()),
        stream_closed=True,
        truncated=False,
        deadline=1.0,
        clock=lambda: 0.0,
        **kwargs,
    )


def _range_response(
    body,
    *,
    status="206 Partial Content",
    declared_length=None,
    content_range=None,
    extra_headers=(),
):
    if declared_length is None:
        declared_length = len(body)
    if content_range is None:
        content_range = f"bytes 0-{max(len(body) - 1, 0)}/{max(len(body), 1)}"
    headers = [
        "Content-Type: application/javascript",
        'ETag: "fixture-v1"',
        f"Content-Length: {declared_length}",
        f"Content-Range: {content_range}",
        *extra_headers,
    ]
    return (
        f"HTTP/1.1 {status}\r\n".encode()
        + b"\r\n".join(header.encode() for header in headers)
        + b"\r\n\r\n"
        + body
    )


def _classify(response, **kwargs):
    arguments = {
        "stream_closed": True,
        "idle_timed_out": False,
        "truncated": False,
        "deadline": 1.0,
        "clock": lambda: 0.0,
    }
    arguments.update(kwargs)
    return classify_range_response(response, **arguments)


def _inspect(response, **kwargs):
    arguments = {
        "stream_closed": True,
        "idle_timed_out": False,
        "truncated": False,
        "deadline": 1.0,
        "clock": lambda: 0.0,
    }
    arguments.update(kwargs)
    return inspect_range_response(response, **arguments)


def test_extracts_only_bounded_critical_javascript_targets_in_document_order():
    html = """
    <link rel="stylesheet" href="/not-critical.css">
    <link rel="modulepreload" href="//cdn.example/module.js?build=secret">
    <script type="application/ld+json" src="/data.json"></script>
    <script type="module" src="/entry.js"></script>
    <link rel="preload alternate" as="script" href="https://assets.example/pre.js">
    <script defer src="/classic.js"></script>
    <script src="/fifth.js"></script>
    """

    assets = _assets(html)

    assert len(assets) == MAX_CRITICAL_ASSETS
    assert [asset.exact_host for asset in assets] == [
        "cdn.example",
        "app.example",
        "assets.example",
        "app.example",
    ]
    request = assets[1].build_range_request()
    assert b"GET /entry.js HTTP/1.1" in request
    assert b"Range: bytes=0-65535" in request


def test_base_url_resolution_deduplicates_and_normalizes_unicode_targets():
    assets = _assets(
        """
        <base href="https://cdn.example/assets/">
        <script type="module" src="./модуль.js?версия=1"></script>
        <link rel="modulepreload" href="https://cdn.example/assets/%D0%BC%D0%BE%D0%B4%D1%83%D0%BB%D1%8C.js?%D0%B2%D0%B5%D1%80%D1%81%D0%B8%D1%8F=1">
        """
    )

    assert len(assets) == 1
    assert assets[0].exact_host == "cdn.example"
    request = assets[0].build_range_request()
    assert request.startswith(b"GET /assets/%D0%BC%D0%BE%D0%B4%D1%83%D0%BB%D1%8C.js?")
    assert b"Host: cdn.example\r\n" in request


def test_rejects_credentials_non_https_non_default_ports_and_oversized_urls():
    oversized = "https://cdn.example/" + "a" * MAX_ASSET_URL_LENGTH
    assets = _assets(
        f"""
        <script src="http://cdn.example/plain.js"></script>
        <script src="https://user:pass@cdn.example/private.js"></script>
        <script src="https://cdn.example:444/wrong-port.js"></script>
        <script src="{oversized}"></script>
        <script src="data:text/javascript,alert(1)"></script>
        <script src="/safe.js"></script>
        """
    )

    assert [asset.exact_host for asset in assets] == ["app.example"]
    assert b"GET /safe.js HTTP/1.1" in assets[0].build_range_request()


@pytest.mark.parametrize(
    ("root", "response_kwargs", "mutator"),
    [
        ("http://app.example/", {}, lambda response: response),
        ("https://app.example/path", {}, lambda response: response),
        ("https://user@app.example/", {}, lambda response: response),
        (
            "https://app.example/",
            {},
            lambda response: response.replace(b"text/html", b"application/json"),
        ),
        (
            "https://app.example/",
            {},
            lambda response: response.replace(
                b"Content-Type: text/html; charset=utf-8\r\n",
                b"Content-Type: text/html\r\nContent-Encoding: gzip\r\n",
            ),
        ),
    ],
)
def test_root_page_must_be_complete_bounded_identity_https_html(
    root, response_kwargs, mutator
):
    response = mutator(_response(b'<script src="/entry.js"></script>'))

    assert (
        extract_critical_bootstrap_assets(
            root,
            response,
            stream_closed=True,
            truncated=False,
            deadline=1.0,
            clock=lambda: 0.0,
            **response_kwargs,
        )
        == ()
    )


def test_partial_truncated_and_expired_root_pages_do_not_emit_targets():
    full = _response(b'<script src="/entry.js"></script>')

    assert extract_critical_bootstrap_assets(
        "https://app.example/",
        full[:-1],
        stream_closed=True,
        truncated=False,
        deadline=1.0,
        clock=lambda: 0.0,
    ) == ()
    assert extract_critical_bootstrap_assets(
        "https://app.example/",
        full,
        stream_closed=True,
        truncated=True,
        deadline=1.0,
        clock=lambda: 0.0,
    ) == ()
    assert extract_critical_bootstrap_assets(
        "https://app.example/",
        full,
        stream_closed=True,
        truncated=False,
        deadline=1.0,
        clock=lambda: 1.0,
    ) == ()


def test_ephemeral_target_cannot_be_serialized_or_leak_target_via_repr():
    (asset,) = _assets('<script src="/entry.js?account=private"></script>')

    assert isinstance(asset, EphemeralBootstrapAsset)
    assert "entry" not in repr(asset)
    assert "account" not in repr(asset)
    with pytest.raises(TypeError):
        vars(asset)
    with pytest.raises(TypeError):
        json.dumps(asset)
    with pytest.raises(TypeError, match="must not be serialized"):
        pickle.dumps(asset)

    request = asset.build_range_request(range_end=7)
    assert b"GET /entry.js?account=private HTTP/1.1" in request
    assert b"Range: bytes=0-7" in request
    assert "entry" not in repr(asset)
    with pytest.raises(RuntimeError, match="forgotten"):
        asset.build_range_request()


@pytest.mark.parametrize("range_end", [-1, MAX_ASSET_URL_LENGTH * 1_000, True, 1.5])
def test_range_request_is_strictly_bounded(range_end):
    (asset,) = _assets('<script src="/entry.js"></script>')

    with pytest.raises(ValueError):
        asset.build_range_request(range_end=range_end)


def test_only_complete_ranged_javascript_response_qualifies():
    partial_content = _range_response(
        b"javascript",
        content_range=f"bytes 0-9/{DEFAULT_RANGE_END + 10}",
    )

    assert _classify(partial_content) is RangeProbeOutcome.COMPLETE


@pytest.mark.parametrize(
    ("content_type", "body"),
    [
        ("text/html", b"<html>maintenance</html>"),
        ("application/json", b"{}"),
        ("application/javascript", b"javascript"),
    ],
)
def test_generic_200_never_proves_a_ranged_javascript_object(content_type, body):
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: "
        + content_type.encode()
        + b"\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\n\r\n"
        + body
    )

    assert _classify(response) is RangeProbeOutcome.UNKNOWN


def test_declared_body_shortfall_requires_eof_or_idle_timeout():
    partial = _range_response(
        b"short",
        declared_length=10,
        content_range="bytes 0-9/100",
    )

    assert _classify(partial) is RangeProbeOutcome.INCOMPLETE
    assert _classify(
        partial,
        stream_closed=False,
        idle_timed_out=True,
    ) is RangeProbeOutcome.INCOMPLETE
    assert _classify(
        partial,
        stream_closed=False,
        idle_timed_out=False,
    ) is RangeProbeOutcome.UNKNOWN
    assert _classify(partial, truncated=True) is RangeProbeOutcome.UNKNOWN


def test_direct_and_geph_evidence_must_bind_the_same_js_object():
    direct = _inspect(
        _range_response(
            b"x" * 2_048,
            declared_length=65_536,
            content_range="bytes 0-65535/1210087",
        ),
    )
    complete = _inspect(
        _range_response(
            b"x" * 65_536,
            content_range="bytes 0-65535/1210087",
        ),
    )
    other = _inspect(
        _range_response(
            b"y" * 65_536,
            content_range="bytes 0-65535/1210088",
        ),
    )

    assert isinstance(direct, RangeProbeEvidence)
    assert direct.outcome is RangeProbeOutcome.INCOMPLETE
    assert complete.outcome is RangeProbeOutcome.COMPLETE
    assert direct.proves_same_object_as(complete)
    assert not direct.proves_same_object_as(other)


def test_content_range_and_declared_framing_must_agree():
    short_but_framing_complete = _range_response(
        b"short",
        declared_length=5,
        content_range="bytes 0-9/100",
    )
    chunked_short = (
        b"HTTP/1.1 206 Partial Content\r\n"
        b"Content-Range: bytes 0-9/100\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
        b"5\r\nshort\r\n0\r\n\r\n"
    )

    assert _classify(short_but_framing_complete) is RangeProbeOutcome.UNKNOWN
    assert _classify(chunked_short) is RangeProbeOutcome.UNKNOWN


def test_chunked_range_delivery_is_framing_aware():
    headers = (
        b"HTTP/1.1 206 Partial Content\r\n"
        b"Content-Type: application/javascript\r\n"
        b'ETag: "fixture-v1"\r\n'
        b"Content-Range: bytes 0-4/100\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
    )
    complete = headers + b"5\r\nhello\r\n0\r\n\r\n"
    incomplete = headers + b"5\r\nhello\r\n"

    assert _classify(complete) is RangeProbeOutcome.COMPLETE
    assert _classify(incomplete) is RangeProbeOutcome.INCOMPLETE


@pytest.mark.parametrize(
    "response",
    [
        _range_response(b"denied", status="403 Forbidden"),
        _range_response(b"redirect", status="302 Found"),
        _range_response(b"body", content_range="bytes 1-4/100"),
        _range_response(b"body", content_range="bytes 0-999999/1000000"),
        _range_response(
            b"body",
            extra_headers=("Content-Encoding: gzip",),
        ),
        (
            b"HTTP/1.1 206 Partial Content\r\n"
            b"Content-Type: application/javascript\r\n"
            b"Content-Length: 4\r\n"
            b"Content-Range: bytes 0-3/"
            + (b"9" * 5_000)
            + b"\r\n\r\nbody"
        ),
        b"not-http",
    ],
)
def test_denial_redirect_malformed_range_and_compression_stay_unknown(response):
    assert _classify(response) is RangeProbeOutcome.UNKNOWN


def test_shared_deadline_prevents_late_complete_result():
    complete = _range_response(b"javascript", content_range="bytes 0-9/100")

    assert _classify(
        complete,
        deadline=1.0,
        clock=lambda: 1.0,
    ) is RangeProbeOutcome.DEADLINE_EXCEEDED
