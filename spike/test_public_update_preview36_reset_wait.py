"""Hermetic preview36 reset waiting: fake clocks and HTTP responses only."""
from datetime import datetime, timezone
from email.message import Message
from email.utils import format_datetime
import io
import json
from pathlib import Path
import subprocess
import sys
import urllib.error

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import public_update_preview36_menu_smoke as menu

EPOCH = 1795160000


def http_date(value):
    return format_datetime(datetime.fromtimestamp(value, timezone.utc), usegmt=True)


class Clock:
    def __init__(self):
        self.wall, self.mono = float(EPOCH), 100.0
        self.sleeps = []
        self.sleep_adjustment = 0
        self.wall_adjustment = 0

    def time(self):
        return self.wall

    def monotonic(self):
        return self.mono

    def advance(self, seconds):
        self.wall += seconds
        self.mono += seconds

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.advance(seconds + self.sleep_adjustment)
        self.wall += self.wall_adjustment


class Response:
    def __init__(self, status=403, *, reset=EPOCH + 8, remaining=None, date=EPOCH, retry=None):
        self.status = status
        self.headers = Message()
        for name, value in {"Date": http_date(date), "X-RateLimit-Limit": "60",
                            "X-RateLimit-Remaining": str(20 if status == 200 else 0)
                            if remaining is None else remaining,
                            "X-RateLimit-Reset": str(reset)}.items():
            self.headers[name] = value
        if retry is not None:
            self.headers["Retry-After"] = retry
        self.body = b'[]' if status == 200 else b'{"message":"API rate limit exceeded"}'

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def read(self, bound):
        assert bound == 256 * 1024 + 1
        return self.body[:bound]


class Opener:
    def __init__(self, clock, responses, durations=None):
        self.clock, self.responses = clock, responses
        self.durations = durations or [0] * len(responses)
        self.calls = []

    def open(self, request, *, timeout):
        assert len(self.calls) < len(self.responses), "unexpected additional probe"
        assert request.full_url == menu.DISCOVERY_URL and timeout == 5
        assert {k.lower(): v for k, v in request.header_items()} == {
            k.lower(): v for k, v in menu.DISCOVERY_HEADERS.items()}
        self.calls.append((self.clock.time(), self.clock.monotonic()))
        index = len(self.calls) - 1
        self.clock.advance(self.durations[index])
        response = self.responses[index]
        if isinstance(response, Exception):
            raise response
        if response.status >= 400:
            raise urllib.error.HTTPError(request.full_url, response.status, "failure", response.headers,
                                         io.BytesIO(response.body))
        return response


@pytest.fixture
def clock(monkeypatch):
    value = Clock()
    monkeypatch.setattr(menu, "time", value)
    def forbidden(*_args, **_kwargs):
        pytest.fail("real transport/native execution forbidden")
    monkeypatch.setattr(menu.urllib.request, "build_opener", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    return value


def run(clock, responses, durations=None):
    opener = Opener(clock, responses, durations)
    report = menu.public_feed_admission_with_reset_wait(opener=opener)
    assert len(json.dumps(report).encode()) <= 16384
    assert report["schema_version"] == 2 and report["policy"] == "one_near_reset_v1"
    assert report["requests_attempted"] == len(opener.calls) == len(report["samples"]) <= 2
    assert report["authenticated"] is report["redirects_followed"] is False
    assert report["future_request_availability_guaranteed"] is False
    return report, opener


@pytest.mark.parametrize("status", [403, 429])
def test_eight_second_reset_preserves_original_sample_and_waits_before_second(clock, status):
    original = menu.public_feed_admission(opener=Opener(clock, [Response(status)]))
    report, opener = run(clock, [Response(status), Response(200, date=EPOCH + 9)])
    assert report["samples"][0] == original
    assert report["admitted"] and report["classification"] == "ready"
    assert clock.sleeps == [9]
    assert opener.calls == [(EPOCH, 100), (EPOCH + 9, 109)]
    wait = report["reset_wait"]
    assert wait["target_unix"] == EPOCH + 9 and wait["requested_seconds"] == wait["elapsed_seconds"] == 9
    assert wait["completed"] is True and wait["refusal_reason"] is None


def test_already_ready_uses_one_probe_and_no_date_requirement(clock):
    response = Response(200)
    del response.headers["Date"]
    report, opener = run(clock, [response])
    assert report["admitted"] and len(opener.calls) == 1
    assert report["reset_wait"] is None and clock.sleeps == []


@pytest.mark.parametrize("case", ["generic403", "noreset", "baddate", "nodate", "duplicatedate",
    "badretry", "duplicateretry", "duplicatereset", "longreset", "longretry", "staledate",
    "futuredate", "pastreset", "negativequota", "network", "readyzero"])
def test_untrusted_or_unrelated_failure_never_waits_or_retries(clock, case):
    response = Response()
    if case == "generic403":
        response.headers.replace_header("X-RateLimit-Remaining", "20")
    elif case == "noreset":
        del response.headers["X-RateLimit-Reset"]
    elif case == "baddate":
        response.headers.replace_header("Date", "not a date")
    elif case == "nodate":
        del response.headers["Date"]
    elif case == "duplicatedate":
        response.headers["Date"] = http_date(EPOCH)
    elif case == "badretry":
        response.headers["Retry-After"] = "-1"
    elif case == "duplicateretry":
        response.headers["Retry-After"] = "3"
        response.headers["Retry-After"] = "3"
    elif case == "duplicatereset":
        response.headers["X-RateLimit-Reset"] = str(EPOCH + 8)
    elif case == "longreset":
        response.headers.replace_header("X-RateLimit-Reset", str(EPOCH + 60))
    elif case == "longretry":
        response.headers["Retry-After"] = "61"
    elif case == "staledate":
        response.headers.replace_header("Date", http_date(EPOCH - 2))
    elif case == "futuredate":
        response.headers.replace_header("Date", http_date(EPOCH + 2))
    elif case == "pastreset":
        response.headers.replace_header("X-RateLimit-Reset", str(EPOCH - 1))
    elif case == "negativequota":
        response.headers.replace_header("X-RateLimit-Remaining", "-1")
    elif case == "network":
        response = TimeoutError("private detail")
    elif case == "readyzero":
        response = Response(200, remaining="0")
    report, opener = run(clock, [response])
    assert not report["admitted"] and len(opener.calls) == 1
    assert report["reset_wait"] is None and clock.sleeps == []


@pytest.mark.parametrize("retry,target", [("12", EPOCH + 14), (http_date(EPOCH + 15), EPOCH + 15)])
def test_retry_after_is_respected_including_response_duration(clock, retry, target):
    report, opener = run(clock, [Response(retry=retry), Response(200, date=target)], [2, 0])
    assert report["admitted"] and opener.calls[1][0] == target
    assert report["reset_wait"]["retry_after_unix"] == target
    assert report["reset_wait"]["requested_seconds"] == target - (EPOCH + 2)


def test_second_rate_limit_is_final_and_never_repeated(clock):
    report, opener = run(clock, [Response(), Response(403, reset=EPOCH + 17, date=EPOCH + 9)])
    assert not report["admitted"] and report["classification"] == "external_rate_limited"
    assert len(opener.calls) == 2 and clock.sleeps == [9]
    assert report["reset_wait"]["completed"] is True


@pytest.mark.parametrize("adjust,wall,reason", [(-1, 0, "wait_incomplete"), (3, 0, "late_wake"),
    (0, 2, "clock_changed"), (0, -2, "wait_incomplete")])
def test_invalid_wake_never_permits_second_probe(clock, adjust, wall, reason):
    clock.sleep_adjustment, clock.wall_adjustment = adjust, wall
    report, opener = run(clock, [Response()])
    assert not report["admitted"] and len(opener.calls) == 1
    assert report["reset_wait"]["completed"] is False
    assert report["reset_wait"]["refusal_reason"] == reason


def test_small_late_wake_is_bounded_and_never_early(clock):
    clock.sleep_adjustment = 0.5
    report, opener = run(clock, [Response(), Response(200, date=EPOCH + 9)])
    assert report["admitted"] and opener.calls[1][0] == EPOCH + 9.5
    assert report["reset_wait"]["elapsed_seconds"] == 9.5


@pytest.mark.parametrize("duration", [11, 70])
def test_expired_sample_and_overall_deadline_fail_closed(clock, duration):
    report, opener = run(clock, [Response(), Response(200, date=EPOCH + 9)], [0, duration])
    assert not report["admitted"] and report["classification"] == "external_unknown"
    assert report["samples"][1]["admitted"] is True  # Original report is never rewritten.
    assert len(opener.calls) == 2


def test_wait_reserves_full_second_sample_budget(clock):
    response = Response(reset=EPOCH + 69, date=EPOCH + 9)
    report, opener = run(clock, [response], [10])
    assert not report["admitted"] and len(opener.calls) == 1 and clock.sleeps == []


def test_late_wake_cannot_spend_reserved_second_sample_budget(clock):
    clock.sleep_adjustment = 1
    response = Response(reset=EPOCH + 64, date=EPOCH + 9)
    report, opener = run(clock, [response], [10])
    assert not report["admitted"] and len(opener.calls) == 1
    assert report["reset_wait"]["refusal_reason"] == "overall_deadline"


@pytest.mark.parametrize("jump,wall,reason", [(70, 0, "overall_deadline"), (0, 2, "clock_changed")])
def test_time_change_between_wake_validation_and_second_probe_refuses(clock, monkeypatch, jump, wall, reason):
    original = clock.monotonic
    reads_after_wake = 0
    def monotonic():
        nonlocal reads_after_wake
        if clock.sleeps:
            reads_after_wake += 1
            if reads_after_wake == 2:
                clock.advance(jump)
                clock.wall += wall
        return original()
    monkeypatch.setattr(clock, "monotonic", monotonic)
    report, opener = run(clock, [Response()])
    assert not report["admitted"] and len(opener.calls) == 1
    assert report["reset_wait"]["refusal_reason"] == reason


def test_rate_limit_headers_then_body_transport_error_never_retry(clock):
    class BrokenBody(io.BytesIO):
        def read(self, *_):
            raise TimeoutError("private detail")
    error = urllib.error.HTTPError(menu.DISCOVERY_URL, 403, "failure", Response().headers, BrokenBody())
    report, opener = run(clock, [error])
    assert not report["admitted"] and len(opener.calls) == 1 and clock.sleeps == []
    assert report["samples"][0]["error_type"] == "TimeoutError"
    assert report["reset_wait"] is None


def test_same_default_opener_and_transport_policy_for_both_calls(clock, monkeypatch):
    opener = Opener(clock, [Response(), Response(200, date=EPOCH + 9)])
    builds = []
    def build(*handlers):
        builds.append(handlers)
        return opener
    monkeypatch.setattr(menu.urllib.request, "build_opener", build)
    monkeypatch.setenv("GH_TOKEN", "must-not-be-used")
    monkeypatch.setenv("HTTPS_PROXY", "http://invalid.example")
    result = menu.public_feed_admission_with_reset_wait()
    assert result["admitted"] and len(builds) == 1 and len(opener.calls) == 2
    assert builds[0][0].proxies == {} and isinstance(builds[0][1], menu.NoRedirect)
