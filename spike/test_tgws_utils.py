import sys
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
