"""Deterministic lazy-worker ordering, with virtual threads and no runtime I/O."""
import pytest

import pending_navigation_probe_runtime as runtime


class VirtualLock:
    """Dispatch one competing actor at a lock boundary, never start a thread."""
    def __init__(self):
        self.held = False
        self.before_enter = None
        self.after_release = None

    def __enter__(self):
        callback, self.before_enter = self.before_enter, None
        if callback is not None:
            callback()
        assert not self.held, "unexpected nested lifecycle lock"
        self.held = True
        return self

    def __exit__(self, *_error):
        assert self.held
        self.held = False
        callback, self.after_release = self.after_release, None
        if callback is not None:
            callback()


class VirtualThread:
    def __init__(self, *, target, name, daemon, events, start_error=None):
        assert name == "slipstream-browser-probe" and daemon is True
        self.target = target
        self.events = events
        self.start_error = start_error
        self.started = self.finished = False
        self.start_calls = self.join_calls = 0

    def start(self):
        self.start_calls += 1
        self.events.append("start")
        if self.start_error is not None:
            raise self.start_error
        assert not self.started
        self.started = True

    def run_target(self):
        assert self.started and not self.finished
        self.events.append("run")
        try:
            self.target()
        finally:
            self.finished = True

    def join(self, timeout):
        self.join_calls += 1
        self.events.append("join")
        assert timeout == runtime.IPC_TIMEOUT_SECONDS
        # Match Thread.join's documented pre-start refusal without real threads.
        if not self.started:
            raise RuntimeError("cannot join thread before it is started")
        if not self.finished:
            self.run_target()


class Fixture:
    def __init__(self, *, pending=1):
        self.pending = pending
        self.events, self.threads, self.launches, self.completed = [], [], [], []
        self.start_error = None
        self.lock = VirtualLock()
        self.worker = runtime.LazyPendingNavigationProbeWorker(
            pending_jobs=lambda: self.pending,
            launch_worker=self.launch,
            thread_factory=self.make_thread,
            worker_completed=self.completed.append,
        )
        self.worker._lock = self.lock

    def make_thread(self, **kwargs):
        thread = VirtualThread(**kwargs, events=self.events, start_error=self.start_error)
        self.threads.append(thread)
        return thread

    def launch(self):
        self.launches.append("launch")
        self.pending = 0
        return "fixture-owned-completion"


def test_close_at_thread_publication_never_joins_an_unstarted_thread():
    f = Fixture()
    outcomes = []
    def competing_close():
        assert len(f.threads) == 1 and f.worker._thread is f.threads[0]
        f.events.append("close")
        outcomes.append(f.worker.close())
    f.lock.after_release = competing_close

    assert f.worker.notify_job_ready() is True
    assert outcomes == [True]
    assert f.events == ["start", "close", "join", "run"]
    assert not f.worker.active() and f.worker._stop.is_set()
    assert f.launches == f.completed == []
    assert f.threads[0].finished and f.threads[0].join_calls == 1


def test_stop_between_fast_check_and_lock_acquisition_refuses_new_thread():
    f = Fixture()
    outcomes = []
    f.lock.before_enter = lambda: outcomes.append(f.worker.close())

    assert f.worker.notify_job_ready() is False
    assert outcomes == [True]
    assert f.threads == f.launches == f.completed == []
    assert not f.worker.active() and f.worker._stop.is_set()


def test_normal_lazy_start_coalesces_then_reports_confirmed_completion():
    f = Fixture(pending=0)
    assert f.worker.notify_job_ready() is False
    assert f.threads == []
    f.pending = 1
    assert f.worker.notify_job_ready() is True
    assert f.worker.active() and f.worker.notify_job_ready() is False
    assert len(f.threads) == 1 and f.threads[0].start_calls == 1
    f.threads[0].run_target()
    assert f.launches == ["launch"]
    assert f.completed == ["fixture-owned-completion"]
    assert not f.worker.active()
    assert f.worker.close() is True
    assert f.threads[0].join_calls == 0


def test_never_started_close_is_terminal_and_repeatable():
    f = Fixture()
    assert f.worker.close() is True
    assert f.worker.close() is True
    assert f.worker.notify_job_ready() is False
    assert f.threads == f.launches == f.completed == []


def test_repeated_close_joins_started_owner_once_and_does_not_launch():
    f = Fixture()
    assert f.worker.notify_job_ready() is True
    assert f.worker.close() is True
    assert f.worker.close() is True
    assert f.threads[0].join_calls == 1 and f.threads[0].finished
    assert f.launches == f.completed == []
    assert not f.worker.active()


@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt])
def test_start_failure_releases_only_its_thread_and_remains_retryable(error_type):
    f = Fixture()
    error = error_type("fixture-start-failed")
    f.start_error = error
    with pytest.raises(error_type) as caught:
        f.worker.notify_job_ready()
    assert caught.value is error
    assert not f.worker.active() and not f.worker._stop.is_set()
    assert len(f.threads) == 1 and not f.threads[0].started
    assert f.threads[0].join_calls == 0
    f.start_error = None
    assert f.worker.notify_job_ready() is True
    f.threads[1].run_target()
    assert f.launches == ["launch"] and f.completed == ["fixture-owned-completion"]
    assert f.worker.close() is True


def test_stop_before_virtual_target_runs_prevents_browser_launch():
    f = Fixture()
    assert f.worker.notify_job_ready() is True
    f.worker._stop.set()
    f.threads[0].run_target()
    assert not f.worker.active()
    assert f.launches == f.completed == []
    assert f.worker.close() is True
