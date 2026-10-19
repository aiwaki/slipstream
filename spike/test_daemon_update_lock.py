"""Real descriptor lifetime, with disposable files and Python children only."""
import fcntl
from pathlib import Path
import subprocess
import sys
import time

import pytest


CHILD = r"""
from pathlib import Path
import sys, time
ready, release, finished = map(Path, sys.argv[1:])
ready.write_text('ready')
deadline = time.monotonic() + 10
while not release.exists() and time.monotonic() < deadline:
    time.sleep(0.01)
finished.write_text('finished')
"""

OWNER = r"""
import fcntl, os, sys
import tproxy
lock, child, ready, release, finished, inherit = sys.argv[1:]
fd = os.open(lock, os.O_RDWR)
fcntl.flock(fd, fcntl.LOCK_EX)
tproxy._INSTALL_OPERATION_LOCK_FD = fd if inherit == '1' else None
result = tproxy._run(sys.executable, '-c', child, ready, release, finished)
raise SystemExit(result.returncode)
"""


def wait_for(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


@pytest.mark.parametrize("inherit", [True, False], ids=["inherited-lock", "negative-control"])
def test_installer_child_lock_survives_parent_crash_only_when_inherited(tmp_path, inherit):
    """A dead worker is not permission to race its still-running native child."""
    lock = tmp_path / "installer.lock"
    lock.touch(mode=0o600)
    ready, release, finished = [tmp_path / name for name in ("ready", "release", "finished")]
    with lock.open("r+") as contender:
        owner = subprocess.Popen(
            [sys.executable, "-c", OWNER, str(lock), CHILD,
             str(ready), str(release), str(finished), "1" if inherit else "0"],
            cwd=Path(__file__).resolve().parent,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        try:
            assert wait_for(ready.exists), "the disposable installer child did not start"
            owner.kill()
            owner.wait(timeout=3)
            try:
                fcntl.flock(contender.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                held = True
            else:
                fcntl.flock(contender.fileno(), fcntl.LOCK_UN)
                held = False
            assert held == inherit, "lock ownership after parent exit did not match child inheritance"

            release.touch()
            assert wait_for(finished.exists), "the disposable installer child did not finish"

            def acquire_after_child_exit():
                try:
                    fcntl.flock(contender.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    return False
                fcntl.flock(contender.fileno(), fcntl.LOCK_UN)
                return True

            assert wait_for(acquire_after_child_exit), "the exited child retained installer ownership"
        finally:
            release.touch(exist_ok=True)
            if owner.poll() is None:
                owner.kill()
            owner.wait(timeout=3)
            if owner.stderr is not None:
                owner.stderr.close()
