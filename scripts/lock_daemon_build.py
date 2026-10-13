"""Hold one checkout's daemon freeze/staging lock across shell exec and children."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
import stat
import sys

LOCK_FD_ENV = "SLIPSTREAM_DAEMON_BUILD_LOCK_FD"


def require_lock_identity(fd: int, path: Path) -> None:
    opened = os.fstat(fd)
    named = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(named.st_mode)
        or opened.st_uid != os.getuid()
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
    ):
        raise RuntimeError("daemon build lock identity differs from this checkout")


def main() -> None:
    # Both public entry points use the same file; build_and_stage nests the
    # lower-level freeze while retaining the same open file description.
    mode, repo, *command = sys.argv[1:]
    path = Path(repo).resolve() / "spike/.daemon-build.lock"
    if mode == "--verify-held":
        fd = int(os.environ[LOCK_FD_ENV])
        require_lock_identity(fd, path)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return
    if mode != "--exec" or not command:
        raise ValueError("expected --exec REPO COMMAND or --verify-held REPO")
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    require_lock_identity(fd, path)
    fcntl.flock(fd, fcntl.LOCK_EX)
    # Do not unlink the lock file: a waiter already owns its inode. exec avoids
    # an unlocked orphan child if a separate Python supervisor were killed.
    os.set_inheritable(fd, True)
    environment = dict(os.environ, **{LOCK_FD_ENV: str(fd)})
    os.execvpe(command[0], command, environment)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        raise SystemExit(f"Cannot own daemon build lock: {error}") from error
