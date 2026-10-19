"""Exercise the real directory validator against a hermetic macOS layout."""
import os
from pathlib import Path
import re
import stat
from types import SimpleNamespace

import pytest
import tproxy


@pytest.fixture
def macos_layout(monkeypatch):
    # /var/run is normally root:daemon 0775. It is not suitable ancestry
    # for a root-controlled protocol directory under the existing contract.
    nodes = {
        "/private": [0o755, 0, 0],
        "/private/var": [0o755, 0, 0],
        "/private/var/run": [0o775, 0, 1],
        "/private/var/db": [0o755, 0, 0],
        "/private/var/db/dev.slipstream-update": [0o755, 0, 0],
    }
    effects = []

    def canonical(path):
        value = os.fspath(path)
        return "/private" + value if value == "/var" or value.startswith("/var/") else value

    def lstat(path):
        mode, uid, gid = nodes[canonical(path)]
        return SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_uid=uid, st_gid=gid)

    def mkdir(path, mode):
        path = canonical(path)
        if path in nodes:
            raise FileExistsError(path)
        assert os.path.dirname(path) in nodes, "parent must already exist"
        nodes[path] = [mode, 0, 0]
        effects.append(("mkdir", path, mode))

    def chown(path, uid, gid):
        path = canonical(path)
        nodes[path][1:] = [uid, gid]
        effects.append(("chown", path, uid, gid))

    def chmod(path, mode):
        path = canonical(path)
        nodes[path][0] = mode
        effects.append(("chmod", path, mode))

    # Replace tproxy's OS boundary, not the validator. No real path is mutated.
    monkeypatch.setattr(tproxy, "os", SimpleNamespace(
        path=SimpleNamespace(realpath=canonical, dirname=os.path.dirname),
        lstat=lstat, mkdir=mkdir, chown=chown, chmod=chmod,
    ))
    monkeypatch.setattr(tproxy, "_update_sync_directory", lambda path: effects.append(("sync", path)))
    return nodes, effects


def test_production_mailbox_supports_standard_macos_ancestry(macos_layout):
    nodes, effects = macos_layout
    parent = tproxy._DAEMON_UPDATE_REQUESTS
    mailbox = parent + "/501-0123456789abcdef0123456789abcdef"
    tproxy._update_private_directory(parent, 0o755)
    tproxy._update_private_directory(mailbox, owner=501)
    assert nodes["/private" + parent] == [0o755, 0, 0]
    assert nodes["/private" + mailbox] == [0o700, 501, 0]
    assert nodes["/private/var/run"] == [0o775, 0, 1]
    previous = list(effects)
    tproxy._update_private_directory(parent, 0o755)
    tproxy._update_private_directory(mailbox, owner=501)
    assert effects == previous, "idempotent preparation must not change existing ownership"


def test_old_run_ancestry_is_still_rejected_before_any_mutation(macos_layout):
    _, effects = macos_layout
    with pytest.raises(RuntimeError, match="unsafe update directory ancestry"):
        tproxy._update_private_directory("/var/run/slipstream-update-requests", 0o755)
    assert effects == []


@pytest.mark.parametrize("mode,uid", [(0o775, 0), (0o777, 0), (0o755, 501)])
def test_new_mailbox_rejects_writable_or_foreign_ancestry(macos_layout, mode, uid):
    nodes, effects = macos_layout
    nodes["/private/var/db/dev.slipstream-update"] = [mode, uid, 0]
    with pytest.raises(RuntimeError, match="unsafe update directory ancestry"):
        tproxy._update_private_directory(tproxy._DAEMON_UPDATE_REQUESTS, 0o755)
    assert effects == []


def test_app_and_root_use_the_same_mailbox_location():
    source = (Path(__file__).resolve().parents[1] /
              "app-tauri/src-tauri/src/daemon_update.rs").read_text()
    rust_path = re.search(r'const REQUEST_BASE: &str = "([^"]+)";', source).group(1)
    assert rust_path == tproxy._DAEMON_UPDATE_REQUESTS
    assert Path(rust_path).parent == Path(tproxy._DAEMON_UPDATE_ROOT)
