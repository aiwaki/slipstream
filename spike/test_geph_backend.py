import ast
import json
import os
from pathlib import Path
from types import SimpleNamespace

import geph_backend


def result(returncode=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def ownership(pid=321, uid=502):
    return {
        "pid": pid,
        "uid": uid,
        "launchd_label": "dev.slipstream.geph",
        "executable": "/private/runtime/geph5-client",
        "config": "/private/runtime/geph-active.yaml",
    }


def test_ownership_path_stays_inside_user_application_support():
    assert geph_backend.ownership_path(
        "/Users/example", "geph-owned.json"
    ) == (
        "/Users/example/Library/Application Support/"
        "dev.slipstream.tray/geph-owned.json"
    )
    assert geph_backend.ownership_path("", "geph-owned.json") is None


def test_read_ownership_accepts_regular_json_and_rejects_symlink(tmp_path):
    claim = tmp_path / "geph-owned.json"
    claim.write_text(json.dumps(ownership()), encoding="utf-8")
    link = tmp_path / "claim-link.json"
    link.symlink_to(claim)

    assert geph_backend.read_ownership(claim) == ownership()
    assert geph_backend.read_ownership(link) is None


def test_read_ownership_rejects_oversized_or_non_object_claim(tmp_path):
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (geph_backend.MAX_OWNERSHIP_BYTES + 1))
    array = tmp_path / "array.json"
    array.write_text("[]", encoding="utf-8")

    assert geph_backend.read_ownership(oversized) is None
    assert geph_backend.read_ownership(array) is None


def test_listener_owned_requires_exact_pid_executable_and_config():
    calls = []

    def runner(*args):
        calls.append(args)
        if args[0] == "/usr/sbin/lsof":
            return result(stdout="321\n")
        if args[0] == "/bin/ps":
            return result(
                stdout=(
                    "/private/runtime/geph5-client --config "
                    "/private/runtime/geph-active.yaml\n"
                )
            )
        return result(returncode=1)

    assert geph_backend.listener_owned(runner, 9954, ownership())
    assert calls == [
        (
            "/usr/sbin/lsof",
            "-nP",
            "-iTCP:9954",
            "-sTCP:LISTEN",
            "-t",
        ),
        ("/bin/ps", "-p", "321", "-o", "command="),
    ]
    assert not geph_backend.listener_owned(
        runner,
        9954,
        ownership(),
        listener_process_id=321,
        command="/private/runtime/geph5-client --config /tmp/other.yaml",
    )


def test_boolean_or_nonpositive_process_identity_is_never_owned():
    claim = ownership(pid=1, uid=1)

    assert not geph_backend.state_matches(claim, True, "ignored")
    assert not geph_backend.state_matches(claim, 0, "ignored")
    claim["pid"] = True
    assert not geph_backend.state_matches(claim, 1, "ignored")


def test_owned_launch_target_requires_exact_label_and_file_owner():
    claim = ownership(uid=502)

    assert geph_backend.owned_launch_target(
        claim, 502, "dev.slipstream.geph"
    ) == "gui/502/dev.slipstream.geph"
    assert geph_backend.owned_launch_target(
        claim, 503, "dev.slipstream.geph"
    ) is None
    assert geph_backend.owned_launch_target(
        claim, True, "dev.slipstream.geph"
    ) is None


def test_backend_never_uses_broad_process_matching_or_process_termination():
    source = Path(geph_backend.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".", 1)[0])

    assert imported.isdisjoint({"signal", "socket", "subprocess", "threading"})
    assert "pkill" not in source
    assert "pgrep" not in source
    assert "kill(" not in source
