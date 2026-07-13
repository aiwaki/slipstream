import ast
import os
from pathlib import Path
from types import SimpleNamespace

import pf_adapter


def result(returncode=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def test_flush_targets_only_private_rulesets():
    calls = []

    def runner(*args):
        calls.append(args)
        return result()

    pf_adapter.flush_private_anchor(runner, "com.apple/slipstream")

    assert calls == [
        ("pfctl", "-a", "com.apple/slipstream", "-F", "rules"),
        ("pfctl", "-a", "com.apple/slipstream", "-F", "nat"),
    ]


def test_load_targets_private_anchor_and_removes_temporary_ruleset():
    observed = {}

    def runner(*args):
        observed["args"] = args
        observed["path"] = args[-1]
        observed["rules"] = Path(args[-1]).read_text(encoding="utf-8")
        return result()

    loaded = pf_adapter.load_private_anchor(
        runner,
        "com.apple/slipstream",
        "rdr pass on lo0 proto tcp port 443 -> 127.0.0.1 port {port}\n",
        1080,
    )

    assert loaded.returncode == 0
    assert observed["args"][:4] == (
        "pfctl",
        "-a",
        "com.apple/slipstream",
        "-f",
    )
    assert observed["rules"].endswith("port 1080\n")
    assert not os.path.exists(observed["path"])


def test_token_file_is_private_and_parser_is_strict(tmp_path):
    path = tmp_path / "pf.token"

    pf_adapter.write_token("123456", path)

    assert path.stat().st_mode & 0o777 == 0o600
    assert pf_adapter.read_token(path) == "123456"
    path.write_text("123abc\n", encoding="ascii")
    assert pf_adapter.read_token(path) is None
    pf_adapter.remove_token(path)
    assert not path.exists()


def test_preceding_interceptor_requires_both_https_actions_before_parent():
    outputs = {
        ("pfctl", "-sn"): 'rdr-anchor "zapret"\nrdr-anchor "com.apple/*"\n',
        ("pfctl", "-sr"): 'anchor "zapret"\nanchor "com.apple/*"\n',
        ("pfctl", "-a", "zapret", "-sn"): (
            "rdr pass on lo0 proto tcp from any to any port 443 "
            "-> 127.0.0.1 port 1234\n"
        ),
        ("pfctl", "-a", "zapret", "-sr"): (
            "pass out route-to (lo0 127.0.0.1) proto tcp port 443\n"
        ),
    }

    def runner(*args):
        return result(stdout=outputs.get(args, ""))

    assert pf_adapter.preceding_https_interceptors(
        runner, "com.apple/*"
    ) == ["zapret"]


def test_state_snapshot_is_compact_and_uses_explicit_runtime_state():
    def runner(*args):
        outputs = {
            ("pfctl", "-s", "info"): "Status: Enabled\n",
            ("pfctl", "-a", "com.apple/slipstream", "-sn"): "port 1080\n",
            ("pfctl", "-a", "com.apple/slipstream", "-sr"): (
                "route-to (lo0 127.0.0.1)\n"
            ),
        }
        return result(stdout=outputs.get(args, ""))

    assert pf_adapter.state_snapshot(
        runner,
        "com.apple/slipstream",
        1080,
        True,
        ["zapret"],
        lambda: True,
    ) == {
        "applied": True,
        "enabled": True,
        "anchor": "com.apple/slipstream",
        "parent_loaded": True,
        "interceptor_conflicts": ["zapret"],
        "rules_loaded": True,
    }


def test_adapter_does_not_own_process_or_network_policy():
    source = Path(pf_adapter.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".", 1)[0])

    assert imported.isdisjoint(
        {"asyncio", "socket", "ssl", "subprocess", "threading", "urllib"}
    )
    assert '"-d"' not in source
    assert '"all"' not in source
