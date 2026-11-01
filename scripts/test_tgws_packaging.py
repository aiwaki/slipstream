"""TG source/packaging contracts; these checks do not build a frozen daemon."""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "vendor/tg-ws-proxy"


class TelegramPackagingTests(unittest.TestCase):
    def test_source_inventory_matches_every_imported_module(self):
        source = json.loads((VENDOR / "SOURCE.json").read_text())
        modules = {str(path.relative_to(VENDOR)) for path in (VENDOR / "proxy").glob("*.py")}
        self.assertEqual(set(source["upstream_files_sha256"]), modules)
        self.assertEqual(source["import_scope"], ["LICENSE", "proxy/*.py"])
        self.assertEqual((VENDOR / "VERSION").read_text().strip(), source["upstream_version"])
        self.assertEqual(source["upstream_tag"], "v" + source["upstream_version"])
        self.assertEqual(hashlib.sha256((VENDOR / "LICENSE").read_bytes()).hexdigest(), source["license_sha256"])
        for digest in source["upstream_files_sha256"].values():
            self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_event_loop_is_imported_and_preserves_upstream_identity(self):
        source = json.loads((VENDOR / "SOURCE.json").read_text())
        module = VENDOR / "proxy/event_loop.py"
        self.assertEqual(hashlib.sha256(module.read_bytes()).hexdigest(), source["upstream_files_sha256"]["proxy/event_loop.py"])
        tree = ast.parse((VENDOR / "proxy/tg_ws_proxy.py").read_text())
        self.assertTrue(any(
            isinstance(node, ast.ImportFrom) and node.level == 1
            and node.module == "event_loop"
            and any(alias.name == "install_self_pipe_guard" for alias in node.names)
            for node in ast.walk(tree)
        ))

    def test_relative_import_closure_is_inside_the_vendored_package(self):
        modules = {path.stem for path in (VENDOR / "proxy").glob("*.py")}
        for path in (VENDOR / "proxy").glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                if not isinstance(node, ast.ImportFrom) or not node.level:
                    continue
                self.assertEqual(node.level, 1, str(path))
                if node.module:
                    self.assertIn(node.module.split(".")[0], modules, str(path))

    def test_spec_collects_proxy_from_its_own_location_outside_repo_cwd(self):
        # Exercise spec wiring only. Actual PyInstaller discovery/data-hook
        # output and a built daemon remain separate qualification boundaries.
        calls = {}
        hooks = types.ModuleType("PyInstaller.utils.hooks")
        hooks.collect_all = lambda name: ([], [], [])

        def collect_submodules(name):
            calls["package"] = name
            calls["package_root"] = next(Path(path) / name for path in sys.path if (Path(path) / name / "__init__.py").is_file())
            return ["proxy.packaging_collection_sentinel"]

        hooks.collect_submodules = collect_submodules

        def analysis(*args, **kwargs):
            calls["analysis"] = (args, kwargs)
            return types.SimpleNamespace(pure=[], scripts=[], binaries=[], datas=[])

        namespace = {"SPECPATH": str(ROOT / "spike"), "Analysis": analysis,
                     "PYZ": lambda *a, **kw: None, "EXE": lambda *a, **kw: None,
                     "COLLECT": lambda *a, **kw: None}
        original_cwd = Path.cwd()
        original_path = list(sys.path)
        try:
            with tempfile.TemporaryDirectory() as directory, patch.dict(sys.modules, {"PyInstaller.utils.hooks": hooks}):
                os.chdir(directory)
                exec(compile((ROOT / "spike/slipstreamd.spec").read_text(), "slipstreamd.spec", "exec"), namespace)
        finally:
            os.chdir(original_cwd)
            sys.path[:] = original_path
        self.assertEqual(calls["package"], "proxy")
        self.assertEqual(calls["package_root"], VENDOR / "proxy")
        args, kwargs = calls["analysis"]
        self.assertEqual(args[0], [str(ROOT / "spike/tproxy.py")])
        self.assertEqual(kwargs["pathex"], [str(VENDOR)])
        self.assertIn("proxy.packaging_collection_sentinel", kwargs["hiddenimports"])


if __name__ == "__main__":
    unittest.main()
