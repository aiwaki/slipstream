"""Exercise real source-owned SPDX generation in workflow Bash without network/builds."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import textwrap
import unittest

import test_geph_source_owned_consumers as workflows
import test_geph_source_owned_sbom as fixtures


STEPS = {
    "dependency-audit.yml": "Materialize the reviewed Geph source graph",
    "build-geph.yml": "Build and audit the vendored dependency inventory",
}

DRIVER = textwrap.dedent(r'''
    import json, os, shutil, sys
    from pathlib import Path
    fixture = json.loads(Path(os.environ["GENERATION_FIXTURE"]).read_text())
    name, args = Path(sys.argv[0]).name, sys.argv[1:]
    with Path(fixture["commands"]).open("a") as log:
        log.write(json.dumps({"name": name, "args": args}) + "\n")
    if name == "curl":
        assert args[-3] == fixture["crate_url"] and args[-2] == "-o"
        shutil.copyfile(fixture["crate"], args[-1])
    elif name == "git":
        assert args == ["show", "-s", "--format=%ct", "a" * 40]
        print(1784159400)
    elif name == "cargo":
        assert args[0] == "metadata" and "--locked" in args
        assert args[args.index("--features") + 1] == "aws_lambda"
        assert args[args.index("--filter-platform") + 1] in fixture["targets"]
        root = Path(args[args.index("--manifest-path") + 1]).parent
        if fixture["tamper"]:
            (root / fixture["owned_file"]).write_text("// tampered\n")
        graph = fixture["metadata"]
        for package in graph["packages"]:
            if "manifest_path" in package:
                relative = Path(package["manifest_path"]).relative_to(fixture["source_root"])
                package["manifest_path"] = str(root / relative)
        print(json.dumps(graph))
    else:
        raise AssertionError("unexpected command: " + name)
''')


class SourceOwnedGenerationWorkflowTests(unittest.TestCase):
    def run_generation(self, workflow: str, *, tamper: bool = False, shell: str | None = None):
        fixture = fixtures.SourceOwnedGephSbomTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        root = fixture.fixture.root.resolve() / "workflow"
        root.mkdir()
        (root / "scripts").symlink_to(workflows.ROOT / "scripts", target_is_directory=True)
        vendor = root / "vendor/geph"
        vendor.mkdir(parents=True)
        for name, original in (("SOURCE.json", fixture.fixture.contract_path),
                               ("VERSION", fixture.fixture.version_path),
                               ("Cargo.lock", fixture.lock)):
            shutil.copyfile(original, vendor / name)
        metadata = root / "tmp/geph-metadata"
        metadata.mkdir(parents=True)
        for target, path in fixture.metadata:
            shutil.copyfile(path, metadata / (target + ".json"))
        (root / "out").mkdir()
        owned_file = fixture.source["embedded_packages"]["packages"][0]["path"] + "/src/lib.rs"
        if tamper and workflow == "build-geph.yml":
            (fixture.root / owned_file).write_text("// tampered\n")
        fixture_path = root / "fixture.json"
        fixture_path.write_text(json.dumps({
            "crate": str(fixture.fixture.crate_path), "crate_url": fixture.source["crate"]["url"],
            "metadata": fixture.graph(), "source_root": str(fixture.root),
            "targets": fixture.source["targets"], "tamper": tamper, "owned_file": owned_file,
            "commands": str(root / "commands.jsonl"),
        }))
        commands = root / "bin"
        commands.mkdir()
        (commands / "python3").symlink_to(Path(sys.executable).resolve())
        for name in ("curl", "cargo", "git"):
            path = commands / name
            path.write_text("#!/usr/bin/env python3\n" + DRIVER)
            path.chmod(0o755)
        if shell is None:
            shell = workflows.workflow_shell(workflow, STEPS[workflow])
        if workflow == "build-geph.yml":
            shell = shell.split('audit_verify_args=("${audit_native_args[@]}")', 1)[0]
        for original, value in {
            "/tmp/": str(root / "tmp") + "/",
            "fixture/slipstream": "aiwaki/slipstream",
            "${{ steps.source.outputs.native_sqlite }}": "false",
            "${{ steps.source.outputs.source_owned }}": "true",
            "${{ steps.source.outputs.root }}": str(fixture.root),
            "${{ steps.source.outputs.workspace }}": str(root / "evidence"),
        }.items():
            shell = shell.replace(original, value)
        self.assertNotIn("${{", shell)
        result = subprocess.run(
            ["/bin/bash", "-c", shell], cwd=root,
            env={**os.environ, "PATH": str(commands) + ":/usr/bin:/bin",
                 "GENERATION_FIXTURE": str(fixture_path), "GITHUB_SHA": "a" * 40,
                 "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True, text=True, timeout=20,
        )
        destination = "dist-geph-audit" if workflow == "dependency-audit.yml" else "out"
        return fixture, result, root / destination / "geph5-client.spdx.json"

    def test_workflows_generate_exact_source_owned_inventory(self):
        for workflow in STEPS:
            with self.subTest(workflow=workflow):
                fixture, result, output = self.run_generation(workflow)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(json.loads(output.read_text()), fixture.document())

    def test_workflows_reject_tampered_source_before_writing_spdx(self):
        for workflow in STEPS:
            with self.subTest(workflow=workflow):
                _, result, output = self.run_generation(workflow, tamper=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("materialized embedded file bytes disagree with SOURCE", result.stderr)
                self.assertFalse(output.exists())

    def test_omitting_materialized_source_root_fails_before_writing_spdx(self):
        for workflow in STEPS:
            with self.subTest(workflow=workflow):
                shell = workflows.workflow_shell(workflow, STEPS[workflow])
                expected = ('--source-root "$source_root"' if workflow == "dependency-audit.yml"
                            else '--source-root "${{ steps.source.outputs.root }}"')
                self.assertIn(expected, shell)
                shell = "\n".join(line for line in shell.splitlines() if expected not in line)
                _, result, output = self.run_generation(workflow, shell=shell)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("requires explicit materialized source_root", result.stderr)
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
