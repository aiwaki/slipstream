from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD_DEPS = ROOT / "scripts/ensure_macos_build_deps.sh"
PYTHON_LOCKS = {
    "runtime": ROOT / "spike/requirements-runtime.txt",
    "test": ROOT / "spike/requirements.txt",
    "build": ROOT / "spike/requirements-build.txt",
}
RELEASE_PYTHON = "3.13.14"
TAURI_RELEASE_TARGET = "aarch64-apple-darwin"
ACTION_PINS = {
    "actions/checkout": (
        "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        "v7.0.0",
    ),
    "actions/setup-python": (
        "ece7cb06caefa5fff74198d8649806c4678c61a1",
        "v6.3.0",
    ),
    "actions/setup-node": (
        "820762786026740c76f36085b0efc47a31fe5020",
        "v7.0.0",
    ),
    "browser-actions/setup-chrome": (
        "2e1d749697dd1612b833dba4a722266286fbefcd",
        "v2.1.2",
    ),
    "actions/cache": (
        "55cc8345863c7cc4c66a329aec7e433d2d1c52a9",
        "v6.1.0",
    ),
    "actions/upload-artifact": (
        "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "v7.0.1",
    ),
    "actions/download-artifact": (
        "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        "v8.0.1",
    ),
    "actions/attest": (
        "a1948c3f048ba23858d222213b7c278aabede763",
        "v4.1.1",
    ),
    "softprops/action-gh-release": (
        "3d0d9888cb7fd7b750713d6e236d1fcb99157228",
        "v3.0.2",
    ),
    "dtolnay/rust-toolchain": (
        "4be7066ada62dd38de10e7b70166bc74ed198c30",
        "stable-2026-06-30",
    ),
}


def write_executable(path: Path, body: str = "exit 0\n") -> None:
    path.write_text(f"#!/bin/bash\nset -eu\n{body}", encoding="utf-8")
    path.chmod(0o755)


class BuildConfigTests(unittest.TestCase):
    def run_build_deps(
        self,
        bin_dir: Path,
        brew: Path,
        **environment: str,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(environment)
        env["PATH"] = str(bin_dir)
        env["SLIPSTREAM_HOMEBREW_BIN"] = str(brew)
        return subprocess.run(
            ("/bin/bash", str(BUILD_DEPS)),
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
            env=env,
        )

    def test_geph_source_regressions_run_before_vendor_build(self):
        workflow = (ROOT / ".github/workflows/build-geph.yml").read_text()
        test = 'python3 scripts/run_geph_synthetic_tests.py --source-root "$source_root"'
        self.assertIn(test, workflow)
        self.assertLess(workflow.index(test), workflow.index('cargo install'))
        # The helper compiles with --no-run, then runs exact reviewed cases in
        # the OS sandbox. The workflow must not execute the upstream lib suite.
        self.assertNotIn('cargo test --manifest-path "$source_root/Cargo.toml"', workflow)

        build = self._geph_workflow_shell("Build the exact locked universal binary")
        native = build.split('if [ "${{ steps.source.outputs.native_sqlite }}" = true ]; then', 1)[1].split("\nelse\n", 1)[0]
        self.assertNotIn("strip ", native)
        self.assertIn("--jobs 1", native)
        self.assertIn("--build-jobs 1", native)
        self.assertLess(native.index("build_geph_native_release.py\""), native.index("scripts/run_geph_synthetic_tests.py"))
        self.assertLess(native.index("scripts/run_geph_synthetic_tests.py"), native.index("geph_native_sqlite_bundle.py pack"))

    @staticmethod
    def _geph_workflow_shell(name: str) -> str:
        workflow = (ROOT / ".github/workflows/build-geph.yml").read_text()
        marker = "        name: " + name + "\n"
        if marker not in workflow:
            marker = "      - name: " + name + "\n"
        step = workflow.split(marker, 1)[1].split("\n      - ", 1)[0]
        lines = []
        for line in step.split("        run: |\n", 1)[1].splitlines():
            if line and not line.startswith("          "):
                break
            lines.append(line[10:])
        return "\n".join(lines)

    @staticmethod
    def _retain_geph_shell_evidence(name: str, root: Path, result: subprocess.CompletedProcess) -> None:
        destination = os.environ.get("SLIPSTREAM_GEPH_WORKFLOW_TEST_EVIDENCE")
        if destination:
            output = Path(destination) / name
            output.mkdir(parents=True, exist_ok=False)
            (output / "result.json").write_text(json.dumps({"returncode": result.returncode,
                "stdout": result.stdout[-20000:], "stderr": result.stderr[-20000:]}))
            commands = root / "commands.jsonl"
            (output / "commands.jsonl").write_text(commands.read_text() if commands.exists() else "")

    def test_geph_producer_shell_contract(self) -> None:
        import sys
        import textwrap

        # These inert commands execute the real workflow shells; even the
        # sandbox control is simulated, with no compiler or socket invocation.
        driver = textwrap.dedent(r'''
            import json, os, subprocess, sys
            from pathlib import Path
            ROOT = Path(__file__).resolve().parents[2] if Path(__file__).parent.name == "bin" else Path(__file__).resolve().parents[1]
            config = json.loads((ROOT / "fixture.json").read_text())
            native, owned = config["native"], config["owned"]
            binary = "sealed universal bytes" + ("" if native else " aws_smithy")
            name, args = Path(sys.argv[0]).name, sys.argv[1:]
            with (ROOT / "commands.jsonl").open("a") as stream:
                stream.write(json.dumps({"name": name, "args": args, "cwd": os.getcwd(),
                    "environment": {key: value for key, value in os.environ.items() if key in
                        ("HOME", "CARGO_HOME", "CARGO_NET_OFFLINE", "RUSTC", "PATH", "RUSTFLAGS", "GH_TOKEN", "AWS_SECRET_ACCESS_KEY")}}) + "\n")
            def value(flag): return args[args.index(flag) + 1]
            def fail(stage):
                if config["failure"] == stage: raise SystemExit("controlled refusal at " + stage)
            def clean():
                assert not {"RUSTFLAGS", "GH_TOKEN", "AWS_SECRET_ACCESS_KEY"}.intersection(os.environ)
                assert os.environ["PATH"] == "/usr/bin:/bin"
                assert Path(os.environ["HOME"]).name == "home"
            def write(path, content="{}"):
                path = Path(path); path.parent.mkdir(parents=True, exist_ok=True); path.write_text(content)
            if name == "rustup":
                assert args[:1] == ["which"]
                print(ROOT / "tools/bin" / args[1])
            elif name == "xcrun":
                print(ROOT / "tools/sdk" if args[-1] == "--show-sdk-path" else ROOT / "tools/bin" / args[-1])
            elif name == "curl": write(value("-o"), args[args.index("-o") - 1])
            elif name == "cargo":
                manifest = Path(value("--path")) / "Cargo.toml" if args[0] == "install" else Path(value("--manifest-path"))
                assert manifest.is_file()
                assert "--locked" in args
                if not native:
                    assert args[0] in ("metadata", "install")
                    if args[0] == "metadata": print('{}')
                    else: write(Path(value("--root")) / "bin/geph5-client", binary)
                elif "--offline" in args:
                    clean()
                    assert args[0] == "fetch" and "--target" not in args
                    assert os.environ["CARGO_NET_OFFLINE"] == "true"
                    assert (Path(os.environ["CARGO_HOME"]) / "cache-seal.json").is_file()
                    fail("offline-fetch")
                else:
                    clean()
                    assert args[0] == "fetch" and "--target" not in args
                    assert "CARGO_NET_OFFLINE" not in os.environ
                    assert not list(Path(os.environ["CARGO_HOME"]).iterdir())
                    fail("online-fetch")
                    write(Path(os.environ["CARGO_HOME"]) / "fetched", "full lock")
            elif name == "sandbox-exec":
                clean()
                assert args[:1] == ["-f"]
                assert Path(args[1]).read_text() == "(version 1)\n(allow default)\n(deny network*)\n"
                if args[3] == "-c":
                    assert 'errno.EPERM' in args[4] and 'connect_ex' in args[4]
                    fail("network-control")
                    print('{"network_errno":1}')
                else: raise SystemExit(subprocess.run(args[2:]).returncode)
            elif name == "geph_vendor_source.py":
                assert value("--source") == "vendor/geph/SOURCE.json"
                if args[0] == "verify": print(Path(value("--source")).read_text())
                else:
                    fail("materialize")
                    if native:
                        assert Path(value("--native-sqlite-archive")).read_text().startswith("https://sqlite.org/")
                    else: assert "--native-sqlite-archive" not in args
                    root = Path(value("--output")) / "geph5-client-0.4.3"
                    write(root / "Cargo.toml")
                    print(json.dumps({"root": str(root)}))
            elif name == "seal_geph_cargo_cache.py":
                assert (Path(value("--fetched-cargo-home")) / "fetched").read_text() == "full lock"
                assert not Path(value("--output")).exists()
                fail("seal")
                write(Path(value("--output")) / "cache-seal.json")
                print('{}')
            elif name == "build_geph_native_release.py":
                clean()
                assert value("--jobs") == "1"
                assert Path(value("--cargo-home")).name == "cargo-home"
                assert not Path(value("--output")).exists()
                for tool in ("cargo", "rustc", "python", "clang", "ar", "lipo", "sdk", "libclang", "cmake"):
                    path = Path(value("--" + tool)); assert path == path.resolve() and path.exists()
                fail("producer")
                out = Path(value("--output"))
                write(out / "source/geph5-client-0.4.3/Cargo.toml")
                write(out / "evidence/geph5-client", "sealed universal bytes")
                write(out / "evidence/native-release.json")
                for target in ("aarch64-apple-darwin", "x86_64-apple-darwin"):
                    write(out / "evidence" / target / "native-build.json")
                    write(out / "evidence" / target / "linked/cargo_metadata")
                print('{}')
            elif name == "run_geph_synthetic_tests.py":
                if native:
                    assert value("--build-jobs") == "1"
                    proof = Path(value("--native-receipt"))
                    assert proof.name == "native-build.json" and proof.is_file()
                    assert Path(value("--native-artifacts-root")) == proof.parent.parent
                else: assert "--native-receipt" not in args
                assert (Path(value("--source-root")) / "Cargo.toml").is_file()
                assert not Path(value("--evidence-dir")).exists()
                fail("runtime")
                write(Path(value("--evidence-dir")) / "result.json")
            elif name == "geph_native_sqlite_bundle.py":
                assert args[0] == "pack"
                assert Path(value("--receipt")).name == "native-release.json"
                assert Path(value("--published-binary")).read_text() == "sealed universal bytes"
                assert not Path(value("--output")).exists()
                fail("bundle")
                write(value("--output"), "retained full proof")
                print('{}')
            elif name == "make_geph_vendor_sbom.py":
                assert args[0] == "generate"
                if native:
                    assert Path(value("--source-root")).joinpath("Cargo.toml").is_file()
                    assert Path(value("--native-receipt")).is_file()
                else: assert "--native-receipt" not in args
                metadata = [args[i+1] for i, arg in enumerate(args) if arg == "--cargo-metadata"]
                assert len(metadata) == 2
                for entry in metadata:
                    target, path = entry.split("=", 1)
                    if native:
                        assert Path(path) == Path(value("--native-artifacts-root")) / target / "linked/cargo_metadata"
                    assert Path(path).is_file()
                fail("spdx")
                write(value("--output"))
            elif name == "dependency_audit.py":
                assert value("--policy") == "security/geph-dependency-audit-policy.json"
                if args[0] in ("scan", "verify"):
                    assert value("--vendored-transitive-dependencies") == "full"
                    if native or owned: assert value("--source") == "vendor/geph/SOURCE.json"
                    else: assert "--source" not in args
                    if native:
                        assert Path(value("--native-receipt")).is_file()
                        assert Path(value("--native-receipt")).parent == Path(value("--native-artifacts-root"))
                    else: assert "--native-receipt" not in args
                    if args[0] == "scan":
                        if native:
                            assert value("--native-advisory-evidence") == "security/geph-native-sqlite-advisories"
                        else: assert "--native-advisory-evidence" not in args
                        if native or owned:
                            assert Path(value("--evidence-dir")).name == "dependency-audit-evidence"
                            assert not Path(value("--evidence-dir")).exists()
                        else: assert "--evidence-dir" not in args
                        assert len(value("--evaluation-date")) == 10
                        if owned:
                            original = Path(value("--source-owned-evidence"))
                            assert str(original) == "security/geph-source-owned-advisories"
                            assert (original / "review.json").read_text() == "original review"
                            write(Path(value("--evidence-dir")) / "source-owned/review.json", "original review")
                            # The verified release must use the retained snapshot,
                            # even if author input changes after scanning.
                            (original / "review.json").write_text("changed after scan")
                    else:
                        assert "--evidence-dir" not in args and "--native-advisory-evidence" not in args
                        if owned:
                            retained = Path(value("--source-owned-evidence"))
                            assert retained.parent.name == "dependency-audit-evidence" and retained.name == "source-owned"
                            assert (retained / "review.json").read_text() == "original review"
                    if not owned: assert "--source-owned-evidence" not in args
                    fail("audit-" + args[0])
                if "--output" in args: write(value("--output"))
            elif name == "geph_source_owned_bundle.py":
                assert owned and args[0] == "pack"
                assert value("--policy") == "security/geph-dependency-audit-policy.json"
                retained = Path(value("--evidence-root"))
                assert retained.parent.name == "dependency-audit-evidence" and retained.name == "source-owned"
                assert (retained / "review.json").read_text() == "original review"
                assert Path("security/geph-source-owned-advisories/review.json").read_text() == "changed after scan"
                fail("owned-bundle")
                write(value("--output"), "retained full source review proof")
            elif name == "gh":
                assert args[:2] == ["attestation", "verify"]
                assert value("--repo") == "aiwaki/slipstream"
                assert value("--signer-workflow") == "aiwaki/slipstream/.github/workflows/build-geph.yml"
                assert value("--source-digest") == "a" * 40
                if native or owned:
                    assert value("--signer-digest") == "a" * 40
                    assert value("--source-ref") == "refs/heads/main"
                    assert value("--predicate-type") in ("https://slsa.dev/provenance/v1", "https://spdx.dev/Document/v2.3")
                assert "--deny-self-hosted-runners" in args
                fail("attestation-command")
                print('{}')
            elif name == "verify_geph_release.py":
                assert args[0] == "verify-attestations"
                assert value("--source") == "vendor/geph/SOURCE.json"
                assert len(list(Path(value("--release-dir")).iterdir())) == 8 + native + owned
                fail("attestations")
            elif name == "lipo":
                assert not native
                if args[0] == "-create":
                    for path in args[3:]: assert Path(path).read_text() == binary
                    write(value("-output"), binary)
                else: assert Path(args[0]).read_text() == binary
            elif name == "strip":
                assert not native and Path(args[-1]).read_text() == binary
            elif name == "git": print("1700000000")
            else: raise AssertionError((name, args))
        ''')
        names = ("Materialize the reviewed Geph source", "Build the exact locked universal binary",
                 "Build and audit the vendored dependency inventory", "Assemble the internal release payload",
                 "Verify stored Geph attestations")
        scenarios = []
        for native, owned in ((False, False), (True, False), (False, True), (True, True)):
            failures = ["", "materialize", "runtime", "spdx", "audit-scan", "audit-verify", "attestation-command"]
            if native: failures += ["online-fetch", "seal", "network-control", "offline-fetch", "producer", "bundle"]
            if native or owned: failures += ["attestations"]
            if owned: failures += ["owned-bundle"]
            scenarios += [(native, owned, failure) for failure in failures]
        for native, owned, failure in scenarios:
            with self.subTest(native=native, owned=owned, failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                for directory in ("scripts", "tools/bin", "tools/lib", "tools/sdk", "runner temp", "security", "vendor/geph", "workflow-tmp"):
                    (root / directory).mkdir(parents=True, exist_ok=True)
                (root / "fixture.json").write_text(json.dumps({"failure": failure, "native": native, "owned": owned}))
                source = {}
                if native: source["native_sqlite"] = {"archive": {"url": "https://sqlite.org/2026/sqlite.zip"}}
                if owned:
                    source["embedded_packages"] = [{"name": "source-owned-fixture"}]
                    (root / "security/geph-source-owned-advisories").mkdir()
                    (root / "security/geph-source-owned-advisories/review.json").write_text("original review")
                (root / "vendor/geph/SOURCE.json").write_text(json.dumps(source))
                for name, content in (("VERSION", "0.4.3\n"), ("Cargo.lock", "fixture lock"), ("LICENSE", "fixture license")):
                    (root / "vendor/geph" / name).write_text(content)
                (root / "security/geph-dependency-audit-policy.json").write_text('{}')
                for name in ("geph_vendor_source", "seal_geph_cargo_cache", "build_geph_native_release",
                             "run_geph_synthetic_tests", "geph_native_sqlite_bundle", "make_geph_vendor_sbom",
                             "dependency_audit", "verify_geph_release", "geph_source_owned_bundle"):
                    prefix = "def no_cargo_config(*args): pass\nif __name__ == '__main__':\n" if name == "build_geph_native_release" else ""
                    body = textwrap.indent(driver, "    ") if prefix else driver
                    (root / "scripts" / (name + ".py")).write_text(prefix + body)
                for name in ("rustup", "xcrun", "curl", "cargo", "sandbox-exec", "gh", "git", "lipo", "strip"):
                    path = root / "tools/bin" / name
                    path.write_text("#!" + str(Path(sys.executable).resolve()) + "\n" + driver)
                    path.chmod(0o755)
                for name in ("rustc", "clang", "ar", "cmake"):
                    write_executable(root / "tools/bin" / name, "exit 99\n")
                (root / "tools/lib/libclang.dylib").write_text("fixture tool")
                (root / "tools/bin/python3").symlink_to(Path(sys.executable).resolve())
                output = root / "step-output"
                env = {**os.environ, "PATH": str(root / "tools/bin") + ":/usr/bin:/bin",
                       "RUNNER_TEMP": str(root / "runner temp"), "GITHUB_OUTPUT": str(output),
                       "GITHUB_SHA": "a" * 40, "GEPH_TARGETS": "aarch64-apple-darwin,x86_64-apple-darwin",
                       "GH_TOKEN": "sentinel-not-a-secret", "RUSTFLAGS": "unwanted", "AWS_SECRET_ACCESS_KEY": "sentinel"}
                outputs = {"workspace": ""}
                for name in names:
                    shell = self._geph_workflow_shell(name)
                    substitutions = {"github.repository": "aiwaki/slipstream",
                                     "needs.resolve.outputs.crate_url": "https://static.crates.io/geph.crate"}
                    substitutions.update({"steps.source.outputs." + key: value for key, value in outputs.items()})
                    for key, value in substitutions.items(): shell = shell.replace("${{ " + key + " }}", value)
                    shell = shell.replace("/usr/bin/sandbox-exec", str(root / "tools/bin/sandbox-exec"))
                    shell = shell.replace("/tmp/", str(root / "workflow-tmp") + "/")
                    self.assertNotIn("${{", shell)
                    result = subprocess.run(["/bin/bash", "-c", shell], cwd=root, env=env,
                                            capture_output=True, text=True, timeout=15)
                    if result.returncode: break
                    if output.exists(): outputs.update(dict(line.split("=", 1) for line in output.read_text().splitlines()))
                self._retain_geph_shell_evidence(f"producer-native{int(native)}-owned{int(owned)}-" + (failure or "success"), root, result)
                commands = [json.loads(line) for line in (root / "commands.jsonl").read_text().splitlines()]
                command_names = [entry["name"] for entry in commands]
                self.assertEqual(result.returncode == 0, not failure, result.stdout + result.stderr)
                if failure:
                    logs = "\n".join(p.read_text() for p in (root / "runner temp").rglob("*.log"))
                    self.assertIn("controlled refusal at " + failure, result.stderr + logs)
                else:
                    self.assertEqual((root / "out/geph5-client").read_text(), "sealed universal bytes" + ("" if native else " aws_smithy"))
                    expected = {"geph5-client", "geph5-client.LICENSE", "geph5-client.VERSION", "geph5-client.SOURCE.json",
                                "geph5-client.Cargo.lock", "geph5-client.spdx.json", "geph5-client-dependency-audit.json", "SHA256SUMS"}
                    if native: expected.add("geph5-client-native-sqlite-evidence.tar")
                    if owned: expected.add("geph5-client-source-review-evidence.tar")
                    self.assertEqual({path.name for path in (root / "out").iterdir()}, expected)
                    attestations = [entry["args"] for entry in commands if entry["name"] == "gh"]
                    self.assertEqual(len(attestations), len(expected) + 1)
                    self.assertEqual({Path(args[2]).name for args in attestations[:-1]}, expected)
                    self.assertEqual(attestations[-1][attestations[-1].index("--predicate-type") + 1], "https://spdx.dev/Document/v2.3")
                    self.assertEqual(command_names[-1], "verify_geph_release.py" if native or owned else "gh")
                    if owned:
                        self.assertEqual((root / "out/geph5-client-source-review-evidence.tar").read_text(), "retained full source review proof")
                order = ["seal_geph_cargo_cache.py", "build_geph_native_release.py", "run_geph_synthetic_tests.py",
                         "geph_native_sqlite_bundle.py", "make_geph_vendor_sbom.py", "verify_geph_release.py"]
                seen = [command_names.index(name) for name in order if name in command_names]
                self.assertEqual(seen, sorted(seen))
                if failure in ("materialize", "online-fetch", "seal", "network-control", "offline-fetch", "producer", "runtime"):
                    self.assertFalse((root / "out/geph5-client").exists())
                if failure in ("spdx", "audit-scan", "audit-verify", "owned-bundle"):
                    self.assertFalse((root / "out/SHA256SUMS").exists())
                    self.assertNotIn("gh", command_names)
                if owned:
                    calls = [entry["args"][0] for entry in commands if entry["name"] in ("dependency_audit.py", "geph_source_owned_bundle.py")]
                    if "pack" in calls: self.assertEqual(calls, ["fetch-scanner", "scan", "verify", "pack"])
                    if failure in ("audit-scan", "audit-verify"):
                        self.assertNotIn("pack", calls)
                        self.assertFalse((root / "out/geph5-client-source-review-evidence.tar").exists())
                if native: self.assertNotIn("strip", command_names)

    def test_geph_audit_evidence_is_retained_after_failure_before_assembly(self) -> None:
        workflow = (ROOT / ".github/workflows/build-geph.yml").read_text()
        audit = workflow.index("      - name: Build and audit the vendored dependency inventory")
        retain = workflow.index("      - name: Retain Geph dependency audit evidence")
        assembly = workflow.index("      - name: Assemble the internal release payload")
        self.assertLess(audit, retain)
        self.assertLess(retain, assembly)
        step = workflow[retain:assembly]
        self.assertIn("if: always() && (steps.source.outputs.native_sqlite == 'true' || steps.source.outputs.source_owned == 'true')", step)
        self.assertIn("path: ${{ steps.source.outputs.workspace }}/dependency-audit-evidence/", step)
        self.assertNotIn("path: out/", step)
        self.assertIn("retention-days: 7", step)

    def test_geph_existing_release_requires_full_proof(self) -> None:
        import sys
        import textwrap

        shell = self._geph_workflow_shell("Decide whether review or build is required")
        for key, value in {"github.repository": "aiwaki/slipstream", "steps.upstream.outputs.version": "0.4.3",
                           "steps.upstream.outputs.crate_sha256": "c" * 64}.items():
            shell = shell.replace("${{ " + key + " }}", value)
        driver = textwrap.dedent(r'''
            import json, os, sys
            from pathlib import Path
            root = Path(__file__).resolve().parents[1]
            config = json.loads((root / "fixture.json").read_text())
            fail_at, native, owned = config["failure"], config["native"], config["owned"]
            name, args = Path(sys.argv[0]).name, sys.argv[1:]
            with (root / "commands.jsonl").open("a") as log:
                log.write(json.dumps({"name": name, "args": args}) + "\n")
            assets = {"geph5-client", "geph5-client.LICENSE", "geph5-client.VERSION", "geph5-client.SOURCE.json",
                      "geph5-client.Cargo.lock", "geph5-client.spdx.json", "geph5-client-dependency-audit.json",
                      "SHA256SUMS"}
            native_bundle = "geph5-client-native-sqlite-evidence.tar"
            owned_bundle = "geph5-client-source-review-evidence.tar"
            if native: assets.add(native_bundle)
            if owned: assets.add(owned_bundle)
            challenged_bundle = owned_bundle if owned else native_bundle
            def value(flag): return args[args.index(flag) + 1]
            def fail(stage):
                if fail_at == stage: raise SystemExit("controlled refusal at " + stage)
            if name == "gh":
                if args[:2] == ["release", "view"]:
                    print("\n".join(sorted(assets - ({challenged_bundle} if fail_at == "missing-asset" else set()))))
                elif args[0] == "api":
                    endpoint = args[-1]
                    if "/git/ref/tags/" in endpoint:
                        print(json.dumps({"object": {"type": "tag" if fail_at == "tag-type" else "commit", "sha": "a" * 40}}))
                    elif "/contents/" in endpoint:
                        assert endpoint.endswith("?ref=" + "a" * 40)
                        fail("historical-policy")
                        print('{"historical":true}')
                    else:
                        assert "/releases/tags/" in endpoint
                        print('{}')
                else:
                    assert args[:2] == ["attestation", "verify"]
                    assert value("--repo") == "aiwaki/slipstream"
                    assert value("--signer-workflow") == "aiwaki/slipstream/.github/workflows/build-geph.yml"
                    assert value("--signer-digest") == value("--source-digest") == "a" * 40
                    assert value("--source-ref") == "refs/heads/main"
                    assert value("--predicate-type") in ("https://slsa.dev/provenance/v1", "https://spdx.dev/Document/v2.3")
                    assert "--deny-self-hosted-runners" in args
                    fail("attestation-command")
                    print('{}')
            elif name == "curl": Path(value("-o")).write_text(args[args.index("-o") - 1])
            elif name == "geph_vendor_source.py":
                assert value("--source") == "vendor/geph/SOURCE.json"
                if args[0] == "verify":
                    source = json.loads(Path(value("--source")).read_text())
                    print(json.dumps({**source, "release_tag":"geph-vendor-0.4.3-r1"}))
                else:
                    assert native
                    fail("materialize")
                    source = json.loads(Path(value("--source")).read_text())
                    assert Path(value("--crate")).read_text() == source["crate"]["url"]
                    assert Path(value("--native-sqlite-archive")).read_text() == source["native_sqlite"]["archive"]["url"]
                    materialized = Path(value("--output")) / "independent-source"
                    materialized.mkdir(parents=True); (materialized / "marker").write_text("independent")
                    print(json.dumps({"root": str(materialized)}))
            elif name == "download_github_release_assets.py":
                patterns = [args[i+1] for i, a in enumerate(args) if a == "--pattern"]
                assert len(patterns) == 8 + native + owned and set(patterns) == assets
                release = Path(value("--output")); assert not release.exists(); release.mkdir()
                for asset in assets:
                    if asset == challenged_bundle and fail_at == "missing-bundle": continue
                    (release / asset).write_text("tampered" if asset == challenged_bundle and fail_at == "tampered-bundle" else "fixture asset")
            elif name == "verify_geph_release.py":
                assert value("--source") == "vendor/geph/SOURCE.json"
                if args[0] == "verify-assets":
                    release = Path(value("--release-dir"))
                    for bundle in assets.intersection({native_bundle, owned_bundle}):
                        if not (release / bundle).is_file(): raise SystemExit("controlled refusal at missing-bundle")
                        if (release / bundle).read_text() != "fixture asset": raise SystemExit("controlled refusal at tampered-bundle")
                    fail("assets")
                    result = {"asset_count": len(assets)}
                    if native:
                        proof = Path(value("--native-output-root")); assert not proof.exists()
                        proof = proof / "returned-proof"; proof.mkdir(parents=True)
                        receipt = proof / "returned-receipt.json"; receipt.write_text('{}')
                        result["native_evidence"] = {"receipt_path": str(receipt), "artifacts_root": str(proof)}
                    else: assert "--native-output-root" not in args
                    if owned:
                        assert json.loads(Path(value("--source-owned-policy")).read_text()) == {"historical": True}
                        requested = Path(value("--source-owned-output-root")); assert not requested.exists()
                        extracted = requested / "returned-owned-root"; extracted.mkdir(parents=True)
                        (extracted / "review.json").write_text("authenticated review")
                        result["source_owned_evidence"] = {"root": str(extracted)}
                    else: assert "--source-owned-policy" not in args and "--source-owned-output-root" not in args
                    print(json.dumps(result))
                else: fail("attestations" if args[0] == "verify-attestations" else "metadata")
            elif name == "make_geph_vendor_sbom.py":
                if native:
                    assert Path(value("--source-root")).joinpath("marker").read_text() == "independent"
                    assert Path(value("--native-receipt")).name == "returned-receipt.json"
                    assert Path(value("--native-artifacts-root")).name == "returned-proof"
                else: assert not {"--source-root", "--native-receipt", "--native-artifacts-root"}.intersection(args)
                assert value("--source-commit") == "a" * 40
                fail("spdx")
            elif name == "dependency_audit.py":
                assert value("--source-commit") == "a" * 40
                assert value("--vendored-transitive-dependencies") == "full"
                assert value("--source") == "vendor/geph/SOURCE.json"
                if native:
                    assert Path(value("--native-receipt")).name == "returned-receipt.json"
                    assert Path(value("--native-artifacts-root")).name == "returned-proof"
                else: assert not {"--native-receipt", "--native-artifacts-root"}.intersection(args)
                if owned:
                    extracted = Path(value("--source-owned-evidence"))
                    assert extracted.name == "returned-owned-root"
                    assert (extracted / "review.json").read_text() == "authenticated review"
                else: assert "--source-owned-evidence" not in args
                policy = json.loads(Path(value("--policy")).read_text())
                fail("historical-audit" if policy.get("historical") else "current-audit")
            else: raise AssertionError((name, args))
        ''')
        scenarios = []
        for native, owned in ((True, False), (False, True), (True, True)):
            failures = ["", "missing-asset", "tag-type", "historical-policy", "missing-bundle", "tampered-bundle", "assets", "spdx",
                        "historical-audit", "current-audit", "attestation-command", "attestations"]
            if native: failures += ["materialize"]
            scenarios += [(native, owned, failure) for failure in failures]
        for native, owned, failure in scenarios:
            with self.subTest(native=native, owned=owned, failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                for directory in ("scripts", "bin", "runner temp", "vendor/geph", "security"):
                    (root / directory).mkdir(parents=True, exist_ok=True)
                (root / "fixture.json").write_text(json.dumps({"failure": failure, "native": native, "owned": owned}))
                source = {"crate": {"url": "https://static.crates.io/geph.crate"}}
                if native: source["native_sqlite"] = {"archive": {"url": "https://sqlite.org/2026/sqlite.zip"}}
                if owned: source["embedded_packages"] = [{"name": "source-owned-fixture"}]
                (root / "vendor/geph/SOURCE.json").write_text(json.dumps(source))
                (root / "security/geph-dependency-audit-policy.json").write_text('{}')
                for name in ("geph_vendor_source.py", "download_github_release_assets.py", "verify_geph_release.py",
                             "make_geph_vendor_sbom.py", "dependency_audit.py"):
                    (root / "scripts" / name).write_text(driver)
                for name in ("gh", "curl"):
                    path = root / "bin" / name
                    path.write_text("#!" + str(Path(sys.executable).resolve()) + "\n" + driver); path.chmod(0o755)
                (root / "bin/python3").symlink_to(Path(sys.executable).resolve())
                output = root / "step-output"
                result = subprocess.run(["/bin/bash", "-c", shell], cwd=root,
                    env={**os.environ, "PATH": str(root / "bin") + ":/usr/bin:/bin",
                         "RUNNER_TEMP": str(root / "runner temp"), "GITHUB_OUTPUT": str(output)},
                    capture_output=True, text=True, timeout=15)
                self._retain_geph_shell_evidence(f"existing-native{int(native)}-owned{int(owned)}-" + (failure or "success"), root, result)
                self.assertEqual(result.returncode == 0, not failure, result.stdout + result.stderr)
                self.assertEqual("should_build=false" in output.read_text(), not failure)
                commands = [json.loads(line) for line in (root / "commands.jsonl").read_text().splitlines()]
                names = [entry["name"] for entry in commands]
                audits = [entry for entry in commands if entry["name"] == "dependency_audit.py"]
                attestations = [entry["args"] for entry in commands if entry["name"] == "gh" and entry["args"][:2] == ["attestation", "verify"]]
                asset_checks = [i for i, entry in enumerate(commands) if entry["name"] == "verify_geph_release.py" and entry["args"][0] == "verify-assets"]
                if asset_checks:
                    policies = [i for i, entry in enumerate(commands) if entry["name"] == "gh" and entry["args"][0] == "api" and "/contents/" in entry["args"][-1]]
                    self.assertEqual(len(policies), 1)
                    self.assertLess(policies[0], names.index("download_github_release_assets.py"))
                    self.assertLess(policies[0], asset_checks[0])
                if not failure:
                    self.assertEqual(len(audits), 2)
                    self.assertEqual(len(attestations), 9 + native + owned)
                    expected = {"geph5-client", "geph5-client.LICENSE", "geph5-client.VERSION", "geph5-client.SOURCE.json",
                                "geph5-client.Cargo.lock", "geph5-client.spdx.json", "geph5-client-dependency-audit.json", "SHA256SUMS"}
                    if native: expected.add("geph5-client-native-sqlite-evidence.tar")
                    if owned: expected.add("geph5-client-source-review-evidence.tar")
                    self.assertEqual({Path(args[2]).name for args in attestations[:-1]}, expected)
                    self.assertEqual(attestations[-1][attestations[-1].index("--predicate-type") + 1], "https://spdx.dev/Document/v2.3")
                    if owned:
                        roots = [entry["args"][entry["args"].index("--source-owned-evidence") + 1] for entry in audits]
                        self.assertEqual(roots[0], roots[1])
                elif failure in ("missing-asset", "tag-type", "historical-policy"):
                    self.assertNotIn("download_github_release_assets.py", names)
                else:
                    self.assertIn("controlled refusal at " + failure, result.stderr)
                if failure in ("missing-asset", "tag-type", "historical-policy", "missing-bundle", "tampered-bundle", "assets", "materialize", "spdx"):
                    self.assertEqual(audits, [])
                    self.assertEqual(attestations, [])
                if failure == "historical-audit":
                    self.assertEqual(len(audits), 1)
                    self.assertEqual(attestations, [])
                if failure in ("attestation-command", "attestations"):
                    self.assertEqual(len(audits), 1)

    def test_local_build_disables_updater_artifacts(self) -> None:
        config = json.loads(
            (ROOT / "app-tauri/src-tauri/tauri.local.conf.json").read_text()
        )

        self.assertIs(config["bundle"]["createUpdaterArtifacts"], False)

    def test_release_build_keeps_updater_artifacts(self) -> None:
        config = json.loads((ROOT / "app-tauri/src-tauri/tauri.conf.json").read_text())

        self.assertIs(config["bundle"]["createUpdaterArtifacts"], True)

    def test_package_scripts_split_local_and_release_builds(self) -> None:
        package = json.loads((ROOT / "app-tauri/package.json").read_text())
        scripts = package["scripts"]

        self.assertIn("tauri.local.conf.json", scripts["build:local"])
        self.assertIn("tauri build", scripts["build:release"])
        self.assertIn(f"--target {TAURI_RELEASE_TARGET}", scripts["build:release"])
        self.assertEqual(scripts["build"], "npm run build:release")

    def test_browser_probe_is_packaged_as_a_non_gui_cargo_binary(self) -> None:
        config = json.loads((ROOT / "app-tauri/src-tauri/tauri.conf.json").read_text())
        cargo = (ROOT / "app-tauri/src-tauri/Cargo.toml").read_text(encoding="utf-8")
        app_main = (ROOT / "app-tauri/src-tauri/src/main.rs").read_text(
            encoding="utf-8"
        )
        helper_main = (
            ROOT / "app-tauri/src-tauri/src/bin/slipstream-browser-probe.rs"
        ).read_text(encoding="utf-8")
        watchdog_main = (
            ROOT / "app-tauri/src-tauri/src/bin/slipstream-update-watchdog.rs"
        ).read_text(encoding="utf-8")
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        owned_geph = (
            ROOT / ".github/workflows/owned-geph-qualification.yml"
        ).read_text(encoding="utf-8")

        self.assertEqual(config["mainBinaryName"], "slipstream")
        self.assertNotIn(
            "browser-probe/slipstream-browser-probe",
            config["bundle"]["resources"],
        )
        self.assertIn('name = "slipstream-browser-probe"', cargo)
        self.assertNotIn("run_browser_probe_if_requested", app_main)
        self.assertNotIn("use slipstream_lib", helper_main)
        self.assertIn('#[path = "../browser_probe.rs"]', helper_main)
        self.assertNotIn("use slipstream_lib", watchdog_main)
        self.assertIn('#[path = "../updater_transaction.rs"]', watchdog_main)
        self.assertIn('/usr/bin/codesign --verify --strict "$helper"', workflow)
        self.assertIn('/usr/bin/otool -L "$helper"', workflow)
        self.assertIn(
            'watchdog="$app/Contents/MacOS/slipstream-update-watchdog"',
            workflow,
        )
        self.assertIn('/usr/bin/codesign --verify --strict "$watchdog"', workflow)
        self.assertIn('/usr/bin/otool -L "$watchdog"', workflow)
        self.assertIn("Print :CFBundleExecutable", workflow)
        self.assertIn(
            'helper="$app/Contents/MacOS/slipstream-browser-probe"',
            owned_geph,
        )
        self.assertIn('/usr/bin/codesign --verify --strict "$helper"', owned_geph)
        self.assertIn('/usr/bin/otool -L "$helper"', owned_geph)
        self.assertIn(
            'watchdog="$app/Contents/MacOS/slipstream-update-watchdog"',
            owned_geph,
        )
        self.assertIn('/usr/bin/codesign --verify --strict "$watchdog"', owned_geph)
        self.assertIn('/usr/bin/otool -L "$watchdog"', owned_geph)
        self.assertIn("Print :CFBundleExecutable", owned_geph)
        self.assertIn(
            "cargo test --locked --bin slipstream-browser-probe",
            workflow,
        )
        self.assertIn(
            "cargo test --locked --test updater_installer_mechanics -- --test-threads=1",
            workflow,
        )
        self.assertIn(
            "cargo clippy --locked --all-targets -- -D warnings",
            workflow,
        )
        self.assertNotIn(
            "cargo clippy --locked --bin slipstream-browser-probe",
            workflow,
        )

    def test_packaged_workflows_use_the_explicit_tauri_target(self) -> None:
        workflow_names = ("ci.yml",)
        combined = ""
        for name in workflow_names:
            workflow = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
            combined += workflow
            self.assertIn(
                f"SLIPSTREAM_TAURI_TARGET: {TAURI_RELEASE_TARGET}",
                workflow,
            )
            self.assertIn(
                "target/${SLIPSTREAM_TAURI_TARGET}/release/bundle",
                workflow,
            )
        self.assertNotIn("target/release/bundle", combined)
        self.assertGreaterEqual(
            combined.count('--target "$SLIPSTREAM_TAURI_TARGET"'),
            2,
        )

    def test_exact_main_candidate_qualifies_native_update_notification(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        job = workflow[
            workflow.index(
                "  packaged-update-notification-qualification:"
            ) : workflow.index("  packaged-app-lifecycle-heavy:")
        ]
        aggregate = workflow[workflow.index("  packaged-app-lifecycle:") :]

        self.assertIn("needs: [changes, assemble-release-candidate]", job)
        self.assertIn("github.event_name == 'push'", job)
        self.assertIn("github.ref == 'refs/heads/main'", job)
        self.assertIn("release-candidate-${{ github.sha }}", job)
        self.assertIn("scripts/macos_update_notification_smoke.py", job)
        self.assertIn('--repository "${{ github.repository }}"', job)
        self.assertIn('--source-commit "$GITHUB_SHA"', job)
        self.assertIn('--candidate-run-id "$GITHUB_RUN_ID"', job)
        self.assertIn(
            '--candidate-run-attempt "${{ steps.candidate-producer.outputs.run_attempt }}"',
            job,
        )
        self.assertIn('--qualification-run-attempt "$GITHUB_RUN_ATTEMPT"', job)
        self.assertIn("Authenticate the exact candidate producer attempt", job)
        self.assertIn("/attempts/$candidate_attempt/jobs?per_page=100", job)
        self.assertIn("--candidate-run-metadata", job)
        self.assertIn("--candidate-run-jobs", job)
        self.assertIn("--candidate-run-artifacts", job)
        self.assertIn("SLIPSTREAM_DISPOSABLE_CI", job)
        self.assertIn("update-notification-qualification.json", job)
        self.assertIn("Slipstream-update-notification-qualified-${{ github.sha }}", job)
        self.assertIn("packaged-update-notification-qualification", aggregate)
        self.assertIn(
            "needs.packaged-update-notification-qualification.result", aggregate
        )

    def test_daemon_version_tracks_root_version(self) -> None:
        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        daemon = (ROOT / "spike/tproxy.py").read_text(encoding="utf-8")

        self.assertIn(f'DAEMON_VERSION = "{version}"', daemon)

    def test_daemon_bundle_can_include_route_policy_keys(self) -> None:
        spec = (ROOT / "spike/slipstreamd.spec").read_text(encoding="utf-8")

        self.assertIn("route-policy-keys.json", spec)
        self.assertIn("datas.append", spec)
        self.assertIn("SPECPATH", spec)
        self.assertNotIn("os.getcwd()", spec)

    def test_release_workflow_promotes_candidate_metadata(self) -> None:
        workflow = (ROOT / ".github/workflows/build-app.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "Create tag-specific release metadata without rebuilding", workflow
        )
        self.assertIn("scripts/verify_release_artifacts.py", workflow)
        self.assertIn("--release-dir dist-release", workflow)
        self.assertIn("dist-release/dependency-audit.json", workflow)
        self.assertIn("scripts/make_release_manifest.py", workflow)
        self.assertIn("dist-release/Slipstream.spdx.json", workflow)
        self.assertIn("dist-release/artifact-manifest.json", workflow)
        self.assertIn('--source-commit "$SOURCE_COMMIT"', workflow)
        self.assertIn('--target "$SLIPSTREAM_TAURI_TARGET"', workflow)
        self.assertNotIn("npm run build", workflow)
        self.assertNotIn(".buildvenv/bin/pyinstaller", workflow.lower())

    def test_release_publisher_requires_exact_main_dependency_audit(self) -> None:
        workflow = (ROOT / ".github/workflows/build-app.yml").read_text(
            encoding="utf-8"
        )
        resolution = workflow[
            workflow.index(
                "- name: Resolve exact candidate and qualification runs"
            ) : workflow.index("- uses: actions/download-artifact@")
        ]

        self.assertIn("dependency_audit_run_id:", workflow)
        self.assertIn(
            "DEPENDENCY_AUDIT_INPUT: "
            "${{ github.event.inputs.dependency_audit_run_id }}",
            resolution,
        )
        self.assertIn(
            "actions/workflows/dependency-audit.yml/runs?"
            "branch=main&event=push&status=completed&per_page=100",
            resolution,
        )
        self.assertIn('select(.head_sha == \\"$SOURCE_COMMIT\\")', resolution)
        self.assertIn('select(.conclusion == \\"success\\")', resolution)
        self.assertIn(
            '"repos/${{ github.repository }}/actions/runs/$dependency_audit_run"',
            resolution,
        )
        self.assertIn('"head_branch": "main"', resolution)
        self.assertIn('"conclusion": "success"', resolution)
        self.assertIn(
            'dependency-audit.yml <<< "$dependency_audit_metadata"', resolution
        )
        self.assertIn(
            "actions/runs/$dependency_audit_run/jobs?filter=latest&per_page=100",
            resolution,
        )
        self.assertIn(
            'required = ("audit", "geph-vendor-audit", ' '"Required dependency audit")',
            resolution,
        )
        self.assertIn("total != len(jobs)", resolution)
        self.assertIn('job.get("run_attempt") != expected_attempt', resolution)
        self.assertIn('job.get("status") != "completed"', resolution)
        self.assertIn('job.get("conclusion") != "success"', resolution)
        self.assertIn(
            'echo "dependency_audit_run_id=$dependency_audit_run"', resolution
        )
        self.assertIn(
            'echo "dependency_audit_run_attempt=$dependency_audit_attempt"',
            resolution,
        )

    def test_dependency_audit_runs_on_changes_and_on_a_schedule(self) -> None:
        workflow = (ROOT / ".github/workflows/dependency-audit.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("pull_request:", workflow)
        self.assertIn("schedule:", workflow)
        self.assertIn('cron: "17 4 * * 1"', workflow)
        self.assertIn("--platform linux-amd64", workflow)
        self.assertIn('--filter-platform "$SLIPSTREAM_TAURI_TARGET"', workflow)
        self.assertIn("scripts/dependency_audit.py scan", workflow)
        self.assertIn("scripts/dependency_audit.py verify", workflow)
        self.assertIn("dist-audit/dependency-audit.json", workflow)
        self.assertIn("geph-vendor-audit:", workflow)
        self.assertIn("scripts/geph_vendor_source.py extract", workflow)
        self.assertIn("scripts/make_geph_vendor_sbom.py generate", workflow)
        self.assertIn("security/geph-dependency-audit-policy.json", workflow)
        self.assertIn("--vendored-transitive-dependencies full", workflow)

    def test_release_pipeline_reuses_one_immutable_candidate(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        qualification = (
            ROOT / ".github/workflows/owned-geph-qualification.yml"
        ).read_text(encoding="utf-8")
        readiness = (ROOT / ".github/workflows/release-readiness.yml").read_text(
            encoding="utf-8"
        )
        publisher = (ROOT / ".github/workflows/build-app.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("release-candidate-${{ github.sha }}", ci)
        self.assertIn("scripts/release_candidate.py create", ci)
        self.assertIn("--source-tree", ci)
        self.assertIn("--source-archive-sha256", ci)
        self.assertIn("--app-tree", ci)
        self.assertIn("actions/attest@", ci)
        self.assertEqual(ci.count("Build the frozen daemon"), 1)
        self.assertEqual(ci.count("Build the packaged app"), 1)
        self.assertIn("Seal the single packaged build for parallel qualification", ci)
        self.assertNotIn("--bundles app", ci)
        self.assertIn('test -f "$bundle/macos/Slipstream.app.tar.gz"', ci)
        self.assertIn("needs: [changes, packaged-app-build]", ci)
        self.assertIn("Assemble immutable main release candidate", ci)
        self.assertGreaterEqual(
            ci.count("name: release-candidate-${{ github.sha }}"), 3
        )

        self.assertIn("release-candidate-${{ github.sha }}", qualification)
        self.assertIn("scripts/release_candidate.py verify", qualification)
        self.assertIn("name: owned-geph-diagnostic", qualification)
        self.assertIn("inputs.diagnostic_only == true", qualification)
        self.assertIn("group: account-backed-geph", qualification)
        self.assertNotIn("scripts/release_candidate.py create-proof", qualification)
        self.assertNotIn("actions/attest@", qualification)
        self.assertNotIn("id-token: write", qualification)
        self.assertNotIn("attestations: write", qualification)
        self.assertNotIn("artifact-metadata: write", qualification)
        self.assertNotIn("Build the frozen daemon", qualification)
        self.assertNotIn("Build the packaged app", qualification)

        self.assertIn("release-candidate-${{ github.sha }}", readiness)
        self.assertIn("scripts/live_site_release_smoke.py", readiness)
        self.assertIn("scripts/packaged_invisibility_soak.py", readiness)
        self.assertIn("--duration-seconds 1800", readiness)
        self.assertIn(
            "Require passed live-site matrix before the long soak", readiness
        )
        self.assertIn(
            "Slipstream-live-site-diagnostics-${{ github.sha }}-${{ github.run_attempt }}",
            readiness,
        )
        self.assertIn(
            "Slipstream-invisibility-soak-diagnostics-${{ github.sha }}-${{ github.run_attempt }}",
            readiness,
        )
        live_gate = readiness[
            readiness.index("Run account-backed Safari and Chrome live-site gate") :
            readiness.index("Preserve bounded live-site diagnostics for this attempt")
        ]
        marker = "live-sites.exit"
        secret_guard = ': "${SLIPSTREAM_GEPH_ACCOUNT_SECRET:'
        self.assertIn(marker, live_gate)
        self.assertLess(
            live_gate.index(marker),
            live_gate.index(secret_guard),
        )
        self.assertLess(
            live_gate.index(marker),
            live_gate.index("python3 scripts/geph_owned_lifecycle_smoke.py"),
        )
        self.assertIn('value.get("ready") is not True', readiness)
        self.assertLess(
            readiness.index("Require passed live-site matrix before the long soak"),
            readiness.index("Run measured 30-minute background invisibility soak"),
        )
        self.assertIn("scripts/release_readiness.py create", readiness)
        self.assertIn("scripts/release_candidate.py create-proof", readiness)
        self.assertIn("group: account-backed-geph", readiness)
        self.assertEqual(
            readiness.count("python3 scripts/geph_owned_lifecycle_smoke.py"),
            1,
        )
        self.assertEqual(
            readiness.count("scripts/chromium_semantic_packaged_smoke.py"),
            1,
        )
        self.assertEqual(readiness.count("scripts/live_site_release_smoke.py"), 1)
        self.assertEqual(
            readiness.count("secrets.SLIPSTREAM_GEPH_ACCOUNT_SECRET"),
            1,
        )
        self.assertIn(
            "--qualification-workflow .github/workflows/release-readiness.yml",
            readiness,
        )
        self.assertEqual(readiness.count("actions/attest@"), 2)
        self.assertIn("timeout-minutes: 75", readiness)
        self.assertLess(
            live_gate.index("scripts/chromium_semantic_packaged_smoke.py"),
            live_gate.index("scripts/live_site_release_smoke.py"),
        )
        self.assertIn(
            "Verify the account-backed gate cleaned product-owned state",
            readiness,
        )
        self.assertLess(
            readiness.index(
                "Verify the account-backed gate cleaned product-owned state"
            ),
            readiness.index("Run measured 30-minute background invisibility soak"),
        )
        self.assertLess(
            readiness.index("Run measured 30-minute background invisibility soak"),
            readiness.index(
                "Preserve bounded invisibility-soak diagnostics for this attempt"
            ),
        )
        self.assertLess(
            readiness.index(
                "Preserve bounded invisibility-soak diagnostics for this attempt"
            ),
            readiness.index("Verify the soak left no product-owned system path"),
        )
        self.assertLess(
            readiness.index("Verify the soak left no product-owned system path"),
            readiness.index(
                "Bind qualification and measured readiness to one workflow attempt"
            ),
        )
        self.assertIn("scripts/packaged_transport_mechanics_smoke.py", readiness)
        self.assertIn("dist-readiness/transport-mechanics.json", readiness)
        self.assertNotIn("Slipstream-transport-matrix-${{ github.sha }}", readiness)
        self.assertNotIn("scripts/release_transport_matrix.py create", ci)
        self.assertIn("Attest exact release-readiness evidence", readiness)
        self.assertIn("Slipstream cleanup residue: $2", readiness)
        self.assertIn("browser_probe_runtime", readiness)
        self.assertIn("--expected-workflow-run-attempt", readiness)
        self.assertNotIn("Build the frozen daemon", readiness)
        self.assertNotIn("Build the packaged app", readiness)

        for protected in (qualification, readiness):
            self.assertNotRegex(
                protected,
                r"(?m)^\s+!\s+(?:sudo\s+)?launchctl\s+print\b",
            )
            self.assertNotRegex(
                protected,
                r"(?m)^\s+!\s+security\s+find-generic-password\b",
            )

    def test_account_backed_workflows_share_a_three_dispatch_daily_budget(
        self,
    ) -> None:
        workflows = {
            "release-readiness.yml": (
                ROOT / ".github/workflows/release-readiness.yml"
            ).read_text(encoding="utf-8"),
            "owned-geph-qualification.yml": (
                ROOT / ".github/workflows/owned-geph-qualification.yml"
            ).read_text(encoding="utf-8"),
        }
        protected_jobs = {
            "release-readiness.yml": "  exact-candidate-readiness:",
            "owned-geph-qualification.yml": (
                "  account-backed-owned-geph-diagnostic:"
            ),
        }

        for workflow_name, workflow in workflows.items():
            budget_start = workflow.index("  account-backed-run-budget:")
            protected_start = workflow.index(protected_jobs[workflow_name])
            budget_job = workflow[budget_start:protected_start]
            protected_header_end = workflow.index("    runs-on:", protected_start)
            protected_header = workflow[protected_start:protected_header_end]
            protected_job = workflow[protected_start:]

            self.assertLess(budget_start, protected_start)
            self.assertIn("runs-on: ubuntu-latest", budget_job)
            self.assertIn("actions: read", budget_job)
            self.assertIn("contents: read", budget_job)
            self.assertNotIn("environment:", budget_job)
            self.assertNotIn("secrets.", budget_job)
            self.assertNotIn("continue-on-error", budget_job)
            self.assertNotIn("always()", budget_job)
            self.assertIn(
                "Reserve one of three daily account-backed dispatches",
                budget_job,
            )
            self.assertIn(
                "actions/workflows/release-readiness.yml/runs", budget_job
            )
            self.assertIn(
                "actions/workflows/owned-geph-qualification.yml/runs",
                budget_job,
            )
            self.assertIn("-f branch=main", budget_job)
            self.assertIn("-f event=workflow_dispatch", budget_job)
            self.assertIn('utc_day="$(date -u +%F)"', budget_job)
            self.assertIn('-f "created=$created_range"', budget_job)
            self.assertIn("-F per_page=100", budget_job)
            self.assertIn(
                "python3 scripts/account_backed_run_budget.py verify", budget_job
            )
            self.assertIn('--current-run-id "$GITHUB_RUN_ID"', budget_job)
            self.assertIn(
                '--current-run-attempt "$GITHUB_RUN_ATTEMPT"', budget_job
            )
            self.assertIn("needs: account-backed-run-budget", protected_job)
            self.assertIn("environment: geph-qualification", protected_job)
            self.assertIn("github.run_attempt == '1'", budget_job)
            self.assertIn("github.run_attempt == '1'", protected_header)
            self.assertNotIn("always()", protected_header)
            self.assertIn(
                "needs.account-backed-run-budget.result == 'success'",
                protected_header,
            )
            self.assertIn("group: account-backed-geph", workflow)
            self.assertIn("queue: max", workflow)
            self.assertIn(
                "Never rerun a protected\n  # run that predates this budget job",
                workflow,
            )

        self.assertEqual(
            workflows["release-readiness.yml"].count(
                "scripts/account_backed_run_budget.py verify"
            ),
            1,
        )
        self.assertEqual(
            workflows["owned-geph-qualification.yml"].count(
                "scripts/account_backed_run_budget.py verify"
            ),
            1,
        )
        owned_budget = workflows["owned-geph-qualification.yml"][
            workflows["owned-geph-qualification.yml"].index(
                "  account-backed-run-budget:"
            ) : workflows["owned-geph-qualification.yml"].index(
                "  account-backed-owned-geph-diagnostic:"
            )
        ]
        self.assertNotIn("inputs.diagnostic_only", owned_budget)

        secret_workflows = {
            path.name
            for path in (ROOT / ".github/workflows").glob("*.yml")
            if "secrets.SLIPSTREAM_GEPH_ACCOUNT_SECRET"
            in path.read_text(encoding="utf-8")
        }
        self.assertEqual(
            secret_workflows,
            {"owned-geph-qualification.yml", "release-readiness.yml"},
        )

    def test_candidate_signing_and_attestation_have_least_privilege(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        publisher = (ROOT / ".github/workflows/build-app.yml").read_text(
            encoding="utf-8"
        )
        build = workflow[
            workflow.index("  packaged-app-build:") : workflow.index(
                "  sign-updater-archive:"
            )
        ]
        signer = workflow[
            workflow.index("  sign-updater-archive:") : workflow.index(
                "  assemble-release-candidate:"
            )
        ]
        assembly = workflow[
            workflow.index("  assemble-release-candidate:") : workflow.index(
                "  attest-release-candidate:"
            )
        ]
        attestation = workflow[
            workflow.index("  attest-release-candidate:") : workflow.index(
                "  packaged-browser-qualification:"
            )
        ]

        self.assertIn("npm ci --ignore-scripts", build)
        self.assertIn("Build the packaged app with a disposable updater key", build)
        self.assertIn("tauri signer generate", build)
        self.assertIn("trap cleanup_disposable_key EXIT", build)
        self.assertNotIn("${{ secrets.", build)
        self.assertNotIn("TAURI_SIGNING_PRIVATE_KEY: ${{ secrets.", assembly)
        self.assertEqual(
            workflow.count("${{ secrets.TAURI_SIGNING_PRIVATE_KEY }}"),
            1,
        )
        self.assertEqual(
            workflow.count("${{ secrets.TAURI_SIGNING_PRIVATE_KEY_PASSWORD }}"),
            1,
        )
        self.assertIn('node "$signer" signer sign', signer)
        self.assertNotIn("actions/checkout@", signer)
        self.assertNotIn("npm ci", signer)
        self.assertNotIn("tauri build", signer)
        self.assertNotIn("cargo ", signer)
        self.assertIn("updater-signing-input-${{ github.sha }}", signer)
        self.assertIn("EXPECTED_ARTIFACT_DIGEST", signer)
        self.assertIn("actions/runs/$GITHUB_RUN_ID/artifacts", signer)
        self.assertIn("artifact service digest mismatch", signer)
        self.assertIn('re.fullmatch(r"[0-9a-f]{64}", expected_digest)', signer)
        self.assertIn('matches[0].get("digest") != f"sha256:{expected_digest}"', signer)
        self.assertIn("@tauri-apps/cli/-/cli-2.11.3.tgz", signer)
        self.assertIn(
            "@tauri-apps/cli-darwin-arm64/-/cli-darwin-arm64-2.11.3.tgz", signer
        )
        self.assertIn(
            "1049507bccfcb83ecf8b9fbeb49fd47c4c16b8ad3caddde808361d7886c901bea9651af196a9a8179821e47e58bf39943e14b821109a2d2b1086f5a4adf2be19",
            signer,
        )
        self.assertIn(
            "071a5a33c6ec0a85ecdf077858a6216acfc6d60b3bfabec1f9ee169f2464d8612854ea2e241d61a0be84e982d76435db61c8ba54576b367a1b430776b952f87b",
            signer,
        )
        self.assertLess(
            signer.index("Bootstrap the independently checksummed Tauri signer"),
            signer.index("TAURI_SIGNING_PRIVATE_KEY: ${{ secrets."),
        )
        self.assertLess(
            signer.index("Verify exact-run signing input and artifact digest"),
            signer.index("TAURI_SIGNING_PRIVATE_KEY: ${{ secrets."),
        )
        self.assertNotIn("id-token: write", build)
        self.assertNotIn("attestations: write", build)
        self.assertNotIn("actions/attest@", build)
        self.assertNotIn("id-token: write", signer)
        self.assertNotIn("attestations: write", signer)
        self.assertIn("scripts/verify_updater_artifacts.py", assembly)
        self.assertLess(
            assembly.index("scripts/verify_updater_artifacts.py"),
            assembly.index("Assemble immutable main release candidate"),
        )
        self.assertIn("cmp \\", assembly)
        self.assertIn("signing-proof.json", assembly)
        self.assertIn("current-run artifact service identity mismatch", assembly)
        self.assertIn('re.fullmatch(r"[0-9a-f]{64}", digest)', assembly)
        self.assertIn('matches[0].get("digest") != f"sha256:{digest}"', assembly)
        self.assertNotIn("tauri build", assembly)
        self.assertNotIn("disposable-updater.key", assembly)

        product_checks = workflow[
            workflow.index("  product-checks:") : workflow.index(
                "  chromium-webrequest-contract:"
            )
        ]
        self.assertNotIn("id-token: write", product_checks)
        self.assertNotIn("attestations: write", product_checks)
        self.assertNotIn("artifact-metadata: write", product_checks)

        self.assertIn("id-token: write", attestation)
        self.assertIn("attestations: write", attestation)
        self.assertEqual(attestation.count("actions/attest@"), 2)
        self.assertNotIn("actions/checkout@", attestation)
        self.assertNotIn("${{ secrets.", attestation)
        self.assertNotIn("\n        run:", attestation)
        self.assertIn("- attest-release-candidate", workflow)
        self.assertIn("- sign-updater-archive", workflow)
        self.assertIn("- assemble-release-candidate", workflow)

        self.assertIn("release_candidate_run_id", publisher)
        self.assertIn("release_candidate_run_attempt", publisher)
        self.assertIn("qualification_run_id", publisher)
        self.assertIn("qualification_run_attempt", publisher)
        self.assertIn("readiness_run_id", publisher)
        self.assertIn("readiness_run_attempt", publisher)
        self.assertIn("scripts/release_candidate.py verify", publisher)
        self.assertIn("scripts/release_candidate.py verify-proof", publisher)
        self.assertIn("--expected-workflow-run-attempt", publisher)
        self.assertIn("--expected-qualification-run-attempt", publisher)
        self.assertIn("--expected-candidate-run-attempt", publisher)
        self.assertIn("--source-ref refs/heads/main", publisher)
        self.assertIn("scripts/release_readiness.py verify", publisher)
        self.assertIn(
            "--transport-report dist-readiness/transport-mechanics.json", publisher
        )
        self.assertIn(
            "cp dist-readiness/transport-mechanics.json dist-release/", publisher
        )
        self.assertIn("--require-passed", publisher)
        self.assertIn(
            "${{ github.repository }}/.github/workflows/release-readiness.yml",
            publisher,
        )
        self.assertNotIn("owned-geph-qualification.yml", publisher)
        self.assertIn(
            "qualification and readiness must use one protected workflow run",
            publisher,
        )
        self.assertNotIn("Build + sign the app", publisher)
        self.assertNotIn("Build the self-contained daemon", publisher)
        self.assertNotIn("run_packaged_lifecycle_smoke.sh", publisher)

    def test_packaged_visibility_gate_measures_real_macos_state(self) -> None:
        smoke = (ROOT / "scripts/pending_navigation_browser_probe_smoke.py").read_text(
            encoding="utf-8"
        )
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

        self.assertIn("CGWindowListCopyWindowInfo", smoke)
        self.assertIn('(LSAPPINFO, "listen", "+all"', smoke)
        self.assertIn("PostShowProcess", smoke)
        self.assertIn("frontmost application", smoke)
        self.assertIn("LaunchServices listener observed no owned lifecycle", smoke)
        self.assertIn("LaunchServices lifecycle did not fully exit", smoke)
        self.assertIn("_assert_pinned_executable_unchanged", smoke)
        self.assertNotIn('"visible_window": False', smoke)
        self.assertIn("packaged_chromium_headless_shell", smoke)
        self.assertIn("Qualify packaged lazy sandboxed browser observation", ci)
        browser_job = ci[
            ci.index("  packaged-browser-qualification:") : ci.index(
                "  packaged-app-lifecycle-heavy:"
            )
        ]
        self.assertNotIn("browser-actions/setup-chrome", browser_job)
        self.assertNotIn("--chrome-executable", browser_job)

    def test_required_workflows_keep_docs_only_checks_lightweight(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        audit = (ROOT / ".github/workflows/dependency-audit.yml").read_text(
            encoding="utf-8"
        )
        windows = (
            ROOT / ".github/workflows/windows-packet-adapter-qualification.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("changes:", ci)
        self.assertIn("if: needs.changes.outputs.product == 'true'", ci)
        self.assertIn("needs: [changes, packaged-app-build]", ci)
        self.assertIn("packaged-browser-qualification:", ci)
        self.assertIn("name: release-candidate-${{ github.sha }}", ci)
        self.assertIn("Validate repository documentation", ci)
        self.assertIn("test_documentation.py", ci)
        self.assertIn('git diff --check "$base" "$GITHUB_SHA"', ci)
        self.assertIn("\n  checks:\n", ci)
        self.assertIn("  checks:\n    name: checks\n", ci)
        self.assertIn("\n  packaged-app-lifecycle:\n", ci)
        self.assertIn(
            "  packaged-app-lifecycle:\n    name: packaged-app-lifecycle\n", ci
        )
        self.assertIn("name: Required dependency audit", audit)
        self.assertIn("pull_request:\n    paths:", windows)
        self.assertIn('branches: ["main"]', windows)

    def test_geph_source_contract_has_one_fail_closed_pr_bootstrap_path(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        audit = (ROOT / ".github/workflows/dependency-audit.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("geph_bootstrap: ${{ steps.scope.outputs.geph_bootstrap }}", ci)
        self.assertIn("python3 scripts/ci_scope.py", ci)
        self.assertIn('--event-name "$GITHUB_EVENT_NAME"', ci)
        self.assertIn('--github-output "$GITHUB_OUTPUT"', ci)
        self.assertEqual(ci.count("GEPH_BOOTSTRAP:"), 2)
        self.assertIn("Verify reviewed Geph source transition", ci)
        self.assertIn("if: needs.changes.outputs.geph_bootstrap == 'true'", ci)
        self.assertIn('mktemp -d "$RUNNER_TEMP/geph-transition-previous.XXXXXX"', ci)
        self.assertNotIn('rm -rf "$previous"', ci)
        self.assertIn('git cat-file -e "$BASE_SHA^{commit}"', ci)
        self.assertIn('git show "$BASE_SHA:vendor/geph/SOURCE.json"', ci)
        self.assertIn(
            'git show "$BASE_SHA:security/geph-dependency-audit-policy.json"',
            ci,
        )
        self.assertIn("scripts/geph_vendor_source.py verify-transition", ci)
        self.assertIn('--previous-policy "$previous/dependency-audit-policy.json"', ci)
        self.assertIn("--policy security/geph-dependency-audit-policy.json", ci)
        self.assertIn(
            "Geph source-contract PR: common gates and required dependency audit apply",
            ci,
        )
        self.assertIn(
            "Geph source-contract bootstrap: packaged binary waits for main", ci
        )
        self.assertIn("needs.changes.outputs.geph_bootstrap != 'true'", ci)
        self.assertEqual(ci.count("main cannot use the Geph bootstrap path"), 2)
        self.assertNotIn("scripts/ci_scope.py", audit)

    def test_packaged_build_verifies_exact_attested_geph_release(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        build = workflow[
            workflow.index("  packaged-app-build:") : workflow.index(
                "  sign-updater-archive:"
            )
        ]
        geph = build[
            build.index("Fetch and verify the recorded Geph build") : build.index(
                "Materialize pinned Chromium headless shell"
            )
        ]

        self.assertIn("attestations: read", build)
        self.assertIn("scripts/geph_vendor_source.py verify", geph)
        self.assertIn('["release_tag"]', geph)
        self.assertIn("releases/tags/$tag", geph)
        self.assertIn("verify_geph_release.py verify-metadata", geph)
        self.assertIn('--expected-tag "$tag"', geph)
        metadata_call = geph.split("verify_geph_release.py verify-metadata", 1)[1].split('          tag_ref=', 1)[0]
        self.assertIn("--source vendor/geph/SOURCE.json", metadata_call)
        self.assertLess(
            geph.index("verify_geph_release.py verify-metadata"),
            geph.index("scripts/download_github_release_assets.py"),
        )
        self.assertIn("git/ref/tags/$tag", geph)
        self.assertIn('[ "$tag_type" = commit ]', geph)
        self.assertLess(
            geph.index("git/ref/tags/$tag"),
            geph.index("scripts/download_github_release_assets.py"),
        )
        for asset in (
            "geph5-client",
            "geph5-client.LICENSE",
            "geph5-client.VERSION",
            "geph5-client.SOURCE.json",
            "geph5-client.Cargo.lock",
            "geph5-client.spdx.json",
            "geph5-client-dependency-audit.json",
            "SHA256SUMS",
        ):
            self.assertIn(f"--pattern {asset}", geph)
        self.assertIn("scripts/verify_geph_release.py verify-assets", geph)
        self.assertIn('--metadata "$release_metadata"', geph)
        self.assertIn('--expected-tag "$tag"', geph)
        self.assertIn("scripts/make_geph_vendor_sbom.py verify", geph)
        self.assertIn("scripts/dependency_audit.py verify", geph)
        self.assertIn("umask 077", geph)
        self.assertIn("application/vnd.github.raw+json", geph)
        self.assertIn(
            "contents/security/geph-dependency-audit-policy.json?ref=$tag_commit",
            geph,
        )
        self.assertIn('--policy "$historical_policy"', geph)
        self.assertNotIn(
            "--policy security/geph-dependency-audit-policy.json",
            geph,
        )
        self.assertNotIn('git show "$tag_commit:', geph)
        self.assertIn("--vendored-transitive-dependencies full", geph)
        self.assertIn('--source-commit "$tag_commit"', geph)
        self.assertIn("gh attestation verify", geph)
        self.assertIn('--signer-workflow "$signer_workflow"', geph)
        self.assertIn('--signer-digest "$tag_commit"', geph)
        self.assertIn('--source-digest "$tag_commit"', geph)
        self.assertIn("--source-ref refs/heads/main", geph)
        self.assertIn("--predicate-type https://slsa.dev/provenance/v1", geph)
        self.assertIn("--predicate-type https://spdx.dev/Document/v2.3", geph)
        self.assertIn("--deny-self-hosted-runners", geph)
        self.assertIn('--format json > "$provenance_json"', geph)
        self.assertIn('--format json > "$spdx_attestation_json"', geph)
        self.assertIn("verify_geph_release.py verify-attestations", geph)
        self.assertIn('--provenance-json "$provenance_json"', geph)
        self.assertIn('--spdx-json "$spdx_attestation_json"', geph)
        attestation_call = geph.split("verify_geph_release.py verify-attestations", 1)[1].split("          /usr/bin/lipo", 1)[0]
        self.assertIn("--source vendor/geph/SOURCE.json", attestation_call)
        self.assertIn('--native-output-root "$geph_workspace/native-evidence"', geph)
        self.assertIn('--native-sqlite-archive "$geph_workspace/sqlite.zip"', geph)
        self.assertIn('["native_evidence"]["receipt_path"]', geph)
        self.assertIn('["native_evidence"]["artifacts_root"]', geph)
        self.assertNotIn("rm -rf", geph)
        self.assertIn("-verify_arch arm64 x86_64", geph)
        self.assertLess(
            geph.index("scripts/dependency_audit.py verify"),
            geph.index("gh attestation verify"),
        )
        copy_index = geph.index('cp "$geph_release/geph5-client"')
        for verifier in (
            "verify_geph_release.py verify-metadata",
            "scripts/verify_geph_release.py verify-assets",
            "scripts/make_geph_vendor_sbom.py verify",
            "scripts/dependency_audit.py verify",
            "--predicate-type https://slsa.dev/provenance/v1",
            "--predicate-type https://spdx.dev/Document/v2.3",
            "verify_geph_release.py verify-attestations",
            "-verify_arch arm64 x86_64",
        ):
            self.assertLess(geph.index(verifier), copy_index)

    def test_packaged_geph_consumer_conditionally_materializes_native_evidence(self) -> None:
        import sys
        import textwrap

        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        step = workflow.split("      - name: Fetch and verify the recorded Geph build\n", 1)[1].split(
            "      - name: Materialize pinned Chromium headless shell\n", 1)[0]
        shell = "\n".join(line[10:] for line in step.split("        run: |\n", 1)[1].splitlines())
        shell = shell.replace("${{ github.repository }}", "aiwaki/slipstream").replace("/usr/bin/lipo", "lipo")
        driver = textwrap.dedent(r'''
            import json, os, sys
            from pathlib import Path
            name, args = Path(sys.argv[0]).name, sys.argv[1:]
            native = os.environ["GEPH_FIXTURE_NATIVE"] == "true"
            source = json.loads(Path("vendor/geph/SOURCE.json").read_text())
            state_path = Path("fixture-state.json")
            state = json.loads(state_path.read_text()) if state_path.exists() else {}
            with Path("commands.jsonl").open("a") as log:
                log.write(json.dumps({"name": name, "args": args}) + "\n")
            def value(flag):
                return args[args.index(flag) + 1]
            def done(stage, result=None):
                state_path.write_text(json.dumps(state))
                if os.environ.get("GEPH_FIXTURE_FAIL") == stage:
                    raise SystemExit("controlled refusal at " + stage)
                if result is not None:
                    print(json.dumps(result))
            def reviewed_source():
                assert value("--source") == "vendor/geph/SOURCE.json"
            if name == "gh":
                if args[0] == "api":
                    endpoint = args[-1]
                    if "/git/ref/tags/" in endpoint:
                        print(json.dumps({"object": {"type": "commit", "sha": "a" * 40}}))
                    elif "/contents/" in endpoint:
                        assert endpoint.endswith("?ref=" + "a" * 40)
                        print('{"historical":true}')
                    else:
                        assert "/releases/tags/" in endpoint
                        print("{}")
                else:
                    assert args[:2] == ["attestation", "verify"]
                    assert value("--signer-digest") == value("--source-digest") == "a" * 40
                    assert value("--source-ref") == "refs/heads/main"
                    assert "--deny-self-hosted-runners" in args
                    if "--format" in args:
                        print("{}")
            elif name == "curl":
                url = args[args.index("-o") - 1]
                assert url in (source["crate"]["url"], source["native_sqlite"]["archive"]["url"])
                Path(value("-o")).write_text(url)
            elif name == "lipo":
                assert Path(args[0]).read_bytes() == b"fixture universal binary"
            elif name == "geph_vendor_source.py":
                reviewed_source()
                if args[0] == "verify":
                    result = {"release_tag": "geph-vendor-0.4.3-r1"}
                    if native:
                        result["native_sqlite"] = "d" * 64
                    done("source", result)
                else:
                    assert native and args[0] == "extract"
                    assert Path(value("--crate")).read_text() == source["crate"]["url"]
                    assert Path(value("--native-sqlite-archive")).read_text() == source["native_sqlite"]["archive"]["url"]
                    materialized = Path(value("--output")) / "independently-materialized-source"
                    materialized.mkdir(parents=True)
                    (materialized / "marker").write_text("independent source")
                    state["source_root"] = str(materialized)
                    done("materialize", {"root": str(materialized)})
            elif name == "download_github_release_assets.py":
                patterns = [args[i + 1] for i, arg in enumerate(args) if arg == "--pattern"]
                expected = {"geph5-client", "geph5-client.LICENSE", "geph5-client.VERSION", "geph5-client.SOURCE.json",
                            "geph5-client.Cargo.lock", "geph5-client.spdx.json", "geph5-client-dependency-audit.json", "SHA256SUMS"}
                if native:
                    expected.add("geph5-client-native-sqlite-evidence.tar")
                assert len(patterns) == len(expected) and set(patterns) == expected
                release = Path(value("--output"))
                release.mkdir()
                for asset in expected:
                    (release / asset).write_bytes(b"fixture universal binary" if asset == "geph5-client" else b"fixture asset")
                state["release"] = str(release)
                done("download")
            elif name == "verify_geph_release.py":
                reviewed_source()
                if args[0] == "verify-assets":
                    assert value("--release-dir") == state["release"]
                    result = {"asset_count": 9 if native else 8}
                    if native:
                        requested = Path(value("--native-output-root"))
                        assert not requested.exists()
                        proof_root = requested / "returned-proof-root"
                        proof_root.mkdir(parents=True)
                        receipt = proof_root / "returned-release-proof.json"
                        receipt.write_text("{}")
                        state.update(native_receipt=str(receipt), native_artifacts=str(proof_root))
                        result["native_evidence"] = {"receipt_path": str(receipt), "artifacts_root": str(proof_root)}
                    else:
                        assert "--native-output-root" not in args
                    done("assets", result)
                else:
                    done("attestations" if args[0] == "verify-attestations" else "metadata", {})
            elif name == "make_geph_vendor_sbom.py":
                reviewed_source()
                if native:
                    assert value("--native-receipt") == state["native_receipt"]
                    assert value("--native-artifacts-root") == state["native_artifacts"]
                    assert value("--source-root") == state["source_root"]
                    assert (Path(value("--source-root")) / "marker").read_text() == "independent source"
                else:
                    assert not {"--source-root", "--native-receipt", "--native-artifacts-root"}.intersection(args)
                done("spdx", {})
            elif name == "dependency_audit.py":
                assert json.loads(Path(value("--policy")).read_text()) == {"historical": True}
                assert value("--source-commit") == "a" * 40
                if native:
                    assert value("--source") == "vendor/geph/SOURCE.json"
                    assert value("--native-receipt") == state["native_receipt"]
                    assert value("--native-artifacts-root") == state["native_artifacts"]
                else:
                    assert not {"--source", "--native-receipt", "--native-artifacts-root"}.intersection(args)
                done("audit", {})
            else:
                raise AssertionError((name, args))
        ''')
        scenarios = [(False, ""), (True, ""), *[(True, stage) for stage in (
            "assets", "materialize", "spdx", "audit", "attestations")]]
        for native, failure in scenarios:
            with self.subTest(native=native, failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                (root / "scripts").mkdir()
                (root / "bin").mkdir()
                runner = root / "runner temp"
                runner.mkdir()
                source = {"crate": {"url": "https://static.crates.io/crates/geph5-client/geph5-client-0.4.3.crate"}}
                if native:
                    source["native_sqlite"] = {"archive": {"url": "https://sqlite.org/2026/sqlite-amalgamation-3530200.zip"}}
                source_path = root / "vendor/geph/SOURCE.json"
                source_path.parent.mkdir(parents=True)
                source_path.write_text(json.dumps(source))
                for name in ("geph_vendor_source.py", "download_github_release_assets.py", "verify_geph_release.py",
                             "make_geph_vendor_sbom.py", "dependency_audit.py"):
                    (root / "scripts" / name).write_text(driver)
                (root / "bin/python3").symlink_to(Path(sys.executable).resolve())
                for name in ("gh", "curl", "lipo"):
                    executable = root / "bin" / name
                    executable.write_text(f"#!{sys.executable}\n" + driver)
                    executable.chmod(0o755)
                binary = root / "app-tauri/src-tauri/binaries/geph5-client-aarch64-apple-darwin"
                binary.parent.mkdir(parents=True)
                binary.write_bytes(b"stale binary must not survive")
                env = dict(os.environ, PATH=f"{root / 'bin'}:{os.environ['PATH']}", RUNNER_TEMP=str(runner),
                           GEPH_FIXTURE_NATIVE=str(native).lower(), GEPH_FIXTURE_FAIL=failure)
                result = subprocess.run(["/bin/bash", "-c", shell], cwd=root, env=env,
                                        capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 1 if failure else 0, result.stderr)
                calls = [json.loads(line) for line in (root / "commands.jsonl").read_text().splitlines()]
                workspaces = list(runner.glob("geph-consumer.*"))
                self.assertEqual(len(workspaces), 1)
                workspace = workspaces[0]
                self.assertEqual(workspace.stat().st_mode & 0o777, 0o700)
                self.assertTrue((workspace / "release/geph5-client").is_file())
                self.assertTrue((workspace / "verified-assets.json").is_file())
                if failure:
                    self.assertIn("controlled refusal at " + failure, result.stderr)
                    self.assertFalse(binary.exists())
                    self.assertFalse(any(call["name"] == "lipo" for call in calls))
                else:
                    self.assertEqual(binary.read_bytes(), b"fixture universal binary")
                    report = json.loads((workspace / "verified-assets.json").read_text())
                    self.assertEqual(report["asset_count"], 9 if native else 8)
                    attestations = [call for call in calls if call["name"] == "gh" and call["args"][:2] == ["attestation", "verify"]]
                    self.assertEqual(len(attestations), 10 if native else 9)
                downloads = [call for call in calls if call["name"] == "curl"]
                if native and failure != "assets":
                    self.assertEqual(len(downloads), 2)
                    self.assertTrue((workspace / "geph5-client.crate").is_file())
                    self.assertTrue((workspace / "sqlite.zip").is_file())
                else:
                    self.assertEqual(downloads, [])

    def test_every_geph_release_download_uses_the_bounded_helper(self) -> None:
        workflows = tuple((ROOT / ".github/workflows").glob("*.yml"))
        direct_downloads = []
        helper_users = []
        for path in workflows:
            text = path.read_text(encoding="utf-8")
            if "gh release download" in text:
                direct_downloads.append(path.name)
            if "scripts/download_github_release_assets.py" in text:
                helper_users.append(path.name)

        self.assertEqual(direct_downloads, [])
        self.assertEqual(
            sorted(helper_users),
            ["build-geph.yml", "ci.yml"],
        )

    def test_release_workflow_keeps_manual_previews_off_the_stable_feed(self) -> None:
        workflow = (ROOT / ".github/workflows/build-app.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn('tag="v${v}"', workflow)
        self.assertIn('"0.1.9-preview.${preview_sequence}"', workflow)
        self.assertIn('[ "$preview_sequence" = 23 ]', workflow)
        self.assertIn("release or Git tag already exists", workflow)
        self.assertIn("git/matching-refs/tags/$tag", workflow)
        self.assertIn("releases?per_page=100", workflow)
        self.assertIn('select(.tag_name == \\"$tag\\")', workflow)
        self.assertIn("resume_release_id=", workflow)
        self.assertIn(
            "existing release is not an exact resumable publication", workflow
        )
        self.assertIn("group: build-app-${{ github.ref }}", workflow)
        resolve_tag = workflow[workflow.index("- name: Resolve version and tag") :]
        self.assertIn("GH_TOKEN: ${{ github.token }}", resolve_tag[:500])
        self.assertIn("prerelease=true", workflow)
        self.assertIn("prerelease=false", workflow)
        self.assertIn("prerelease: ${{ steps.ver.outputs.prerelease }}", workflow)
        self.assertIn("Manual runs produce prereleases", workflow)

    def test_release_workflow_verifies_draft_and_remote_publication(self) -> None:
        workflow = (ROOT / ".github/workflows/build-app.yml").read_text(
            encoding="utf-8"
        )

        upload = workflow.index("Upload exact release draft")
        release_id = workflow.index("Resolve exact release transaction ID")
        draft_verify = workflow.index(
            "Verify the sole exact release draft before publication"
        )
        publish = workflow.index("Publish only the verified exact release draft")
        remote_verify = workflow.index(
            "Verify exact remote publication postconditions"
        )
        archival = workflow.index("Idempotently verify previous preview archival")
        self.assertLess(upload, release_id)
        self.assertLess(release_id, draft_verify)
        self.assertLess(draft_verify, publish)
        self.assertLess(publish, remote_verify)
        self.assertLess(remote_verify, archival)

        draft = workflow[upload:draft_verify]
        self.assertIn("id: release-draft", draft)
        self.assertIn("if: steps.ver.outputs.resume_release_id == ''", draft)
        self.assertIn("draft: true", draft)
        self.assertIn("overwrite_files: false", draft)
        self.assertIn("fail_on_unmatched_files: true", draft)
        self.assertIn(
            "target_commitish: ${{ steps.ver.outputs.source_commit }}", draft
        )

        id_contract = workflow[release_id:draft_verify]
        self.assertIn("steps.release-draft.outputs.id", id_contract)
        self.assertIn("steps.ver.outputs.resume_release_id", id_contract)
        self.assertIn('echo "id=$release_id"', id_contract)

        draft_contract = workflow[draft_verify:publish]
        self.assertIn("steps.release.outputs.id", draft_contract)
        self.assertIn("if: steps.ver.outputs.resume_release_id == ''", draft_contract)
        self.assertIn("git/matching-refs/tags/", draft_contract)
        self.assertIn("releases?per_page=100", draft_contract)
        self.assertIn("scripts/verify_published_release.py", draft_contract)
        self.assertIn("--state draft", draft_contract)

        publish_contract = workflow[publish:remote_verify]
        self.assertIn("releases/$RELEASE_ID", publish_contract)
        self.assertIn("-F draft=false", publish_contract)
        self.assertIn("continue-on-error: true", publish_contract)
        self.assertIn("authoritative remote verification will decide", publish_contract)
        self.assertIn("steps.release.outputs.id", publish_contract)
        self.assertNotIn("softprops/action-gh-release", publish_contract)

        remote_contract = workflow[remote_verify:archival]
        self.assertIn("releases/tags/", remote_contract)
        self.assertIn("git/ref/tags/", remote_contract)
        self.assertIn("releases?per_page=100", remote_contract)
        self.assertIn("scripts/verify_published_release.py", remote_contract)
        self.assertIn("--tag-ref", remote_contract)
        self.assertIn("--state published", remote_contract)
        self.assertIn("steps.release.outputs.id", remote_contract)

        archival_contract = workflow[archival:]
        self.assertNotIn("::warning::", archival_contract)
        self.assertIn("releases/tags/$previous_tag", archival_contract)
        self.assertIn("releases/$previous_id", archival_contract)
        self.assertIn("archive_verified=false", archival_contract)
        self.assertIn('archive_verified=true', archival_contract)
        self.assertIn("archival_release_name", archival_contract)
        self.assertIn('previous preview archival postcondition failed', archival_contract)

    def test_common_ci_runs_windows_only_for_windows_or_shared_adapter_paths(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        scope = (ROOT / "scripts/ci_scope.py").read_text(encoding="utf-8")

        self.assertIn("windows: ${{ steps.scope.outputs.windows }}", workflow)
        self.assertIn('"crates/slipstream-core/"', scope)
        self.assertIn('"crates/slipstream-windows-adapter/"', scope)
        self.assertIn('"vendor/wintun/"', scope)
        self.assertIn(
            "if: needs.changes.outputs.product == 'true' && needs.changes.outputs.windows == 'true'",
            workflow,
        )
        self.assertIn("WINDOWS_SCOPE: ${{ needs.changes.outputs.windows }}", workflow)
        self.assertIn('if [ "$WINDOWS_SCOPE" = true ]; then', workflow)

    def test_release_workflow_presents_dmg_and_archives_previous_preview(self) -> None:
        workflow = (ROOT / ".github/workflows/build-app.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("DMG для установки", workflow)
        self.assertIn("dmg_name=", workflow)
        self.assertIn("releases/download/${{ steps.ver.outputs.tag }}", workflow)
        self.assertIn("Idempotently verify previous preview archival", workflow)
        self.assertIn(
            "if: steps.ver.outputs.channel == 'preview' && steps.previous.outputs.tag != ''",
            workflow,
        )
        self.assertIn("-preview\\.[0-9]+", workflow)
        self.assertIn("releases/$previous_id", workflow)
        self.assertIn("-f name=\"$archival_name\"", workflow)
        self.assertLess(
            workflow.index("Verify exact remote publication postconditions"),
            workflow.index("Idempotently verify previous preview archival"),
        )

    def test_release_workflow_binds_tags_and_notes_to_the_built_commit(self) -> None:
        workflow = (ROOT / ".github/workflows/build-app.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "target_commitish: ${{ steps.ver.outputs.source_commit }}", workflow
        )
        self.assertIn("select(.draft | not)", workflow)
        self.assertIn('[ "$GITHUB_REF" = refs/heads/main ]', workflow)

    def test_release_workflow_attests_only_verified_payloads(self) -> None:
        workflow = (ROOT / ".github/workflows/build-app.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("id-token: write", workflow)
        self.assertIn("attestations: write", workflow)
        self.assertIn("artifact-metadata: write", workflow)
        self.assertEqual(
            workflow.count(
                "uses: actions/attest@a1948c3f048ba23858d222213b7c278aabede763"
            ),
            1,
        )
        self.assertIn("Attest tag-specific release metadata", workflow)
        self.assertIn("gh attestation verify", workflow)
        self.assertIn('--source-digest "$SOURCE_COMMIT"', workflow)
        self.assertIn("--predicate-type https://spdx.dev/Document/v2.3", workflow)
        self.assertIn("--deny-self-hosted-runners", workflow)
        self.assertLess(
            workflow.index("scripts/verify_release_artifacts.py"),
            workflow.index("Attest tag-specific release metadata"),
        )

    def test_release_workflow_requires_remote_policy_only_for_stable(self) -> None:
        workflow = (ROOT / ".github/workflows/build-app.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn('--channel "${{ steps.ver.outputs.channel }}"', workflow)
        self.assertIn("не содержит remote policy assets", workflow)
        self.assertNotIn("Package signed route policy channel", workflow)

    def test_release_workflow_qualifies_the_built_app_before_publish(self) -> None:
        workflow = (ROOT / ".github/workflows/build-app.yml").read_text(
            encoding="utf-8"
        )
        wrapper = (ROOT / "scripts/run_packaged_lifecycle_smoke.sh").read_text(
            encoding="utf-8"
        )
        lifecycle = (ROOT / "scripts/pf_installed_lifecycle_smoke.py").read_text(
            encoding="utf-8"
        )

        self.assertIn("scripts/release_candidate.py verify-proof", workflow)
        self.assertIn(
            "--expected-qualification-workflow .github/workflows/release-readiness.yml",
            workflow,
        )
        self.assertNotIn("owned-geph-qualification.yml", workflow)
        self.assertNotIn("scripts/run_packaged_lifecycle_smoke.sh", workflow)
        self.assertIn("scripts/pf_installed_lifecycle_smoke.py", wrapper)
        self.assertIn('--app-bundle "$app_bundle"', wrapper)
        self.assertIn("GITHUB_ACTIONS", wrapper)
        self.assertIn("--safaridriver-url", wrapper)
        self.assertNotIn("driver_port=19445", wrapper)
        self.assertIn('sock.bind(("127.0.0.1", 0))', wrapper)
        self.assertIn("for attempt in 1 2", wrapper)
        self.assertIn("Unable to start the server:", wrapper)
        self.assertIn("retrying once on a fresh loopback port", wrapper)
        self.assertIn("stalled_system_resolver", lifecycle)
        self.assertIn("dormant_before_query_then_active", lifecycle)
        syntax = subprocess.run(
            ("/bin/bash", "-n", str(ROOT / "scripts/run_packaged_lifecycle_smoke.sh")),
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def test_packaged_lifecycle_wrapper_refuses_non_ci_execution(self) -> None:
        environment = os.environ.copy()
        environment.pop("GITHUB_ACTIONS", None)
        environment.pop("SLIPSTREAM_DISPOSABLE_CI", None)
        result = subprocess.run(
            (
                "/bin/bash",
                str(ROOT / "scripts/run_packaged_lifecycle_smoke.sh"),
                "/tmp/not-a-slipstream-app",
            ),
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
            env=environment,
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("refusing Safari lifecycle smoke", result.stderr)

    def test_geph_vendor_workflow_proposes_a_pr(self) -> None:
        workflow = (ROOT / ".github/workflows/build-geph.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("pull-requests: write", workflow)
        self.assertIn("group: build-geph-main", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn('branch="automation/geph-${version}"', workflow)
        self.assertIn("gh pr create", workflow)
        self.assertIn("--base main", workflow)
        self.assertNotIn("git push origin HEAD:main", workflow)
        self.assertNotIn("git push ||", workflow)
        self.assertNotIn("gh pr review", workflow)
        self.assertNotIn("gh pr merge", workflow)
        self.assertNotIn("--auto", workflow)

    def test_reviewed_geph_revision_does_not_follow_newer_upstream(self) -> None:
        workflow = (ROOT / ".github/workflows/build-geph.yml").read_text()
        section = workflow.split("      - id: upstream", 1)[1].split("      - id: state", 1)[0]
        shell = section.split("        run: |\n", 1)[1]
        shell = "\n".join(line[10:] for line in shell.splitlines())
        self.assertIn("github.event_name == 'push'", section)
        self.assertIn("inputs.build_reviewed", section)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            import shutil
            # Production runs from a full checkout; keep its helper import
            # closure in this deliberately reduced, offline fixture too.
            for relative in ("scripts/geph_vendor_source.py", "scripts/geph_native_sqlite.py",
                             "vendor/geph/SOURCE.json",
                             "vendor/geph/VERSION", "vendor/geph/Cargo.lock"):
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            curl = bin_dir / "curl"
            curl.write_text("#!/bin/sh\necho unexpected-upstream-request >&2\nexit 71\n")
            curl.chmod(0o755)
            output = root / "output"
            env = dict(os.environ, BUILD_REVIEWED="true", GITHUB_REF="refs/heads/main",
                       GITHUB_OUTPUT=str(output), PATH=f"{bin_dir}:{os.environ['PATH']}")
            result = subprocess.run(["bash", "-c", shell], cwd=root, env=env,
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("version=" + (ROOT / "vendor/geph/VERSION").read_text().strip(), output.read_text())
            self.assertNotIn("unexpected-upstream-request", result.stderr)
            output.unlink()
            env["GITHUB_REF"] = "refs/heads/unreviewed"
            result = subprocess.run(["bash", "-c", shell], cwd=root, env=env,
                                    capture_output=True, text=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())
            env["GITHUB_REF"] = "refs/heads/main"
            with (root / "vendor/geph/Cargo.lock").open("a") as handle:
                handle.write("\n# invalid lock identity\n")
            result = subprocess.run(["bash", "-c", shell], cwd=root, env=env,
                                    capture_output=True, text=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())

    def test_geph_vendor_workflow_reviews_source_before_building(self) -> None:
        workflow = (ROOT / ".github/workflows/build-geph.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("scripts/geph_vendor_source.py prepare", workflow)
        self.assertIn(
            "scripts/geph_vendor_source.py retire-h2-transition-exception",
            workflow,
        )
        self.assertIn("vendor/geph/SOURCE.json", workflow)
        self.assertIn("vendor/geph/Cargo.lock", workflow)
        self.assertIn("security/geph-dependency-audit-policy.json", workflow)
        self.assertIn("needs.resolve.outputs.should_prepare == 'true'", workflow)
        self.assertIn("needs.resolve.outputs.should_build == 'true'", workflow)
        self.assertIn("cargo install", workflow)
        self.assertIn("--locked", workflow)
        self.assertIn('--path "$source_root"', workflow)
        self.assertIn("lipo out/geph5-client -verify_arch arm64 x86_64", workflow)
        self.assertNotIn("lipo -verify_arch arm64 x86_64 out/geph5-client", workflow)
        self.assertNotIn("cargo install geph5-client --version", workflow)
        self.assertIn("scripts/make_geph_vendor_sbom.py generate", workflow)
        self.assertIn("security/geph-dependency-audit-policy.json", workflow)
        self.assertIn("--vendored-transitive-dependencies full", workflow)
        self.assertIn("overwrite_files: false", workflow)
        self.assertEqual(
            workflow.count(
                "uses: actions/attest@a1948c3f048ba23858d222213b7c278aabede763"
            ),
            2,
        )
        self.assertLess(
            workflow.index("scripts/geph_vendor_source.py prepare"),
            workflow.index("gh pr create"),
        )
        self.assertLess(
            workflow.index(
                "scripts/geph_vendor_source.py retire-h2-transition-exception"
            ),
            workflow.index("git add --"),
        )
        self.assertLess(
            workflow.index("scripts/dependency_audit.py verify"),
            workflow.index("Publish the verified internal dependency release"),
        )

    def test_external_actions_use_reviewed_immutable_pins(self) -> None:
        pattern = re.compile(r"uses:\s+([^\s@]+)@([0-9a-f]{40})\s+#\s+([^\s]+)")
        seen: set[str] = set()

        for workflow in sorted((ROOT / ".github/workflows").glob("*.yml")):
            text = workflow.read_text(encoding="utf-8")
            for line in text.splitlines():
                if "uses:" not in line:
                    continue
                match = pattern.search(line)
                self.assertIsNotNone(
                    match,
                    f"mutable, unlabelled, or unknown external action in {workflow}: {line}",
                )
                assert match is not None
                action, sha, label = match.groups()
                self.assertIn(
                    action,
                    ACTION_PINS,
                    f"unreviewed external action in {workflow}: {line}",
                )
                self.assertEqual(
                    (sha, label),
                    ACTION_PINS[action],
                    f"unexpected release pin in {workflow}: {line}",
                )
                seen.add(action)

        self.assertEqual(seen, set(ACTION_PINS))

    def test_node_jobs_use_the_supported_lts(self) -> None:
        for workflow in sorted((ROOT / ".github/workflows").glob("*.yml")):
            text = workflow.read_text(encoding="utf-8")
            if "actions/setup-node@" not in text:
                continue
            self.assertIn('node-version: "24"', text, str(workflow))
            self.assertNotRegex(text, r"node-version:\s*20\b")

    def test_python_jobs_use_the_exact_release_patch(self) -> None:
        setup_count = 0
        version_count = 0
        for workflow in sorted((ROOT / ".github/workflows").glob("*.yml")):
            text = workflow.read_text(encoding="utf-8")
            setup_count += text.count("uses: actions/setup-python@")
            version_count += text.count(f'python-version: "{RELEASE_PYTHON}"')
            self.assertNotIn('python-version: "3.13"', text, str(workflow))

        self.assertGreater(setup_count, 0)
        self.assertEqual(version_count, setup_count)

    def test_python_locks_pin_and_hash_every_distribution(self) -> None:
        expected_packages = {
            "runtime": {
                "certifi",
                "cryptography",
                "h2",
                "hpack",
                "hyperframe",
                "scapy",
            },
            "test": {
                "certifi",
                "cryptography",
                "h2",
                "hpack",
                "hyperframe",
                "pytest",
                "scapy",
            },
            "build": {
                "certifi",
                "cryptography",
                "h2",
                "hpack",
                "hyperframe",
                "pyinstaller",
                "scapy",
            },
        }
        requirement_pattern = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s]+)")
        hash_pattern = re.compile(r"--hash=sha256:([0-9a-f]{64})")
        lock_versions: dict[str, dict[str, str]] = {}

        for kind, path in PYTHON_LOCKS.items():
            text = path.read_text(encoding="utf-8")
            self.assertIn("scripts/update_python_locks.sh", text)
            logical_lines: list[str] = []
            current = ""
            for raw_line in text.splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                current = f"{current} {line}".strip()
                if current.endswith("\\"):
                    current = current[:-1].rstrip()
                    continue
                logical_lines.append(current)
                current = ""
            self.assertFalse(current, f"unterminated requirement in {path}")

            packages: set[str] = set()
            versions: dict[str, str] = {}
            for requirement in logical_lines:
                self.assertNotRegex(
                    requirement,
                    r"^(?:-e|--editable)\s",
                    f"editable requirement in {path}: {requirement}",
                )
                self.assertNotRegex(
                    requirement,
                    r"(?:^|[\s@])(?:git\+|https?://)",
                    f"URL or VCS requirement in {path}: {requirement}",
                )
                match = requirement_pattern.match(requirement)
                self.assertIsNotNone(
                    match, f"unlocked requirement in {path}: {requirement}"
                )
                assert match is not None
                package = match.group(1).lower()
                packages.add(package)
                versions[package] = match.group(2)
                self.assertTrue(
                    hash_pattern.search(requirement),
                    f"unhashed requirement in {path}: {requirement}",
                )
                self.assertNotIn("@", match.group(2), requirement)

            self.assertLessEqual(expected_packages[kind], packages)
            if kind != "build":
                self.assertNotIn("pyinstaller", packages)
            if kind != "test":
                self.assertNotIn("pytest", packages)
            lock_versions[kind] = versions

        for kind in ("test", "build"):
            for package, version in lock_versions["runtime"].items():
                self.assertEqual(lock_versions[kind].get(package), version)

    def test_python_install_paths_are_hash_locked_and_binary_only(self) -> None:
        build_sources = [
            ROOT / ".github/workflows/ci.yml",
            ROOT / "spike/build_daemon.sh",
        ]
        combined = "\n".join(path.read_text(encoding="utf-8") for path in build_sources)

        self.assertGreaterEqual(combined.count("requirements-build.txt"), 3)
        self.assertGreaterEqual(combined.count("--require-hashes"), 3)
        self.assertGreaterEqual(combined.count("--only-binary=:all:"), 3)
        self.assertNotIn("-r spike/requirements.txt pyinstaller", combined)
        self.assertNotIn("scapy cryptography certifi pyinstaller", combined)
        self.assertNotIn("pip install --quiet --upgrade pip", combined)

        source_installer = (ROOT / "spike/tproxy.py").read_text(encoding="utf-8")
        install_start = source_installer.index("if not os.path.exists(py):")
        install_end = source_installer.index("prog_args = [py, script", install_start)
        source_install = source_installer[install_start:install_end]
        self.assertIn("requirements-runtime.txt", source_install)
        self.assertIn('"--require-hashes"', source_install)
        self.assertIn('"--only-binary=:all:"', source_install)
        self.assertNotRegex(
            source_install,
            r'"scapy",\s*"cryptography",\s*"certifi"',
        )

    def test_python_lock_update_tool_is_pinned_and_syntax_checked(self) -> None:
        updater = ROOT / "scripts/update_python_locks.sh"
        text = updater.read_text(encoding="utf-8")
        self.assertIn('pip_tools_version="7.5.3"', text)
        self.assertIn('python_minor" != "3.13"', text)
        self.assertIn("--generate-hashes", text)
        self.assertIn("--allow-unsafe", text)

        syntax = subprocess.run(
            ("/bin/bash", "-n", str(updater)),
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def test_release_workflows_use_checked_macos_build_dependencies(self) -> None:
        for name in ("build-geph.yml",):
            workflow = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
            self.assertIn("bash scripts/ensure_macos_build_deps.sh", workflow)
            self.assertNotIn("brew install protobuf cmake pkg-config || true", workflow)

        syntax = subprocess.run(
            ("/bin/bash", "-n", str(BUILD_DEPS)),
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def test_release_kinds_cannot_replace_each_others_latest_pointer(self) -> None:
        app = (ROOT / ".github/workflows/build-app.yml").read_text(encoding="utf-8")
        geph = (ROOT / ".github/workflows/build-geph.yml").read_text(encoding="utf-8")

        self.assertIn("make_latest=true", app)
        self.assertIn("make_latest=false", app)
        self.assertIn("make_latest: ${{ steps.ver.outputs.make_latest }}", app)
        self.assertIn('release_name="Slipstream $v"', app)
        self.assertIn("body_path: dist-release/release-notes.md", app)
        self.assertIn("generate_release_notes: true", app)
        self.assertIn("Resolve previous app release tag", app)
        self.assertIn("test($tag_pattern)", app)
        self.assertIn("-preview\\.[0-9]+$", app)
        self.assertIn("previous_tag: ${{ steps.previous.outputs.tag }}", app)
        self.assertIn(".prerelease == $prerelease", app)
        self.assertIn("gh api --paginate", app)
        self.assertIn('--arg current_tag "$current_tag"', app)
        self.assertIn('--arg tag_pattern "$tag_pattern"', app)
        self.assertIn('--argjson prerelease "$prerelease"', app)
        self.assertNotIn('--jq "$filter"', app)
        self.assertNotIn('cp "$B/dmg/"*.dmg "$OUT/" 2>/dev/null || true', app)

        self.assertIn('branches: ["main"]', geph)
        self.assertIn("prerelease: true", geph)
        self.assertIn("make_latest: false", geph)
        self.assertIn("This is not an app release", geph)

    def test_previous_release_filter_is_valid_jq_and_excludes_current_tag(self) -> None:
        workflow = (ROOT / ".github/workflows/build-app.yml").read_text(
            encoding="utf-8"
        )
        step_start = workflow.index("- name: Resolve previous app release tag")
        step_end = workflow.index(
            "- name: Resolve exact candidate and qualification runs"
        )
        step = workflow[step_start:step_end]
        match = re.search(r"(?m)^\s*filter='([^']+)'$", step)
        self.assertIsNotNone(match)
        jq_filter = match.group(1)
        releases = [
            {
                "tag_name": "v0.1.9-preview.23",
                "draft": False,
                "prerelease": True,
            },
            {
                "tag_name": "v0.1.9-preview.22",
                "draft": False,
                "prerelease": True,
            },
            {
                "tag_name": "v0.1.9-preview.21",
                "draft": True,
                "prerelease": True,
            },
            {
                "tag_name": "v0.1.8",
                "draft": False,
                "prerelease": False,
            },
        ]
        filtered = subprocess.run(
            (
                "jq",
                "-r",
                "--arg",
                "current_tag",
                "v0.1.9-preview.23",
                "--arg",
                "tag_pattern",
                r"^v[0-9]+\.[0-9]+\.[0-9]+-preview\.[0-9]+$",
                "--argjson",
                "prerelease",
                "true",
                jq_filter,
            ),
            input=json.dumps(releases),
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        self.assertEqual(filtered.returncode, 0, filtered.stderr)
        self.assertEqual(filtered.stdout.splitlines(), ["v0.1.9-preview.22"])

    def test_release_workflow_multiline_python_payloads_compile_after_yaml_dedent(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/build-app.yml").read_text(
            encoding="utf-8"
        )
        step_start = workflow.index("      - name: Resolve version and tag\n")
        step_end = workflow.index("\n      - ", step_start + 1)
        step = workflow[step_start:step_end]
        run_marker = "        run: |\n"
        self.assertEqual(step.count(run_marker), 1)
        run_lines = step.split(run_marker, 1)[1].splitlines()
        content_indent = min(
            len(line) - len(line.lstrip()) for line in run_lines if line.strip()
        )
        self.assertEqual(content_indent, 10)
        for line in run_lines:
            if line.strip():
                self.assertTrue(line.startswith(" " * content_indent))
        effective_script = "\n".join(
            line[content_indent:] if line.strip() else "" for line in run_lines
        )

        tokens = shlex.split(effective_script, comments=True, posix=True)
        payloads = [
            tokens[index + 2]
            for index, token in enumerate(tokens[:-2])
            if token == "python3"
            and tokens[index + 1] == "-c"
            and "\n" in tokens[index + 2]
        ]
        self.assertEqual(len(payloads), 3)
        for payload in payloads:
            compile(
                payload,
                "build-app.yml Resolve version and tag python3 -c",
                "exec",
            )

    def test_publisher_repair_reuses_only_a_bounded_qualified_ancestor(self) -> None:
        workflow = (ROOT / ".github/workflows/build-app.yml").read_text(
            encoding="utf-8"
        )
        resolution_start = workflow.index("- name: Resolve version and tag")
        resolution_end = workflow.index("- name: Resolve previous app release tag")
        resolution = workflow[resolution_start:resolution_end]
        publication_start = workflow.index(
            "- name: Resolve exact candidate and qualification runs"
        )
        publication = workflow[publication_start:]

        self.assertIn("release_source_commit:", workflow)
        self.assertIn("fetch-depth: 5", workflow)
        self.assertIn('[ "$GITHUB_RUN_ATTEMPT" = 1 ]', resolution)
        self.assertIn(
            'git merge-base --is-ancestor "$RELEASE_SOURCE_INPUT" "$GITHUB_SHA"',
            resolution,
        )
        self.assertIn("publisher repair must run from live main", resolution)
        self.assertIn(
            "expected_repair_source=6ba71ef75d821ee74cedcee5d8a9c83495da7c76",
            resolution,
        )
        self.assertIn(
            "expected_first_repair=1e0d03130405020a761504c1e65827f76020de47",
            resolution,
        )
        self.assertIn(
            "expected_second_repair=06885e10d22a435175034023d6cc9b51d3666b34",
            resolution,
        )
        self.assertIn(
            'git merge-base --is-ancestor "$expected_second_repair" "$GITHUB_SHA"',
            resolution,
        )
        self.assertIn('git rev-parse "$expected_first_repair^"', resolution)
        self.assertIn('git rev-parse "$expected_second_repair^"', resolution)
        self.assertIn("known two-repair .23 prefix", resolution)
        self.assertIn('repair_cursor="$GITHUB_SHA"', resolution)
        self.assertIn("git rev-list --parents -n 1", resolution)
        self.assertIn("publisher repair history must be linear", resolution)
        self.assertIn('[ "$repair_commit_count" -le 4 ]', resolution)
        self.assertIn(
            "publisher repair permits at most four workflow-only commits", resolution
        )
        self.assertIn("git diff --no-renames --name-only -z", resolution)
        self.assertIn("read -r -d '' repair_file", resolution)
        self.assertIn("repair_file_count", resolution)
        self.assertIn("git ls-tree", resolution)
        self.assertIn('[ "$repair_mode" = 100644 ]', resolution)
        self.assertIn('[ "$repair_type" = blob ]', resolution)
        self.assertIn("repair_has_workflow=true", resolution)
        self.assertIn("repair_has_contract=true", resolution)
        self.assertIn("repair_has_checkpoint=true", resolution)
        self.assertIn("must change exactly the workflow", resolution)
        self.assertIn(
            "for repair_workflow in ci.yml dependency-audit.yml", resolution
        )
        self.assertIn('select(.head_sha == \\"$repair_cursor\\")', resolution)
        self.assertIn('"head_branch": "main"', resolution)
        self.assertIn('"event": "push"', resolution)
        self.assertIn('"path": f".github/workflows/{workflow}"', resolution)
        self.assertIn("repair run belongs to a different repository", resolution)
        self.assertIn('"checks", "packaged-app-lifecycle"', resolution)
        self.assertIn('"Required dependency audit"', resolution)
        self.assertIn("repair run job list is incomplete", resolution)
        self.assertIn('case "$repair_commit_count" in', resolution)
        self.assertIn("3|4) ;;", resolution)
        self.assertIn("three or four validated repair commits", resolution)
        self.assertIn(
            "publisher repair requires all four exact evidence run IDs", publication
        )
        self.assertIn('echo "source_commit=$source_commit"', resolution)
        self.assertIn(
            "release-candidate-${{ steps.ver.outputs.source_commit }}", publication
        )
        self.assertIn('--source-commit "$SOURCE_COMMIT"', publication)
        self.assertIn('--source-digest "$SOURCE_COMMIT"', publication)
        self.assertIn(
            "target_commitish: ${{ steps.ver.outputs.source_commit }}", publication
        )
        self.assertNotIn("${{ github.sha }}", publication)
        publisher_attestation_start = publication.index(
            "- name: Verify tag-specific publisher attestations"
        )
        publisher_attestation_end = publication.index(
            "- name: Write release notes", publisher_attestation_start
        )
        publisher_attestation = publication[
            publisher_attestation_start:publisher_attestation_end
        ]
        product_publication = (
            publication[:publisher_attestation_start]
            + publication[publisher_attestation_end:]
        )
        self.assertNotIn("$GITHUB_SHA", product_publication)
        self.assertIn('--source-digest "$GITHUB_SHA"', publisher_attestation)

    def test_publisher_installs_and_preflights_locked_runtime_dependencies(self) -> None:
        workflow = (ROOT / ".github/workflows/build-app.yml").read_text(
            encoding="utf-8"
        )
        install_start = workflow.index(
            "- name: Install and preflight locked release verification dependencies"
        )
        download_start = workflow.index(
            "- uses: actions/download-artifact@", install_start
        )
        verify_start = workflow.index(
            "- name: Verify exact immutable candidate and qualification proof"
        )
        install = workflow[install_start:download_start]

        self.assertIn("cache: pip", workflow)
        self.assertIn("cache-dependency-path: spike/requirements-runtime.txt", workflow)
        self.assertIn("--only-binary=:all:", install)
        self.assertIn("--require-hashes", install)
        self.assertIn("-r spike/requirements-runtime.txt", install)
        self.assertIn("python3 -m pip check", install)
        self.assertIn(
            "PYTHONPATH=scripts python3 -c 'import verify_release_artifacts'",
            install,
        )
        self.assertLess(install_start, download_start)
        self.assertLess(download_start, verify_start)

    def test_publisher_repair_allowlist_exposes_rename_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)

            def git(*args: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ("git", "-C", str(repo), *args),
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=5,
                )

            git("init", "-q")
            git("config", "user.name", "Slipstream Tests")
            git("config", "user.email", "tests@slipstream.invalid")
            product_path = repo / "app-tauri/src/product.rs"
            product_path.parent.mkdir(parents=True)
            product_path.write_text("product source\n", encoding="utf-8")
            git("add", "app-tauri/src/product.rs")
            git("commit", "-qm", "Add product source")
            (repo / ".github/workflows").mkdir(parents=True)
            git(
                "mv",
                "app-tauri/src/product.rs",
                ".github/workflows/build-app.yml",
            )

            changed = set(
                git("diff", "--no-renames", "--name-only", "HEAD")
                .stdout.strip()
                .splitlines()
            )
            allowlist = {
                ".github/workflows/build-app.yml",
                "docs/CURRENT_STATE.md",
                "scripts/test_build_config.py",
            }
            self.assertEqual(
                changed,
                {
                    "app-tauri/src/product.rs",
                    ".github/workflows/build-app.yml",
                },
            )
            self.assertFalse(changed <= allowlist)

    def test_publisher_repair_history_is_exact_linear_and_per_edge_allowlisted(
        self,
    ) -> None:
        allowlist = {
            ".github/workflows/build-app.yml",
            "docs/CURRENT_STATE.md",
            "scripts/test_build_config.py",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)

            def git(*args: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ("git", "-C", str(repo), *args),
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=5,
                )

            def commit_repair(text: str, message: str) -> str:
                for path, suffix in (
                    (workflow, "workflow"),
                    (contract, "contract"),
                    (checkpoint, "checkpoint"),
                ):
                    path.write_text(f"{text} {suffix}\n", encoding="utf-8")
                git("add", *sorted(allowlist))
                git("commit", "-qm", message)
                return git("rev-parse", "HEAD").stdout.strip()

            def valid_repair_chain(
                source: str,
                first_repair: str,
                second_repair: str,
                head: str,
            ) -> bool:
                first_lineage = git(
                    "rev-list", "--parents", "-n", "1", first_repair
                )
                second_lineage = git(
                    "rev-list", "--parents", "-n", "1", second_repair
                )
                if first_lineage.stdout.split() != [first_repair, source]:
                    return False
                if second_lineage.stdout.split() != [second_repair, first_repair]:
                    return False
                if subprocess.run(
                    (
                        "git",
                        "-C",
                        str(repo),
                        "merge-base",
                        "--is-ancestor",
                        second_repair,
                        head,
                    ),
                    capture_output=True,
                    check=False,
                    timeout=5,
                ).returncode != 0:
                    return False
                cursor = head
                count = 0
                while cursor != source:
                    lineage = git("rev-list", "--parents", "-n", "1", cursor)
                    commits = lineage.stdout.split()
                    if len(commits) != 2 or commits[0] != cursor:
                        return False
                    parent = commits[1]
                    count += 1
                    if count > 4:
                        return False
                    changed = set(
                        git(
                            "diff",
                            "--no-renames",
                            "--name-only",
                            parent,
                            cursor,
                        )
                        .stdout.strip()
                        .splitlines()
                    )
                    if changed != allowlist:
                        return False
                    for path in changed:
                        for tree in (parent, cursor):
                            entry = git("ls-tree", tree, "--", path).stdout.split()
                            if len(entry) < 3 or entry[:2] != ["100644", "blob"]:
                                return False
                    cursor = parent
                return 3 <= count <= 4

            git("init", "-q", "-b", "main")
            git("config", "user.name", "Slipstream Tests")
            git("config", "user.email", "tests@slipstream.invalid")
            workflow = repo / ".github/workflows/build-app.yml"
            contract = repo / "scripts/test_build_config.py"
            checkpoint = repo / "docs/CURRENT_STATE.md"
            product = repo / "app-tauri/src/product.rs"
            for path in (workflow, contract, checkpoint, product):
                path.parent.mkdir(parents=True, exist_ok=True)
            product.write_text("qualified product\n", encoding="utf-8")
            source = commit_repair("qualified", "Qualified source")
            git("add", "app-tauri/src/product.rs")
            git("commit", "--amend", "-qm", "Qualified source")
            source = git("rev-parse", "HEAD").stdout.strip()
            first = commit_repair("repair one", "First publisher repair")
            second = commit_repair("repair two", "Second publisher repair")
            third = commit_repair("repair three", "Third publisher repair")
            fourth = commit_repair("repair four", "Fourth publisher repair")
            fifth = commit_repair("repair five", "Fifth publisher repair")
            self.assertTrue(valid_repair_chain(source, first, second, third))
            self.assertTrue(valid_repair_chain(source, first, second, fourth))
            self.assertFalse(valid_repair_chain(source, first, second, second))
            self.assertFalse(valid_repair_chain(source, first, second, fifth))
            self.assertFalse(valid_repair_chain(source, source, second, third))
            self.assertFalse(valid_repair_chain(source, first, third, third))

            git("checkout", "-qb", "bypass-second", first)
            commit_repair("parallel repair two", "Parallel second repair")
            bypass_third = commit_repair(
                "parallel repair three", "Parallel third repair"
            )
            self.assertFalse(
                valid_repair_chain(source, first, second, bypass_third)
            )

            git("checkout", "-qb", "reverted-product", second)
            product.write_text("modified product\n", encoding="utf-8")
            commit_repair("bad repair three", "Modify product")
            git("add", "app-tauri/src/product.rs")
            git("commit", "--amend", "-qm", "Modify product")
            product.write_text("qualified product\n", encoding="utf-8")
            commit_repair("bad repair four", "Revert product")
            git("add", "app-tauri/src/product.rs")
            git("commit", "--amend", "-qm", "Revert product")
            bad_fourth = git("rev-parse", "HEAD").stdout.strip()
            self.assertFalse(
                valid_repair_chain(source, first, second, bad_fourth)
            )

            git("checkout", "-qb", "type-change", second)
            checkpoint.unlink()
            checkpoint.symlink_to("../scripts/test_build_config.py")
            commit_repair("type repair three", "Change path type")
            git("add", "docs/CURRENT_STATE.md")
            git("commit", "--amend", "-qm", "Change path type")
            checkpoint.unlink()
            type_fourth = commit_repair("type repair four", "Restore path type")
            self.assertFalse(
                valid_repair_chain(source, first, second, type_fourth)
            )

            git("checkout", "-qb", "side", second)
            git("commit", "--allow-empty", "-qm", "Side repair")
            git("checkout", "-qb", "merge-repair", second)
            commit_repair("merge base repair", "Merge base repair")
            git("merge", "--no-ff", "-s", "ours", "-qm", "Merge repair", "side")
            merge = git("rev-parse", "HEAD").stdout.strip()
            self.assertFalse(valid_repair_chain(source, first, second, merge))

            git("checkout", "-qb", "unrelated")
            unrelated_source = commit_repair("unrelated", "Unrelated source")
            self.assertFalse(
                valid_repair_chain(unrelated_source, first, second, third)
            )

    def test_stable_channel_stays_closed_until_notarization_exists(self) -> None:
        workflow = (ROOT / ".github/workflows/build-app.yml").read_text(
            encoding="utf-8"
        )
        gate = workflow.index("- name: Keep incomplete stable channel closed")
        checkout = workflow.index("- uses: actions/checkout@")

        self.assertLess(gate, checkout)
        self.assertIn("if: github.event_name == 'push'", workflow[gate:checkout])
        self.assertIn("Stable release publication is disabled", workflow[gate:checkout])
        self.assertIn("exit 1", workflow[gate:checkout])

    def test_build_dependency_helper_skips_homebrew_when_tools_exist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bin_dir = Path(temporary)
            for command in ("protoc", "cmake", "pkg-config"):
                write_executable(bin_dir / command)
            marker = bin_dir / "brew-called"
            brew = bin_dir / "brew"
            write_executable(brew, ': > "$SLIPSTREAM_BREW_MARKER"\nexit 97\n')

            result = self.run_build_deps(
                bin_dir,
                brew,
                SLIPSTREAM_BREW_MARKER=str(marker),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(marker.exists())

    def test_build_dependency_helper_installs_only_missing_formula(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bin_dir = Path(temporary)
            for command in ("cmake", "pkg-config"):
                write_executable(bin_dir / command)
            log = bin_dir / "brew.log"
            auto_update_log = bin_dir / "brew-auto-update.log"
            brew = bin_dir / "brew"
            write_executable(
                brew,
                """printf '%s\\n' \"$*\" > \"$SLIPSTREAM_BREW_LOG\"
printf '%s\\n' \"$HOMEBREW_NO_AUTO_UPDATE\" > \"$SLIPSTREAM_BREW_AUTO_UPDATE_LOG\"
printf '#!/bin/bash\\nexit 0\\n' > \"$SLIPSTREAM_FAKE_BIN/protoc\"
/bin/chmod +x \"$SLIPSTREAM_FAKE_BIN/protoc\"
""",
            )

            result = self.run_build_deps(
                bin_dir,
                brew,
                SLIPSTREAM_BREW_LOG=str(log),
                SLIPSTREAM_BREW_AUTO_UPDATE_LOG=str(auto_update_log),
                SLIPSTREAM_FAKE_BIN=str(bin_dir),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                log.read_text(encoding="utf-8").strip(), "install protobuf"
            )
            self.assertEqual(auto_update_log.read_text(encoding="utf-8").strip(), "1")

    def test_build_dependency_helper_installs_multiple_formulae_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bin_dir = Path(temporary)
            write_executable(bin_dir / "pkg-config")
            log = bin_dir / "brew.log"
            brew = bin_dir / "brew"
            write_executable(
                brew,
                """printf '%s\\n' \"$*\" >> \"$SLIPSTREAM_BREW_LOG\"
for command in protoc cmake; do
  printf '#!/bin/bash\\nexit 0\\n' > \"$SLIPSTREAM_FAKE_BIN/$command\"
  /bin/chmod +x \"$SLIPSTREAM_FAKE_BIN/$command\"
done
""",
            )

            result = self.run_build_deps(
                bin_dir,
                brew,
                SLIPSTREAM_BREW_LOG=str(log),
                SLIPSTREAM_FAKE_BIN=str(bin_dir),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                log.read_text(encoding="utf-8").splitlines(),
                ["install protobuf cmake"],
            )

    def test_build_dependency_helper_propagates_homebrew_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bin_dir = Path(temporary)
            for command in ("cmake", "pkg-config"):
                write_executable(bin_dir / command)
            brew = bin_dir / "brew"
            write_executable(brew, 'printf "brew failed\\n" >&2\nexit 42\n')

            result = self.run_build_deps(bin_dir, brew)

            self.assertEqual(result.returncode, 42)
            self.assertIn("brew failed", result.stderr)

    def test_build_dependency_helper_rejects_false_install_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bin_dir = Path(temporary)
            for command in ("cmake", "pkg-config"):
                write_executable(bin_dir / command)
            brew = bin_dir / "brew"
            write_executable(brew)

            result = self.run_build_deps(bin_dir, brew)

            self.assertEqual(result.returncode, 1)
            self.assertIn("still unavailable: protoc", result.stderr)

    def test_wintun_crash_gate_retains_one_bounded_process_handle(self) -> None:
        workflow = (
            ROOT / ".github/workflows/windows-packet-adapter-qualification.yml"
        ).read_text(encoding="utf-8")
        runner = (ROOT / "scripts/run_bounded_windows_cargo_test.ps1").read_text(
            encoding="utf-8"
        )

        self.assertIn("scripts/run_bounded_windows_cargo_test.ps1", workflow)
        self.assertIn("-TimeoutSeconds 120", workflow)
        self.assertNotIn("Tee-Object -Variable output", workflow)
        self.assertIn("Start-Process", runner)
        self.assertIn("function Stop-RetainedProcessTree", runner)
        self.assertIn("$process.WaitForExit(250)", runner)
        self.assertNotIn("$process.WaitForExit()", runner)
        self.assertIn("$drainTimer.ElapsedMilliseconds -lt 2000", runner)
        self.assertNotIn("$stableSamples", runner)
        self.assertIn("$Process.Kill($true)", runner)
        self.assertIn("if (-not $Process.WaitForExit($WaitMilliseconds))", runner)
        self.assertIn("throw $cleanupFailure", runner)
        self.assertNotIn("[void]$process.WaitForExit", runner)
        self.assertIn("RedirectStandardOutput", runner)
        self.assertIn("RedirectStandardError", runner)
        for forbidden in (
            "Get-Process",
            "Stop-Process",
            "taskkill",
            "Win32_Process",
            "ProcessName",
        ):
            self.assertNotIn(forbidden, runner)


if __name__ == "__main__":
    unittest.main()
