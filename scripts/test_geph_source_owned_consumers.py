"""Run consumer workflow Bash with inert CLIs; no network, scanner or Geph build."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
OWNED_ASSET = "geph5-client-source-review-evidence.tar"
NATIVE_ASSET = "geph5-client-native-sqlite-evidence.tar"


def workflow_shell(filename: str, name: str) -> str:
    text = (ROOT / ".github/workflows" / filename).read_text()
    step = text.split("      - name: " + name + "\n", 1)[1]
    lines = step.split("        run: |\n", 1)[1].splitlines()
    body = []
    for line in lines:
        if line and not line.startswith("          "):
            break
        body.append(line[10:])
    return "\n".join(body).replace("${{ github.repository }}", "fixture/slipstream")


DRIVER = textwrap.dedent(r'''
    import json, sys
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    fixture = json.loads((root / "fixture.json").read_text())
    owned, native, failure = (fixture[key] for key in ("owned", "native", "failure"))
    name, args = Path(sys.argv[0]).name, sys.argv[1:]
    with (root / "commands.jsonl").open("a") as log:
        log.write(json.dumps({"name": name, "args": args}) + "\n")
    def value(flag): return args[args.index(flag) + 1]
    def fail(stage):
        if failure == stage: raise SystemExit("controlled refusal: " + stage)
    def require_historical(path):
        assert json.loads(Path(path).read_text()) == {"historical": True}
    owned_asset = "geph5-client-source-review-evidence.tar"
    native_asset = "geph5-client-native-sqlite-evidence.tar"
    if name == "geph_vendor_source.py":
        assert value("--source") == "vendor/geph/SOURCE.json"
        if args[0] == "verify":
            fail("source")
            summary = {"release_tag": "geph-vendor-0.4.3-r1", "embedded_packages": {"package": {}} if owned else {}}
            if native: summary["native_sqlite"] = "reviewed"
            print(json.dumps(summary))
        else:
            assert native
            assert Path(value("--native-sqlite-archive")).is_file()
            materialized = Path(value("--output")) / "independent-source"
            materialized.mkdir(parents=True)
            (materialized / "marker").write_text("independent")
            print(json.dumps({"root": str(materialized)}))
    elif name == "gh":
        if args[0] == "api":
            endpoint = args[-1]
            if "/git/ref/tags/" in endpoint:
                print(json.dumps({"object": {"type": "commit", "sha": "a" * 40}}))
            elif "/contents/" in endpoint:
                assert endpoint.endswith("?ref=" + "a" * 40)
                print("invalid policy" if failure == "policy" else '{"historical":true}')
            else: print('{}')
        else:
            assert args[:2] == ["attestation", "verify"]
            assert value("--signer-digest") == value("--source-digest") == "a" * 40
            fail("attestations")
            print('{}')
    elif name == "download_github_release_assets.py":
        patterns = [args[i + 1] for i, arg in enumerate(args) if arg == "--pattern"]
        assert (owned_asset in patterns) == owned
        assert (native_asset in patterns) == native
        assert len(patterns) == len(set(patterns)) == 8 + owned + native
        fail("missing-asset")
        release = Path(value("--output")); assert not release.exists(); release.mkdir()
        for asset in patterns: (release / asset).write_text("fixture asset")
    elif name == "verify_geph_release.py":
        if args[0] == "verify-assets":
            assert ("--source-owned-policy" in args) == owned
            assert ("--source-owned-output-root" in args) == owned
            assert ("--native-output-root" in args) == native
            result = {}
            if owned:
                require_historical(value("--source-owned-policy"))
                target = Path(value("--source-owned-output-root")); assert not target.exists()
                proof = target / "returned-owned-proof"; proof.mkdir(parents=True)
                (proof / "review.json").write_text("retained source review")
                result["source_owned_evidence"] = {"root": str(proof)}
            if native:
                target = Path(value("--native-output-root")); assert not target.exists()
                proof = target / "returned-native-proof"; proof.mkdir(parents=True)
                receipt = proof / "receipt.json"; receipt.write_text('{}')
                result["native_evidence"] = {"receipt_path": str(receipt), "artifacts_root": str(proof)}
            fail("assets")
            if failure == "missing-root": result.pop("source_owned_evidence", None)
            print(json.dumps(result))
        else: print('{}')
    elif name == "make_geph_vendor_sbom.py":
        assert ("--source-root" in args) == native
        if native:
            assert Path(value("--source-root")).joinpath("marker").read_text() == "independent"
            assert Path(value("--native-receipt")).parent.name == "returned-native-proof"
    elif name == "dependency_audit.py":
        if args[0] == "fetch-scanner": raise SystemExit(0)
        assert value("--vendored-transitive-dependencies") == "full"
        standalone = value("--source-commit") == "b" * 40
        assert args.count("--source") == int(owned or (native and not standalone))
        assert ("--source-owned-evidence" in args) == owned
        assert ("--native-receipt" in args) == (native and not standalone)
        assert ("--native-artifacts-root" in args) == (native and not standalone)
        if not standalone:
            assert args[0] == "verify"
            require_historical(value("--policy"))
            if owned:
                proof = Path(value("--source-owned-evidence"))
                assert proof.name == "returned-owned-proof"
                assert (proof / "review.json").read_text() == "retained source review"
            if native: assert Path(value("--native-artifacts-root")).name == "returned-native-proof"
        elif args[0] == "scan":
            assert ("--evidence-dir" in args) == owned
            if owned:
                assert value("--source-owned-evidence") == "security/geph-source-owned-advisories"
                evidence = Path(value("--evidence-dir")); assert not evidence.exists()
                evidence.mkdir(parents=True)
                (evidence / "receipt.json").write_text('{"status":"retained"}')
                (evidence / "source.json").write_bytes(Path(value("--source")).read_bytes())
                (evidence / "source-owned").mkdir()
                (evidence / "source-owned/review.json").write_text("retained source review")
            if native: raise SystemExit("native scan requires explicit build proof")
            fail("scan")
            Path(value("--output")).write_text('{}')
        elif owned:
            assert value("--source") == "dist-geph-audit/evidence/source.json"
            assert value("--source-owned-evidence") == "dist-geph-audit/evidence/source-owned"
            assert Path(value("--source-owned-evidence"), "review.json").read_text() == "retained source review"
        fail("audit" if not standalone else "verify" if args[0] == "verify" else "unused")
    elif name == "curl": Path(value("-o")).write_text("independent archive")
    elif name == "lipo": assert Path(args[0]).is_file()
    else: raise AssertionError((name, args))
''')


class SourceOwnedConsumerWorkflowTests(unittest.TestCase):
    def run_shell(self, workflow: str, step: str, *, owned: bool, native: bool = False,
                  failure: str = "") -> tuple[Path, subprocess.CompletedProcess, list[dict]]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        for directory in ("scripts", "bin", "runner temp", "vendor/geph", "security", "dist-geph-audit"):
            (root / directory).mkdir(parents=True, exist_ok=True)
        (root / "fixture.json").write_text(json.dumps({"owned": owned, "native": native, "failure": failure}))
        (root / "vendor/geph/SOURCE.json").write_text(json.dumps({
            "crate": {"url": "https://invalid.example/geph.crate"},
            "native_sqlite": {"archive": {"url": "https://invalid.example/sqlite.zip"}}}))
        (root / "security/geph-dependency-audit-policy.json").write_text('{"current":true}')
        for name in ("geph_vendor_source.py", "download_github_release_assets.py", "verify_geph_release.py",
                     "make_geph_vendor_sbom.py", "dependency_audit.py"):
            (root / "scripts" / name).write_text(DRIVER)
        for name in ("gh", "curl", "lipo"):
            path = root / "bin" / name
            path.write_text("#!" + str(Path(sys.executable).resolve()) + "\n" + DRIVER)
            path.chmod(0o755)
        (root / "bin/python3").symlink_to(Path(sys.executable).resolve())
        shell = workflow_shell(workflow, step).replace("/usr/bin/lipo", "lipo")
        result = subprocess.run(["/bin/bash", "-c", shell], cwd=root, capture_output=True, text=True,
            timeout=15, env={**os.environ, "PATH": str(root / "bin") + ":/usr/bin:/bin",
                             "RUNNER_TEMP": str(root / "runner temp"), "GITHUB_SHA": "b" * 40})
        commands = [json.loads(line) for line in (root / "commands.jsonl").read_text().splitlines()]
        return root, result, commands

    def test_release_consumer_keeps_legacy_native_and_combined_lanes(self):
        for owned, native in ((False, False), (False, True), (True, False), (True, True)):
            with self.subTest(owned=owned, native=native):
                root, result, commands = self.run_shell("ci.yml", "Fetch and verify the recorded Geph build",
                                                       owned=owned, native=native)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue((root / "app-tauri/src-tauri/binaries/geph5-client-aarch64-apple-darwin").is_file())
                policy = next(i for i, c in enumerate(commands) if c["name"] == "gh" and "/contents/" in c["args"][-1])
                assets = next(i for i, c in enumerate(commands) if c["name"] == "verify_geph_release.py" and c["args"][0] == "verify-assets")
                self.assertLess(policy, assets)
                attested = [Path(c["args"][2]).name for c in commands if c["name"] == "gh" and c["args"][:2] == ["attestation", "verify"]]
                self.assertEqual(OWNED_ASSET in attested, owned)
                self.assertEqual(NATIVE_ASSET in attested, native)

    def test_release_consumer_failures_never_install_payload(self):
        for failure in ("source", "policy", "missing-asset", "assets", "missing-root", "audit", "attestations"):
            with self.subTest(failure=failure):
                root, result, commands = self.run_shell("ci.yml", "Fetch and verify the recorded Geph build",
                                                       owned=True, failure=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / "app-tauri/src-tauri/binaries/geph5-client-aarch64-apple-darwin").exists())
                if failure in ("source", "policy", "missing-asset", "assets", "missing-root"):
                    self.assertNotIn("dependency_audit.py", [c["name"] for c in commands])

    def test_standalone_scan_verifies_retained_source_owned_inputs(self):
        for owned in (False, True):
            with self.subTest(owned=owned):
                root, result, commands = self.run_shell("dependency-audit.yml", "Enforce the Geph dependency policy", owned=owned)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual((root / "dist-geph-audit/evidence/source-owned/review.json").exists(), owned)
                self.assertEqual([c["args"][0] for c in commands if c["name"] == "dependency_audit.py"],
                                 ["fetch-scanner", "scan", "verify"])

    def test_standalone_failure_retains_diagnostics_and_stops_verification(self):
        for failure in ("scan", "verify"):
            with self.subTest(failure=failure):
                root, result, commands = self.run_shell("dependency-audit.yml", "Enforce the Geph dependency policy",
                                                       owned=True, failure=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue((root / "dist-geph-audit/evidence/receipt.json").is_file())
                self.assertTrue((root / "dist-geph-audit/evidence/source-owned/review.json").is_file())
                verified = any(c["name"] == "dependency_audit.py" and c["args"][0] == "verify" for c in commands)
                self.assertEqual(verified, failure == "verify")
        text = (ROOT / ".github/workflows/dependency-audit.yml").read_text().split("  geph-vendor-audit:", 1)[1]
        upload = text.split("      - uses: actions/upload-artifact@", 1)[1].split("  required:", 1)[0]
        self.assertIn("if: always()", upload)
        self.assertIn("path: dist-geph-audit/", upload)

    def test_standalone_native_policy_cannot_pass_without_build_proof(self):
        for owned in (False, True):
            with self.subTest(owned=owned):
                _, result, commands = self.run_shell("dependency-audit.yml", "Enforce the Geph dependency policy",
                                                    owned=owned, native=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("native scan requires explicit build proof", result.stderr)
                self.assertFalse(any(c["name"] == "dependency_audit.py" and c["args"][0] == "verify" for c in commands))


if __name__ == "__main__":
    unittest.main()
