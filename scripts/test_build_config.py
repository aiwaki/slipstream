from __future__ import annotations

import json
import os
import re
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
        self.assertIn('--source-commit "$GITHUB_SHA"', workflow)
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
        self.assertIn('select(.head_sha == \\"$GITHUB_SHA\\")', resolution)
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
        self.assertIn("scripts/release_candidate.py create-proof", qualification)
        self.assertIn("Attest exact qualification proof", qualification)
        proof_block = qualification[
            qualification.index(
                "Bind qualification proof to the exact candidate"
            ) : qualification.index("Attest exact qualification proof")
        ]
        self.assertIn("--expected-candidate-run-attempt", proof_block)
        self.assertIn(
            '--app-tree "$RUNNER_TEMP/candidate-app/Slipstream.app"', proof_block
        )
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
        self.assertIn('value.get("ready") is not True', readiness)
        self.assertLess(
            readiness.index("Require passed live-site matrix before the long soak"),
            readiness.index("Run measured 30-minute background invisibility soak"),
        )
        self.assertIn("scripts/release_readiness.py create", readiness)
        self.assertIn("scripts/packaged_transport_mechanics_smoke.py", readiness)
        self.assertIn("dist-readiness/transport-mechanics.json", readiness)
        self.assertNotIn("Slipstream-transport-matrix-${{ github.sha }}", readiness)
        self.assertNotIn("scripts/release_transport_matrix.py create", ci)
        self.assertIn("Attest exact release-readiness evidence", readiness)
        self.assertIn("--expected-workflow-run-attempt", readiness)
        self.assertNotIn("Build the frozen daemon", readiness)
        self.assertNotIn("Build the packaged app", readiness)

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
        self.assertIn(
            "${{ github.repository }}/.github/workflows/owned-geph-qualification.yml",
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
        self.assertIn("-verify_arch arm64 x86_64", geph)
        self.assertLess(
            geph.index("scripts/dependency_audit.py verify"),
            geph.index("gh attestation verify"),
        )
        copy_index = geph.index("cp /tmp/geph/geph5-client")
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
        self.assertIn("target_commitish: ${{ github.sha }}", draft)

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

        self.assertIn("target_commitish: ${{ github.sha }}", workflow)
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
        self.assertIn('--source-digest "$GITHUB_SHA"', workflow)
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
        self.assertIn("owned-geph-qualification.yml", workflow)
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
            "runtime": {"certifi", "cryptography", "scapy"},
            "test": {"certifi", "cryptography", "pytest", "scapy"},
            "build": {"certifi", "cryptography", "pyinstaller", "scapy"},
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
        self.assertIn('test(\\"$tag_pattern\\")', app)
        self.assertIn("-preview\\.[0-9]+$", app)
        self.assertIn("previous_tag: ${{ steps.previous.outputs.tag }}", app)
        self.assertIn(".prerelease == $prerelease", app)
        self.assertIn("gh api --paginate", app)
        self.assertNotIn('cp "$B/dmg/"*.dmg "$OUT/" 2>/dev/null || true', app)

        self.assertIn('branches: ["main"]', geph)
        self.assertIn("prerelease: true", geph)
        self.assertIn("make_latest: false", geph)
        self.assertIn("This is not an app release", geph)

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
