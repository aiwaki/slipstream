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
    "actions/cache": (
        "55cc8345863c7cc4c66a329aec7e433d2d1c52a9",
        "v6.1.0",
    ),
    "actions/upload-artifact": (
        "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "v7.0.1",
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
        config = json.loads((ROOT / "app-tauri/src-tauri/tauri.local.conf.json").read_text())

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

    def test_packaged_workflows_use_the_explicit_tauri_target(self) -> None:
        workflow_names = (
            "build-app.yml",
            "ci.yml",
            "owned-geph-qualification.yml",
        )
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

    def test_release_workflow_packages_signed_route_policy_channel(self) -> None:
        workflow = (ROOT / ".github/workflows/build-app.yml").read_text(encoding="utf-8")

        self.assertIn("Prepare route policy trust keys", workflow)
        self.assertIn("SLIP_ROUTE_POLICY_PUBLIC_KEYS_JSON", workflow)
        self.assertIn("spike/route-policy-keys.json", workflow)
        self.assertIn("Package signed route policy channel", workflow)
        self.assertIn("SLIP_ROUTE_POLICY_PRIVATE_KEY", workflow)
        self.assertIn("spike/.buildvenv/bin/python -m unittest", workflow)
        self.assertIn("--bundled-manifest", workflow)
        self.assertIn("--channel-index", workflow)
        self.assertIn("route-policy-latest.json", workflow)
        self.assertIn("dist-release/route-policy.json", workflow)
        self.assertIn("Verify release artifacts", workflow)
        self.assertIn("scripts/verify_release_artifacts.py", workflow)
        self.assertIn("--release-dir dist-release", workflow)
        self.assertIn("Build deterministic target SPDX SBOM", workflow)
        self.assertIn("scripts/make_release_sbom.py", workflow)
        self.assertIn("Resolve target dependency graph", workflow)
        self.assertIn("cargo metadata", workflow)
        self.assertIn("--filter-platform \"$SLIPSTREAM_TAURI_TARGET\"", workflow)
        self.assertIn("--cargo-metadata /tmp/slipstream-cargo-metadata.json", workflow)
        self.assertIn("--geph-source-file vendor/geph/SOURCE.json", workflow)
        self.assertIn("Audit release dependencies", workflow)
        self.assertIn("scripts/dependency_audit.py scan", workflow)
        self.assertIn("security/dependency-audit-policy.json", workflow)
        self.assertIn("dist-release/dependency-audit.json", workflow)
        self.assertIn("Build release artifact manifest", workflow)
        self.assertIn("scripts/make_release_manifest.py", workflow)
        self.assertIn("dist-release/Slipstream.spdx.json", workflow)
        self.assertIn("dist-release/artifact-manifest.json", workflow)
        self.assertIn('--source-commit "$GITHUB_SHA"', workflow)
        self.assertIn('--target "$SLIPSTREAM_TAURI_TARGET"', workflow)

    def test_dependency_audit_runs_on_changes_and_on_a_schedule(self) -> None:
        workflow = (
            ROOT / ".github/workflows/dependency-audit.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("pull_request:", workflow)
        self.assertIn("schedule:", workflow)
        self.assertIn('cron: "17 4 * * 1"', workflow)
        self.assertIn("--platform linux-amd64", workflow)
        self.assertIn("--filter-platform \"$SLIPSTREAM_TAURI_TARGET\"", workflow)
        self.assertIn("scripts/dependency_audit.py scan", workflow)
        self.assertIn("scripts/dependency_audit.py verify", workflow)
        self.assertIn("dist-audit/dependency-audit.json", workflow)
        self.assertIn("geph-vendor-audit:", workflow)
        self.assertIn("scripts/geph_vendor_source.py extract", workflow)
        self.assertIn("scripts/make_geph_vendor_sbom.py generate", workflow)
        self.assertIn("security/geph-dependency-audit-policy.json", workflow)
        self.assertIn("--vendored-transitive-dependencies full", workflow)

    def test_release_workflow_uses_the_recorded_verified_geph_artifact(self) -> None:
        workflow = (ROOT / ".github/workflows/build-app.yml").read_text(encoding="utf-8")

        self.assertIn('version="$(tr -d \'[:space:]\' < vendor/geph/VERSION)"', workflow)
        self.assertIn('json.load(open("vendor/geph/SOURCE.json"))["release_revision"]', workflow)
        self.assertIn('tag="geph-vendor-$version-r$release_revision"', workflow)
        self.assertIn("--pattern 'geph5-client.VERSION'", workflow)
        self.assertIn("--pattern 'geph5-client.LICENSE'", workflow)
        self.assertIn("--pattern 'geph5-client.SOURCE.json'", workflow)
        self.assertIn("--pattern 'geph5-client.Cargo.lock'", workflow)
        self.assertIn("--pattern 'geph5-client.spdx.json'", workflow)
        self.assertIn("--pattern 'geph5-client-dependency-audit.json'", workflow)
        self.assertIn("--pattern 'SHA256SUMS'", workflow)
        self.assertIn('asset_version="$(tr -d \'[:space:]\' < /tmp/geph/geph5-client.VERSION)"', workflow)
        self.assertIn('"$asset_version" = "$version"', workflow)
        self.assertIn("shasum -a 256 -c SHA256SUMS", workflow)
        self.assertIn("cmp /tmp/geph/geph5-client.SOURCE.json vendor/geph/SOURCE.json", workflow)
        self.assertIn("--vendored-transitive-dependencies full", workflow)
        self.assertIn("release_revision", workflow)
        self.assertIn("scripts/make_geph_vendor_sbom.py verify", workflow)
        self.assertIn('commits/$tag" --jq .sha', workflow)
        self.assertIn('"$vendor_commit" = "$tag_commit"', workflow)
        self.assertIn(".github/workflows/build-geph.yml", workflow)
        self.assertIn("--predicate-type https://spdx.dev/Document/v2.3", workflow)
        self.assertIn("geph5-client-current-audit.json", workflow)
        self.assertIn('--evaluation-date "$(date -u +%F)"', workflow)
        self.assertNotIn("select(startswith(\"geph-vendor-\"))", workflow)

    def test_release_workflow_keeps_manual_previews_off_the_stable_feed(self) -> None:
        workflow = (ROOT / ".github/workflows/build-app.yml").read_text(encoding="utf-8")

        self.assertIn('tag="v${v}-preview.${GITHUB_RUN_NUMBER}"', workflow)
        self.assertIn('prerelease="true"', workflow)
        self.assertIn('prerelease="false"', workflow)
        self.assertIn("prerelease: ${{ steps.ver.outputs.prerelease }}", workflow)
        self.assertIn("Manual runs produce prereleases", workflow)

    def test_release_workflow_binds_tags_and_notes_to_the_built_commit(self) -> None:
        workflow = (ROOT / ".github/workflows/build-app.yml").read_text(encoding="utf-8")

        self.assertIn("target_commitish: ${{ github.sha }}", workflow)
        self.assertIn("select(.draft | not)", workflow)
        self.assertIn('[ "$GITHUB_REF" = "refs/heads/main" ]', workflow)

    def test_release_workflow_attests_only_verified_payloads(self) -> None:
        workflow = (ROOT / ".github/workflows/build-app.yml").read_text(encoding="utf-8")

        self.assertIn("id-token: write", workflow)
        self.assertIn("attestations: write", workflow)
        self.assertIn("artifact-metadata: write", workflow)
        self.assertEqual(
            workflow.count(
                "uses: actions/attest@a1948c3f048ba23858d222213b7c278aabede763"
            ),
            2,
        )
        self.assertIn("Attest verified release provenance", workflow)
        self.assertIn("subject-path: dist-release/*", workflow)
        self.assertIn("Attest application SBOM", workflow)
        self.assertIn("sbom-path: dist-release/Slipstream.spdx.json", workflow)
        self.assertIn("Verify stored release attestations", workflow)
        self.assertIn("gh attestation verify", workflow)
        self.assertIn('--source-digest "$GITHUB_SHA"', workflow)
        self.assertIn("--predicate-type https://spdx.dev/Document/v2.3", workflow)
        self.assertIn("--deny-self-hosted-runners", workflow)
        self.assertIn(
            "gh attestation verify Slipstream-macos-arm64.zip --repo",
            workflow,
        )
        self.assertLess(
            workflow.index("Verify release artifacts"),
            workflow.index("Attest verified release provenance"),
        )
        self.assertLess(
            workflow.index("Attest application SBOM"),
            workflow.index("Publish release"),
        )

    def test_release_workflow_requires_remote_policy_only_for_stable(self) -> None:
        workflow = (ROOT / ".github/workflows/build-app.yml").read_text(encoding="utf-8")

        self.assertIn("if: steps.ver.outputs.channel == 'stable'", workflow)
        self.assertIn('--channel "${{ steps.ver.outputs.channel }}"', workflow)
        self.assertIn("не содержит remote policy assets", workflow)
        self.assertIn("подписанным каналом route policy", workflow)

    def test_release_workflow_qualifies_the_built_app_before_publish(self) -> None:
        workflow = (ROOT / ".github/workflows/build-app.yml").read_text(encoding="utf-8")
        wrapper = (ROOT / "scripts/run_packaged_lifecycle_smoke.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("Qualify the release app lifecycle", workflow)
        self.assertIn('SLIPSTREAM_DISPOSABLE_CI: "1"', workflow)
        self.assertIn("scripts/run_packaged_lifecycle_smoke.sh", workflow)
        self.assertIn("scripts/pf_installed_lifecycle_smoke.py", wrapper)
        self.assertIn('--app-bundle "$app_bundle"', wrapper)
        self.assertIn("GITHUB_ACTIONS", wrapper)
        self.assertIn("--safaridriver-url", wrapper)
        self.assertNotIn("driver_port=19445", wrapper)
        self.assertIn('sock.bind(("127.0.0.1", 0))', wrapper)
        self.assertIn("for attempt in 1 2", wrapper)
        self.assertIn("Unable to start the server:", wrapper)
        self.assertIn("retrying once on a fresh loopback port", wrapper)

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
        self.assertIn("vendor/geph/SOURCE.json", workflow)
        self.assertIn("vendor/geph/Cargo.lock", workflow)
        self.assertIn("needs.resolve.outputs.should_prepare == 'true'", workflow)
        self.assertIn("needs.resolve.outputs.should_build == 'true'", workflow)
        self.assertIn("cargo install", workflow)
        self.assertIn("--locked", workflow)
        self.assertIn("--path \"$source_root\"", workflow)
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
            workflow.index("scripts/dependency_audit.py verify"),
            workflow.index("Publish the verified internal dependency release"),
        )

    def test_external_actions_use_reviewed_immutable_pins(self) -> None:
        pattern = re.compile(
            r"uses:\s+([^\s@]+)@([0-9a-f]{40})\s+#\s+([^\s]+)"
        )
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
                self.assertIsNotNone(match, f"unlocked requirement in {path}: {requirement}")
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
            ROOT / ".github/workflows/build-app.yml",
            ROOT / ".github/workflows/ci.yml",
            ROOT / ".github/workflows/owned-geph-qualification.yml",
            ROOT / "spike/build_daemon.sh",
        ]
        combined = "\n".join(path.read_text(encoding="utf-8") for path in build_sources)

        self.assertGreaterEqual(combined.count("requirements-build.txt"), 4)
        self.assertGreaterEqual(combined.count("--require-hashes"), 5)
        self.assertGreaterEqual(combined.count("--only-binary=:all:"), 5)
        self.assertNotIn("-r spike/requirements.txt pyinstaller", combined)
        self.assertNotIn("scapy cryptography certifi pyinstaller", combined)
        self.assertNotIn("pip install --quiet --upgrade pip", combined)

        source_installer = (ROOT / "spike/tproxy.py").read_text(encoding="utf-8")
        install_start = source_installer.index('if not os.path.exists(py):')
        install_end = source_installer.index('prog_args = [py, script', install_start)
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
        for name in ("build-app.yml", "build-geph.yml"):
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

        self.assertIn('make_latest="true"', app)
        self.assertIn('make_latest="false"', app)
        self.assertIn("make_latest: ${{ steps.ver.outputs.make_latest }}", app)
        self.assertIn('release_name="Slipstream $v (preview ${GITHUB_RUN_NUMBER})"', app)
        self.assertIn("body_path: dist-release/release-notes.md", app)
        self.assertIn("generate_release_notes: true", app)
        self.assertIn("Resolve previous app release tag", app)
        self.assertIn('startswith(\\"v\\")', app)
        self.assertIn("previous_tag: ${{ steps.previous.outputs.tag }}", app)
        self.assertIn(".prerelease == $prerelease", app)
        self.assertIn("gh api --paginate", app)
        self.assertNotIn('cp "$B/dmg/"*.dmg "$OUT/" 2>/dev/null || true', app)

        self.assertIn('branches: ["main"]', geph)
        self.assertIn("prerelease: true", geph)
        self.assertIn("make_latest: false", geph)
        self.assertIn("This is not an app release", geph)

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
            self.assertEqual(log.read_text(encoding="utf-8").strip(), "install protobuf")
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


if __name__ == "__main__":
    unittest.main()
