from __future__ import annotations

import json
import os
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class BuildConfigTests(unittest.TestCase):
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
        self.assertEqual(scripts["build"], "npm run build:release")

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

    def test_release_workflow_uses_the_recorded_verified_geph_artifact(self) -> None:
        workflow = (ROOT / ".github/workflows/build-app.yml").read_text(encoding="utf-8")

        self.assertIn('version="$(tr -d \'[:space:]\' < vendor/geph/VERSION)"', workflow)
        self.assertIn('tag="geph-vendor-$version"', workflow)
        self.assertIn("--pattern 'geph5-client.VERSION'", workflow)
        self.assertIn("--pattern 'geph5-client.LICENSE'", workflow)
        self.assertIn("--pattern 'SHA256SUMS'", workflow)
        self.assertIn('asset_version="$(tr -d \'[:space:]\' < /tmp/geph/geph5-client.VERSION)"', workflow)
        self.assertIn('"$asset_version" = "$version"', workflow)
        self.assertIn("shasum -a 256 -c SHA256SUMS", workflow)
        self.assertNotIn("select(startswith(\"geph-vendor-\"))", workflow)

    def test_release_workflow_keeps_manual_previews_off_the_stable_feed(self) -> None:
        workflow = (ROOT / ".github/workflows/build-app.yml").read_text(encoding="utf-8")

        self.assertIn('tag="v${v}-preview.${GITHUB_RUN_NUMBER}"', workflow)
        self.assertIn('prerelease="true"', workflow)
        self.assertIn('prerelease="false"', workflow)
        self.assertIn("prerelease: ${{ steps.ver.outputs.prerelease }}", workflow)
        self.assertIn("Manual runs produce prereleases", workflow)

    def test_release_workflow_requires_remote_policy_only_for_stable(self) -> None:
        workflow = (ROOT / ".github/workflows/build-app.yml").read_text(encoding="utf-8")

        self.assertIn("if: steps.ver.outputs.channel == 'stable'", workflow)
        self.assertIn('--channel "${{ steps.ver.outputs.channel }}"', workflow)
        self.assertIn("Preview releases omit the remote policy channel.", workflow)

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


if __name__ == "__main__":
    unittest.main()
