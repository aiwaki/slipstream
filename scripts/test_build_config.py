from __future__ import annotations

import json
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


if __name__ == "__main__":
    unittest.main()
