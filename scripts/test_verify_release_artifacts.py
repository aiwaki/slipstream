from __future__ import annotations

import json
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import make_appcast
import make_route_policy_bundle
import verify_release_artifacts


class VerifyReleaseArtifactsTests(unittest.TestCase):
    def _write_release_dir(self, root: Path, *, tag: str = "v0.1.5") -> None:
        version = "0.1.5"
        repository = "aiwaki/slipstream"
        (root / "Slipstream-macos-arm64.zip").write_bytes(b"zip")
        (root / "Slipstream.app.tar.gz").write_bytes(b"archive")
        (root / "Slipstream.app.tar.gz.sig").write_text("sig-value\n", encoding="utf-8")
        (root / "latest.json").write_text(
            json.dumps(
                make_appcast.build_appcast(
                    version=version,
                    tag=tag,
                    repository=repository,
                    signature="sig-value\n",
                    pub_date="2026-07-09T12:00:00Z",
                ),
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        private_key, public_keys = make_route_policy_bundle.generate_route_policy_keypair(
            key_id="release"
        )
        bundle, _ = make_route_policy_bundle.build_signed_route_policy_bundle(
            manifest=make_route_policy_bundle.tproxy.route_policy_manifest(),
            key_id="release",
            private_key=private_key,
        )
        bundle_path = root / "route-policy.json"
        bundle_path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
        (root / "route-policy-keys.json").write_text(
            json.dumps({"keys": public_keys}, indent=2) + "\n",
            encoding="utf-8",
        )
        channel = make_route_policy_bundle.build_route_policy_channel_index(
            bundle_path=bundle_path,
            bundle_url=(
                f"https://github.com/aiwaki/slipstream/releases/download/"
                f"{tag}/route-policy.json"
            ),
        )
        (root / "route-policy-latest.json").write_text(
            json.dumps(channel, indent=2) + "\n",
            encoding="utf-8",
        )

    def test_accepts_complete_release_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_release_dir(root)

            result = verify_release_artifacts.verify_release_artifacts(
                release_dir=root,
                repository="aiwaki/slipstream",
                tag="v0.1.5",
                version="0.1.5",
            )

            self.assertEqual(result["version"], "0.1.5")
            self.assertEqual(result["route_policy"]["key_id"], "release")
            self.assertEqual(result["route_policy_channel"]["source"], "bundled")

    def test_accepts_preview_release_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tag = "v0.1.5-preview.42"
            self._write_release_dir(root, tag=tag)

            result = verify_release_artifacts.verify_release_artifacts(
                release_dir=root,
                repository="aiwaki/slipstream",
                tag=tag,
                version="0.1.5",
            )

            self.assertEqual(result["tag"], tag)
            self.assertTrue(result["appcast"]["url"].endswith(f"/{tag}/Slipstream.app.tar.gz"))

    def test_rejects_route_policy_channel_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_release_dir(root)
            channel_path = root / "route-policy-latest.json"
            channel = json.loads(channel_path.read_text(encoding="utf-8"))
            channel["sha256"] = "0" * 64
            channel_path.write_text(json.dumps(channel), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "route-policy-latest.json sha256"):
                verify_release_artifacts.verify_release_artifacts(
                    release_dir=root,
                    repository="aiwaki/slipstream",
                    tag="v0.1.5",
                    version="0.1.5",
                )

    def test_rejects_appcast_url_for_wrong_release(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_release_dir(root)
            appcast_path = root / "latest.json"
            appcast = json.loads(appcast_path.read_text(encoding="utf-8"))
            appcast["platforms"][make_appcast.PLATFORM]["url"] = (
                "https://github.com/aiwaki/slipstream/releases/download/"
                "v0.1.4/Slipstream.app.tar.gz"
            )
            appcast_path.write_text(json.dumps(appcast), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "appcast URL"):
                verify_release_artifacts.verify_release_artifacts(
                    release_dir=root,
                    repository="aiwaki/slipstream",
                    tag="v0.1.5",
                    version="0.1.5",
                )

    def test_cli_verifies_release_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_release_dir(root)

            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(
                    verify_release_artifacts.main(
                        [
                            "--release-dir",
                            str(root),
                            "--repository",
                            "aiwaki/slipstream",
                            "--tag",
                            "v0.1.5",
                            "--version",
                            "0.1.5",
                        ]
                    ),
                    0,
                )
            self.assertEqual(json.loads(out.getvalue())["version"], "0.1.5")


if __name__ == "__main__":
    unittest.main()
