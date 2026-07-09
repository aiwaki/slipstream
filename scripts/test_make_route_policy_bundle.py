from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path

import make_route_policy_bundle

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,  # noqa: F401
    )

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


@unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography is required for route policy signing")
class MakeRoutePolicyBundleTests(unittest.TestCase):
    def test_build_bundle_includes_hash_and_verifies(self) -> None:
        manifest = make_route_policy_bundle.tproxy.route_policy_manifest()
        manifest["source"] = "signed:test"
        private_key = base64.b64encode(b"\x01" * 32).decode("ascii")

        bundle, public_keys = make_route_policy_bundle.build_signed_route_policy_bundle(
            manifest=manifest,
            key_id="test",
            private_key=private_key,
        )

        self.assertEqual(
            bundle["sha256"],
            make_route_policy_bundle.tproxy.route_policy_hash(manifest),
        )
        self.assertEqual(
            make_route_policy_bundle.tproxy.verify_signed_route_policy_bundle(
                bundle,
                public_keys,
            ),
            manifest,
        )

        tampered = json.loads(json.dumps(bundle))
        tampered["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            make_route_policy_bundle.tproxy.verify_signed_route_policy_bundle(
                tampered,
                public_keys,
            )

    def test_cli_writes_bundle_and_public_keys(self) -> None:
        manifest = make_route_policy_bundle.tproxy.route_policy_manifest()
        manifest["source"] = "signed:cli"
        private_key = base64.b64encode(b"\x02" * 32).decode("ascii")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path = root / "manifest.json"
            key_path = root / "route-policy.key"
            output_path = root / "route-policy.json"
            public_keys_path = root / "route-policy-keys.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            key_path.write_text(private_key + "\n", encoding="utf-8")

            self.assertEqual(
                make_route_policy_bundle.main(
                    [
                        "--manifest",
                        str(manifest_path),
                        "--key-id",
                        "cli",
                        "--private-key-file",
                        str(key_path),
                        "--output",
                        str(output_path),
                        "--public-keys-output",
                        str(public_keys_path),
                    ]
                ),
                0,
            )

            bundle = json.loads(output_path.read_text(encoding="utf-8"))
            public_keys = json.loads(public_keys_path.read_text(encoding="utf-8"))["keys"]
            self.assertEqual(bundle["key_id"], "cli")
            self.assertEqual(
                bundle["sha256"],
                make_route_policy_bundle.tproxy.route_policy_hash(manifest),
            )
            self.assertEqual(
                make_route_policy_bundle.tproxy.verify_signed_route_policy_bundle(
                    bundle,
                    public_keys,
                ),
                manifest,
            )

    def test_cli_can_sign_bundled_manifest_without_manifest_file(self) -> None:
        private_key = base64.b64encode(b"\x03" * 32).decode("ascii")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key_path = root / "route-policy.key"
            output_path = root / "route-policy.json"
            public_keys_path = root / "route-policy-keys.json"
            key_path.write_text(private_key + "\n", encoding="utf-8")

            self.assertEqual(
                make_route_policy_bundle.main(
                    [
                        "--bundled-manifest",
                        "--key-id",
                        "bundled",
                        "--private-key-file",
                        str(key_path),
                        "--output",
                        str(output_path),
                        "--public-keys-output",
                        str(public_keys_path),
                    ]
                ),
                0,
            )

            bundle = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(bundle["manifest"]["source"], "bundled")
            self.assertEqual(
                bundle["sha256"],
                make_route_policy_bundle.tproxy.route_policy_hash(
                    make_route_policy_bundle.tproxy.route_policy_manifest()
                ),
            )

    def test_cli_verify_accepts_generated_bundle(self) -> None:
        private_key = base64.b64encode(b"\x04" * 32).decode("ascii")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key_path = root / "route-policy.key"
            output_path = root / "route-policy.json"
            public_keys_path = root / "route-policy-keys.json"
            key_path.write_text(private_key + "\n", encoding="utf-8")

            self.assertEqual(
                make_route_policy_bundle.main(
                    [
                        "--bundled-manifest",
                        "--key-id",
                        "verify",
                        "--private-key-file",
                        str(key_path),
                        "--output",
                        str(output_path),
                        "--public-keys-output",
                        str(public_keys_path),
                    ]
                ),
                0,
            )
            self.assertEqual(
                make_route_policy_bundle.main(
                    [
                        "--verify",
                        "--bundle",
                        str(output_path),
                        "--public-keys",
                        str(public_keys_path),
                    ]
                ),
                0,
            )

    def test_cli_writes_channel_index_for_generated_bundle(self) -> None:
        private_key = base64.b64encode(b"\x05" * 32).decode("ascii")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key_path = root / "route-policy.key"
            bundle_path = root / "route-policy.json"
            index_path = root / "latest.json"
            key_path.write_text(private_key + "\n", encoding="utf-8")

            self.assertEqual(
                make_route_policy_bundle.main(
                    [
                        "--bundled-manifest",
                        "--key-id",
                        "channel",
                        "--private-key-file",
                        str(key_path),
                        "--output",
                        str(bundle_path),
                    ]
                ),
                0,
            )
            self.assertEqual(
                make_route_policy_bundle.main(
                    [
                        "--channel-index",
                        "--bundle",
                        str(bundle_path),
                        "--bundle-url",
                        "https://policy.example.org/channel/route-policy.json",
                        "--output",
                        str(index_path),
                    ]
                ),
                0,
            )

            index = json.loads(index_path.read_text(encoding="utf-8"))
            self.assertEqual(
                index["kind"],
                make_route_policy_bundle.tproxy.ROUTE_POLICY_CHANNEL_KIND,
            )
            self.assertEqual(
                index["schema"],
                make_route_policy_bundle.tproxy.ROUTE_POLICY_CHANNEL_SCHEMA_VERSION,
            )
            self.assertEqual(index["key_id"], "channel")
            self.assertEqual(index["source"], "bundled")
            self.assertEqual(
                index["sha256"],
                make_route_policy_bundle.hash_file(bundle_path),
            )

    def test_cli_generates_keypair_without_overwriting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private_path = root / "route-policy.key"
            public_keys_path = root / "route-policy-keys.json"
            bundle_path = root / "route-policy.json"

            self.assertEqual(
                make_route_policy_bundle.main(
                    [
                        "--generate-keypair",
                        "--key-id",
                        "generated",
                        "--private-key-output",
                        str(private_path),
                        "--public-keys-output",
                        str(public_keys_path),
                    ]
                ),
                0,
            )

            self.assertEqual(private_path.stat().st_mode & 0o777, 0o600)
            private_key = private_path.read_text(encoding="utf-8").strip()
            public_keys = make_route_policy_bundle.tproxy.load_trusted_route_policy_keys(
                path=str(public_keys_path),
                embedded_keys={},
            )
            self.assertIn("generated", public_keys)

            self.assertEqual(
                make_route_policy_bundle.main(
                    [
                        "--bundled-manifest",
                        "--key-id",
                        "generated",
                        "--private-key-file",
                        str(private_path),
                        "--output",
                        str(bundle_path),
                    ]
                ),
                0,
            )
            bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
            self.assertEqual(
                make_route_policy_bundle.tproxy.verify_signed_route_policy_bundle(
                    bundle,
                    public_keys,
                )["source"],
                "bundled",
            )
            self.assertGreater(len(base64.b64decode(private_key)), 0)

            with self.assertRaises(FileExistsError):
                make_route_policy_bundle.main(
                    [
                        "--generate-keypair",
                        "--key-id",
                        "generated",
                        "--private-key-output",
                        str(private_path),
                        "--public-keys-output",
                        str(public_keys_path),
                    ]
                )


if __name__ == "__main__":
    unittest.main()
