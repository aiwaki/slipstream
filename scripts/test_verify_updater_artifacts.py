from __future__ import annotations

import base64
import hashlib
import io
import json
import plistlib
import tarfile
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import verify_updater_artifacts


TEST_VERSION = "0.1.9-preview.23"
TEST_KEY_ID = bytes.fromhex("6e72260bc77ec47f")
TEST_PRIVATE_SEED = bytes(range(32))


def _outer_public_key(private_key: Ed25519PrivateKey, key_id: bytes) -> str:
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    inner = (
        "untrusted comment: minisign public key: test\n"
        + base64.b64encode(b"Ed" + key_id + public_key).decode("ascii")
        + "\n"
    )
    return base64.b64encode(inner.encode("utf-8")).decode("ascii")


def _outer_signature(
    private_key: Ed25519PrivateKey, key_id: bytes, archive: bytes
) -> str:
    primary_signature = private_key.sign(
        hashlib.blake2b(archive, digest_size=64).digest()
    )
    trusted_comment = "timestamp:1783600000\tfile:Slipstream.app.tar.gz"
    global_signature = private_key.sign(
        primary_signature + trusted_comment.encode("utf-8")
    )
    inner = (
        "untrusted comment: signature from minisign secret key\n"
        + base64.b64encode(b"ED" + key_id + primary_signature).decode("ascii")
        + "\ntrusted comment: "
        + trusted_comment
        + "\n"
        + base64.b64encode(global_signature).decode("ascii")
        + "\n"
    )
    return base64.b64encode(inner.encode("utf-8")).decode("ascii")


def _add_bytes(
    archive: tarfile.TarFile, name: str, data: bytes, *, mode: int = 0o644
) -> None:
    info = tarfile.TarInfo(name)
    info.mode = mode
    info.size = len(data)
    info.mtime = 1_783_600_000
    archive.addfile(info, io.BytesIO(data))


def _add_directory(archive: tarfile.TarFile, name: str) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    info.mtime = 1_783_600_000
    archive.addfile(info)


def _info_plist_bytes(
    *, version: str, lsui_element: bool, target_size: int | None = None
) -> bytes:
    value = {
        "CFBundleExecutable": "slipstream",
        "CFBundleIdentifier": "dev.slipstream.tray",
        "CFBundleShortVersionString": version,
        "CFBundleVersion": version,
        "CFBundlePackageType": "APPL",
        "LSMinimumSystemVersion": "13.0",
        "LSUIElement": lsui_element,
    }
    if target_size is None:
        return plistlib.dumps(value)
    value["UpdaterVerifierPadding"] = ""
    base = plistlib.dumps(value)
    padding_size = target_size - len(base)
    if padding_size < 0:
        raise ValueError("requested Info.plist fixture is too small")
    value["UpdaterVerifierPadding"] = "x" * padding_size
    result = plistlib.dumps(value)
    if len(result) != target_size:
        raise AssertionError("Info.plist fixture size is not deterministic")
    return result


def _rust_archive_limit(name: str) -> int:
    source = (
        verify_updater_artifacts.ROOT
        / "app-tauri/src-tauri/src/app_update.rs"
    ).read_text(encoding="utf-8")
    prefix = f"pub const {name}: "
    matches = [line for line in source.splitlines() if line.startswith(prefix)]
    if len(matches) != 1:
        raise AssertionError(f"could not find one Rust archive limit named {name}")
    expression = matches[0].split("=", 1)[1].strip().removesuffix(";")
    result = 1
    for factor in expression.split("*"):
        result *= int(factor.strip().replace("_", ""))
    return result


def write_signed_updater_fixture(
    root: Path,
    *,
    version: str = TEST_VERSION,
    plist_version: str | None = None,
    lsui_element: bool = True,
    private_seed: bytes = TEST_PRIVATE_SEED,
    config_private_seed: bytes | None = None,
    extra_member: tarfile.TarInfo | None = None,
    plist_target_size: int | None = None,
) -> Path:
    private_key = Ed25519PrivateKey.from_private_bytes(private_seed)
    config_private_key = Ed25519PrivateKey.from_private_bytes(
        config_private_seed if config_private_seed is not None else private_seed
    )
    outer_public_key = _outer_public_key(config_private_key, TEST_KEY_ID)
    signing_public_key = _outer_public_key(private_key, TEST_KEY_ID)
    plist_version = plist_version if plist_version is not None else version
    info_plist = _info_plist_bytes(
        version=plist_version,
        lsui_element=lsui_element,
        target_size=plist_target_size,
    )
    archive_path = root / verify_updater_artifacts.ARCHIVE_NAME
    with tarfile.open(archive_path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        for directory in (
            "Slipstream.app",
            "Slipstream.app/Contents",
            "Slipstream.app/Contents/MacOS",
        ):
            _add_directory(archive, directory)
        _add_bytes(archive, verify_updater_artifacts.INFO_PLIST, info_plist)
        _add_bytes(
            archive,
            verify_updater_artifacts.MAIN_EXECUTABLE,
            b"fixture-prefix\0" + signing_public_key.encode("ascii") + b"\0fixture-suffix",
            mode=0o755,
        )
        if extra_member is not None:
            archive.addfile(extra_member, io.BytesIO(b"x") if extra_member.isfile() else None)
    archive_bytes = archive_path.read_bytes()
    (root / verify_updater_artifacts.SIGNATURE_NAME).write_text(
        _outer_signature(private_key, TEST_KEY_ID, archive_bytes) + "\n",
        encoding="ascii",
    )
    config_path = root / "tauri.conf.json"
    config_path.write_text(
        json.dumps(
            {
                "identifier": "dev.slipstream.tray",
                "mainBinaryName": "slipstream",
                "version": version,
                "bundle": {"macOS": {"minimumSystemVersion": "13.0"}},
                "plugins": {"updater": {"pubkey": outer_public_key}},
            }
        ),
        encoding="utf-8",
    )
    return config_path


class VerifyUpdaterArtifactsTests(unittest.TestCase):
    def test_offline_verifier_limits_match_runtime_archive_limits(self) -> None:
        pairs = {
            "MAX_UPDATE_ARCHIVE_BYTES": verify_updater_artifacts.MAX_ARCHIVE_BYTES,
            "MAX_UPDATE_UNCOMPRESSED_BYTES": (
                verify_updater_artifacts.MAX_UNCOMPRESSED_BYTES
            ),
            "MAX_ARCHIVE_ENTRIES": verify_updater_artifacts.MAX_ARCHIVE_ENTRIES,
            "MAX_ARCHIVE_ENTRY_BYTES": (
                verify_updater_artifacts.MAX_ARCHIVE_ENTRY_BYTES
            ),
            "MAX_INFO_PLIST_BYTES": verify_updater_artifacts.MAX_PLIST_BYTES,
        }
        self.assertEqual(
            {name: _rust_archive_limit(name) for name in pairs},
            pairs,
        )

    def test_accepts_exact_signed_hidden_app_archive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = write_signed_updater_fixture(root)

            result = verify_updater_artifacts.verify_updater_artifacts(
                release_dir=root,
                version=TEST_VERSION,
                tauri_config=config,
            )

            self.assertTrue(result["verified"])
            self.assertEqual(result["archive"]["bundle_version"], TEST_VERSION)
            self.assertTrue(result["archive"]["lsui_element"])
            self.assertEqual(result["archive"]["embedded_pubkey_count"], 1)
            self.assertEqual(len(result["archive"]["sha256"]), 64)
            self.assertEqual(len(result["signature"]["sha256"]), 64)
            self.assertEqual(len(result["tauri_config"]["pubkey_sha256"]), 64)

    def test_cli_emits_reusable_offline_proof(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = write_signed_updater_fixture(root)
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(
                    verify_updater_artifacts.main(
                        [
                            "--release-dir",
                            str(root),
                            "--version",
                            TEST_VERSION,
                            "--tauri-config",
                            str(config),
                        ]
                    ),
                    0,
                )
            self.assertTrue(json.loads(output.getvalue())["verified"])

    def test_rejects_archive_tampering_after_signature(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = write_signed_updater_fixture(root)
            archive = root / verify_updater_artifacts.ARCHIVE_NAME
            archive.write_bytes(archive.read_bytes() + b"tampered")

            with self.assertRaisesRegex(ValueError, "minisign verification failed"):
                verify_updater_artifacts.verify_updater_artifacts(
                    release_dir=root, version=TEST_VERSION, tauri_config=config
                )

    def test_rejects_signature_from_wrong_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = write_signed_updater_fixture(
                root, config_private_seed=bytes(reversed(range(32)))
            )

            with self.assertRaisesRegex(ValueError, "minisign verification failed"):
                verify_updater_artifacts.verify_updater_artifacts(
                    release_dir=root, version=TEST_VERSION, tauri_config=config
                )

    def test_rejects_signed_archive_for_a_different_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = write_signed_updater_fixture(root, plist_version="0.1.9-preview.22")

            with self.assertRaisesRegex(ValueError, "CFBundleShortVersionString"):
                verify_updater_artifacts.verify_updater_artifacts(
                    release_dir=root, version=TEST_VERSION, tauri_config=config
                )

    def test_rejects_source_configuration_for_a_different_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = write_signed_updater_fixture(root)
            value = json.loads(config.read_text(encoding="utf-8"))
            value["version"] = "0.1.9-preview.24"
            config.write_text(json.dumps(value), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "configuration version"):
                verify_updater_artifacts.verify_updater_artifacts(
                    release_dir=root, version=TEST_VERSION, tauri_config=config
                )

    def test_rejects_signed_archive_without_lsui_element(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = write_signed_updater_fixture(root, lsui_element=False)

            with self.assertRaisesRegex(ValueError, "LSUIElement"):
                verify_updater_artifacts.verify_updater_artifacts(
                    release_dir=root, version=TEST_VERSION, tauri_config=config
                )

    def test_accepts_signed_archive_with_a_normal_relative_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            link = tarfile.TarInfo("Slipstream.app/Contents/MacOS/slipstream-link")
            link.type = tarfile.SYMTYPE
            link.linkname = "slipstream"
            config = write_signed_updater_fixture(root, extra_member=link)

            result = verify_updater_artifacts.verify_updater_artifacts(
                release_dir=root, version=TEST_VERSION, tauri_config=config
            )
            self.assertTrue(result["verified"])

    def test_rejects_contained_symlink_with_parent_component(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            link = tarfile.TarInfo("Slipstream.app/Contents/Resources/escape")
            link.type = tarfile.SYMTYPE
            link.linkname = "../MacOS/slipstream"
            config = write_signed_updater_fixture(root, extra_member=link)

            with self.assertRaisesRegex(ValueError, "parent traversal"):
                verify_updater_artifacts.verify_updater_artifacts(
                    release_dir=root, version=TEST_VERSION, tauri_config=config
                )

    def test_symlink_target_corpus_is_safe_subset_of_runtime_rule(self) -> None:
        member = "Slipstream.app/Contents/MacOS/slipstream-link"
        for target in ("slipstream", "Frameworks/Helper.framework/Helper"):
            with self.subTest(target=target):
                self.assertEqual(
                    verify_updater_artifacts._safe_link_target(member, target),
                    target,
                )
        for target in (
            "",
            "/tmp/escape",
            "../MacOS/slipstream",
            "Frameworks/../MacOS/slipstream",
            "./slipstream",
            "Frameworks//Helper",
            "Frameworks\\Helper",
            "Frameworks/Helper\x00suffix",
        ):
            with self.subTest(target=target), self.assertRaises(ValueError):
                verify_updater_artifacts._safe_link_target(member, target)

    def test_rejects_signed_archive_with_an_absolute_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            link = tarfile.TarInfo("Slipstream.app/Contents/Resources/escape")
            link.type = tarfile.SYMTYPE
            link.linkname = "/tmp/escape"
            config = write_signed_updater_fixture(root, extra_member=link)

            with self.assertRaisesRegex(ValueError, "unsafe link"):
                verify_updater_artifacts.verify_updater_artifacts(
                    release_dir=root, version=TEST_VERSION, tauri_config=config
                )

    def test_rejects_signed_archive_with_a_symlink_that_escapes_the_app(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            link = tarfile.TarInfo("Slipstream.app/Contents/Resources/escape")
            link.type = tarfile.SYMTYPE
            link.linkname = "../../../../tmp/escape"
            config = write_signed_updater_fixture(root, extra_member=link)

            with self.assertRaisesRegex(ValueError, "parent traversal"):
                verify_updater_artifacts.verify_updater_artifacts(
                    release_dir=root, version=TEST_VERSION, tauri_config=config
                )

    def test_accepts_info_plist_at_exact_runtime_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = write_signed_updater_fixture(
                root,
                plist_target_size=verify_updater_artifacts.MAX_PLIST_BYTES,
            )

            result = verify_updater_artifacts.verify_updater_artifacts(
                release_dir=root, version=TEST_VERSION, tauri_config=config
            )

            self.assertTrue(result["verified"])

    def test_rejects_info_plist_one_byte_over_runtime_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = write_signed_updater_fixture(
                root,
                plist_target_size=verify_updater_artifacts.MAX_PLIST_BYTES + 1,
            )

            with self.assertRaisesRegex(ValueError, "Info.plist.*size limit"):
                verify_updater_artifacts.verify_updater_artifacts(
                    release_dir=root, version=TEST_VERSION, tauri_config=config
                )

    def test_rejects_signed_archive_with_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            escaped = tarfile.TarInfo("Slipstream.app/../escape")
            escaped.size = 1
            config = write_signed_updater_fixture(root, extra_member=escaped)

            with self.assertRaisesRegex(ValueError, "unsafe path"):
                verify_updater_artifacts.verify_updater_artifacts(
                    release_dir=root, version=TEST_VERSION, tauri_config=config
                )


if __name__ == "__main__":
    unittest.main()
