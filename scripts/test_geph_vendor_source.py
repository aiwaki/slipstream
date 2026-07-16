from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

import geph_vendor_source


VERSION = "0.3.0"


class GephVendorSourceTests(unittest.TestCase):
    def _crate(self, root: Path, *, unsafe: bool = False) -> Path:
        path = root / f"geph5-client-{VERSION}.crate"
        prefix = f"geph5-client-{VERSION}"
        manifest = f'''[package]
name = "geph5-client"
version = "{VERSION}"
edition = "2021"

[[bin]]
name = "geph5-client"
path = "src/main.rs"
'''.encode()
        with tarfile.open(path, "w:gz") as archive:
            for name, payload in (
                (f"{prefix}/Cargo.toml", manifest),
                (f"{prefix}/src/main.rs", b"fn main() {}\n"),
                (f"{prefix}/Cargo.lock", b"stale packaged lock\n"),
            ):
                item = tarfile.TarInfo(name)
                item.size = len(payload)
                item.mode = 0o644
                archive.addfile(item, io.BytesIO(payload))
            if unsafe:
                link = tarfile.TarInfo(f"{prefix}/escape")
                link.type = tarfile.SYMTYPE
                link.linkname = "../../escape"
                archive.addfile(link)
        return path

    def test_prepare_is_deterministic_and_replaces_packaged_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            crate = self._crate(root)
            digest = geph_vendor_source.hash_file(crate)
            first = root / "first"
            second = root / "second"

            first_contract = geph_vendor_source.prepare_source_contract(
                crate_path=crate,
                version=VERSION,
                crate_sha256=digest,
                output_dir=first,
            )
            second_contract = geph_vendor_source.prepare_source_contract(
                crate_path=crate,
                version=VERSION,
                crate_sha256=digest,
                output_dir=second,
            )

            self.assertEqual(first_contract, second_contract)
            self.assertEqual((first / "Cargo.lock").read_bytes(), (second / "Cargo.lock").read_bytes())
            self.assertNotIn("stale packaged lock", (first / "Cargo.lock").read_text())
            self.assertEqual(
                json.loads((first / "SOURCE.json").read_text()),
                first_contract,
            )
            self.assertEqual(
                hashlib.sha256((first / "Cargo.lock").read_bytes()).hexdigest(),
                first_contract["lock_sha256"],
            )

    def test_verify_rejects_tampered_crate_or_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            crate = self._crate(root)
            output = root / "vendor"
            geph_vendor_source.prepare_source_contract(
                crate_path=crate,
                version=VERSION,
                crate_sha256=geph_vendor_source.hash_file(crate),
                output_dir=output,
            )
            geph_vendor_source.verify_source_contract(
                source_path=output / "SOURCE.json",
                version_path=output / "VERSION",
                cargo_lock_path=output / "Cargo.lock",
                crate_path=crate,
            )

            (output / "Cargo.lock").write_text("tampered\n")
            with self.assertRaisesRegex(ValueError, "Cargo.lock"):
                geph_vendor_source.verify_source_contract(
                    source_path=output / "SOURCE.json",
                    version_path=output / "VERSION",
                    cargo_lock_path=output / "Cargo.lock",
                )

            (output / "Cargo.lock").write_text("version = 4\n")
            source = json.loads((output / "SOURCE.json").read_text())
            source["lock_sha256"] = geph_vendor_source.hash_file(output / "Cargo.lock")
            (output / "SOURCE.json").write_text(json.dumps(source))
            crate.write_bytes(crate.read_bytes() + b"tampered")
            with self.assertRaisesRegex(ValueError, "downloaded Geph crate"):
                geph_vendor_source.verify_source_contract(
                    source_path=output / "SOURCE.json",
                    version_path=output / "VERSION",
                    cargo_lock_path=output / "Cargo.lock",
                    crate_path=crate,
                )

    def test_extract_rejects_links(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            crate = self._crate(root, unsafe=True)
            with self.assertRaisesRegex(ValueError, "unsafe Geph crate member"):
                geph_vendor_source.extract_crate(
                    crate_path=crate,
                    version=VERSION,
                    output=root / "out",
                )

    def test_contract_rejects_unknown_fields_and_upstream_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            crate = self._crate(root)
            output = root / "vendor"
            digest = geph_vendor_source.hash_file(crate)
            geph_vendor_source.prepare_source_contract(
                crate_path=crate,
                version=VERSION,
                crate_sha256=digest,
                output_dir=output,
            )
            with self.assertRaisesRegex(ValueError, "requested upstream version"):
                geph_vendor_source.verify_source_contract(
                    source_path=output / "SOURCE.json",
                    version_path=output / "VERSION",
                    cargo_lock_path=output / "Cargo.lock",
                    expected_version="0.3.1",
                )

            source = json.loads((output / "SOURCE.json").read_text())
            source["timestamp"] = "forbidden"
            (output / "SOURCE.json").write_text(json.dumps(source))
            with self.assertRaisesRegex(ValueError, "fields"):
                geph_vendor_source.load_source_contract(output / "SOURCE.json")


if __name__ == "__main__":
    unittest.main()
