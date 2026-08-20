from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import geph_vendor_source


VERSION = "0.3.0"


class GephVendorSourceTests(unittest.TestCase):
    def _transition_lock(self, *packages: tuple[str, str]) -> bytes:
        lines = ["version = 3", ""]
        for name, version in packages:
            lines.extend(
                (
                    "[[package]]",
                    f'name = "{name}"',
                    f'version = "{version}"',
                    "",
                )
            )
        return "\n".join(lines).encode()

    def _transition_contract(
        self,
        root: Path,
        *,
        version: str,
        revision: int,
        lock: bytes,
        crate_salt: str = "",
    ) -> Path:
        root.mkdir(parents=True)
        (root / "VERSION").write_text(f"{version}\n")
        (root / "Cargo.lock").write_bytes(lock)
        crate_sha256 = hashlib.sha256(f"{version}:{crate_salt}".encode()).hexdigest()
        source = {
            "schema_version": geph_vendor_source.SCHEMA_VERSION,
            "crate": {
                "name": geph_vendor_source.CRATE_NAME,
                "version": version,
                "url": geph_vendor_source.CRATE_URL.format(
                    name=geph_vendor_source.CRATE_NAME,
                    version=version,
                ),
                "sha256": crate_sha256,
            },
            "features": list(geph_vendor_source.FEATURES),
            "targets": list(geph_vendor_source.TARGETS),
            "lock_sha256": hashlib.sha256(lock).hexdigest(),
            "release_revision": revision,
        }
        (root / "SOURCE.json").write_text(json.dumps(source, sort_keys=True))
        return root

    def _transition_policy(self, path: Path, *, h2_exception: bool) -> Path:
        exceptions = []
        if h2_exception:
            exceptions.append(
                {
                    "id": geph_vendor_source.H2_TRANSITION_EXCEPTION_ID,
                    "package": "h2",
                    "version": "0.4.15",
                }
            )
        path.write_text(
            json.dumps(
                {
                    "exceptions": exceptions,
                    "rules": {"unreviewed": "block"},
                    "schema_version": 1,
                },
                sort_keys=True,
            )
        )
        return path

    def _verify_transition(
        self,
        previous: Path,
        current: Path,
        current_policy: Path,
        previous_policy: Path | None = None,
    ) -> dict:
        return geph_vendor_source.verify_source_transition(
            previous_source_path=previous / "SOURCE.json",
            previous_version_path=previous / "VERSION",
            previous_cargo_lock_path=previous / "Cargo.lock",
            previous_policy_path=previous_policy or current_policy,
            current_source_path=current / "SOURCE.json",
            current_version_path=current / "VERSION",
            current_cargo_lock_path=current / "Cargo.lock",
            current_policy_path=current_policy,
        )

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

    def test_transition_accepts_exact_version_upgrade_and_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous = self._transition_contract(
                root / "previous",
                version="0.3.0",
                revision=1,
                lock=self._transition_lock(("geph5-client", "0.3.0"), ("h2", "0.4.15")),
            )
            current = self._transition_contract(
                root / "current",
                version="0.3.9",
                revision=1,
                lock=self._transition_lock(("geph5-client", "0.3.9"), ("h2", "0.4.15")),
            )
            policy = self._transition_policy(root / "policy.json", h2_exception=True)

            result = self._verify_transition(previous, current, policy)
            self.assertEqual(result["transition"], "upgrade")
            self.assertEqual(result["previous_release_tag"], "geph-vendor-0.3.0-r1")
            self.assertEqual(result["current_release_tag"], "geph-vendor-0.3.9-r1")
            self.assertTrue(result["h2_0_4_15_present"])

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                status = geph_vendor_source.main(
                    [
                        "verify-transition",
                        "--previous-source",
                        str(previous / "SOURCE.json"),
                        "--previous-version-file",
                        str(previous / "VERSION"),
                        "--previous-cargo-lock",
                        str(previous / "Cargo.lock"),
                        "--previous-policy",
                        str(policy),
                        "--current-source",
                        str(current / "SOURCE.json"),
                        "--current-version-file",
                        str(current / "VERSION"),
                        "--current-cargo-lock",
                        str(current / "Cargo.lock"),
                        "--current-policy",
                        str(policy),
                    ]
                )
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(stdout.getvalue()), result)

    def test_transition_accepts_one_same_version_revision_and_removed_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous = self._transition_contract(
                root / "previous",
                version="0.3.0",
                revision=1,
                lock=self._transition_lock(("geph5-client", "0.3.0"), ("h2", "0.4.15")),
            )
            current = self._transition_contract(
                root / "current",
                version="0.3.0",
                revision=2,
                lock=self._transition_lock(("geph5-client", "0.3.0"), ("h2", "0.4.16")),
            )
            previous_policy = self._transition_policy(
                root / "previous-policy.json", h2_exception=True
            )
            current_policy = self._transition_policy(
                root / "current-policy.json", h2_exception=False
            )

            result = self._verify_transition(
                previous,
                current,
                current_policy,
                previous_policy,
            )
            self.assertEqual(result["transition"], "revision")
            self.assertEqual(result["current_release_tag"], "geph-vendor-0.3.0-r2")
            self.assertFalse(result["h2_0_4_15_present"])
            self.assertEqual(
                result["policy_transition"],
                "removed-temporary-h2-exception",
            )

    def test_transition_rejects_version_and_revision_regressions(self) -> None:
        cases = (
            ("downgrade", "0.3.9", 1, "0.3.0", 1, "downgrade"),
            ("upgrade revision", "0.3.0", 1, "0.3.9", 2, "revision 1"),
            ("revision reuse", "0.3.0", 1, "0.3.0", 1, "reused"),
            ("revision decrease", "0.3.0", 2, "0.3.0", 1, "decreases"),
            ("revision jump", "0.3.0", 1, "0.3.0", 3, "exactly one"),
            ("prerelease", "0.3.0", 1, "0.3.1-alpha.1", 1, "exact semantic"),
        )
        for label, old_version, old_revision, new_version, new_revision, message in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                previous = self._transition_contract(
                    root / "previous",
                    version=old_version,
                    revision=old_revision,
                    lock=self._transition_lock(("geph5-client", old_version), ("h2", "0.4.16")),
                )
                current = self._transition_contract(
                    root / "current",
                    version=new_version,
                    revision=new_revision,
                    lock=self._transition_lock(("geph5-client", new_version), ("h2", "0.4.16")),
                )
                policy = self._transition_policy(root / "policy.json", h2_exception=False)
                with self.assertRaisesRegex(ValueError, message):
                    self._verify_transition(previous, current, policy)

    def test_transition_rejects_same_version_crate_identity_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lock = self._transition_lock(("geph5-client", "0.3.0"), ("h2", "0.4.16"))
            previous = self._transition_contract(
                root / "previous", version="0.3.0", revision=1, lock=lock
            )
            current = self._transition_contract(
                root / "current",
                version="0.3.0",
                revision=2,
                lock=lock,
                crate_salt="different",
            )
            policy = self._transition_policy(root / "policy.json", h2_exception=False)
            with self.assertRaisesRegex(ValueError, "preserve crate identity"):
                self._verify_transition(previous, current, policy)

    def test_transition_rejects_contract_and_lock_tampering(self) -> None:
        mutations = (
            ("schema", lambda source: source.__setitem__("schema_version", 2), "schema"),
            (
                "boolean schema",
                lambda source: source.__setitem__("schema_version", True),
                "schema",
            ),
            ("features", lambda source: source.__setitem__("features", []), "features"),
            ("targets", lambda source: source.__setitem__("targets", []), "targets"),
            (
                "crate name",
                lambda source: source["crate"].__setitem__("name", "other-client"),
                "crate identity",
            ),
        )
        for label, mutate, message in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                lock = self._transition_lock(("geph5-client", "0.3.0"), ("h2", "0.4.16"))
                previous = self._transition_contract(
                    root / "previous", version="0.3.0", revision=1, lock=lock
                )
                current = self._transition_contract(
                    root / "current", version="0.3.0", revision=2, lock=lock
                )
                source = json.loads((current / "SOURCE.json").read_text())
                mutate(source)
                (current / "SOURCE.json").write_text(json.dumps(source))
                policy = self._transition_policy(root / "policy.json", h2_exception=False)
                with self.assertRaisesRegex(ValueError, message):
                    self._verify_transition(previous, current, policy)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lock = self._transition_lock(("geph5-client", "0.3.0"), ("h2", "0.4.16"))
            previous = self._transition_contract(
                root / "previous", version="0.3.0", revision=1, lock=lock
            )
            current = self._transition_contract(
                root / "current", version="0.3.0", revision=2, lock=lock
            )
            (current / "Cargo.lock").write_bytes(lock + b"# tampered\n")
            policy = self._transition_policy(root / "policy.json", h2_exception=False)
            with self.assertRaisesRegex(ValueError, "does not match"):
                self._verify_transition(previous, current, policy)

    def test_transition_parses_lock_and_binds_temporary_h2_exception(self) -> None:
        cases = (
            ("present without exception", "0.4.15", False, "requires exactly one"),
            ("absent with exception", "0.4.16", True, "forbidden"),
        )
        for label, h2_version, exception, message in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                previous_lock = self._transition_lock(
                    ("geph5-client", "0.3.0"), ("h2", "0.4.15")
                )
                current_lock = self._transition_lock(
                    ("geph5-client", "0.3.0"), ("h2", h2_version)
                )
                previous = self._transition_contract(
                    root / "previous", version="0.3.0", revision=1, lock=previous_lock
                )
                current = self._transition_contract(
                    root / "current", version="0.3.0", revision=2, lock=current_lock
                )
                previous_policy = self._transition_policy(
                    root / "previous-policy.json", h2_exception=True
                )
                current_policy = self._transition_policy(
                    root / "current-policy.json", h2_exception=exception
                )
                with self.assertRaisesRegex(ValueError, message):
                    self._verify_transition(
                        previous,
                        current,
                        current_policy,
                        previous_policy,
                    )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lock = self._transition_lock(("geph5-client", "0.3.0"), ("h2", "0.4.15"))
            previous = self._transition_contract(
                root / "previous", version="0.3.0", revision=1, lock=lock
            )
            current = self._transition_contract(
                root / "current", version="0.3.0", revision=2, lock=lock
            )
            previous_policy = self._transition_policy(
                root / "previous-policy.json", h2_exception=True
            )
            current_policy = self._transition_policy(
                root / "current-policy.json", h2_exception=True
            )
            policy_data = json.loads(current_policy.read_text())
            policy_data["exceptions"][0]["version"] = "0.4.16"
            current_policy.write_text(json.dumps(policy_data))
            with self.assertRaisesRegex(ValueError, "wrong package identity"):
                self._verify_transition(
                    previous,
                    current,
                    current_policy,
                    previous_policy,
                )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous_lock = self._transition_lock(("geph5-client", "0.3.0"))
            invalid_lock = b'version = 3\n[[package]\nname = "geph5-client"\n'
            previous = self._transition_contract(
                root / "previous", version="0.3.0", revision=1, lock=previous_lock
            )
            current = self._transition_contract(
                root / "current", version="0.3.0", revision=2, lock=invalid_lock
            )
            policy = self._transition_policy(root / "policy.json", h2_exception=False)
            with self.assertRaisesRegex(ValueError, "not valid TOML"):
                self._verify_transition(previous, current, policy)

    def test_transition_rejects_inconsistent_previous_lock_policy_pair(self) -> None:
        cases = (
            ("locked without exception", "0.4.15", False, "requires exactly one"),
            ("absent with exception", "0.4.16", True, "forbidden"),
        )
        for label, h2_version, exception, message in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                previous = self._transition_contract(
                    root / "previous",
                    version="0.3.0",
                    revision=1,
                    lock=self._transition_lock(
                        ("geph5-client", "0.3.0"), ("h2", h2_version)
                    ),
                )
                current = self._transition_contract(
                    root / "current",
                    version="0.3.0",
                    revision=2,
                    lock=self._transition_lock(
                        ("geph5-client", "0.3.0"), ("h2", "0.4.16")
                    ),
                )
                previous_policy = self._transition_policy(
                    root / "previous-policy.json", h2_exception=exception
                )
                current_policy = self._transition_policy(
                    root / "current-policy.json", h2_exception=False
                )
                with self.assertRaisesRegex(ValueError, message):
                    self._verify_transition(
                        previous,
                        current,
                        current_policy,
                        previous_policy,
                    )

    def test_transition_rejects_policy_additions_and_unrelated_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous = self._transition_contract(
                root / "previous",
                version="0.3.0",
                revision=1,
                lock=self._transition_lock(
                    ("geph5-client", "0.3.0"), ("h2", "0.4.16")
                ),
            )
            current = self._transition_contract(
                root / "current",
                version="0.3.0",
                revision=2,
                lock=self._transition_lock(
                    ("geph5-client", "0.3.0"), ("h2", "0.4.15")
                ),
            )
            previous_policy = self._transition_policy(
                root / "previous-policy.json", h2_exception=False
            )
            current_policy = self._transition_policy(
                root / "current-policy.json", h2_exception=True
            )
            with self.assertRaisesRegex(ValueError, "additions or changes"):
                self._verify_transition(
                    previous,
                    current,
                    current_policy,
                    previous_policy,
                )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous = self._transition_contract(
                root / "previous",
                version="0.3.0",
                revision=1,
                lock=self._transition_lock(
                    ("geph5-client", "0.3.0"), ("h2", "0.4.15")
                ),
            )
            current = self._transition_contract(
                root / "current",
                version="0.3.0",
                revision=2,
                lock=self._transition_lock(
                    ("geph5-client", "0.3.0"), ("h2", "0.4.16")
                ),
            )
            previous_policy = self._transition_policy(
                root / "previous-policy.json", h2_exception=True
            )
            current_policy = self._transition_policy(
                root / "current-policy.json", h2_exception=False
            )
            current_data = json.loads(current_policy.read_text())
            current_data["rules"]["informational"] = "record"
            current_policy.write_text(json.dumps(current_data))
            with self.assertRaisesRegex(ValueError, "only remove"):
                self._verify_transition(
                    previous,
                    current,
                    current_policy,
                    previous_policy,
                )

            current_data = json.loads(previous_policy.read_text())
            current_data["exceptions"] = []
            current_data["schema_version"] = True
            current_policy.write_text(json.dumps(current_data))
            with self.assertRaisesRegex(ValueError, "only remove"):
                self._verify_transition(
                    previous,
                    current,
                    current_policy,
                    previous_policy,
                )

    def test_retire_h2_transition_exception_is_atomic_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lock = root / "Cargo.lock"
            lock.write_bytes(
                self._transition_lock(("geph5-client", "0.3.0"), ("h2", "0.4.16"))
            )
            policy = self._transition_policy(root / "policy.json", h2_exception=True)
            before = json.loads(policy.read_text())
            before["exceptions"].append(
                {
                    "id": "unrelated-reviewed-exception",
                    "package": "example",
                    "version": "1.0.0",
                }
            )
            policy.write_text(json.dumps(before, indent=2, sort_keys=True) + "\n")

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                status = geph_vendor_source.main(
                    [
                        "retire-h2-transition-exception",
                        "--cargo-lock",
                        str(lock),
                        "--policy",
                        str(policy),
                    ]
                )
            result = json.loads(stdout.getvalue())
            self.assertEqual(status, 0)
            self.assertTrue(result["changed"])
            self.assertEqual(
                result["removed_exception"],
                geph_vendor_source.H2_TRANSITION_EXCEPTION_ID,
            )
            after = json.loads(policy.read_text())
            expected = dict(before)
            expected["exceptions"] = [before["exceptions"][1]]
            self.assertEqual(after, expected)

            payload = policy.read_bytes()
            inode = policy.stat().st_ino
            second = geph_vendor_source.retire_h2_transition_exception(
                cargo_lock_path=lock,
                policy_path=policy,
            )
            self.assertFalse(second["changed"])
            self.assertEqual(policy.read_bytes(), payload)
            self.assertEqual(policy.stat().st_ino, inode)

    def test_retire_h2_transition_exception_never_removes_while_locked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lock = root / "Cargo.lock"
            lock.write_bytes(
                self._transition_lock(("geph5-client", "0.3.0"), ("h2", "0.4.15"))
            )
            policy = self._transition_policy(root / "policy.json", h2_exception=True)
            payload = policy.read_bytes()
            inode = policy.stat().st_ino

            result = geph_vendor_source.retire_h2_transition_exception(
                cargo_lock_path=lock,
                policy_path=policy,
            )
            self.assertFalse(result["changed"])
            self.assertEqual(policy.read_bytes(), payload)
            self.assertEqual(policy.stat().st_ino, inode)

            missing = self._transition_policy(
                root / "missing-policy.json", h2_exception=False
            )
            with self.assertRaisesRegex(ValueError, "still requires"):
                geph_vendor_source.retire_h2_transition_exception(
                    cargo_lock_path=lock,
                    policy_path=missing,
                )

    def test_retire_h2_transition_exception_rejects_non_exact_bridge(self) -> None:
        for label, duplicate, message in (
            ("wrong identity", False, "wrong package identity"),
            ("duplicate", True, "duplicate"),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                lock = root / "Cargo.lock"
                lock.write_bytes(
                    self._transition_lock(
                        ("geph5-client", "0.3.0"),
                        ("h2", "0.4.16"),
                    )
                )
                policy = self._transition_policy(root / "policy.json", h2_exception=True)
                data = json.loads(policy.read_text())
                if duplicate:
                    data["exceptions"].append(dict(data["exceptions"][0]))
                else:
                    data["exceptions"][0]["version"] = "0.4.16"
                policy.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
                payload = policy.read_bytes()
                inode = policy.stat().st_ino

                with self.assertRaisesRegex(ValueError, message):
                    geph_vendor_source.retire_h2_transition_exception(
                        cargo_lock_path=lock,
                        policy_path=policy,
                    )
                self.assertEqual(policy.read_bytes(), payload)
                self.assertEqual(policy.stat().st_ino, inode)


if __name__ == "__main__":
    unittest.main()
