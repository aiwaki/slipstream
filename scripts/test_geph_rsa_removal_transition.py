"""Freeze this reviewed r3 -> RSA-only r4 transition, not future live policy."""
import copy
import json
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import geph_vendor_source as source
import test_geph_vendor_source as fixture_module


BINDING = (
    "de39d92abd79787d432bcd45f074398f91dbbf3baa843401b90f7bcbb1b36286",
    "c941a26c6fd308f0057544166c153945ecd54456507a836c155dff8877d5e4f0",
    "69d5de39654dea018075469d20ea7892cc35f5af0466d19a7811ef3316b60df7",
    "560504e697c28f2114ec16414e5dc372e1903df986ba36792aab9a12c34631cb",
)


class RsaRemovalTransitionTests(unittest.TestCase):
    def setUp(self):
        fixtures = Path(__file__).parent / "fixtures"
        self.previous = json.loads((fixtures / "geph-registry-policy-r3.json").read_text())
        self.current = json.loads((fixtures / "geph-rsa-removal-policy-r4.json").read_text())

    def verify(self, current=None, binding=BINDING):
        return source._verify_policy_transition(
            previous_policy=self.previous, current_policy=current or self.current,
            previous_h2_present=False, current_h2_present=False,
            verified_source_binding=binding,
        )

    def test_exact_source_bound_removal_and_new_review(self):
        self.assertEqual(self.verify(), "removed-rsa-with-reviewed-source-owned-replacement")
        removed = [entry for entry in self.previous["exceptions"] if entry not in self.current["exceptions"]]
        self.assertEqual(len(removed), 2)
        self.assertTrue(all(entry["package"] == "rsa" and entry["version"] == "0.8.2" for entry in removed))
        self.assertEqual([entry for entry in self.previous["exceptions"] if entry not in removed], self.current["exceptions"])

    def test_policy_only_or_any_source_lock_mutation_is_refused(self):
        for binding in [None, *(tuple("0" * 64 if j == i else item for j, item in enumerate(BINDING)) for i in range(4))]:
            with self.subTest(binding=binding), self.assertRaises(ValueError):
                self.verify(binding=binding)

    def test_review_expiry_reason_or_unrelated_policy_mutations_are_refused(self):
        changes = [
            ("source_owned_review", "expires", "2099-01-01"),
            ("source_owned_review", "source_sha256", "0" * 64),
            ("source_owned_review", "review_sha256", "0" * 64),
            ("scanner", "version", "0.0.0"),
        ]
        for section, key, value in changes:
            candidate = copy.deepcopy(self.current)
            candidate[section][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                self.verify(candidate)
        for key in ("reason", "expires"):
            candidate = copy.deepcopy(self.current)
            candidate["exceptions"][0][key] = "2099-01-01" if key == "expires" else "changed"
            with self.subTest(exception=key), self.assertRaises(ValueError):
                self.verify(candidate)
        renewed = copy.deepcopy(self.current)
        renewed["exceptions"] = self.previous["exceptions"]
        with self.assertRaises(ValueError):
            self.verify(renewed)

    def test_transition_policy_uses_the_source_snapshot_already_verified(self):
        fixture = fixture_module.GephVendorSourceTests()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lock = fixture._transition_lock(("geph5-client", "0.4.3"))
            previous = fixture._transition_contract(root / "previous", version="0.4.3", revision=1, lock=lock)
            current = fixture._transition_contract(root / "current", version="0.4.3", revision=2, lock=lock)
            policy = fixture._transition_policy(root / "policy.json", h2_exception=False)
            expected = tuple(hashlib.sha256(path.read_bytes()).hexdigest() for path in (
                previous / "SOURCE.json", previous / "Cargo.lock", current / "SOURCE.json", current / "Cargo.lock"))
            load_policy = source._load_geph_policy

            def replace_path_after_source_validation(*args, **kwargs):
                (current / "SOURCE.json").write_text("different later bytes")
                return load_policy(*args, **kwargs)

            with mock.patch.object(source, "_load_geph_policy", side_effect=replace_path_after_source_validation), \
                    mock.patch.object(source, "_verify_policy_transition", wraps=source._verify_policy_transition) as verify:
                result = fixture._verify_transition(previous, current, policy)
            self.assertEqual(verify.call_args.kwargs["verified_source_binding"], expected)
            self.assertEqual(result["current_source_sha256"], expected[2])


if __name__ == "__main__":
    unittest.main()
