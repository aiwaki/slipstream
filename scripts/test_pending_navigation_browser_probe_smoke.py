import tempfile
from pathlib import Path

from scripts import pending_navigation_browser_probe_smoke as smoke


def test_profile_residue_matches_only_exact_worker_nonce() -> None:
    with tempfile.TemporaryDirectory() as raw_directory:
        root = Path(raw_directory)
        expected = root / ("slipstream-browser-probe-" + "a" * 32)
        expected.mkdir()
        (root / "slipstream-browser-probe-smoke-fixture").mkdir()
        (root / ("slipstream-browser-probe-" + "g" * 32)).mkdir()
        (root / ("slipstream-browser-probe-" + "b" * 31)).mkdir()

        assert smoke._profile_residue(root) == {expected}
