from __future__ import annotations

import unittest
import tempfile
from pathlib import Path
from unittest import mock

import packaged_invisibility_soak as soak


class FakeClock:
    def __init__(self) -> None:
        self.value = 100.0

    def monotonic(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class PackagedInvisibilitySoakTests(unittest.TestCase):
    def test_profile_residue_uses_the_effective_macos_temp_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / (
                "slipstream-browser-probe-" + "a" * 32
            )
            profile.mkdir()
            with (
                mock.patch.object(soak.tempfile, "gettempdir", return_value=temporary),
                mock.patch.dict(soak.os.environ, {"TMPDIR": temporary}),
            ):
                self.assertIn(str(profile.resolve()), soak._profiles())

    def test_sample_window_measures_full_1800_seconds_after_readiness(self) -> None:
        clock = FakeClock()
        observed: list[float] = []
        measured, samples, max_gap = soak._sample_window(
            1800,
            lambda: observed.append(clock.monotonic()),
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )
        self.assertEqual(measured, 1800)
        self.assertEqual(samples, 3600)
        self.assertEqual(max_gap, 0.5)
        self.assertEqual(observed[0], 100.0)
        self.assertEqual(observed[-1], 1899.5)

    def test_live_heartbeat_rejects_stale_status_after_daemon_crash(self) -> None:
        with self.assertRaisesRegex(soak.SoakError, "became stale"):
            soak._validate_live_heartbeat(
                {
                    "state": "active",
                    "pid": 42,
                    "heartbeat_seq": 8,
                    "updated_at": 100.0,
                },
                expected_pid=42,
                previous_seq=8,
                last_change_monotonic=10.0,
                now_wall=106.0,
                now_monotonic=16.0,
            )

    def test_live_heartbeat_must_keep_advancing(self) -> None:
        with self.assertRaisesRegex(soak.SoakError, "stopped advancing"):
            soak._validate_live_heartbeat(
                {
                    "state": "active",
                    "pid": 42,
                    "heartbeat_seq": 8,
                    "updated_at": 105.0,
                },
                expected_pid=42,
                previous_seq=8,
                last_change_monotonic=10.0,
                now_wall=106.0,
                now_monotonic=16.0,
            )

    def test_live_heartbeat_accepts_owned_progress(self) -> None:
        seq, changed = soak._validate_live_heartbeat(
            {
                "state": "active",
                "pid": 42,
                "heartbeat_seq": 9,
                "updated_at": 105.5,
            },
            expected_pid=42,
            previous_seq=8,
            last_change_monotonic=10.0,
            now_wall=106.0,
            now_monotonic=16.0,
        )
        self.assertEqual(seq, 9)
        self.assertEqual(changed, 16.0)


if __name__ == "__main__":
    unittest.main()
