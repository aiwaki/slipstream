#!/usr/bin/env python3
"""Bounded, read-only visibility samples around a real public update.

This is sampled phase evidence, not a continuous visibility or notification
delivery proof. Opening the menu and authorizing an update are explicit user
actions: their interaction interval is reported separately, never silently
included in a claim of zero background focus/window changes.
"""
from __future__ import annotations

import math
import re
import threading
import time

PHASES = ("discovery", "interaction", "handoff", "terminal")
MAX_SAMPLES = 2000
SECURITY_AGENT = "/System/Library/CoreServices/SecurityAgent.app/Contents/MacOS/SecurityAgent"


class VisibilityError(RuntimeError):
    pass


def security_agent_front(listing: str, front: str) -> bool:
    """Recognize only the exact frontmost SecurityAgent LS record; retain no titles."""
    found = []
    for block in re.split(r"(?m)(?=^\s*\d+\) )", listing):
        lines = block.lstrip().splitlines()
        first = lines[0] if lines else ""
        if front not in re.findall(r"ASN:0x[0-9a-f]+-0x[0-9a-f]+:", first, re.I):
            continue
        found.append(block)
    return len(found) == 1 and (
        re.findall(r'\bbundleID="([^"]+)"', found[0]) == ["com.apple.SecurityAgent"]
        and re.findall(r'executable path="([^"]+)"', found[0]) == [SECURITY_AGENT]
    )


def native_snapshot() -> dict:
    # These existing helpers use bounded read-only lsappinfo queries and
    # CoreGraphics. The window filter excludes only the OS status-item layer.
    # Do not import the browser-specific monitor or start a browser worker.
    if __package__:
        from . import pending_navigation_browser_probe_smoke as visibility
    else:
        import pending_navigation_browser_probe_smoke as visibility
    front = visibility._frontmost_asn()
    listing = visibility._launch_services_listing()
    entries = visibility._slipstream_launch_services_entries(listing)
    windows = visibility._slipstream_window_ids()
    return {
        "frontmost_asn": front,
        "security_agent_front": security_agent_front(listing, front),
        "window_ids": sorted(windows),
        "dock_visible": any(entry.dock_visible for entry in entries),
    }


class PublicUpdateVisibility:
    def __init__(self, *, interval: float = 0.5, duration: float = 900.0) -> None:
        if not (math.isfinite(interval) and 0.5 <= interval <= 2.0
                and math.isfinite(duration) and 1.0 <= duration <= 900.0):
            raise ValueError("invalid visibility bounds")
        self.interval = interval
        self.duration = duration
        self.phase = "discovery"
        self.samples: list[dict] = []
        self.transitions: list[dict] = []
        self.failures: set[str] = set()
        self.baseline: str | None = None
        self.started: float | None = None
        self.finished: float | None = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _now(self) -> float:
        return time.monotonic()

    def _snapshot(self) -> dict:
        return native_snapshot()

    def _capture(self) -> None:
        began = self._now()
        with self._lock:
            phase = self.phase
        value = self._snapshot()
        ended = self._now()
        if (not isinstance(value, dict)
                or not isinstance(value.get("frontmost_asn"), str)
                or not re.fullmatch(r"ASN:0x[0-9a-f]+-0x[0-9a-f]+:",
                                    value["frontmost_asn"], re.I)
                or type(value.get("security_agent_front")) is not bool
                or type(value.get("dock_visible")) is not bool
                or not isinstance(value.get("window_ids"), list)
                or len(value["window_ids"]) > 128
                or any(type(v) is not int or v <= 0 for v in value["window_ids"])
                or not all(math.isfinite(v) for v in (began, ended))
                or ended < began):
            raise VisibilityError("invalid visibility sample")
        with self._lock:
            if self.started is None or len(self.samples) >= MAX_SAMPLES:
                raise VisibilityError("visibility sample budget exhausted")
            crossed = phase != self.phase
            if self.baseline is None:
                self.baseline = value["frontmost_asn"]
            front_changed = value["frontmost_asn"] != self.baseline
            sample = {
                "phase": phase, "crossed_phase_boundary": crossed,
                "started_after_seconds": round(began - self.started, 6),
                "ended_after_seconds": round(ended - self.started, 6),
                "observed_at_unix": time.time(), **value,
                "frontmost_changed": front_changed,
            }
            self.samples.append(sample)
            if value["dock_visible"]:
                self.failures.add("dock_visible")
            # A read overlapping a phase change cannot be attributed to either
            # interval. Keep it, but do not silently count it as a strict sample.
            if not crossed and phase != "interaction":
                if value["window_ids"]:
                    self.failures.add("background_window")
                if front_changed:
                    self.failures.add("background_frontmost_change")
            if ended - self.started > self.duration:
                self.failures.add("observation_deadline_exceeded")
                self._stop.set()

    def _sample(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self._capture()
            except Exception:
                with self._lock:
                    self.failures.add("snapshot_unavailable")
                self._stop.set()

    def start(self) -> None:
        if self.started is not None:
            raise VisibilityError("visibility sampler already started")
        self.started = self._now()
        self.transitions.append({"phase": self.phase, "after_seconds": 0.0})
        self._capture()  # Establish the baseline before the OLD app is launched.
        self._thread = threading.Thread(target=self._sample, daemon=True)
        self._thread.start()

    def set_phase(self, phase: str) -> None:
        if phase not in PHASES or self.started is None or self.finished is not None:
            raise VisibilityError("invalid visibility phase transition")
        with self._lock:
            if PHASES.index(phase) < PHASES.index(self.phase):
                raise VisibilityError("visibility phase cannot move backwards")
            if phase != self.phase:
                self.phase = phase
                self.transitions.append({
                    "phase": phase, "after_seconds": round(self._now() - self.started, 6),
                })

    def close(self) -> dict:
        if self.started is None:
            raise VisibilityError("visibility sampler was not started")
        if self.finished is None:
            self._stop.set()
            if self._thread is not None:
                self._thread.join(timeout=16.0)
            if self._thread is not None and self._thread.is_alive():
                with self._lock:
                    self.failures.add("sampler_did_not_stop")
            else:
                try:
                    self._capture()  # Retain a final sample even after a short terminal phase.
                except Exception:
                    with self._lock:
                        self.failures.add("snapshot_unavailable")
            self.finished = self._now()
        with self._lock:
            samples = list(self.samples)
            failures = set(self.failures)
            transitions = list(self.transitions)
        counts = {phase: sum(s["phase"] == phase and not s["crossed_phase_boundary"]
                             for s in samples) for phase in PHASES}
        if counts["discovery"] < 2 or counts["terminal"] < 1:
            failures.add("required_phase_not_observed")
        gaps = [max(0.0, later["started_after_seconds"] - earlier["ended_after_seconds"])
                for earlier, later in zip(samples, samples[1:])]
        return {
            "schema_version": 1,
            "status": "passed" if not failures else "failed",
            "coverage": "bounded point samples; user interaction reported separately",
            "full_transition_invisibility_qualified": False,
            "notification_delivery_qualified": False,
            "interaction_focus_window_interval_qualified": False,
            "sample_interval_seconds": self.interval,
            "duration_limit_seconds": self.duration,
            "elapsed_seconds": round(self.finished - self.started, 6),
            "max_observation_gap_seconds": round(max(gaps, default=0.0), 6),
            "phase_sample_counts": counts, "phase_transitions": transitions,
            "security_agent_interaction_samples": sum(
                s["phase"] == "interaction" and not s["crossed_phase_boundary"]
                and s["security_agent_front"] for s in samples),
            "failures": sorted(failures), "samples": samples,
        }

    def assert_passed(self) -> dict:
        """Close and check only the sampled contract stated in the returned evidence."""
        result = self.close()
        if result["status"] != "passed":
            raise VisibilityError("public update sampled visibility failed: "
                                  + ",".join(result["failures"]))
        return result
