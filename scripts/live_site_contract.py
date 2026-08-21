"""Shared privacy-bounded contract for protected live-site evidence."""

from __future__ import annotations


TERMINAL_BROWSER_REASONS = frozenset(
    {
        "browser_process_conflict",
        "browser_process_unavailable",
        "browser_start_failed",
        "browser_observation_failed",
        "devtools_unavailable",
        "document_invalid",
        "document_too_short",
        "driver_unavailable",
        "navigation_denied",
        "navigation_rejected",
        "readiness_signals_invalid",
        "readiness_timeout",
        "session_configuration_failed",
        "session_create_failed",
        # Retained for previously preserved schema-v2 reports. The current
        # producer emits one of the exact setup-stage reasons above instead.
        "session_unavailable",
        "target_unavailable",
    }
)
