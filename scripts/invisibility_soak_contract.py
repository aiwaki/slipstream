"""Shared schema and bounded cleanup diagnostics for the packaged soak."""

from __future__ import annotations

SCHEMA_VERSION = 2
SYSTEM_CLEANUP_PATHS = (
    ("launchd_plist", "/Library/LaunchDaemons/dev.slipstream.tproxy.plist"),
    ("install_runtime", "/usr/local/slipstream"),
    (
        "install_attestation",
        "/Library/Application Support/dev.slipstream.tray",
    ),
    ("pf_enable_token", "/var/run/slipstream-pf.token"),
    ("pf_loopback_lease", "/var/run/slipstream-pf-lo0-skip.json"),
    ("daemon_status", "/var/run/slipstream.status"),
    ("daemon_status_tmp", "/var/run/slipstream.status.tmp"),
    ("auto_geph_state", "/var/run/slipstream-autogeph.json"),
    ("strategy_state", "/var/run/slipstream-strat.json"),
    ("tgws_link", "/var/run/slipstream-tgws.link"),
    ("semantic_socket", "/var/run/slipstream-semantic.sock"),
    ("browser_probe_socket", "/var/run/slipstream-browser-probe.sock"),
    (
        "browser_probe_runtime",
        "/var/run/slipstream-browser-probe-workers",
    ),
)
SYSTEM_CLEANUP_LABELS = frozenset(
    label for label, _path in SYSTEM_CLEANUP_PATHS
) | frozenset(
    {
        "launchd_job",
        "pf_nat_anchor",
        "pf_filter_anchor",
        "daemon_listener",
        "cleanup_state_unstable",
    }
)
CLEANUP_REPORT_SYMBOLS = frozenset(
    {"tray_process", "product_cleanup_unexpected", "uninstall_command"}
) | frozenset(
    f"{kind}:{label}"
    for kind in ("probe", "residue")
    for label in SYSTEM_CLEANUP_LABELS
)
