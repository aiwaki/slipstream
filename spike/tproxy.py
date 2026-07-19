#!/usr/bin/env python3
"""tproxy — transparent tlsrec proxy + DoH via a private pf anchor.

Two blocks were found on the target network:
  1. SNI DPI  -> beaten by tlsrec (tiny first TLS record).
  2. DNS poisoning -> blocked domains resolve to a stub IP (87.228.47.x) with no
     real server, so desync is useless. Beaten by re-resolving the SNI over DoH
     (DNS-over-HTTPS) and connecting to the REAL IP.

A transparent pf redirect captures local TCP/443 (browser, Discord, the updater)
without replacing the system ruleset. QUIC remains untouched. For each connection
we read the ClientHello, parse the SNI, DoH-resolve it to the real IP, then
forward a tlsrec-split ClientHello to that real IP.

Run:   sudo python3 tproxy.py [--verbose]
Stop:  Ctrl-C  (flushes only Slipstream's private pf anchor)
ESCAPE HATCH if connectivity breaks (other terminal):
    sudo pfctl -a com.apple/slipstream -F rules
    sudo pfctl -a com.apple/slipstream -F nat
"""
import argparse
import asyncio
import atexit
import base64
import errno
import filecmp
import fcntl
import hashlib
import ipaddress
import json
import logging
import math
from collections import OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor
import os
import pwd
import re
import resource
import shlex
import signal
import socket
import ssl
import shutil
import stat
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlencode, urlparse
import urllib.request

import connection_probe
import geph_backend
import install_guard
import pf_adapter
import route_circuit
import route_circuit_registry
import route_policy_activation as route_policy_activation_contract
import route_policy_activation_adapter
import route_policy_bundle as route_policy_bundle_contract
import route_policy_manifest as route_policy_manifest_contract
from primes import build_fake_stun, classify as classify_voice_payload
from routing_recovery import (
    ConnectionOutcome,
    POLICY_PROTECTED_LOCAL_BYPASS_GROUPS,
    RECOVERY_INVALIDATE_STRATEGY,
    RECOVERY_NONE,
    RECOVERY_RECHECK,
    RECOVERY_RESTART_OWNED_GEPH,
    RECOVERY_RESWEEP_EXACT_HOST,
    RECOVERY_WARN_EXTERNAL,
    RecoveryAction,
    RecoveryContext,
    reduce_connection_outcome,
)
from routing_policy import (
    ROUTE_DIRECT,
    ROUTE_DIRECT_FIRST,
    ROUTE_GEO_EXIT,
    ROUTE_LOCAL_BYPASS,
    ROUTE_UNKNOWN,
    SERVICE_ANTHROPIC,
    SERVICE_DISCORD,
    SERVICE_GENERIC,
    SERVICE_GITHUB,
    SERVICE_GOOGLE,
    SERVICE_OPENAI,
    SERVICE_SPOTIFY,
    SERVICE_STEAM_STORE,
    SERVICE_TELEGRAM,
    SERVICE_YOUTUBE,
    STRATEGY_DIRECT,
    STRATEGY_DIRECT_FIRST,
    STRATEGY_FAKE_ONLY,
    STRATEGY_GENERAL,
    STRATEGY_GEPH,
    classify_route_policy,
    host_matches as _host_matches,
    is_russian,
    match_policy as _match_policy,
    normalize_host,
)
from xbox_dns import resolve as xbox_dns_resolve


class _ScapyMacNoiseFilter(logging.Filter):
    def filter(self, record):
        return "MAC address to reach destination not found" not in record.getMessage()


logging.getLogger("scapy.runtime").addFilter(_ScapyMacNoiseFilter())


class LegacyGlobalPfConflict(RuntimeError):
    """A global HTTPS redirect targets our port but has no ownership proof."""


class OwnedPfStateError(RuntimeError):
    """Slipstream-owned PF state could not be recovered without global mutation."""


PROXY_PORT = 1080
DIOCNATLOOK = 0xC0544417
PF_OUT = 2
FIRST_REC_CAP = 64
VERBOSE = False

# DoH resolvers (connect by IP, no bootstrap DNS needed). SNI may itself be
# DPI-blocked -> we tlsrec its ClientHello too.
DOH = [("1.1.1.1", "cloudflare-dns.com"), ("8.8.8.8", "dns.google")]

PF_ANCHOR = "com.apple/slipstream"
PF_PARENT_ANCHOR = "com.apple/*"
PF_CONFIG_PATH = "/etc/pf.conf"
PF_TOKEN_PATH = "/var/run/slipstream-pf.token"
PF_SKIP_LEASE_PATH = "/var/run/slipstream-pf-lo0-skip.json"
PF_LOOPBACK_INTERFACE = "lo0"
PF_CONFLICT_CHECK_INTERVAL = 15.0
try:
    RUNTIME_WAKE_GAP_SECONDS = max(
        5.0,
        float(os.environ.get("SLIP_RUNTIME_WAKE_GAP_SECONDS", "30")),
    )
except (TypeError, ValueError):
    RUNTIME_WAKE_GAP_SECONDS = 30.0
PF_RULES = """\
rdr on lo0 inet proto tcp from any to ! 127.0.0.0/8 port 443 -> 127.0.0.1 port {port}
pass out quick on ! lo0 route-to (lo0 127.0.0.1) inet proto tcp from any to any port 443 user != root
pass out quick on lo0 inet proto tcp from any to any port 443 no state
pass in quick on lo0 reply-to (lo0 127.0.0.1) inet proto tcp from any to 127.0.0.1 port {port}
"""
# NOTE: QUIC (UDP/443) is intentionally NOT blocked. YouTube/googlevideo video runs
# over QUIC/HTTP3, and QUIC to those hosts WORKS on this TSPU (verified 2026-07-07:
# Version-Negotiation replies in ~0.04s). The old QUIC block (Codex #11-#15) forced
# the browser onto TCP, which IS DPI-dropped for googlevideo -> video died. Leaving
# QUIC alone restores native HTTP3 playback. Slipstream therefore owns no UDP/443
# block table at all.

_pf_applied = False
_pf_fd = None
_pf_enable_token = None
_pf_interceptor_conflicts = []
_doh_cache = OrderedDict()      # host -> (ips, expiry_monotonic)
# Dedicated pool for the blocking off-loop work (DoH resolves, fake injection).
# The default asyncio executor is tiny (~cpu+4); a browser opening many new hosts
# floods it with slow DoH queries and the whole proxy stalls. 64 workers + DoH
# de-dup keeps the app responsive under a browser's connection burst.
_POOL = ThreadPoolExecutor(max_workers=64, thread_name_prefix="slip")
_doh_inflight = {}             # host -> asyncio.Future (collapse concurrent DoH)
_xbox_dns_inflight = {}        # host -> asyncio.Future (on-demand resolver only)
# Negative cache: a host that failed the whole ladder is "dead" for a cooldown,
# during which it gets ONE fast-fail attempt instead of 7 — stops retry-storms
# from a persistently-blocked host (e.g. Telegram DC sockets hammering forever).
DEAD_TTL = 60.0
_dead = {}                     # host -> expiry_monotonic

# Public status the menu-bar app polls. It intentionally carries only a compact
# health contract; raw host-level evidence stays in the owner-only log.
STATUS_PATH = "/var/run/slipstream.status"
STATUS_SCHEMA_VERSION = 2
STATUS_PUBLIC_MODE = 0o644
DAEMON_VERSION = "0.1.9"
_conn_count = 0                # live proxied connections
_connection_tasks = set()
_status_write_lock = threading.RLock()
_shutdown_started = threading.Event()
_pf_teardown_complete = threading.Event()
SHUTDOWN_DRAIN_SECONDS = 10.0
SHUTDOWN_DRAIN_QUIET_SECONDS = 0.1

# --------------------------------------------------- Geph split-tunnel (hybrid)
# The hybrid route keeps local DPI bypass independent from the optional Geph
# exit. Reviewed geo-exit services may use Geph only while its owned SOCKS
# listener is verified; otherwise they retain their original pre-PF destination.
# Russian/local-bypass services never enter Geph.
GEPH_ENABLED = os.environ.get("SLIP_GEPH", "1") != "0"
# Use Slipstream's owned geph5-client (:9954). A separately-running Geph.app on
# :9909 is diagnostics-only unless SLIP_GEPH_PORT explicitly opts into it.
_env_geph_port = os.environ.get("SLIP_GEPH_PORT")
GEPH_OWNED_PORT = 9954
GEPH_EXTERNAL_PORT = 9909
GEPH_PORTS = [int(_env_geph_port)] if _env_geph_port else [GEPH_OWNED_PORT]
GEPH_OWNERSHIP_FILE = "geph-owned.json"
GEPH_LAUNCHD_LABEL = "dev.slipstream.geph"
_geph_up = False               # set by network_monitor's periodic probe
_geph_port = None              # the live SOCKS port (set by probe_geph)
_geph_owned = False
_geph_port_conflict = False
_external_geph_detected = False
_geph_active_sessions = 0
_geph_restart_draining = False
_geph_session_lock = threading.Lock()
_geph_backend_hold_until = 0.0
_geph_backend_hold_reason = ""
_pf_state_lock = threading.Lock()
_fd_pressure = False
_fd_pressure_reason = ""
_fd_pressure_at = 0.0
_fd_pressure_lock = threading.Lock()
_fd_reserve = []
BASELINE_GUARD_RETRY_SECONDS = 30.0
BASELINE_GUARD_BLOCK_REASON = "baseline_https_unavailable"
BASELINE_GUARD_ROLLBACK_REASON = "baseline_rollback_incomplete"
PF_LOOPBACK_UNAVAILABLE_REASON = "pf_loopback_unavailable"
PF_FLUSH_ATTEMPTS = 3
PF_FLUSH_RETRY_DELAY = 0.1
_baseline_guard_lock = threading.Lock()
_baseline_guard_state = {
    "state": "pending",
    "reason": "",
    "updated_at": 0.0,
    "retry_at": 0.0,
    "failures": 0,
}
_system_dns_cache = {
    "ts": 0.0,
    "status": None,
    "resolution_ts": 0.0,
    "resolution_checks": None,
}
SYSTEM_DNS_STATUS_TTL = 30.0
SYSTEM_DNS_RESOLUTION_TTL = 5 * 60.0
SYSTEM_DNS_DIAGNOSTIC_BUDGET = 5.0
BASELINE_RESOLVE_TIMEOUT = 1.5
BASELINE_PREFLIGHT_BUDGET = 10.0

DEFAULT_IP_ATTEMPT_LIMIT = 2
LOCAL_BYPASS_IP_ATTEMPT_LIMIT = 4
IP_ATTEMPT_LIMIT_BY_ROUTE = {
    ROUTE_LOCAL_BYPASS: LOCAL_BYPASS_IP_ATTEMPT_LIMIT,
}
ROUTE_POLICY_VERSION = 2
ROUTE_POLICY_SOURCE = "bundled"
ROUTE_POLICY_SCHEMA_VERSION = route_policy_bundle_contract.SCHEMA_VERSION
ROUTE_POLICY_CHANNEL_KIND = "slipstream.route_policy_channel"
ROUTE_POLICY_CHANNEL_SCHEMA_VERSION = 1

# Services that refuse Russian IPs at the application layer (desync can't help —
# only an exit abroad does). Suffix match. Telegram is deliberately ABSENT: per
# product decision it is NOT tunnelled through geph; its DPI block is handled by
# the bundled tg-ws-proxy (local MTProto proxy), and its raw DC-IP sockets are
# passed direct (see TELEGRAM_NETS) so our desync never mangles MTProto.
OPENAI_HOSTS = ("openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com")
ANTHROPIC_HOSTS = ("anthropic.com", "claude.ai", "claudeusercontent.com")
STEAM_STORE_HOSTS = (
    "steampowered.com", "steamcommunity.com", "steamstatic.com",
    "steamusercontent.com",
    "steamcdn-a.akamaihd.net", "steamcommunity-a.akamaihd.net",
)
GEPH_MISC_HOSTS = (
    "intercomcdn.com",            # OpenAI/Anthropic support widget assets
)

# Flowseal/zapret-style hostlists mark services for LOCAL DPI bypass, not for a
# foreign VPN exit. These hosts should stay on the user's normal route and use
# desync/fake strategies; Geph is reserved for application-layer geo-blocks.
DISCORD_HOSTS = (
    "discord.com", "discord.gg", "discord.media",
    "discordapp.com", "discordapp.net", "discordcdn.com",
    "discord.app", "discord.co", "discord.dev", "discord.design",
    "discord.gift", "discord.gifts", "discord.new", "discord.store",
    "discord.status", "discord-activities.com", "discordactivities.com",
    "discordmerch.com", "discordpartygames.com", "discordsays.com",
    "discordsez.com", "discordstatus.com", "dis.gd",
)
GOOGLE_VIDEO = (
    "googlevideo.com", "youtube.com", "youtu.be", "ytimg.com", "ggpht.com",
    "gvt1.com", "gvt2.com",
)
LOCAL_BYPASS_HOSTS = DISCORD_HOSTS + GOOGLE_VIDEO
TELEGRAM_HOSTS = ("telegram.org", "telegram.me", "telegram.dog", "t.me", "telegra.ph")
GOOGLE_DIRECT_FIRST_HOSTS = ("google.com",)
SPOTIFY_DIRECT_FIRST_HOSTS = ("spotify.com", "spotifycdn.com", "scdn.co")
DIRECT_FIRST_HOSTS = GOOGLE_DIRECT_FIRST_HOSTS + SPOTIFY_DIRECT_FIRST_HOSTS
GITHUB_HOSTS = (
    "github.com",
    "githubassets.com",
    "githubusercontent.com",
    "github.io",
    "github.githubassets.com",
    "api.github.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
)

XBOX_DNS_SERVERS = (
    "111.88.96.50",
    "111.88.96.51",
    "2a00:ab00:1233:26::50",
    "2a00:ab00:1233:26::51",
)

ROUTE_POLICY_TABLE = (
    {
        "domains": TELEGRAM_HOSTS,
        "route_class": ROUTE_DIRECT,
        "service_group": SERVICE_TELEGRAM,
        "strategy_set": STRATEGY_DIRECT,
    },
    {
        "domains": GITHUB_HOSTS,
        "route_class": ROUTE_DIRECT,
        "service_group": SERVICE_GITHUB,
        "strategy_set": STRATEGY_DIRECT,
    },
    {
        "domains": GOOGLE_DIRECT_FIRST_HOSTS,
        "route_class": ROUTE_DIRECT_FIRST,
        "service_group": SERVICE_GOOGLE,
        "strategy_set": STRATEGY_DIRECT_FIRST,
    },
    {
        "domains": SPOTIFY_DIRECT_FIRST_HOSTS,
        "route_class": ROUTE_DIRECT_FIRST,
        "service_group": SERVICE_SPOTIFY,
        "strategy_set": STRATEGY_DIRECT_FIRST,
    },
    {
        "domains": DISCORD_HOSTS,
        "route_class": ROUTE_LOCAL_BYPASS,
        "service_group": SERVICE_DISCORD,
        "strategy_set": STRATEGY_FAKE_ONLY,
    },
    {
        "domains": GOOGLE_VIDEO,
        "route_class": ROUTE_LOCAL_BYPASS,
        "service_group": SERVICE_YOUTUBE,
        "strategy_set": STRATEGY_FAKE_ONLY,
    },
)

GEO_EXIT_POLICY_TABLE = (
    {"domains": OPENAI_HOSTS + ("billing.openai.com",), "service_group": SERVICE_OPENAI},
    {"domains": ANTHROPIC_HOSTS, "service_group": SERVICE_ANTHROPIC},
    {"domains": STEAM_STORE_HOSTS, "service_group": SERVICE_STEAM_STORE},
    {"domains": GEPH_MISC_HOSTS, "service_group": SERVICE_GENERIC},
)
GEPH_HOSTS = tuple(
    domain for policy in GEO_EXIT_POLICY_TABLE for domain in policy["domains"]
)
POLICY_STATE_DIR = "/var/db/slipstream"
ROUTE_POLICY_STATE_PATH = os.path.join(POLICY_STATE_DIR, "route-policy.json")
ROUTE_POLICY_PREVIOUS_PATH = os.path.join(POLICY_STATE_DIR, "route-policy.previous.json")
ROUTE_POLICY_ACTIVATION_PATH = os.path.join(
    POLICY_STATE_DIR,
    "route-policy.activation.json",
)
ROUTE_POLICY_KEYS_PATH = os.path.join(POLICY_STATE_DIR, "route-policy-keys.json")
ROUTE_POLICY_BUNDLED_KEYS_FILENAME = "route-policy-keys.json"
ROUTE_POLICY_REMOTE_URL_ENV = "SLIP_ROUTE_POLICY_URL"
ROUTE_POLICY_KEYS_PATH_ENV = "SLIP_ROUTE_POLICY_KEYS_PATH"
ROUTE_POLICY_FETCH_TIMEOUT = 5.0
ROUTE_POLICY_MAX_BYTES = 256 * 1024
ROUTE_POLICY_REMOTE_INTERVAL = 6 * 60 * 60.0
ROUTE_POLICY_REMOTE_JITTER = 5 * 60.0
ROUTE_POLICY_REMOTE_RETRY_BASE = 15 * 60.0
ROUTE_POLICY_REMOTE_RETRY_MAX = 6 * 60 * 60.0
TRUSTED_ROUTE_POLICY_KEYS = {}
_active_route_policy_manifest = None
_active_route_policy_kind = route_policy_activation_contract.POLICY_BUNDLED
_route_policy_storage = {
    "state": "bundled",
    "path": ROUTE_POLICY_STATE_PATH,
    "source": ROUTE_POLICY_SOURCE,
    "sha256": "",
    "last_error": "",
    "updated_at": 0.0,
}
_route_policy_remote = {
    "state": "disabled",
    "url": "",
    "last_error": "",
    "last_checked": 0.0,
    "last_source": "",
    "last_sha256": "",
    "next_due": 0.0,
    "running": False,
    "failures": 0,
    "last_reason": "",
}
_route_policy_activation_lock = threading.RLock()
_route_policy_trial_generation = 0

DNS_DIAGNOSTIC_HOSTS = (
    ("updates.discord.com", SERVICE_DISCORD),
    ("gateway.discord.gg", SERVICE_DISCORD),
    ("www.youtube.com", SERVICE_YOUTUBE),
    ("redirector.googlevideo.com", SERVICE_YOUTUBE),
)
DNS_POISON_STUB_NETS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "87.228.47.0/24",  # observed ISP poison stub range
    )
)

GEO_BACKEND_GEPH = "geph"
GEO_BACKEND_SMART_DNS = "smart_dns"

HEALTH_OK = "ok"
HEALTH_DEGRADED = "degraded"
HEALTH_BLOCKED = "blocked"
HEALTH_UNKNOWN = "unknown"

FAILURE_PHASE_BACKEND = "backend"
FAILURE_PHASE_CONNECT = "connect"
FAILURE_PHASE_FIRST_PAYLOAD = "first_payload"
FAILURE_PHASE_STREAM = "stream"

BACKEND_LOCAL_ENGINE = "local_engine"
BACKEND_DIRECT = "direct"
BACKEND_EXTERNAL = "external"

RUNTIME_ROUTE_CIRCUIT_CONFIG = route_circuit.CircuitConfig(
    failure_threshold=2,
    open_duration_ms=1000,
    half_open_max_in_flight=1,
    success_threshold=1,
)
RUNTIME_ROUTE_CIRCUIT_REGISTRY_CONFIG = (
    route_circuit_registry.RouteCircuitRegistryConfig(
        max_entries=256,
        idle_ttl_ms=5 * 60 * 1000,
    )
)
_runtime_route_circuits = route_circuit_registry.RouteCircuitRegistry(
    RUNTIME_ROUTE_CIRCUIT_CONFIG,
    RUNTIME_ROUTE_CIRCUIT_REGISTRY_CONFIG,
)

ADDRESS_RACE_TIMEOUT_MS = 9_000
ADDRESS_RACE_STAGGER_MS = 250
ADDRESS_RACE_MAX_CONCURRENT = 2


CANARY_INTERVAL = 10 * 60.0
CANARY_JITTER = 90.0
CANARY_FORCE_MIN_GAP = 60.0
CANARY_FORCE_RETRY_DELAY = 15.0
CANARY_FAILURE_WINDOW = 5 * 60.0
LOCAL_PAYLOAD_CANARY_TIMEOUT = 8.0
LOCAL_PAYLOAD_CANARY_MIN_BYTES = 64
LOCAL_PAYLOAD_DEGRADE_AFTER = 3
LOCAL_BYPASS_RUNTIME_DEGRADE_AFTER = 3
LOCAL_BYPASS_RESWEEP_COOLDOWN = 60.0
LOCAL_BYPASS_RESWEEP_STALE_AFTER = 120.0
GEO_PAYLOAD_CANARY_TIMEOUT = 6.0
QUIC_CANARY_TIMEOUT = 1.5
QUIC_UNSUPPORTED_VERSION = b"\x0a\x0a\x0a\x0a"
QUIC_MIN_INITIAL_SIZE = 1200
GEO_EXIT_RUNTIME_DEGRADE_AFTER = 3
GEPH_RESTART_FAILURE_THRESHOLD = 3
GEPH_RESTART_MIN_HOSTS = 2
GEPH_RESTART_WAKE_WINDOW = 10 * 60.0
GEPH_RESTART_COOLDOWN = 10 * 60.0
GEPH_RESTART_EXECUTION_RETRY = 30.0
GEPH_BACKEND_FAILURE_HOLD = 30.0
FD_PRESSURE_HIGH_CAP = 2048
FD_PRESSURE_LOW_CAP = 1024
FD_PRESSURE_RESERVE = 8
SMART_DNS_OK_TTL = 10 * 60.0
SMART_DNS_GROUPS = (SERVICE_OPENAI, SERVICE_ANTHROPIC)
_smart_dns_ok_until = {}
_smart_dns_last_failure = {"host": "", "reason": "", "ts": 0.0}


def is_discord_host(host):
    return _host_matches(host, DISCORD_HOSTS)


def is_google_video_host(host):
    return _host_matches(host, GOOGLE_VIDEO)


def bundled_route_policy_manifest():
    return {
        "version": ROUTE_POLICY_VERSION,
        "source": ROUTE_POLICY_SOURCE,
        "static_routes": [
            {
                "domains": list(policy["domains"]),
                "route_class": policy["route_class"],
                "service_group": policy["service_group"],
                "strategy_set": policy["strategy_set"],
            }
            for policy in ROUTE_POLICY_TABLE
        ],
        "geo_exit_routes": [
            {
                "domains": list(policy["domains"]),
                "service_group": policy["service_group"],
                "route_class": ROUTE_GEO_EXIT,
                "strategy_set": STRATEGY_GEPH,
            }
            for policy in GEO_EXIT_POLICY_TABLE
        ],
        "attempt_limits": {
            "default": DEFAULT_IP_ATTEMPT_LIMIT,
            **IP_ATTEMPT_LIMIT_BY_ROUTE,
        },
    }


def _copy_route_policy_manifest(manifest):
    return {
        "version": manifest["version"],
        "source": manifest["source"],
        "static_routes": [
            {
                "domains": list(policy["domains"]),
                "route_class": policy["route_class"],
                "service_group": policy["service_group"],
                "strategy_set": policy["strategy_set"],
            }
            for policy in manifest["static_routes"]
        ],
        "geo_exit_routes": [
            {
                "domains": list(policy["domains"]),
                "route_class": policy["route_class"],
                "service_group": policy["service_group"],
                "strategy_set": policy["strategy_set"],
            }
            for policy in manifest["geo_exit_routes"]
        ],
        "attempt_limits": dict(manifest["attempt_limits"]),
    }


def route_policy_manifest():
    manifest = _active_route_policy_manifest
    if manifest is None:
        manifest = bundled_route_policy_manifest()
    return _copy_route_policy_manifest(manifest)


def route_policy_tables(manifest=None):
    manifest = route_policy_manifest() if manifest is None else manifest
    normalized = validate_route_policy_manifest(manifest)
    return normalized["static_routes"], normalized["geo_exit_routes"]


def active_geph_hosts(manifest=None):
    _static_routes, geo_exit_routes = route_policy_tables(manifest)
    return tuple(domain for policy in geo_exit_routes for domain in policy["domains"])


def is_local_bypass_host(host):
    static_routes, _geo_exit_routes = route_policy_tables()
    return any(
        policy["route_class"] == ROUTE_LOCAL_BYPASS
        and _host_matches(host, policy["domains"])
        for policy in static_routes
    )


def _require_policy_int(value, name, *, min_value=0, max_value=100):
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    if value < min_value or value > max_value:
        raise ValueError(f"{name} out of range")
    return value


RoutePolicyManifestError = route_policy_manifest_contract.RoutePolicyManifestError
RoutePolicyBundleError = route_policy_bundle_contract.RoutePolicyBundleError


def validate_route_policy_manifest(manifest):
    return route_policy_manifest_contract.validate_route_policy_manifest(
        manifest,
        ROUTE_POLICY_TABLE,
    )


def route_policy_canonical_bytes(manifest=None):
    manifest = route_policy_manifest() if manifest is None else manifest
    return route_policy_bundle_contract.route_policy_canonical_bytes(
        manifest,
        ROUTE_POLICY_TABLE,
    )


def route_policy_hash(manifest=None):
    manifest = route_policy_manifest() if manifest is None else manifest
    return route_policy_bundle_contract.route_policy_hash(
        manifest,
        ROUTE_POLICY_TABLE,
    )


def verify_signed_route_policy_bundle(bundle, public_keys):
    return route_policy_bundle_contract.verify_signed_route_policy_bundle(
        bundle,
        public_keys,
        ROUTE_POLICY_TABLE,
    )


def _route_policy_identity(manifest, *, kind=None):
    normalized = validate_route_policy_manifest(manifest)
    if kind is None:
        bundled = bundled_route_policy_manifest()
        kind = (
            route_policy_activation_contract.POLICY_BUNDLED
            if route_policy_hash(normalized) == route_policy_hash(bundled)
            else route_policy_activation_contract.POLICY_SIGNED
        )
    return route_policy_activation_contract.PolicyIdentity(
        kind=kind,
        source=normalized["source"],
        sha256=route_policy_hash(normalized),
    )


def _active_route_policy_identity(active_manifest=None):
    manifest = route_policy_manifest() if active_manifest is None else active_manifest
    return _route_policy_identity(manifest, kind=_active_route_policy_kind)


def _stable_route_policy_activation_state(active_manifest, *, previous=None):
    bundled_manifest = bundled_route_policy_manifest()
    return route_policy_activation_contract.PolicyActivationState(
        bundled=_route_policy_identity(
            bundled_manifest,
            kind=route_policy_activation_contract.POLICY_BUNDLED,
        ),
        active=_active_route_policy_identity(active_manifest),
        previous=previous,
        trial_generation=_route_policy_trial_generation,
    )


def apply_route_policy_manifest(manifest, *, kind=None):
    """Activate a validated route policy manifest in memory.

    Remote fetch/persistence is deliberately outside this function. This keeps
    policy updates staged: verify first, activate atomically, then expose the
    active hash in status for diagnostics/rollback decisions.
    """
    global _active_route_policy_kind, _active_route_policy_manifest
    normalized = validate_route_policy_manifest(manifest)
    if kind is None:
        kind = _route_policy_identity(normalized).kind
    if kind not in {
        route_policy_activation_contract.POLICY_BUNDLED,
        route_policy_activation_contract.POLICY_SIGNED,
    }:
        raise ValueError("route policy kind is invalid")
    _active_route_policy_manifest = _copy_route_policy_manifest(normalized)
    _active_route_policy_kind = kind
    return route_policy_status_snapshot()


def _set_route_policy_storage(state, *, source=None, sha256="", error="", path=None):
    _route_policy_storage.update({
        "state": state,
        "path": path or ROUTE_POLICY_STATE_PATH,
        "source": source or "",
        "sha256": sha256,
        "last_error": error,
        "updated_at": time.time(),
    })
    return route_policy_storage_snapshot()


def route_policy_storage_snapshot():
    return dict(_route_policy_storage)


def _set_route_policy_remote(
    state,
    *,
    url="",
    error="",
    source="",
    sha256="",
    now=None,
):
    _route_policy_remote.update({
        "state": state,
        "url": url,
        "last_error": error,
        "last_checked": time.time() if now is None else now,
        "last_source": source,
        "last_sha256": sha256,
    })
    return route_policy_remote_snapshot()


def route_policy_remote_snapshot():
    return dict(_route_policy_remote)


def route_policy_remote_url():
    return os.environ.get(ROUTE_POLICY_REMOTE_URL_ENV, "").strip()


def _route_policy_remote_delay(success, failures, now=None):
    now = time.monotonic() if now is None else now
    jitter = int(now) % int(ROUTE_POLICY_REMOTE_JITTER or 1)
    if success:
        return ROUTE_POLICY_REMOTE_INTERVAL + jitter
    failures = max(1, int(failures or 1))
    delay = ROUTE_POLICY_REMOTE_RETRY_BASE * (2 ** (failures - 1))
    return min(ROUTE_POLICY_REMOTE_RETRY_MAX, delay) + jitter


def _finish_route_policy_remote_update(success, now=None):
    now = time.monotonic() if now is None else now
    failures = 0 if success else int(_route_policy_remote.get("failures") or 0) + 1
    _route_policy_remote["running"] = False
    _route_policy_remote["failures"] = failures
    _route_policy_remote["next_due"] = now + _route_policy_remote_delay(success, failures, now)


def _route_policy_remote_health_runner(reason):
    return asyncio.run(run_route_canaries(f"policy_update:{reason}"))


def _route_policy_remote_thread_main(reason, url):
    success = False
    try:
        success = update_route_policy_from_remote(
            url=url,
            health_runner=lambda: _route_policy_remote_health_runner(reason),
        )
    except Exception as exc:
        _set_route_policy_remote("error", url=url, error=str(exc))
    finally:
        _finish_route_policy_remote_update(success)


def start_route_policy_remote_update_if_due(
    reason="periodic",
    *,
    force=False,
    now=None,
    runner=None,
):
    now = time.monotonic() if now is None else now
    url = route_policy_remote_url()
    if not url:
        _set_route_policy_remote("disabled", now=time.time())
        _route_policy_remote["running"] = False
        _route_policy_remote["next_due"] = 0.0
        _route_policy_remote["failures"] = 0
        _route_policy_remote["last_reason"] = reason
        return False
    if _route_policy_remote.get("running"):
        return False
    if _canary_state.get("running"):
        return False
    next_due = float(_route_policy_remote.get("next_due") or 0.0)
    if not force and next_due and now < next_due:
        return False
    try:
        url = validate_route_policy_remote_url(url)
    except Exception as exc:
        _set_route_policy_remote("error", url=url, error=str(exc))
        _finish_route_policy_remote_update(False, now)
        return False
    _route_policy_remote["running"] = True
    _route_policy_remote["last_reason"] = reason
    if runner is not None:
        success = False
        try:
            success = bool(runner(reason, url))
            return success
        except Exception as exc:
            _set_route_policy_remote("error", url=url, error=str(exc))
            return False
        finally:
            _finish_route_policy_remote_update(success, now)
    threading.Thread(
        target=_route_policy_remote_thread_main,
        args=(reason, url),
        daemon=True,
        name="route-policy-update",
    ).start()
    return True


def _validate_route_policy_key_map(keys):
    if not isinstance(keys, dict):
        raise ValueError("trusted policy keys must be an object")
    normalized = {}
    for key_id, value in keys.items():
        if not isinstance(key_id, str) or not key_id.strip():
            raise ValueError("trusted policy key id must be a non-empty string")
        if not isinstance(value, str):
            raise ValueError(f"trusted policy key {key_id!r} must be base64")
        try:
            raw = base64.b64decode(value, validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"trusted policy key {key_id!r} is not valid base64") from exc
        if len(raw) != 32:
            raise ValueError(f"trusted policy key {key_id!r} is not an Ed25519 key")
        normalized[key_id] = value
    return normalized


def route_policy_bundled_keys_path():
    root = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root, ROUTE_POLICY_BUNDLED_KEYS_FILENAME)


def _load_route_policy_key_file(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, dict) and "keys" in data:
        data = data["keys"]
    return _validate_route_policy_key_map(data)


def load_trusted_route_policy_keys(
    *,
    path=None,
    embedded_keys=None,
    bundled_path=None,
):
    keys = dict(TRUSTED_ROUTE_POLICY_KEYS if embedded_keys is None else embedded_keys)
    if bundled_path is None:
        bundled_path = route_policy_bundled_keys_path()
    keys.update(_load_route_policy_key_file(bundled_path))
    if path is None:
        path = os.environ.get(ROUTE_POLICY_KEYS_PATH_ENV, ROUTE_POLICY_KEYS_PATH)
    keys.update(_load_route_policy_key_file(path))
    return _validate_route_policy_key_map(keys)


def validate_route_policy_remote_url(url):
    if not isinstance(url, str) or not url.strip():
        raise ValueError("remote policy url is empty")
    parsed = urlparse(url.strip())
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("remote policy url must use https")
    return url.strip()


def _fetch_remote_policy_json(
    url,
    *,
    fetcher=None,
    timeout=ROUTE_POLICY_FETCH_TIMEOUT,
    max_bytes=ROUTE_POLICY_MAX_BYTES,
):
    if fetcher is not None:
        data = fetcher(url)
    else:
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "SlipstreamPolicyUpdater/1",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = response.read(max_bytes + 1)
    if isinstance(data, dict):
        body = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return data, body
    if isinstance(data, str):
        data = data.encode("utf-8")
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("remote policy response must be JSON")
    if len(data) > max_bytes:
        raise ValueError("remote policy response is too large")
    body = bytes(data)
    return json.loads(body.decode("utf-8")), body


def _is_route_policy_channel(data):
    return isinstance(data, dict) and "bundle_url" in data


def _fetch_signed_route_policy_bundle_from_channel(
    channel,
    *,
    fetcher=None,
    timeout=ROUTE_POLICY_FETCH_TIMEOUT,
    max_bytes=ROUTE_POLICY_MAX_BYTES,
):
    if channel.get("kind") != ROUTE_POLICY_CHANNEL_KIND:
        raise ValueError("remote policy channel kind is not supported")
    schema = _require_policy_int(
        channel.get("schema"),
        "channel.schema",
        min_value=ROUTE_POLICY_CHANNEL_SCHEMA_VERSION,
        max_value=ROUTE_POLICY_CHANNEL_SCHEMA_VERSION,
    )
    if schema != ROUTE_POLICY_CHANNEL_SCHEMA_VERSION:
        raise ValueError("unsupported remote policy channel schema")
    expected_hash = channel.get("sha256")
    if not isinstance(expected_hash, str) or len(expected_hash) != 64:
        raise ValueError("remote policy channel sha256 is required")
    bundle_url = validate_route_policy_remote_url(channel.get("bundle_url"))
    bundle, bundle_bytes = _fetch_remote_policy_json(
        bundle_url,
        fetcher=fetcher,
        timeout=timeout,
        max_bytes=max_bytes,
    )
    actual_hash = hashlib.sha256(bundle_bytes).hexdigest()
    if actual_hash != expected_hash:
        raise ValueError("remote policy bundle hash mismatch")
    return bundle


def fetch_signed_route_policy_bundle(
    url,
    *,
    fetcher=None,
    timeout=ROUTE_POLICY_FETCH_TIMEOUT,
    max_bytes=ROUTE_POLICY_MAX_BYTES,
):
    url = validate_route_policy_remote_url(url)
    data, _body = _fetch_remote_policy_json(
        url,
        fetcher=fetcher,
        timeout=timeout,
        max_bytes=max_bytes,
    )
    if _is_route_policy_channel(data):
        return _fetch_signed_route_policy_bundle_from_channel(
            data,
            fetcher=fetcher,
            timeout=timeout,
            max_bytes=max_bytes,
        )
    return data
def _route_policy_health_evidence(result):
    if result is True:
        return route_policy_activation_adapter.HealthEvidence(completed=True, ok=1)
    if result is False:
        return route_policy_activation_adapter.HealthEvidence(
            completed=True,
            detail="health gate failed",
        )

    if isinstance(result, (list, tuple)) and len(result) >= 2:
        raw = (result[0], result[1], 0)
    elif isinstance(result, dict):
        raw = (
            result.get("ok", 0),
            result.get("degraded", 0),
            result.get("blocked", 0),
        )
    else:
        return route_policy_activation_adapter.HealthEvidence(
            completed=False,
            detail="health gate did not run",
        )

    counters = []
    for value in raw:
        if isinstance(value, bool) or not isinstance(value, int):
            return route_policy_activation_adapter.HealthEvidence(
                completed=False,
                detail="health gate returned invalid counters",
            )
        parsed = value
        if not 0 <= parsed <= route_policy_activation_contract.MAX_COUNTER:
            return route_policy_activation_adapter.HealthEvidence(
                completed=False,
                detail="health gate returned invalid counters",
            )
        counters.append(parsed)

    ok, degraded, blocked = counters
    detail = ""
    if degraded or blocked or not ok:
        if isinstance(result, dict):
            detail = (
                f"health gate degraded={degraded} blocked={blocked} ok={ok}"
            )
        else:
            detail = f"health gate degraded={degraded} ok={ok}"
    return route_policy_activation_adapter.HealthEvidence(
        completed=True,
        ok=ok,
        degraded=degraded,
        blocked=blocked,
        detail=detail,
    )


def apply_signed_route_policy_bundle_with_health_gate(
    bundle,
    public_keys,
    health_runner,
    *,
    policy_path=ROUTE_POLICY_STATE_PATH,
    previous_path=ROUTE_POLICY_PREVIOUS_PATH,
    activation_path=None,
    now=None,
):
    global _route_policy_trial_generation
    with _route_policy_activation_lock:
        activation_path = _route_policy_activation_state_path(
            policy_path,
            activation_path,
        )
        previous_manifest = route_policy_manifest()
        previous_storage = route_policy_storage_snapshot()
        manifest = verify_signed_route_policy_bundle(bundle, public_keys)
        _route_policy_trial_generation = max(
            _route_policy_trial_generation,
            _read_route_policy_trial_generation(activation_path),
        )
        candidate = _route_policy_identity(
            manifest,
            kind=route_policy_activation_contract.POLICY_SIGNED,
        )
        activation_state = _stable_route_policy_activation_state(previous_manifest)

        def restore_active(policy):
            if policy != activation_state.active:
                raise RuntimeError("reducer requested an unexpected active policy")
            _restore_route_policy_manifest(previous_manifest, policy)

        effects = route_policy_activation_adapter.CandidateEffects(
            persist_trial_generation=lambda generation: (
                _persist_route_policy_trial_generation(
                    activation_path,
                    generation,
                )
            ),
            activate_trial=lambda policy: _activate_candidate_manifest(
                policy,
                candidate,
                manifest,
            ),
            run_health_gate=lambda _policy, _generation: (
                _route_policy_health_evidence(health_runner())
            ),
            commit_candidate=lambda policy, previous, generation: (
                _commit_signed_route_policy_bundle(
                    bundle,
                    public_keys,
                    candidate=policy,
                    previous=previous,
                    trial_generation=generation,
                    policy_path=policy_path,
                    previous_path=previous_path,
                    now=now,
                )
            ),
            restore_active=restore_active,
            record_rejection=lambda _policy, _reason, detail: (
                _set_route_policy_storage(
                    "rejected",
                    source=(
                        previous_storage.get("source")
                        or previous_manifest.get("source")
                    ),
                    sha256=(
                        previous_storage.get("sha256")
                        or route_policy_hash(previous_manifest)
                    ),
                    error=detail,
                    path=policy_path,
                )
            ),
        )
        try:
            result = route_policy_activation_adapter.activate_candidate(
                activation_state,
                candidate,
                effects,
            )
        except route_policy_activation_adapter.PolicyActivationAdapterError as exc:
            _route_policy_trial_generation = max(
                _route_policy_trial_generation,
                exc.state.trial_generation,
            )
            _set_route_policy_storage(
                "error",
                source=previous_manifest.get("source"),
                sha256=route_policy_hash(previous_manifest),
                error=str(exc),
                path=policy_path,
            )
            raise

        _route_policy_trial_generation = max(
            _route_policy_trial_generation,
            result.state.trial_generation,
        )
        if not result.accepted:
            return None
        return result.value or route_policy_status_snapshot()


def update_route_policy_from_remote(
    *,
    url=None,
    public_keys=None,
    fetcher=None,
    health_runner=None,
    policy_path=ROUTE_POLICY_STATE_PATH,
    previous_path=ROUTE_POLICY_PREVIOUS_PATH,
    now=None,
):
    url = url if url is not None else os.environ.get(ROUTE_POLICY_REMOTE_URL_ENV, "")
    now = time.time() if now is None else now
    if not url:
        _set_route_policy_remote("disabled", now=now)
        return False
    try:
        url = validate_route_policy_remote_url(url)
        keys = load_trusted_route_policy_keys() if public_keys is None else public_keys
        if not keys:
            raise ValueError("trusted policy keys are required")
        if health_runner is None:
            raise ValueError("remote policy health gate is required")
        bundle = fetch_signed_route_policy_bundle(url, fetcher=fetcher)
        status = apply_signed_route_policy_bundle_with_health_gate(
            bundle,
            keys,
            health_runner,
            policy_path=policy_path,
            previous_path=previous_path,
            now=now,
        )
        if not status:
            error = route_policy_storage_snapshot().get("last_error", "health gate failed")
            _set_route_policy_remote("rejected", url=url, error=error, now=now)
            return False
        _set_route_policy_remote(
            "applied",
            url=url,
            source=status["source"],
            sha256=status["sha256"],
            now=now,
        )
        return True
    except Exception as exc:
        _set_route_policy_remote("error", url=url, error=str(exc), now=now)
        return False


def _atomic_write_bytes(path, data, *, mode=0o600):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        with open(tmp, "xb") as f:
            f.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        try:
            os.remove(tmp)
        except FileNotFoundError:
            pass
        except Exception:
            pass


def _atomic_write_json(path, data, *, mode=0o600):
    payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    _atomic_write_bytes(path, payload + b"\n", mode=mode)


def _remove_policy_file(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def _policy_file_snapshot(path):
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None
    try:
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError(f"route policy path is not a regular file: {path}")
        with os.fdopen(fd, "rb", closefd=False) as file_handle:
            data = file_handle.read()
        return {
            "data": data,
            "mode": stat.S_IMODE(file_stat.st_mode),
        }
    finally:
        os.close(fd)


def _restore_policy_file_snapshot(path, snapshot):
    if snapshot is None:
        _remove_policy_file(path)
        return
    _atomic_write_bytes(path, snapshot["data"], mode=snapshot["mode"])


def _run_policy_file_transaction(paths, operation):
    unique_paths = tuple(dict.fromkeys(paths))
    snapshots = {path: _policy_file_snapshot(path) for path in unique_paths}
    try:
        return operation()
    except Exception as original_error:
        restore_errors = []
        for path in unique_paths:
            try:
                _restore_policy_file_snapshot(path, snapshots[path])
            except Exception as exc:
                restore_errors.append(f"{path}: {exc}")
        if restore_errors:
            raise RuntimeError(
                f"{original_error}; route policy file restore failed: "
                + "; ".join(restore_errors)
            ) from original_error
        raise


def _route_policy_activation_state_path(policy_path, activation_path=None):
    if activation_path is not None:
        return activation_path
    if os.fspath(policy_path) == ROUTE_POLICY_STATE_PATH:
        return ROUTE_POLICY_ACTIVATION_PATH
    return f"{os.fspath(policy_path)}.activation"


def _validate_route_policy_trial_generation(generation, message):
    if (
        isinstance(generation, bool)
        or not isinstance(generation, int)
        or not 0
        <= generation
        <= route_policy_activation_contract.MAX_TRIAL_GENERATION
    ):
        raise ValueError(message)
    return generation


def _read_route_policy_trial_generation(path):
    snapshot = _policy_file_snapshot(path)
    if snapshot is None:
        return 0
    state = json.loads(snapshot["data"].decode("utf-8"))
    if not isinstance(state, dict):
        raise ValueError("persisted policy activation state is invalid")
    if state.get("contract") != route_policy_activation_contract.CONTRACT_VERSION:
        raise ValueError("unsupported persisted policy activation contract")
    return _validate_route_policy_trial_generation(
        state.get("trial_generation"),
        "persisted policy trial generation is invalid",
    )


def _persist_route_policy_trial_generation(path, generation):
    generation = _validate_route_policy_trial_generation(
        generation,
        "route policy trial generation is invalid",
    )
    current = _read_route_policy_trial_generation(path)
    if generation < current:
        raise RuntimeError("route policy trial generation cannot decrease")
    if generation == current:
        return
    _atomic_write_json(
        path,
        {
            "contract": route_policy_activation_contract.CONTRACT_VERSION,
            "trial_generation": generation,
        },
    )


def _persisted_route_policy_generation(state):
    metadata = state.get("activation")
    if metadata is None:
        return 0
    if not isinstance(metadata, dict):
        raise ValueError("persisted policy activation metadata is invalid")
    if metadata.get("contract") != route_policy_activation_contract.CONTRACT_VERSION:
        raise ValueError("unsupported persisted policy activation contract")
    return _validate_route_policy_trial_generation(
        metadata.get("trial_generation"),
        "persisted policy trial generation is invalid",
    )


def _read_signed_route_policy_state(path, public_keys):
    snapshot = _policy_file_snapshot(path)
    if snapshot is None:
        raise FileNotFoundError(path)
    state = json.loads(snapshot["data"].decode("utf-8"))
    if not isinstance(state, dict) or state.get("schema") != ROUTE_POLICY_SCHEMA_VERSION:
        raise ValueError("unsupported persisted policy schema")
    manifest = verify_signed_route_policy_bundle(state.get("bundle"), public_keys)
    expected_hash = state.get("sha256")
    actual_hash = route_policy_hash(manifest)
    if expected_hash != actual_hash:
        raise ValueError("persisted policy hash mismatch")
    return {
        "state": state,
        "manifest": manifest,
        "identity": _route_policy_identity(
            manifest,
            kind=route_policy_activation_contract.POLICY_SIGNED,
        ),
        "trial_generation": _persisted_route_policy_generation(state),
    }


def signed_route_policy_state(
    bundle,
    public_keys,
    now=None,
    *,
    trial_generation=0,
):
    manifest = verify_signed_route_policy_bundle(bundle, public_keys)
    trial_generation = _validate_route_policy_trial_generation(
        trial_generation,
        "route policy trial generation is invalid",
    )
    return {
        "schema": ROUTE_POLICY_SCHEMA_VERSION,
        "saved_at": time.time() if now is None else now,
        "sha256": route_policy_hash(manifest),
        "source": manifest["source"],
        "bundle": bundle,
        "activation": {
            "contract": route_policy_activation_contract.CONTRACT_VERSION,
            "trial_generation": trial_generation,
        },
    }


def _restore_route_policy_manifest(manifest, identity):
    if _route_policy_identity(manifest, kind=identity.kind) != identity:
        raise RuntimeError("policy manifest does not match reducer identity")
    if identity.kind == route_policy_activation_contract.POLICY_BUNDLED:
        return reset_route_policy_manifest()
    return apply_route_policy_manifest(manifest, kind=identity.kind)


def _activate_candidate_manifest(policy, expected, manifest):
    if policy != expected:
        raise RuntimeError("reducer requested an unexpected candidate policy")
    apply_route_policy_manifest(manifest, kind=policy.kind)


def _commit_signed_route_policy_bundle(
    bundle,
    public_keys,
    *,
    candidate,
    previous,
    trial_generation,
    policy_path=ROUTE_POLICY_STATE_PATH,
    previous_path=ROUTE_POLICY_PREVIOUS_PATH,
    now=None,
):
    state = signed_route_policy_state(
        bundle,
        public_keys,
        now=now,
        trial_generation=trial_generation,
    )
    if state["sha256"] != candidate.sha256:
        raise RuntimeError("candidate bundle does not match reducer identity")
    storage_before = route_policy_storage_snapshot()

    def commit():
        if previous.kind == route_policy_activation_contract.POLICY_SIGNED:
            current = _read_signed_route_policy_state(policy_path, public_keys)
            if current["identity"] != previous:
                raise RuntimeError("persisted active policy does not match reducer state")
            _atomic_write_json(previous_path, current["state"])
        else:
            _remove_policy_file(previous_path)
        _atomic_write_json(policy_path, state)
        _set_route_policy_storage(
            "saved",
            source=state["source"],
            sha256=state["sha256"],
            path=policy_path,
        )
        return route_policy_status_snapshot()

    try:
        return _run_policy_file_transaction(
            (policy_path, previous_path),
            commit,
        )
    except Exception:
        _route_policy_storage.clear()
        _route_policy_storage.update(storage_before)
        raise


def load_persisted_route_policy(
    public_keys,
    *,
    policy_path=ROUTE_POLICY_STATE_PATH,
    activation_path=None,
):
    global _route_policy_trial_generation
    with _route_policy_activation_lock:
        activation_path = _route_policy_activation_state_path(
            policy_path,
            activation_path,
        )
        try:
            durable_generation = _read_route_policy_trial_generation(
                activation_path
            )
        except Exception as exc:
            reset_route_policy_manifest()
            _set_route_policy_storage(
                "invalid",
                source=ROUTE_POLICY_SOURCE,
                sha256=route_policy_hash(),
                error=str(exc),
                path=policy_path,
            )
            return False
        _route_policy_trial_generation = max(
            _route_policy_trial_generation,
            durable_generation,
        )
        if not os.path.exists(policy_path):
            reset_route_policy_manifest()
            _set_route_policy_storage(
                "bundled",
                source=ROUTE_POLICY_SOURCE,
                sha256=route_policy_hash(),
                path=policy_path,
            )
            return False
        try:
            persisted = _read_signed_route_policy_state(policy_path, public_keys)
            apply_route_policy_manifest(
                persisted["manifest"],
                kind=persisted["identity"].kind,
            )
            _route_policy_trial_generation = max(
                _route_policy_trial_generation,
                durable_generation,
                persisted["trial_generation"],
            )
            _set_route_policy_storage(
                "loaded",
                source=persisted["manifest"]["source"],
                sha256=persisted["identity"].sha256,
                path=policy_path,
            )
            return True
        except Exception as exc:
            reset_route_policy_manifest()
            _set_route_policy_storage(
                "invalid",
                source=ROUTE_POLICY_SOURCE,
                sha256=route_policy_hash(),
                error=str(exc),
                path=policy_path,
            )
            return False


def _commit_route_policy_rollback(
    *,
    target,
    target_manifest,
    target_state,
    active_manifest,
    active,
    trial_generation,
    policy_path,
    previous_path,
):
    storage_before = route_policy_storage_snapshot()

    def commit():
        if target.kind == route_policy_activation_contract.POLICY_SIGNED:
            state = dict(target_state)
            state["activation"] = {
                "contract": route_policy_activation_contract.CONTRACT_VERSION,
                "trial_generation": trial_generation,
            }
            _atomic_write_json(policy_path, state)
        else:
            _remove_policy_file(policy_path)
        _remove_policy_file(previous_path)
        _restore_route_policy_manifest(target_manifest, target)
        _set_route_policy_storage(
            (
                "rolled_back"
                if target.kind == route_policy_activation_contract.POLICY_SIGNED
                else "rolled_back_bundled"
            ),
            source=target.source,
            sha256=target.sha256,
            path=policy_path,
        )
        return True

    try:
        return _run_policy_file_transaction(
            (policy_path, previous_path),
            commit,
        )
    except Exception as original_error:
        restore_error = None
        try:
            _restore_route_policy_manifest(active_manifest, active)
        except Exception as exc:
            restore_error = exc
        _route_policy_storage.clear()
        _route_policy_storage.update(storage_before)
        if restore_error is not None:
            raise RuntimeError(
                f"{original_error}; active policy restore failed: {restore_error}"
            ) from original_error
        raise


def rollback_route_policy(
    public_keys,
    *,
    policy_path=ROUTE_POLICY_STATE_PATH,
    previous_path=ROUTE_POLICY_PREVIOUS_PATH,
):
    global _route_policy_trial_generation
    with _route_policy_activation_lock:
        active_manifest = route_policy_manifest()
        active = _active_route_policy_identity(active_manifest)
        bundled_manifest = bundled_route_policy_manifest()
        bundled = _route_policy_identity(
            bundled_manifest,
            kind=route_policy_activation_contract.POLICY_BUNDLED,
        )

        try:
            target_manifest = bundled_manifest
            target_state = None
            previous = None
            if active.kind == route_policy_activation_contract.POLICY_SIGNED:
                current = _read_signed_route_policy_state(policy_path, public_keys)
                if current["identity"] != active:
                    raise RuntimeError(
                        "persisted active policy does not match reducer state"
                    )
                if os.path.exists(previous_path):
                    target_record = _read_signed_route_policy_state(
                        previous_path,
                        public_keys,
                    )
                    target_manifest = target_record["manifest"]
                    target_state = target_record["state"]
                    previous = target_record["identity"]
                else:
                    previous = bundled

            activation_state = _stable_route_policy_activation_state(
                active_manifest,
                previous=previous,
            )
            effects = route_policy_activation_adapter.RollbackEffects(
                commit_rollback=lambda target, generation: (
                    _commit_route_policy_rollback(
                        target=target,
                        target_manifest=target_manifest,
                        target_state=target_state,
                        active_manifest=active_manifest,
                        active=active,
                        trial_generation=generation,
                        policy_path=policy_path,
                        previous_path=previous_path,
                    )
                ),
                restore_active=lambda policy: _restore_route_policy_manifest(
                    active_manifest,
                    policy,
                ),
                record_rejection=lambda _policy, _reason, _detail: None,
            )
            result = route_policy_activation_adapter.rollback_policy(
                activation_state,
                effects,
            )
            _route_policy_trial_generation = max(
                _route_policy_trial_generation,
                result.state.trial_generation,
            )
            if result.accepted:
                return True if result.value is None else bool(result.value)
            _set_route_policy_storage(
                "rollback_error",
                source=active.source,
                sha256=active.sha256,
                error=result.error,
                path=policy_path,
            )
            return False
        except Exception as exc:
            _set_route_policy_storage(
                "rollback_error",
                source=active.source,
                sha256=active.sha256,
                error=str(exc),
                path=policy_path,
            )
            return False


def reset_route_policy_manifest():
    global _active_route_policy_kind, _active_route_policy_manifest
    _active_route_policy_manifest = None
    _active_route_policy_kind = route_policy_activation_contract.POLICY_BUNDLED
    _set_route_policy_storage(
        "bundled",
        source=ROUTE_POLICY_SOURCE,
        sha256=route_policy_hash(),
    )
    return route_policy_status_snapshot()


def route_policy_status_snapshot():
    manifest = route_policy_manifest()
    domains = {
        ROUTE_DIRECT: 0,
        ROUTE_DIRECT_FIRST: 0,
        ROUTE_LOCAL_BYPASS: 0,
        ROUTE_GEO_EXIT: 0,
    }
    groups = {}
    for policy in manifest["static_routes"]:
        route_class = policy["route_class"]
        domains[route_class] = domains.get(route_class, 0) + len(policy["domains"])
        groups[policy["service_group"]] = {
            "route_class": route_class,
            "strategy_set": policy["strategy_set"],
            "domains": len(policy["domains"]),
        }
    for policy in manifest["geo_exit_routes"]:
        domains[ROUTE_GEO_EXIT] = domains.get(ROUTE_GEO_EXIT, 0) + len(policy["domains"])
        groups[policy["service_group"]] = {
            "route_class": ROUTE_GEO_EXIT,
            "strategy_set": STRATEGY_GEPH,
            "domains": groups.get(policy["service_group"], {}).get("domains", 0)
            + len(policy["domains"]),
        }
    return {
        "version": manifest["version"],
        "source": manifest["source"],
        "sha256": route_policy_hash(manifest),
        "domains": domains,
        "groups": groups,
        "attempt_limits": manifest["attempt_limits"],
    }


def route_policy(host, now=None):
    static_routes, geo_exit_routes = route_policy_tables()
    return classify_route_policy(host, static_routes, geo_exit_routes)


def _runtime_route_circuit_now_ms():
    return int(time.monotonic() * 1000)


def _runtime_route_circuit_key(policy, backend, *, owned=True):
    route_class = policy.get("route_class") or ROUTE_UNKNOWN
    service_group = policy.get("service_group") or SERVICE_GENERIC
    if route_class == ROUTE_LOCAL_BYPASS and backend == BACKEND_LOCAL_ENGINE:
        pass
    elif route_class == ROUTE_GEO_EXIT and backend == GEO_BACKEND_SMART_DNS:
        pass
    elif (
        route_class == ROUTE_GEO_EXIT
        and backend == GEO_BACKEND_GEPH
        and owned
    ):
        pass
    else:
        return None
    return route_circuit.RouteCircuitKey(
        service_group=service_group,
        route_class=route_class,
        backend_id=backend,
    )


def _apply_runtime_route_circuit(event):
    try:
        return _runtime_route_circuits.apply(event)
    except Exception as exc:
        # Circuit memory is an optimization. If its clock/state is ever invalid,
        # forget suppression and keep the fixed route usable.
        _runtime_route_circuits.clear()
        if VERBOSE:
            print(f"  route circuit reset: {exc}", file=sys.stderr)
        return None


def runtime_route_circuit_before_request(
    policy,
    backend,
    *,
    owned=True,
    now_ms=None,
):
    key = _runtime_route_circuit_key(policy, backend, owned=owned)
    if key is None:
        return None
    event = route_circuit.CircuitEvent(
        kind=route_circuit.EVENT_BEFORE_REQUEST,
        key=key,
        now_ms=(
            _runtime_route_circuit_now_ms()
            if now_ms is None
            else int(now_ms)
        ),
    )
    return _apply_runtime_route_circuit(event)


def runtime_route_circuit_record_result(
    policy,
    backend,
    ok,
    *,
    owned=True,
    now_ms=None,
):
    key = _runtime_route_circuit_key(policy, backend, owned=owned)
    if key is None:
        return None
    event = route_circuit.CircuitEvent(
        kind=(
            route_circuit.EVENT_RECORD_SUCCESS
            if ok
            else route_circuit.EVENT_RECORD_FAILURE
        ),
        key=key,
        now_ms=(
            _runtime_route_circuit_now_ms()
            if now_ms is None
            else int(now_ms)
        ),
    )
    return _apply_runtime_route_circuit(event)


def runtime_route_circuit_allows(policy, backend, *, owned=True, now_ms=None):
    decision = runtime_route_circuit_before_request(
        policy,
        backend,
        owned=owned,
        now_ms=now_ms,
    )
    return decision is None or decision.kind == route_circuit.DECISION_ALLOW


def reset_runtime_route_circuits():
    _runtime_route_circuits.clear()


def runtime_route_circuit_snapshot():
    return _runtime_route_circuits.snapshot()


def connection_outcome_for_host(
    host,
    ok,
    backend,
    failure_phase="",
    bytes_received=0,
    duration=0.0,
    reason="",
):
    policy = route_policy(host)
    return ConnectionOutcome(
        host=policy["host"],
        service_group=policy["service_group"],
        route_class=policy["route_class"],
        backend=backend,
        failure_phase=failure_phase,
        bytes_received=max(0, int(bytes_received or 0)),
        duration=max(0.0, float(duration or 0.0)),
        reason=str(reason or "")[:200],
        ok=bool(ok),
    )


def _route_health_default(group, route_class=ROUTE_UNKNOWN):
    return {
        "state": HEALTH_UNKNOWN,
        "last_failure": "",
        "last_warning": "",
        "last_warning_host": "",
        "last_checked": 0.0,
        "failures_5m": 0,
        "last_host": "",
        "last_route_class": route_class,
        "last_backend": "",
    }


_route_health = {
    SERVICE_DISCORD: _route_health_default(SERVICE_DISCORD, ROUTE_LOCAL_BYPASS),
    SERVICE_YOUTUBE: _route_health_default(SERVICE_YOUTUBE, ROUTE_LOCAL_BYPASS),
    SERVICE_OPENAI: _route_health_default(SERVICE_OPENAI, ROUTE_GEO_EXIT),
    SERVICE_ANTHROPIC: _route_health_default(SERVICE_ANTHROPIC, ROUTE_GEO_EXIT),
    SERVICE_TELEGRAM: _route_health_default(SERVICE_TELEGRAM, ROUTE_DIRECT),
    SERVICE_STEAM_STORE: _route_health_default(SERVICE_STEAM_STORE, ROUTE_GEO_EXIT),
}
_route_failure_windows = {group: deque() for group in _route_health}
_geph_restart_failures = deque()
_geph_restart_hint = {
    "recommended": False,
    "reason": "",
    "last_failure_host": "",
    "last_failure_reason": "",
    "last_failure_at": 0.0,
    "last_wake_at": 0.0,
    "last_requested_at": 0.0,
    "last_attempt_at": 0.0,
}
_rearm_state = {
    "last_at": 0.0,
    "last_reason": "",
    "last_gap": 0.0,
    "last_iface": "",
    "count": 0,
}
_RUNTIME_REARM_REASONS = frozenset(("wake", "network_change"))
_RUNTIME_REARM_SIGNAL = signal.SIGUSR1
_runtime_rearm_requests = deque(maxlen=8)
_canary_health = {}
_canary_failure_windows = {}
_canary_state = {
    "running": False,
    "last_run": 0.0,
    "last_started": 0.0,
    "next_due": 0.0,
    "pending_reason": "",
    "last_reason": "",
    "total": 0,
    "ok": 0,
    "degraded": 0,
    "warnings": 0,
    "unknown": 0,
}
_geph_last_failure = {"host": "", "reason": "", "ts": 0.0}

# Telegram's MTProto data-centre IP ranges (published, AS62041/AS44907). MTProto
# has no SNI and looks nothing like TLS, so our desync corrupts its handshake and
# breaks the desktop app. We pass these DIRECT (untouched); the real DPI-bypass
# for Telegram is the bundled tg-ws-proxy the user points Telegram at.
TELEGRAM_NETS = (
    ("149.154.160.0", 20), ("91.108.4.0", 22), ("91.108.8.0", 22),
    ("91.108.12.0", 22), ("91.108.16.0", 22), ("91.108.20.0", 22),
    ("91.108.56.0", 22), ("95.161.64.0", 20), ("185.76.151.0", 24),
)
TG_DIRECT_FAIL_WINDOW = 120.0
TG_DIRECT_FAIL_THRESHOLD = 3
TG_PROXY_SUGGEST_TTL = 30 * 60.0
TGWS_ACCEPTED_PATH = "/var/tmp/dev.slipstream.tgws.accepted"
_tg_direct_failures = deque()
_tg_proxy_suggest_until = 0.0
_tg_proxy_ack_seen = 0.0
_tgws_state = "starting"
_tgws_last_error = ""
_tgws_ready_since = 0.0


def set_tgws_state(state, error=""):
    global _tgws_state, _tgws_last_error, _tgws_ready_since
    _tgws_state = state
    _tgws_last_error = error[:200]
    if state == "ready" and not _tgws_ready_since:
        _tgws_ready_since = time.time()
    elif state != "ready":
        _tgws_ready_since = 0.0


def tgws_status(now=None):
    now = time.time() if now is None else now
    return {
        "telegram_proxy": _tgws_state,
        "telegram_proxy_port": TGWS_PORT,
        "telegram_proxy_error": _tgws_last_error,
        "telegram_proxy_ready_for": (
            int(max(0, now - _tgws_ready_since))
            if _tgws_state == "ready" and _tgws_ready_since else 0
        ),
    }


def _ip_in_nets(ip, nets):
    """True if dotted-quad `ip` falls in any (network, prefixlen) in `nets`."""
    try:
        packed = struct.unpack("!I", socket.inet_aton(ip))[0]
    except OSError:
        return False
    for net, bits in nets:
        mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
        if (packed & mask) == (struct.unpack("!I", socket.inet_aton(net))[0] & mask):
            return True
    return False


def note_telegram_direct_failure(reason):
    """After repeated raw Telegram DC failures, ask the tray to offer tg-ws-proxy."""
    global _tg_proxy_suggest_until
    now = time.time()
    _tg_direct_failures.append(now)
    prune_telegram_direct_failures(now)
    if len(_tg_direct_failures) >= TG_DIRECT_FAIL_THRESHOLD:
        _tg_proxy_suggest_until = max(_tg_proxy_suggest_until, now + TG_PROXY_SUGGEST_TTL)
        if VERBOSE:
            print(f">> Telegram direct looks blocked ({reason}); offering tg-ws-proxy",
                  file=sys.stderr)


def note_telegram_direct_success():
    _tg_direct_failures.clear()


def consume_telegram_proxy_acceptance():
    """Clear the current offer after the user opens tg://proxy.

    The ack file lives in /var/tmp so the non-root tray can update it and the root
    daemon can consume it. Only the mtime matters; once consumed, future direct
    Telegram failures can raise a fresh suggestion again.
    """
    global _tg_proxy_suggest_until, _tg_proxy_ack_seen
    try:
        mtime = os.path.getmtime(TGWS_ACCEPTED_PATH)
    except OSError:
        return False
    if mtime <= _tg_proxy_ack_seen:
        return False
    _tg_proxy_ack_seen = mtime
    _tg_direct_failures.clear()
    _tg_proxy_suggest_until = 0.0
    return True


def prune_telegram_direct_failures(now=None):
    now = time.time() if now is None else now
    while _tg_direct_failures and now - _tg_direct_failures[0] > TG_DIRECT_FAIL_WINDOW:
        _tg_direct_failures.popleft()

# Adaptive auto-routing: learn geo-blocked hosts the way the engine learns desync
# strategies, but only after proof. A host the app keeps reconnecting to that
# returns no real content over local desync becomes a candidate. It is promoted
# only if a separate HTTPS payload probe through Geph succeeds. We count
# low-content closes, not raw connects, so a normal page's parallel burst does
# not trip it. Guard: if many distinct hosts fail at once, it is a network
# problem, not a per-host geo-block, so don't promote.
AUTO_GEPH_WINDOW = 60.0       # seconds to accumulate a host's failures over
AUTO_GEPH_HANG = 5.0          # a connection held this long with no content = STUCK
AUTO_GEPH_STORM = 3           # stuck retries in the window = geo-blocked
AUTO_GEPH_FAIL_BYTES = 8192   # a local reply under this = "no real content"
LOCAL_STREAM_IDLE = 15.0      # client-visible downstream silence after payload
CLEAN_EOF_STALL_WINDOW = 5 * 60.0
CLEAN_EOF_STALL_STORM = 2     # repeated client-first clean EOFs before recovery
CLEAN_EOF_STALL_STATE_MAX = 4096
AUTO_GEPH_NET_BAD = 5         # this many hosts failing at once = network problem
AUTO_GEPH_TTL = 7 * 86400.0   # remember a learned host for a week
AUTO_GEPH_CONFIRM_COOLDOWN = 120.0
AUTO_GEPH_CONFIRM_TIMEOUT = 6.0
AUTO_GEPH_CONFIRM_MIN_BYTES = 64
AUTO_GEPH_RUNTIME_MISS_WINDOW = 120.0
AUTO_GEPH_RUNTIME_MISS_STORM = 2
_auto_fail = {}               # host -> list[monotonic] recent stuck closes
_auto_geph = {}               # host -> wall-clock expiry (learned geph hosts)
_auto_geph_confirming = {}    # host -> monotonic start time
_auto_geph_last_probe = {}    # host -> monotonic last proof attempt
_auto_geph_runtime_failures = {}  # host -> list[wall-clock] recent Geph misses
_auto_geph_last_status = {
    "state": "idle",
    "host": "",
    "reason": "",
    "ts": 0.0,
    "bytes": 0,
}
_auto_geph_lock = threading.RLock()
_AUTO_GEPH_PATH = "/var/run/slipstream-autogeph.json"
GEPH_FAIL_LOG_TTL = 60.0
_geph_fail_log = {}           # (host, reason) -> last log monotonic

# Xbox DNS is an app-owned, on-demand resolver backend. It never modifies
# macOS DNS: an exact unknown host reaches it only after a local failure/stall.
XBOX_DNS_CANDIDATE_TTL = 10 * 60.0
_xbox_dns_candidates = {}     # host -> monotonic expiry
XBOX_DNS_ATTEMPT_TTL = 10 * 60.0
_xbox_dns_attempts = {}       # host -> monotonic expiry after one direct lookup
XBOX_DNS_STATE_MAX = 4096
_clean_eof_stalls = {}        # host -> deque[monotonic] repeated client-first stalls

# Runtime local-bypass failures start a private exact-host re-sweep. The state is
# deliberately process-local and aggregate-free: status must not become browsing
# history, and Discord/YouTube must never escape to Geph while recovering.
_local_bypass_resweep_active = {}  # host -> monotonic start time
_local_bypass_resweep_last = {}    # host -> monotonic last attempt
_local_bypass_resweep_lock = threading.RLock()

# geph's own broker-fronting domains — NEVER desync/auto-route these (our daemon
# would otherwise mangle geph's broker access or route geph through itself).
GEPH_INFRA = ("kubernetes.io", "cdn77.org", "cdn77.com", "netlify.app", "vuejs.org")


def _is_geph_infra(host):
    return _host_matches(host, GEPH_INFRA)


def is_geo_exit_route(host):
    """Return whether the host belongs to the reviewed geo-exit route class."""
    return route_policy(host)["route_class"] == ROUTE_GEO_EXIT


def _record_health_event(
    store,
    windows,
    key,
    group,
    route_class,
    host="",
    ok=True,
    reason="",
    state=None,
    now=None,
    soft=False,
    degrade_after=1,
    backend="",
    include_identity=False,
):
    now = time.time() if now is None else now
    if key not in store:
        store[key] = _route_health_default(group, route_class)
        windows[key] = deque()
    previous = store.get(key, _route_health_default(group, route_class))
    q = windows.setdefault(key, deque())
    cutoff = now - CANARY_FAILURE_WINDOW
    while q and q[0] < cutoff:
        q.popleft()
    if ok:
        health_state = HEALTH_OK
        last_failure = ""
        last_warning = ""
        last_warning_host = ""
        last_host = normalize_host(host)
        last_route_class = route_class
        last_backend = backend
    else:
        health_state = state or HEALTH_DEGRADED
        last_failure = reason[:200]
        if soft and health_state == HEALTH_DEGRADED:
            health_state = previous.get("state", HEALTH_UNKNOWN)
            last_warning = reason[:200]
            last_warning_host = normalize_host(host)
            last_failure = previous.get("last_failure", "")
            last_host = previous.get("last_host", "")
            last_route_class = previous.get("last_route_class", route_class)
            last_backend = previous.get("last_backend", "")
        else:
            q.append(now)
            if health_state == HEALTH_DEGRADED and len(q) < degrade_after:
                health_state = previous.get("state", HEALTH_UNKNOWN)
                last_warning = reason[:200]
                last_warning_host = normalize_host(host)
                last_failure = previous.get("last_failure", "")
                last_host = previous.get("last_host", "")
                last_route_class = previous.get("last_route_class", route_class)
                last_backend = previous.get("last_backend", "")
            else:
                last_warning = ""
                last_warning_host = ""
                last_host = normalize_host(host)
                last_route_class = route_class
                last_backend = backend or previous.get("last_backend", "")
    item = {
        "state": health_state,
        "last_failure": last_failure,
        "last_warning": last_warning,
        "last_warning_host": last_warning_host,
        "last_checked": now,
        "failures_5m": len(q),
        "last_host": last_host,
        "last_route_class": last_route_class,
        "last_backend": last_backend,
    }
    if include_identity:
        item["name"] = key
        item["group"] = group
    store[key] = item
    return item


def route_health_event(
    group,
    route_class,
    host="",
    ok=True,
    reason="",
    state=None,
    now=None,
    soft=False,
    degrade_after=1,
    backend="",
):
    return _record_health_event(
        _route_health,
        _route_failure_windows,
        group,
        group,
        route_class,
        host,
        ok,
        reason,
        state,
        now,
        soft,
        degrade_after,
        backend,
    )


def clear_route_strategy_cache(group=None, host=None):
    removed = 0
    if host:
        h = normalize_host(host)
        removed = 1 if _strat_cache.pop(h, None) else 0
        _strat_scores.pop(h, None)
        if removed:
            save_strat_cache()
        return removed
    for cached_host in list(_strat_cache):
        if group is None or route_policy(cached_host)["service_group"] == group:
            _strat_cache.pop(cached_host, None)
            removed += 1
    for scored_host in list(_strat_scores):
        if group is None or route_policy(scored_host)["service_group"] == group:
            _strat_scores.pop(scored_host, None)
    if removed:
        save_strat_cache()
    return removed


def note_local_bypass_runtime_result(
    host,
    ok,
    reason="",
    now=None,
    canary_now=None,
    canary_runner=None,
):
    outcome = connection_outcome_for_host(
        host,
        ok,
        BACKEND_LOCAL_ENGINE,
        failure_phase=FAILURE_PHASE_FIRST_PAYLOAD,
        reason=reason,
    )
    if outcome.route_class != ROUTE_LOCAL_BYPASS:
        return None
    group = outcome.service_group
    if ok:
        return route_health_event(
            group,
            ROUTE_LOCAL_BYPASS,
            host,
            True,
            now=now,
        )

    for action in reduce_connection_outcome(outcome):
        if action.kind == RECOVERY_INVALIDATE_STRATEGY:
            clear_route_strategy_cache(group=action.target)
        elif action.kind == RECOVERY_RESWEEP_EXACT_HOST:
            schedule_local_bypass_resweep(action.target)
        elif action.kind == RECOVERY_RECHECK:
            start_canaries_if_due(
                f"runtime:{action.target}",
                force=True,
                now=canary_now,
                runner=canary_runner,
            )
    item = route_health_event(
        group,
        ROUTE_LOCAL_BYPASS,
        host,
        False,
        reason or "runtime local bypass failed",
        now=now,
        degrade_after=LOCAL_BYPASS_RUNTIME_DEGRADE_AFTER,
    )
    return item


def _health_snapshot_from(store, windows, now=None, include_identity=False):
    now = time.time() if now is None else now
    snap = {}
    for key, item in store.items():
        q = windows.setdefault(key, deque())
        cutoff = now - CANARY_FAILURE_WINDOW
        while q and q[0] < cutoff:
            q.popleft()
        clone = dict(item)
        clone["failures_5m"] = len(q)
        if not q and clone.get("state") in {HEALTH_DEGRADED, HEALTH_BLOCKED}:
            clone["state"] = HEALTH_UNKNOWN
            clone["last_failure"] = ""
        if include_identity:
            clone.setdefault("name", key)
            clone.setdefault("group", key)
        snap[key] = clone
    return snap


def route_health_snapshot(now=None):
    return _health_snapshot_from(_route_health, _route_failure_windows, now)


def route_health_unknown(group, route_class, host="", now=None):
    now = time.time() if now is None else now
    if group not in _route_health:
        _route_health[group] = _route_health_default(group, route_class)
        _route_failure_windows[group] = deque()
    q = _route_failure_windows.setdefault(group, deque())
    cutoff = now - CANARY_FAILURE_WINDOW
    while q and q[0] < cutoff:
        q.popleft()
    _route_health[group] = {
        "state": HEALTH_UNKNOWN,
        "last_failure": "",
        "last_warning": "",
        "last_warning_host": "",
        "last_checked": now,
        "failures_5m": len(q),
        "last_host": normalize_host(host),
        "last_route_class": route_class,
        "last_backend": "",
    }


def _canary_key(spec):
    return spec.get("name") or spec.get("group") or SERVICE_GENERIC


def _canary_state_rank(state):
    if state == HEALTH_BLOCKED:
        return 4
    if state == HEALTH_DEGRADED:
        return 3
    if state == HEALTH_OK:
        return 2
    return 1


def _canary_windows_for_group(group, now):
    cutoff = now - CANARY_FAILURE_WINDOW
    windows = []
    for key, item in _canary_health.items():
        if item.get("group") != group:
            continue
        q = _canary_failure_windows.setdefault(key, deque())
        while q and q[0] < cutoff:
            q.popleft()
        windows.extend(q)
    return deque(sorted(windows))


def _aggregate_canary_group(group, route_class, now=None):
    now = time.time() if now is None else now
    checks = [
        item for item in canary_health_snapshot(now).values()
        if item.get("group") == group
    ]
    if not checks:
        return

    best = max(
        checks,
        key=lambda item: (
            _canary_state_rank(item.get("state", HEALTH_UNKNOWN)),
            item.get("last_checked", 0.0),
        ),
    )
    latest_warning = max(
        (item for item in checks if item.get("last_warning")),
        key=lambda item: item.get("last_checked", 0.0),
        default={},
    )
    state = best.get("state", HEALTH_UNKNOWN)
    previous = _route_health.get(group, _route_health_default(group, route_class))
    if state == HEALTH_UNKNOWN and previous.get("state") == HEALTH_OK:
        best = previous
        state = HEALTH_OK
    aggregate = {
        "state": state,
        "last_failure": (
            best.get("last_failure", "")
            if state in {HEALTH_DEGRADED, HEALTH_BLOCKED}
            else ""
        ),
        "last_warning": latest_warning.get("last_warning", ""),
        "last_warning_host": latest_warning.get("last_warning_host", ""),
        "last_checked": max(item.get("last_checked", 0.0) for item in checks),
        "failures_5m": sum(int(item.get("failures_5m") or 0) for item in checks),
        "last_host": best.get("last_host", ""),
        "last_route_class": best.get("last_route_class", route_class) or route_class,
        "last_backend": best.get("last_backend", ""),
    }
    _route_health[group] = aggregate
    _route_failure_windows[group] = _canary_windows_for_group(group, now)


def canary_health_event(
    spec,
    route_class,
    host="",
    ok=True,
    reason="",
    state=None,
    now=None,
    soft=False,
    degrade_after=1,
    backend="",
):
    key = _canary_key(spec)
    group = spec.get("group", SERVICE_GENERIC)
    item = _record_health_event(
        _canary_health,
        _canary_failure_windows,
        key,
        group,
        route_class,
        host,
        ok,
        reason,
        state,
        now,
        soft,
        degrade_after,
        backend,
        include_identity=True,
    )
    _aggregate_canary_group(group, route_class, now)
    return item


def canary_health_unknown(spec, route_class, host="", now=None):
    now = time.time() if now is None else now
    key = _canary_key(spec)
    group = spec.get("group", SERVICE_GENERIC)
    q = _canary_failure_windows.setdefault(key, deque())
    cutoff = now - CANARY_FAILURE_WINDOW
    while q and q[0] < cutoff:
        q.popleft()
    _canary_health[key] = {
        "name": key,
        "group": group,
        "state": HEALTH_UNKNOWN,
        "last_failure": "",
        "last_warning": "",
        "last_warning_host": "",
        "last_checked": now,
        "failures_5m": len(q),
        "last_host": normalize_host(host),
        "last_route_class": route_class,
        "last_backend": "",
    }
    _aggregate_canary_group(group, route_class, now)


def canary_health_snapshot(now=None):
    return _health_snapshot_from(
        _canary_health,
        _canary_failure_windows,
        now,
        include_identity=True,
    )


def _scutil_proxy_exceptions(raw):
    exceptions = []
    in_exceptions = False
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("ExceptionsList"):
            in_exceptions = True
            continue
        if not in_exceptions:
            continue
        if stripped.startswith("}"):
            in_exceptions = False
            continue
        key, sep, value = stripped.partition(":")
        if not sep or not key.strip().isdigit():
            continue
        exception = value.strip()
        if exception and exception not in exceptions:
            exceptions.append(exception)
    return exceptions


def system_proxy_status_from_scutil(raw):
    kind_by_key = {
        "HTTPEnable": "http",
        "HTTPSEnable": "https",
        "SOCKSEnable": "socks",
        "ProxyAutoConfigEnable": "pac",
        "ProxyAutoDiscoveryEnable": "wpad",
    }
    kinds = []
    for line in raw.splitlines():
        key, sep, value = line.partition(":")
        if not sep or value.strip() != "1":
            continue
        kind = kind_by_key.get(key.strip())
        if kind and kind not in kinds:
            kinds.append(kind)
    exceptions = _scutil_proxy_exceptions(raw)
    return {
        "state": "active" if kinds else "off",
        "kind": ",".join(kinds),
        "exceptions_count": len(exceptions),
        "exceptions_sample": exceptions[:3],
        "stale_exceptions": bool(exceptions and not kinds),
    }


def current_system_proxy_status():
    res = _run("scutil", "--proxy")
    if res.returncode != 0:
        return {"state": "unknown", "kind": "", "error": res.stderr[:200]}
    return system_proxy_status_from_scutil(res.stdout)


def system_dns_status_from_scutil(raw):
    servers = []
    for line in raw.splitlines():
        key, sep, value = line.partition(":")
        if not sep or not key.strip().startswith("nameserver["):
            continue
        server = value.strip().lower()
        if server and server not in servers:
            servers.append(server)

    providers = []
    if any(server in XBOX_DNS_SERVERS for server in servers):
        providers.append("xbox_dns")

    return {
        "state": "xbox_dns" if providers else ("configured" if servers else "unknown"),
        "providers": ",".join(providers),
        "servers": servers[:8],
        "managed_by_slipstream": False,
    }


def _suspicious_dns_answer(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if any(addr in net for net in DNS_POISON_STUB_NETS):
        return True
    return not addr.is_global


def system_dns_resolution_checks(resolver=None):
    resolver = resolver or system_resolve
    checks = []
    saw_suspicious = False
    saw_unknown = False
    for host, group in DNS_DIAGNOSTIC_HOSTS:
        try:
            ips = _dedupe_ips(resolver(host))[:4]
        except Exception as exc:
            ips = []
            error = str(exc)[:120]
        else:
            error = ""

        suspicious = [ip for ip in ips if _suspicious_dns_answer(ip)]
        if suspicious:
            state = "suspicious"
            saw_suspicious = True
        elif ips:
            state = "ok"
        else:
            state = "unknown"
            saw_unknown = True

        item = {
            "host": host,
            "group": group,
            "state": state,
            "ips": ips,
        }
        if suspicious:
            item["suspicious_ips"] = suspicious[:4]
        if error:
            item["error"] = error
        checks.append(item)

    state = "suspicious" if saw_suspicious else ("unknown" if saw_unknown else "ok")
    return {
        "state": state,
        "checks": checks,
    }


def current_system_dns_resolution_checks(now=None):
    now = time.monotonic() if now is None else now
    cached = _system_dns_cache.get("resolution_checks")
    if (
        cached is not None
        and now - _system_dns_cache.get("resolution_ts", 0.0) < SYSTEM_DNS_RESOLUTION_TTL
    ):
        return dict(cached)
    # Status publication is a lifecycle signal and must never initiate DNS.
    # The canary worker refreshes this cache through killable resolver children.
    return {"state": "unknown", "checks": []}


def current_system_dns_status(now=None):
    now = time.monotonic() if now is None else now
    cached = _system_dns_cache.get("status")
    if cached is not None and now - _system_dns_cache.get("ts", 0.0) < SYSTEM_DNS_STATUS_TTL:
        return dict(cached)
    res = _run("scutil", "--dns")
    if res.returncode != 0:
        status = {
            "state": "unknown",
            "providers": "",
            "servers": [],
            "managed_by_slipstream": False,
            "error": res.stderr[:200],
        }
    else:
        status = system_dns_status_from_scutil(res.stdout)
    status["resolution_checks"] = current_system_dns_resolution_checks(now)
    _system_dns_cache.update({"ts": now, "status": dict(status)})
    return status


def smart_dns_available():
    return current_system_dns_status().get("state") == "xbox_dns"


def _smart_dns_mark_ok(group, now=None):
    now = time.time() if now is None else now
    _smart_dns_ok_until[group] = now + SMART_DNS_OK_TTL


def _smart_dns_mark_failure(host, reason, group=None):
    _smart_dns_last_failure.update({
        "host": normalize_host(host),
        "reason": reason[:200],
        "ts": time.time(),
    })
    if group:
        _smart_dns_ok_until.pop(group, None)


def smart_dns_route_enabled(host, now=None):
    policy = route_policy(host)
    if policy["route_class"] != ROUTE_GEO_EXIT:
        return False
    if policy["service_group"] not in SMART_DNS_GROUPS:
        return False
    if not smart_dns_available():
        return False
    now = time.time() if now is None else now
    return _smart_dns_ok_until.get(policy["service_group"], 0.0) > now


def smart_dns_status_snapshot(now=None):
    now = time.time() if now is None else now
    dns = current_system_dns_status()
    groups = sorted(
        group for group, until in _smart_dns_ok_until.items()
        if until > now
    )
    return {
        "state": "ready" if groups else ("available" if dns.get("state") == "xbox_dns" else "off"),
        "providers": dns.get("providers", ""),
        "enabled_groups": groups,
        "last_failure_host": _smart_dns_last_failure["host"],
        "last_failure_reason": _smart_dns_last_failure["reason"],
        "last_failure_at": _smart_dns_last_failure["ts"],
        "managed_by_slipstream": False,
    }


def log_geph_route_failure(host, reason, now=None):
    wall_now = time.time() if now is None else now
    _geph_last_failure.update({
        "host": normalize_host(host),
        "reason": reason[:200],
        "ts": wall_now,
    })
    policy = route_policy(host)
    route_health_event(
        policy["service_group"], ROUTE_GEO_EXIT, host,
        ok=False,
        reason=reason,
        state=HEALTH_BLOCKED if reason == "tunnel down" else HEALTH_DEGRADED,
        degrade_after=1 if reason == "tunnel down" else GEO_EXIT_RUNTIME_DEGRADE_AFTER,
    )
    restart_evidence = note_geph_restart_failure(host, reason, now=wall_now)
    reset_learned_route = note_auto_geph_runtime_failure(host, reason, now=wall_now)
    failure_phase = (
        FAILURE_PHASE_BACKEND
        if reason == "tunnel down"
        else FAILURE_PHASE_CONNECT
        if reason == "SOCKS connect failed"
        else FAILURE_PHASE_FIRST_PAYLOAD
    )
    backend = GEO_BACKEND_GEPH if _geph_owned else BACKEND_EXTERNAL
    outcome = connection_outcome_for_host(
        host,
        False,
        backend,
        failure_phase=failure_phase,
        reason=reason,
    )
    recovery = reduce_connection_outcome(
        outcome,
        RecoveryContext(
            backend_owned=bool(_geph_owned),
            restart_recommended=restart_evidence["recommended"],
            restart_rate_limited=restart_evidence["rate_limited"],
            strategy_invalidation_recommended=reset_learned_route,
            external_state=not _geph_owned,
        ),
    )
    for action in recovery:
        if action.kind == RECOVERY_INVALIDATE_STRATEGY:
            _forget_auto_geph_host(action.target, "geph runtime retries")
        elif action.kind == RECOVERY_RESTART_OWNED_GEPH:
            request_owned_geph_restart(host, reason, now=wall_now)
    if not host:
        return
    now = time.monotonic() if now is None else now
    key = (host.lower().rstrip("."), reason)
    last = _geph_fail_log.get(key)
    if last is not None and now - last < GEPH_FAIL_LOG_TTL:
        return
    _geph_fail_log[key] = now
    if len(_geph_fail_log) > 1024:
        cutoff = now - GEPH_FAIL_LOG_TTL
        for old_key, old_time in list(_geph_fail_log.items()):
            if old_time < cutoff:
                _geph_fail_log.pop(old_key, None)
    print(f">> geph route retry for {host}: {reason}", file=sys.stderr)


def clear_geph_route_failure():
    _geph_last_failure.update({"host": "", "reason": "", "ts": 0.0})
    clear_geph_restart_hint()


def note_geph_wake(now=None):
    now = time.time() if now is None else now
    _geph_restart_hint["last_wake_at"] = now


def _prune_geph_restart_failures(now):
    cutoff = now - CANARY_FAILURE_WINDOW
    while _geph_restart_failures and _geph_restart_failures[0][0] < cutoff:
        _geph_restart_failures.popleft()


def note_geph_restart_failure(host, reason, now=None):
    evidence = {"recommended": False, "rate_limited": False}
    now = time.time() if now is None else now
    if not _geph_up:
        return evidence
    if reason not in {"SOCKS connect failed", "remote closed without response"}:
        return evidence
    wake_at = _geph_restart_hint.get("last_wake_at", 0.0)
    if not wake_at or now - wake_at > GEPH_RESTART_WAKE_WINDOW:
        return evidence

    normalized = normalize_host(host)
    _geph_restart_failures.append((now, normalized, reason[:200]))
    _prune_geph_restart_failures(now)
    hosts = {item[1] for item in _geph_restart_failures if item[1]}
    if len(_geph_restart_failures) < GEPH_RESTART_FAILURE_THRESHOLD:
        return evidence
    if len(hosts) < GEPH_RESTART_MIN_HOSTS:
        return evidence
    last_requested = _geph_restart_hint.get("last_requested_at", 0.0)
    if last_requested and now - last_requested < GEPH_RESTART_COOLDOWN:
        evidence["rate_limited"] = True
        return evidence
    evidence["recommended"] = True
    return evidence


def geph_active_session_count():
    with _geph_session_lock:
        return _geph_active_sessions


def _geph_session_started():
    global _geph_active_sessions
    with _geph_session_lock:
        if _geph_restart_draining:
            return False
        _geph_active_sessions += 1
        return True


def _geph_session_finished():
    global _geph_active_sessions
    with _geph_session_lock:
        _geph_active_sessions = max(0, _geph_active_sessions - 1)


def _begin_geph_restart_drain():
    global _geph_restart_draining
    with _geph_session_lock:
        if _geph_active_sessions > 0 or _geph_restart_draining:
            return False
        _geph_restart_draining = True
        return True


def _finish_geph_restart_drain():
    global _geph_restart_draining
    with _geph_session_lock:
        _geph_restart_draining = False


def request_owned_geph_restart(host, reason, now=None):
    if not _geph_owned:
        return False
    now = time.time() if now is None else now
    _geph_restart_hint.update({
        "recommended": True,
        "reason": "geo-exit tunnel stale after wake",
        "last_failure_host": normalize_host(host),
        "last_failure_reason": reason[:200],
        "last_failure_at": now,
        "last_requested_at": now,
    })
    return True


def clear_geph_restart_hint():
    _geph_restart_failures.clear()
    _geph_restart_hint.update({
        "recommended": False,
        "reason": "",
        "last_failure_host": "",
        "last_failure_reason": "",
        "last_failure_at": 0.0,
        "last_attempt_at": 0.0,
    })


def geph_restart_hint_snapshot(now=None):
    now = time.time() if now is None else now
    _prune_geph_restart_failures(now)
    if not _geph_restart_failures and _geph_restart_hint.get("recommended"):
        _geph_restart_hint.update({
            "recommended": False,
            "reason": "",
            "last_failure_host": "",
            "last_failure_reason": "",
            "last_failure_at": 0.0,
        })
    hosts = {item[1] for item in _geph_restart_failures if item[1]}
    return {
        "recommended": bool(_geph_restart_hint.get("recommended")),
        "reason": _geph_restart_hint.get("reason", ""),
        "last_failure_host": _geph_restart_hint.get("last_failure_host", ""),
        "last_failure_reason": _geph_restart_hint.get("last_failure_reason", ""),
        "last_failure_at": _geph_restart_hint.get("last_failure_at", 0.0),
        "last_wake_at": _geph_restart_hint.get("last_wake_at", 0.0),
        "last_attempt_at": _geph_restart_hint.get("last_attempt_at", 0.0),
        "failures_5m": len(_geph_restart_failures),
        "hosts_5m": len(hosts),
        "cooldown_until": (
            _geph_restart_hint.get("last_requested_at", 0.0) + GEPH_RESTART_COOLDOWN
            if _geph_restart_hint.get("last_requested_at", 0.0)
            else 0.0
        ),
    }


def _owned_geph_launch_target(state, owner_uid):
    return geph_backend.owned_launch_target(state, owner_uid, GEPH_LAUNCHD_LABEL)


def _ownership_file_uid(path):
    return geph_backend.ownership_file_uid(path)


def execute_owned_geph_restart(
    now=None,
    active_sessions=None,
    ownership_path=None,
    ownership_state=None,
    owner_uid=None,
    listener_owned=None,
    runner=None,
    backend_suspender=None,
):
    """Kickstart only Slipstream's verified user LaunchAgent after routing is idle."""
    if _shutdown_started.is_set():
        return "shutdown"
    now = time.time() if now is None else now
    if not _geph_restart_hint.get("recommended"):
        return "idle"
    last_attempt = _geph_restart_hint.get("last_attempt_at", 0.0)
    if last_attempt and now - last_attempt < GEPH_RESTART_EXECUTION_RETRY:
        return "cooldown"
    managed_drain = active_sessions is None
    if active_sessions is not None and int(active_sessions) > 0:
        return "busy"

    ownership_path = ownership_path or geph_ownership_path()
    if not ownership_path:
        return "unverified"
    ownership_state = (
        _read_geph_ownership(ownership_path)
        if ownership_state is None
        else ownership_state
    )
    if owner_uid is None:
        owner_uid = _ownership_file_uid(ownership_path)
        if owner_uid is None:
            return "unverified"
    target = _owned_geph_launch_target(ownership_state, owner_uid)
    if not target:
        return "unverified"
    if listener_owned is None:
        listener_owned = geph_listener_owned(state=ownership_state)
    if not listener_owned:
        return "unverified"
    if managed_drain and not _begin_geph_restart_drain():
        return "busy"

    _geph_restart_hint["last_attempt_at"] = now
    if backend_suspender is None:
        backend_suspender = lambda: suspend_geo_exit_backend(
            "owned Geph restart in progress",
            now=now,
        )
    runner = _run if runner is None else runner
    try:
        if _shutdown_started.is_set():
            if managed_drain:
                _finish_geph_restart_drain()
            return "shutdown"
        backend_suspender()
        if _shutdown_started.is_set():
            if managed_drain:
                _finish_geph_restart_drain()
            return "shutdown"
        result = runner("/bin/launchctl", "kickstart", "-k", target)
    except Exception as error:
        if managed_drain:
            _finish_geph_restart_drain()
        print(f">> owned Geph recovery unavailable: {error}", file=sys.stderr)
        return "unavailable"
    if result.returncode != 0:
        if managed_drain:
            _finish_geph_restart_drain()
        detail = (result.stderr or result.stdout or "launchctl returned an error").strip()
        print(f">> owned Geph recovery unavailable: {detail[:200]}", file=sys.stderr)
        return "unavailable"

    clear_geph_restart_hint()
    note_runtime_rearm("geph_restart")
    print(">> owned Geph LaunchAgent restarted after routing became idle", file=sys.stderr)
    return "restarted"


def prune_auto_geph(now=None):
    del now
    if _auto_geph:
        _auto_geph.clear()
        save_auto_geph()


def load_auto_geph():
    global _auto_geph
    had_legacy_entries = False
    try:
        with open(_AUTO_GEPH_PATH) as f:
            data = json.load(f)
        had_legacy_entries = isinstance(data, dict) and bool(data)
    except Exception:
        pass
    _auto_geph = {}
    if had_legacy_entries:
        save_auto_geph()


def save_auto_geph():
    try:
        with open(_AUTO_GEPH_PATH, "w") as f:
            json.dump(_auto_geph, f)
    except Exception:
        pass


# A successful payload through a foreign exit does not prove that a service
# requires one. Generic local failures therefore never promote a host to Geph.
# Keep the status surface for one transition release while legacy state is pruned.
AUTO_GEPH_ENABLED = False


def _auto_geph_candidate_allowed(host):
    del host
    return False


def _unknown_local_recovery_candidate_allowed(host):
    h = normalize_host(host)
    return bool(h) and not _is_geph_infra(h) and (
        route_policy(h)["route_class"] == ROUTE_UNKNOWN
    )


def _set_auto_geph_status(state, host="", reason="", bytes_read=0):
    _auto_geph_last_status.update({
        "state": state,
        "host": normalize_host(host),
        "reason": reason[:200],
        "ts": time.time(),
        "bytes": int(bytes_read or 0),
    })


def _socks5_connect_blocking(host, port, timeout=3.0):
    socks_port = _geph_port
    if not socks_port:
        return None
    sock = None
    try:
        sock = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        if sock.recv(2)[:2] != b"\x05\x00":
            raise IOError("socks5 no-auth refused")
        hb = host.encode("ascii", "ignore")[:255]
        sock.sendall(
            b"\x05\x01\x00\x03"
            + bytes([len(hb)])
            + hb
            + struct.pack("!H", port)
        )
        rep = sock.recv(4)
        if len(rep) < 4 or rep[1] != 0x00:
            raise IOError(f"socks5 connect rep={rep[1] if len(rep) >= 2 else 'short'}")
        atyp = rep[3]
        if atyp == 0x01:
            sock.recv(4)
        elif atyp == 0x03:
            ln = sock.recv(1)
            if not ln:
                raise IOError("short socks5 domain reply")
            sock.recv(ln[0])
        elif atyp == 0x04:
            sock.recv(16)
        sock.recv(2)
        return sock
    except Exception:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
        return None


def _auto_geph_payload_probe(host, timeout=AUTO_GEPH_CONFIRM_TIMEOUT):
    sock = _socks5_connect_blocking(host, 443, timeout)
    if sock is None:
        return 0
    tls_sock = None
    try:
        ctx = _local_payload_ssl_context()
        tls_sock = ctx.wrap_socket(sock, server_hostname=host)
        tls_sock.settimeout(timeout)
        req = (
            "HEAD / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: SlipstreamAutoGeo/1\r\n"
            "Accept: */*\r\n"
            "Cache-Control: no-cache\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii", "ignore")
        tls_sock.sendall(req)
        data = tls_sock.recv(4096)
        if data.startswith(b"HTTP/"):
            return len(data)
        return 0
    except Exception:
        return 0
    finally:
        try:
            (tls_sock or sock).close()
        except Exception:
            pass


def _confirm_auto_geph(host):
    h = normalize_host(host)
    if not AUTO_GEPH_ENABLED or not _geph_up or not _auto_geph_candidate_allowed(h):
        _set_auto_geph_status("skipped", h, "not eligible")
        return False
    bytes_read = _auto_geph_payload_probe(h)
    if bytes_read < AUTO_GEPH_CONFIRM_MIN_BYTES:
        _set_auto_geph_status("rejected", h, "geph payload probe failed", bytes_read)
        return False
    with _auto_geph_lock:
        if not _auto_geph_candidate_allowed(h):
            _set_auto_geph_status("skipped", h, "route changed")
            return False
        _auto_geph[h] = time.time() + AUTO_GEPH_TTL
        _auto_fail.pop(h, None)
        save_auto_geph()
        _set_auto_geph_status("learned", h, "geph payload confirmed", bytes_read)
    print(
        f">> auto-route: {h} works through Geph after local stalls "
        f"(remembered {AUTO_GEPH_TTL / 86400:.0f}d)",
        file=sys.stderr,
    )
    return True


def _is_auto_geph_runtime_miss(reason):
    return reason in {
        "remote closed without response",
        "SOCKS connect failed",
    }


def _auto_geph_learned_exact_host(host, now=None):
    h = normalize_host(host)
    if not h:
        return False
    wall_now = time.time() if now is None else now
    if _auto_geph.get(h, 0.0) <= wall_now:
        return False
    static_routes, geo_exit_routes = route_policy_tables()
    if _match_policy(h, static_routes) or _match_policy(h, geo_exit_routes):
        return False
    return True


def _forget_auto_geph_host(host, reason):
    h = normalize_host(host)
    if not h:
        return False
    with _auto_geph_lock:
        if h not in _auto_geph:
            return False
        _auto_geph.pop(h, None)
        _auto_fail.pop(h, None)
        _auto_geph_runtime_failures.pop(h, None)
        save_auto_geph()
        _set_auto_geph_status("reset", h, reason)
    print(f">> auto-route: reset {h} after Geph runtime retries", file=sys.stderr)
    return True


def note_auto_geph_runtime_failure(host, reason, now=None):
    if not _is_auto_geph_runtime_miss(reason):
        return False
    h = normalize_host(host)
    if not _auto_geph_learned_exact_host(h, now):
        return False
    wall_now = time.time() if now is None else now
    with _auto_geph_lock:
        if not _auto_geph_learned_exact_host(h, wall_now):
            return False
        q = _auto_geph_runtime_failures.setdefault(h, [])
        q.append(wall_now)
        cutoff = wall_now - AUTO_GEPH_RUNTIME_MISS_WINDOW
        while q and q[0] < cutoff:
            q.pop(0)
        if len(_auto_geph_runtime_failures) > 4096:
            for old_host, values in list(_auto_geph_runtime_failures.items()):
                if not values or values[-1] < cutoff:
                    _auto_geph_runtime_failures.pop(old_host, None)
        if len(q) < AUTO_GEPH_RUNTIME_MISS_STORM:
            return False
    return True


def _schedule_auto_geph_confirmation(host, now=None, runner=None):
    h = normalize_host(host)
    now = time.monotonic() if now is None else now
    if not h:
        return False
    with _auto_geph_lock:
        last = _auto_geph_last_probe.get(h, 0.0)
        if last and now - last < AUTO_GEPH_CONFIRM_COOLDOWN:
            return False
        started = _auto_geph_confirming.get(h)
        if started is not None and now - started < AUTO_GEPH_CONFIRM_TIMEOUT * 2:
            return False
        _auto_geph_last_probe[h] = now
        _auto_geph_confirming[h] = now
        _set_auto_geph_status("checking", h, "local stalls observed")

    def run():
        try:
            (runner or _confirm_auto_geph)(h)
        finally:
            with _auto_geph_lock:
                _auto_geph_confirming.pop(h, None)

    if runner is not None:
        run()
        return True
    threading.Thread(target=run, daemon=True).start()
    return True


def auto_geo_exit_status_snapshot(now=None):
    prune_auto_geph(now)
    with _auto_geph_lock:
        return {
            "enabled": AUTO_GEPH_ENABLED,
            "learned": len(_auto_geph),
            "pending": len(_auto_geph_confirming),
            "last_state": _auto_geph_last_status["state"],
            "last_host": _auto_geph_last_status["host"],
            "last_reason": _auto_geph_last_status["reason"],
            "last_at": _auto_geph_last_status["ts"],
            "last_bytes": _auto_geph_last_status["bytes"],
        }


def note_local_result(host, down_bytes, duration, now=None, confirmation_runner=None):
    """Record a local stall and schedule only an exact local recovery attempt."""
    del confirmation_runner
    h = normalize_host(host)
    if not _unknown_local_recovery_candidate_allowed(h):
        return
    if down_bytes >= AUTO_GEPH_FAIL_BYTES:
        _auto_fail.pop(h, None)                 # got real content -> not blocked
        return
    if duration < AUTO_GEPH_HANG:
        return                                  # fast + low content = normal, ignore
    now = time.monotonic() if now is None else now
    q = _auto_fail.setdefault(h, [])
    q.append(now)
    cutoff = now - AUTO_GEPH_WINDOW
    while q and q[0] < cutoff:
        q.pop(0)
    if len(_auto_fail) > 4096:
        for k in [k for k, v in list(_auto_fail.items()) if not v or v[-1] < cutoff]:
            _auto_fail.pop(k, None)
    if len(q) < AUTO_GEPH_STORM:
        return
    # network-fine guard: if many DISTINCT hosts are failing at once it's the
    # network, not a per-host geo-block — don't sweep everything into the tunnel.
    # (Count hosts with >=2 recent low-content closes; this accumulates before any
    # single host crosses the storm threshold, so a network-wide outage is caught.)
    failing = sum(1 for v in _auto_fail.values()
                  if sum(1 for t in v if t >= cutoff) >= 2)
    if failing >= AUTO_GEPH_NET_BAD:
        return
    # A low-content local storm is ambiguous. Give this exact unknown host one
    # local retry through app-owned Xbox DNS; it never changes system DNS and
    # never implies that the host needs a foreign exit.
    if not _xbox_dns_attempted_recently(h, now):
        _mark_xbox_dns_candidate(h, now)


CANARY_SPECS = (
    {"name": "discord_update", "group": SERVICE_DISCORD, "host": "updates.discord.com"},
    {
        "name": "discord_api",
        "group": SERVICE_DISCORD,
        "host": "discord.com",
        "payload_path": "/api/v10/gateway",
    },
    {
        "name": "discord_gateway",
        "group": SERVICE_DISCORD,
        "host": "gateway.discord.gg",
        "payload_probe": "websocket_upgrade",
    },
    {
        "name": "discord_cdn",
        "group": SERVICE_DISCORD,
        "host": "cdn.discordapp.com",
        "payload_method": "GET",
        "payload_path": "/embed/avatars/0.png",
        "payload_min_bytes": 512,
    },
    {
        "name": "youtube_web",
        "group": SERVICE_YOUTUBE,
        "host": "www.youtube.com",
        "payload_path": "/generate_204",
        "soft": True,
    },
    {
        "name": "youtube_video",
        "group": SERVICE_YOUTUBE,
        "host": "",
        "observed_domains": ("googlevideo.com",),
        "fallback_host": "redirector.googlevideo.com",
        "transport_probe": "quic_version_negotiation",
    },
    {"name": "openai_core", "group": SERVICE_OPENAI, "host": "chatgpt.com"},
    {"name": "anthropic_core", "group": SERVICE_ANTHROPIC, "host": "claude.ai"},
    {
        "name": "steam_store",
        "group": SERVICE_STEAM_STORE,
        "host": "store.steampowered.com",
        "smart_dns": False,
        "payload_probe": "https_payload",
        "payload_method": "GET",
        "payload_path": "/",
        "payload_min_bytes": 2048,
        "degrade_after": GEO_EXIT_RUNTIME_DEGRADE_AFTER,
    },
    {"name": "telegram_proxy", "group": SERVICE_TELEGRAM, "host": ""},
)


def _canary_delay(now=None):
    now = time.monotonic() if now is None else now
    return CANARY_INTERVAL + (int(now) % int(CANARY_JITTER or 1))


def _canary_client_hello(host):
    rec = build_fake_clienthello(host)
    return rec[:5], rec[5:]


def _local_payload_canary_request(host, spec=None):
    if spec and spec.get("payload_probe") == "websocket_upgrade":
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        return (
            "GET /?v=10&encoding=json HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "User-Agent: SlipstreamRouteCanary/1\r\n"
            "\r\n"
        ).encode("ascii", "ignore")
    method = (spec or {}).get("payload_method", "HEAD")
    if method not in {"HEAD", "GET"}:
        method = "HEAD"
    path = (spec or {}).get("payload_path", "/")
    if not isinstance(path, str) or not path.startswith("/"):
        path = "/"
    return (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: SlipstreamRouteCanary/1\r\n"
        f"Accept: */*\r\n"
        f"Cache-Control: no-cache\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii", "ignore")


def _local_payload_min_bytes(spec=None):
    value = (spec or {}).get("payload_min_bytes", LOCAL_PAYLOAD_CANARY_MIN_BYTES)
    if not isinstance(value, int) or isinstance(value, bool):
        return LOCAL_PAYLOAD_CANARY_MIN_BYTES
    return max(1, min(value, 64 * 1024))


def _quic_version_negotiation_probe_packet(dcid=None, scid=None):
    dcid = os.urandom(8) if dcid is None else dcid
    scid = os.urandom(8) if scid is None else scid
    header = (
        b"\xc0"
        + QUIC_UNSUPPORTED_VERSION
        + bytes([len(dcid)])
        + dcid
        + bytes([len(scid)])
        + scid
    )
    if len(header) >= QUIC_MIN_INITIAL_SIZE:
        return header
    return header + (b"\x00" * (QUIC_MIN_INITIAL_SIZE - len(header)))


def _is_quic_version_negotiation_response(data):
    return len(data) >= 5 and bool(data[0] & 0x80) and data[1:5] == b"\x00\x00\x00\x00"


def _quic_version_negotiation_probe(ip, timeout=QUIC_CANARY_TIMEOUT):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    addr = (ip, 443, 0, 0) if family == socket.AF_INET6 else (ip, 443)
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(_quic_version_negotiation_probe_packet(), addr)
        data, _peer = sock.recvfrom(2048)
        return _is_quic_version_negotiation_response(data)
    except Exception:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


async def _run_quic_version_negotiation_probe(ips):
    loop = asyncio.get_running_loop()
    for ip in ips[:DEFAULT_IP_ATTEMPT_LIMIT]:
        ok = await loop.run_in_executor(_POOL, _quic_version_negotiation_probe, ip)
        if ok:
            return True
    return False


def _local_payload_ssl_context():
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def _local_payload_probe(ip, host, strat, spec=None, timeout=LOCAL_PAYLOAD_CANARY_TIMEOUT):
    """Complete a real TLS request over the candidate local-bypass strategy.

    The raw strategy probe only proves that first server TLS bytes came back.
    This probe drives the TLS state machine far enough to write a tiny HTTPS
    HEAD request and read decrypted response bytes, catching stalled paths where
    the handshake succeeds but application data does not move.
    """
    ctx = _local_payload_ssl_context()
    inbio, outbio = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inbio, outbio, server_hostname=host)
    sock = None
    deadline = time.monotonic() + timeout
    first_flight_sent = False
    total = 0
    expect_websocket_upgrade = bool(
        spec and spec.get("payload_probe") == "websocket_upgrade"
    )
    min_bytes = _local_payload_min_bytes(spec)
    observed = bytearray()
    try:
        sock = socket.create_connection((ip, 443), timeout=timeout)
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        while True:
            try:
                obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                out = outbio.read()
                if out:
                    if not first_flight_sent:
                        first_flight_sent = True
                        if strat.get("fake") and out[:1] == b"\x16":
                            try:
                                src_ip, src_port = sock.getsockname()
                                inject_fake_for_host(host, src_ip, src_port, ip, 443)
                            except Exception:
                                pass
                        if out[:1] == b"\x16":
                            out = make_blob(out[:5], out[5:], host, strat.get("cap"))
                    sock.sendall(out)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise socket.timeout("payload canary handshake timeout")
                sock.settimeout(max(0.1, remaining))
                data = sock.recv(65536)
                if not data:
                    raise IOError("eof in handshake")
                inbio.write(data)

        obj.write(_local_payload_canary_request(host, spec))
        while True:
            out = outbio.read()
            if not out:
                break
            sock.sendall(out)

        while time.monotonic() < deadline:
            sock.settimeout(max(0.1, deadline - time.monotonic()))
            try:
                data = sock.recv(65536)
            except socket.timeout:
                break
            if not data:
                break
            inbio.write(data)
            while True:
                try:
                    dec = obj.read(65536)
                except ssl.SSLWantReadError:
                    break
                except ssl.SSLError:
                    return total
                if not dec:
                    break
                total += len(dec)
                if expect_websocket_upgrade:
                    observed.extend(dec)
                    if len(observed) > 4096:
                        del observed[:-4096]
                    first_line = bytes(observed).split(b"\r\n", 1)[0]
                    if first_line.startswith(b"HTTP/1.1 101 "):
                        return max(total, LOCAL_PAYLOAD_CANARY_MIN_BYTES)
                    continue
                if total >= min_bytes:
                    return total
    except Exception:
        return 0
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    if expect_websocket_upgrade:
        return 0
    return total


async def _run_local_payload_probe(ip, host, strat, spec=None):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_POOL, _local_payload_probe, ip, host, strat, spec)


def _geph_payload_probe(host, spec=None, timeout=GEO_PAYLOAD_CANARY_TIMEOUT):
    """Complete a small HTTPS request through Geph's SOCKS listener.

    SOCKS CONNECT plus TLS bytes only proves that an exit stream opens. Store and
    payment pages can still stall at HTTP payload time, so selected geo-exit
    canaries drive the request far enough to read decrypted response bytes.
    """
    port_socks = _geph_port
    if not port_socks:
        return 0
    sock = None
    total = 0
    min_bytes = _local_payload_min_bytes(spec)
    deadline = time.monotonic() + timeout
    try:
        sock = socket.create_connection(("127.0.0.1", port_socks), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        if sock.recv(2)[:2] != b"\x05\x00":
            return 0
        hb = host.encode("ascii", "ignore")[:255]
        sock.sendall(
            b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack("!H", 443)
        )
        rep = sock.recv(4)
        if len(rep) < 4 or rep[1] != 0x00:
            return 0
        atyp = rep[3]
        if atyp == 0x01:
            sock.recv(4)
        elif atyp == 0x03:
            ln = sock.recv(1)
            if not ln:
                return 0
            sock.recv(ln[0])
        elif atyp == 0x04:
            sock.recv(16)
        sock.recv(2)

        ctx = _local_payload_ssl_context()
        tls = ctx.wrap_socket(sock, server_hostname=host)
        sock = tls
        tls.settimeout(timeout)
        tls.sendall(_local_payload_canary_request(host, spec))
        while time.monotonic() < deadline:
            tls.settimeout(max(0.1, deadline - time.monotonic()))
            try:
                data = tls.recv(65536)
            except socket.timeout:
                break
            if not data:
                break
            total += len(data)
            if total >= min_bytes:
                return total
    except Exception:
        return 0
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    return total


async def _run_geph_payload_probe(host, spec=None):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_POOL, _geph_payload_probe, host, spec)


def _close_probe_result(result):
    if not result:
        return
    try:
        result[1].close()
    except Exception:
        pass


async def _try_smart_dns_geo_connect(host, port, first_flight, probe_timeout=3.0):
    if not host or not smart_dns_available():
        return None
    ips = _dedupe_ips(await system_resolve_async(host))
    policy = route_policy(host)
    raced, _attempted = await _race_probe_addresses(
        host,
        port,
        ips[:DEFAULT_IP_ATTEMPT_LIMIT],
        lambda ip: dial_and_probe(
            ip,
            port,
            first_flight,
            probe_timeout=probe_timeout,
        ),
        policy=policy,
        backend=GEO_BACKEND_SMART_DNS,
    )
    return raced


async def _run_smart_dns_geo_canary(spec):
    host = spec["host"]
    policy = route_policy(host)
    if policy["route_class"] != ROUTE_GEO_EXIT:
        return None
    result = await _try_smart_dns_geo_connect(host, 443, build_fake_clienthello(host))
    if result:
        _ip, probe = result
        _close_probe_result(probe)
        _smart_dns_mark_ok(spec["group"])
        clear_geph_route_failure()
        route_health_event(
            spec["group"],
            ROUTE_GEO_EXIT,
            host,
            True,
            backend=GEO_BACKEND_SMART_DNS,
        )
        return True
    _smart_dns_mark_failure(
        host,
        "smart dns probe failed",
        None if spec.get("soft") else spec["group"],
    )
    return False


def _observed_canary_host(group, domains=None):
    for host in reversed(_strat_cache):
        if route_policy(host)["service_group"] == group:
            if domains and not _host_matches(host, domains):
                continue
            return host
    return ""


def _canary_host(spec):
    return (
        spec.get("host")
        or _observed_canary_host(spec["group"], spec.get("observed_domains"))
        or spec.get("fallback_host", "")
    )


async def _run_local_bypass_canary(spec):
    host = _canary_host(spec)
    if not host:
        canary_health_unknown(spec, ROUTE_LOCAL_BYPASS)
        return None
    policy = route_policy(host)
    if policy["route_class"] != ROUTE_LOCAL_BYPASS:
        canary_health_event(
            spec,
            policy["route_class"],
            host,
            False,
            "policy mismatch",
            soft=bool(spec.get("soft")),
        )
        if spec.get("soft"):
            return "warning"
        return False
    ips = await resolve_connection_ips(host, None)
    if not ips:
        canary_health_event(
            spec,
            ROUTE_LOCAL_BYPASS,
            host,
            False,
            "dns failed",
            soft=bool(spec.get("soft")),
        )
        clear_route_strategy_cache(group=spec["group"])
        if spec.get("soft"):
            return "warning"
        return False
    if spec.get("transport_probe") == "quic_version_negotiation":
        if await _run_quic_version_negotiation_probe(ips):
            canary_health_event(spec, ROUTE_LOCAL_BYPASS, host, True)
            return True
        canary_health_event(
            spec,
            ROUTE_LOCAL_BYPASS,
            host,
            False,
            "quic probe failed",
            degrade_after=LOCAL_PAYLOAD_DEGRADE_AFTER,
        )
        health = canary_health_snapshot().get(_canary_key(spec), {})
        if health.get("state") != HEALTH_DEGRADED:
            return "warning"
        return False
    payload_failed = False
    payload_short = False
    min_payload_bytes = _local_payload_min_bytes(spec)
    for strat in strategy_order(host):
        strat_ok = False
        if not strat.get("fake"):
            continue
        for ip in ips[:ip_attempt_limit(host)]:
            # Do not preflight with build_fake_clienthello(): its TLS 1.2
            # AES128-SHA-only offer is rejected by modern Discord endpoints
            # even while real clients work. The payload probe below performs a
            # modern TLS handshake and applies this same local fake/desync
            # strategy to its actual first flight.
            payload_bytes = await _run_local_payload_probe(ip, host, strat, spec)
            if payload_bytes < min_payload_bytes:
                payload_failed = True
                if payload_bytes > 0:
                    payload_short = True
                continue
            strat_ok = True
            _record_strategy_result(host, strat["name"], True)
            if _strat_cache.get(host) != strat["name"]:
                remember_strategy(host, strat["name"])
            canary_health_event(spec, ROUTE_LOCAL_BYPASS, host, True)
            return True
        if not strat_ok:
            _record_strategy_result(host, strat["name"], False)
    clear_route_strategy_cache(group=spec["group"])
    if payload_failed:
        reason = "payload throughput below threshold" if payload_short else "payload probe failed"
        canary_health_event(
            spec,
            ROUTE_LOCAL_BYPASS,
            host,
            False,
            reason,
            degrade_after=LOCAL_PAYLOAD_DEGRADE_AFTER,
            soft=bool(spec.get("soft")),
        )
        health = canary_health_snapshot().get(_canary_key(spec), {})
        if spec.get("soft"):
            return "warning"
        if health.get("state") != HEALTH_DEGRADED:
            return "warning"
        return False
    canary_health_event(
        spec,
        ROUTE_LOCAL_BYPASS,
        host,
        False,
        "strategy probe failed",
        soft=bool(spec.get("soft")),
    )
    if spec.get("soft"):
        return "warning"
    return False


async def _resweep_local_bypass_host(host):
    h = normalize_host(host)
    policy = route_policy(h)
    if not h or policy["route_class"] != ROUTE_LOCAL_BYPASS:
        return False
    ips = await resolve_connection_ips(h, None)
    if not ips:
        return False

    head, body = _canary_client_hello(h)
    attempts = 0
    for strat in strategy_order(h):
        if not strat.get("fake"):
            continue
        strat_ok = False
        for ip in ips[:ip_attempt_limit(h)]:
            attempts += 1
            result = await dial_strategy(ip, 443, head, body, h, strat)
            if result:
                _close_probe_result(result)
                strat_ok = True
                _record_strategy_result(h, strat["name"], True)
                if _strat_cache.get(h) != strat["name"]:
                    remember_strategy(h, strat["name"])
                _dead.pop(h, None)
                return True
            if attempts >= 7:
                break
        if not strat_ok:
            _record_strategy_result(h, strat["name"], False)
        if attempts >= 7:
            break
    return False


def _run_local_bypass_resweep(host):
    try:
        return asyncio.run(_resweep_local_bypass_host(host))
    except Exception as exc:
        if VERBOSE:
            group = route_policy(host)["service_group"]
            print(
                f">> local bypass re-sweep unavailable ({group}): "
                f"{type(exc).__name__}",
                file=sys.stderr,
            )
        return False


def schedule_local_bypass_resweep(host, now=None, runner=None):
    h = normalize_host(host)
    policy = route_policy(h)
    if not h or policy["route_class"] != ROUTE_LOCAL_BYPASS:
        return False
    now = time.monotonic() if now is None else now
    with _local_bypass_resweep_lock:
        last = _local_bypass_resweep_last.get(h, 0.0)
        if last and now - last < LOCAL_BYPASS_RESWEEP_COOLDOWN:
            return False
        started = _local_bypass_resweep_active.get(h)
        if started is not None and now - started < LOCAL_BYPASS_RESWEEP_STALE_AFTER:
            return False
        _local_bypass_resweep_last[h] = now
        _local_bypass_resweep_active[h] = now

    def run():
        try:
            (runner or _run_local_bypass_resweep)(h)
        finally:
            with _local_bypass_resweep_lock:
                _local_bypass_resweep_active.pop(h, None)

    if runner is not None:
        run()
        return True
    threading.Thread(
        target=run,
        daemon=True,
        name=f"local-bypass-resweep-{policy['service_group']}",
    ).start()
    return True


async def _run_geo_exit_canary(spec):
    host = spec["host"]
    policy = route_policy(host)
    if policy["route_class"] != ROUTE_GEO_EXIT:
        canary_health_event(spec, policy["route_class"], host, False, "policy mismatch")
        return False
    if spec.get("smart_dns", True) and smart_dns_available():
        smart_dns_ok = await _run_smart_dns_geo_canary(spec)
        if smart_dns_ok:
            canary_health_event(
                spec,
                ROUTE_GEO_EXIT,
                host,
                True,
                backend=GEO_BACKEND_SMART_DNS,
            )
            return True
    if not _geph_up:
        canary_health_event(
            spec,
            ROUTE_GEO_EXIT,
            host,
            False,
            "tunnel down",
            HEALTH_BLOCKED,
        )
        return False
    if spec.get("payload_probe") == "https_payload":
        payload_bytes = await _run_geph_payload_probe(host, spec)
        if payload_bytes >= _local_payload_min_bytes(spec):
            clear_geph_route_failure()
            canary_health_event(spec, ROUTE_GEO_EXIT, host, True, backend=GEO_BACKEND_GEPH)
            return True
        reason = (
            "payload throughput below threshold"
            if payload_bytes > 0
            else "payload probe failed"
        )
        canary_health_event(
            spec,
            ROUTE_GEO_EXIT,
            host,
            False,
            reason,
            soft=bool(spec.get("soft")),
            degrade_after=int(spec.get("degrade_after", 1) or 1),
        )
        if spec.get("soft"):
            return "warning"
        health = canary_health_snapshot().get(_canary_key(spec), {})
        if health.get("state") != HEALTH_DEGRADED:
            return "warning"
        return False
    result = await dial_via_geph(host, 443, build_fake_clienthello(host))
    if result:
        _close_probe_result(result)
        clear_geph_route_failure()
        canary_health_event(spec, ROUTE_GEO_EXIT, host, True, backend=GEO_BACKEND_GEPH)
        return True
    canary_health_event(
        spec,
        ROUTE_GEO_EXIT,
        host,
        False,
        "SOCKS connect failed",
        soft=bool(spec.get("soft")),
        degrade_after=int(spec.get("degrade_after", 1) or 1),
    )
    if spec.get("soft"):
        return "warning"
    health = canary_health_snapshot().get(_canary_key(spec), {})
    if health.get("state") != HEALTH_DEGRADED:
        return "warning"
    return False


async def _run_telegram_proxy_canary(spec):
    ok = _tgws_state == "ready"
    canary_health_event(
        spec, ROUTE_DIRECT, "127.0.0.1",
        ok=ok,
        reason="" if ok else f"telegram proxy {_tgws_state}",
        state=HEALTH_DEGRADED,
    )
    return ok


async def run_route_canaries(reason="periodic"):
    ok = degraded = unknown = warnings = total = 0
    for spec in CANARY_SPECS:
        total += 1
        try:
            policy = route_policy(spec.get("host"))
            if spec["group"] == SERVICE_TELEGRAM:
                passed = await _run_telegram_proxy_canary(spec)
            elif spec["group"] in (SERVICE_DISCORD, SERVICE_YOUTUBE):
                passed = await _run_local_bypass_canary(spec)
            elif policy["route_class"] == ROUTE_GEO_EXIT:
                passed = await _run_geo_exit_canary(spec)
            else:
                canary_health_event(
                    spec, policy["route_class"], spec.get("host", ""),
                    ok=False,
                    reason="unknown route policy",
                )
                passed = False
            if passed == "warning":
                warnings += 1
            elif passed is None:
                unknown += 1
            elif passed:
                ok += 1
            else:
                degraded += 1
        except Exception as e:
            degraded += 1
            canary_health_event(
                spec, ROUTE_UNKNOWN, spec.get("host", ""),
                ok=False,
                reason=f"canary error: {e}",
            )
    _canary_state.update({
        "last_run": time.time(),
        "last_reason": reason,
        "total": total,
        "ok": ok,
        "degraded": degraded,
        "warnings": warnings,
        "unknown": unknown,
    })
    return ok, degraded


def finish_canaries(now=None):
    now = time.monotonic() if now is None else now
    normal_next_due = now + _canary_delay(now)
    pending_reason = _canary_state.get("pending_reason", "")
    pending_due = _canary_state.get("next_due", 0.0)
    _canary_state["running"] = False
    if pending_reason and pending_due:
        _canary_state["next_due"] = min(pending_due, normal_next_due)
    else:
        _canary_state["next_due"] = normal_next_due


def _schedule_forced_canary_retry(reason, now):
    if not reason:
        return
    retry_due = now + CANARY_FORCE_RETRY_DELAY
    current_due = _canary_state.get("next_due", 0.0)
    if not current_due or retry_due < current_due:
        _canary_state["next_due"] = retry_due
    _canary_state["pending_reason"] = reason


def _canary_thread_main(reason):
    try:
        asyncio.run(run_route_canaries(reason))
    except Exception as e:
        print(f">> route canaries error: {e}", file=sys.stderr)
    try:
        _refresh_system_dns_resolution_checks()
    except Exception as e:
        print(f">> system DNS diagnostics error: {e}", file=sys.stderr)
    finally:
        finish_canaries()


def start_canaries_if_due(reason="periodic", force=False, now=None, runner=None):
    now = time.monotonic() if now is None else now
    if _canary_state["running"]:
        if force:
            _schedule_forced_canary_retry(reason, now)
        return False
    if force and _canary_state["last_started"] and now - _canary_state["last_started"] < CANARY_FORCE_MIN_GAP:
        _schedule_forced_canary_retry(reason, now)
        return False
    if not force and _canary_state["next_due"] and now < _canary_state["next_due"]:
        return False
    run_reason = reason
    if not force and _canary_state.get("pending_reason"):
        run_reason = _canary_state["pending_reason"]
        _canary_state["pending_reason"] = ""
    _canary_state["running"] = True
    _canary_state["last_started"] = now
    if runner is not None:
        try:
            runner(run_reason)
        finally:
            finish_canaries(now)
        return True
    threading.Thread(target=_canary_thread_main, args=(run_reason,), daemon=True).start()
    return True


def canary_status_snapshot(now=None):
    now = time.monotonic() if now is None else now
    next_due = _canary_state.get("next_due", 0.0)
    return {
        "running": bool(_canary_state.get("running")),
        "last_run": _canary_state.get("last_run", 0.0),
        "last_reason": _canary_state.get("last_reason", ""),
        "next_due_in": int(max(0, next_due - now)) if next_due else 0,
        "total": _canary_state.get("total", 0),
        "ok": _canary_state.get("ok", 0),
        "degraded": _canary_state.get("degraded", 0),
        "warnings": _canary_state.get("warnings", 0),
        "unknown": _canary_state.get("unknown", 0),
        "checks": canary_health_snapshot(),
    }


def note_runtime_rearm(reason, gap=0.0, iface="", now=None):
    now = time.time() if now is None else now
    _rearm_state.update({
        "last_at": now,
        "last_reason": str(reason or "")[:80],
        "last_gap": max(0.0, float(gap or 0.0)),
        "last_iface": str(iface or "")[:80],
        "count": int(_rearm_state.get("count", 0)) + 1,
    })


def _queue_runtime_rearm(reason):
    """Queue a bounded monitor-thread rearm request from a signal handler."""
    if reason not in _RUNTIME_REARM_REASONS:
        raise ValueError(f"unsupported runtime rearm reason: {reason}")
    _runtime_rearm_requests.append(reason)


def _drain_runtime_rearms():
    """Return each queued reason once, preserving first-seen order."""
    pending = []
    seen = set()
    while _runtime_rearm_requests:
        reason = _runtime_rearm_requests.popleft()
        if reason not in seen:
            pending.append(reason)
            seen.add(reason)
    return pending


def _runtime_rearm_signal_handler(signum, _frame):
    if signum == _RUNTIME_REARM_SIGNAL:
        _queue_runtime_rearm("network_change")


def _apply_runtime_rearm(reason, *, now, iface="", gap=0.0):
    """Apply real and qualification lifecycle events through one path."""
    if reason not in _RUNTIME_REARM_REASONS:
        raise ValueError(f"unsupported runtime rearm reason: {reason}")
    reset_baseline_guard(now=now)
    note_runtime_rearm(reason, gap=gap, iface=iface, now=now)
    if reason == "wake":
        note_geph_wake(now)
    start_canaries_if_due(reason, force=True)


def rearm_status_snapshot(now=None):
    now = time.time() if now is None else now
    last_at = float(_rearm_state.get("last_at", 0.0) or 0.0)
    return {
        "last_at": last_at,
        "last_reason": _rearm_state.get("last_reason", ""),
        "last_gap": int(float(_rearm_state.get("last_gap", 0.0) or 0.0)),
        "last_iface": _rearm_state.get("last_iface", ""),
        "count": int(_rearm_state.get("count", 0) or 0),
        "seconds_since": int(max(0.0, now - last_at)) if last_at else 0,
    }


def _public_route_state(route_health, route_class):
    matching = [
        item for item in route_health.values()
        if item.get("last_route_class") == route_class
    ]
    if not matching:
        return {"state": HEALTH_UNKNOWN, "updated_at": 0.0}
    best = max(
        matching,
        key=lambda item: (
            _canary_state_rank(item.get("state", HEALTH_UNKNOWN)),
            float(item.get("last_checked", 0.0) or 0.0),
        ),
    )
    return {
        "state": best.get("state", HEALTH_UNKNOWN),
        "updated_at": float(best.get("last_checked", 0.0) or 0.0),
    }


def _public_pf_status(pf_state):
    conflict = bool(pf_state.get("interceptor_conflicts"))
    if conflict:
        state = "conflict"
    elif pf_state.get("rules_loaded"):
        state = "ready"
    elif pf_state.get("enabled"):
        state = "inactive"
    else:
        state = "off"
    return {
        "state": state,
        "applied": bool(pf_state.get("applied")),
        "enabled": bool(pf_state.get("enabled")),
        "rules_loaded": bool(pf_state.get("rules_loaded")),
        "interceptor_conflict": conflict,
    }


def _public_proxy_status(proxy):
    return {
        "state": proxy.get("state", "unknown"),
        "kind": proxy.get("kind", ""),
        "managed_by_slipstream": bool(proxy.get("managed_by_slipstream")),
    }


def _public_dns_status(dns):
    resolution = dns.get("resolution_checks")
    if not isinstance(resolution, dict):
        resolution = {}
    return {
        "state": dns.get("state", "unknown"),
        "providers": dns.get("providers", ""),
        "managed_by_slipstream": bool(dns.get("managed_by_slipstream")),
        "resolution_state": resolution.get("state", "unknown"),
    }


def status_v2_snapshot(state, iface, voice_iface, now=None):
    del iface, voice_iface  # Interface names are not part of the public contract.
    now = time.time() if now is None else now
    route_health = route_health_snapshot(now)
    pf_state = pf_state_snapshot(PROXY_PORT)
    system_proxy = current_system_proxy_status()
    system_dns = current_system_dns_status()
    canaries = canary_status_snapshot()
    rearm = rearm_status_snapshot(now)
    geph_restart = geph_restart_hint_snapshot(now)
    geph_sessions = geph_active_session_count()
    auto_geo_exit = auto_geo_exit_status_snapshot(now)
    telegram = tgws_status(now)
    baseline_guard = baseline_guard_snapshot(now)
    public_daemon_state = (
        "dormant"
        if baseline_guard["state"] in {"blocked", "retry", "rollback_failed"}
        else state
    )
    geph_state = (
        "up"
        if _geph_up
        else "down"
        if _geph_port is not None or _geph_port_conflict
        else "off"
    )

    if baseline_guard["state"] in {"blocked", "retry", "rollback_failed"}:
        recovery_state = {
            "blocked": "paused",
            "retry": "waiting",
            "rollback_failed": "recovering",
        }[baseline_guard["state"]]
        recovery_reason = baseline_guard["reason"]
    elif _fd_pressure:
        recovery_state = "recovering"
        recovery_reason = "resource_pressure"
    elif geph_restart["recommended"]:
        recovery_state = "recovering"
        recovery_reason = (
            "owned_geph_restart_waiting_for_idle"
            if geph_sessions
            else "owned_geph_restart_pending"
        )
    elif rearm["last_at"]:
        recovery_state = "rearmed"
        recovery_reason = ""
    else:
        recovery_state = "idle"
        recovery_reason = ""

    return {
        "schema_version": STATUS_SCHEMA_VERSION,
        "daemon": {
            "version": DAEMON_VERSION,
            "state": public_daemon_state,
            "pid": os.getpid(),
            "updated_at": now,
            "connections": _conn_count,
            "hosts_learned": len(_strat_cache),
            "dead_hosts": len(_dead),
        },
        "routes": {
            route_class: _public_route_state(route_health, route_class)
            for route_class in (ROUTE_LOCAL_BYPASS, ROUTE_GEO_EXIT, ROUTE_DIRECT)
        },
        "backends": {
            "local_engine": {
                "state": (
                    "rollback"
                    if baseline_guard["state"] == "rollback_failed"
                    else "paused"
                    if baseline_guard["state"] in {"blocked", "retry"}
                    else "ready"
                    if pf_state.get("rules_loaded")
                    else ("conflict" if pf_state.get("interceptor_conflicts") else "inactive")
                ),
            },
            "geph": {
                "state": geph_state,
                "owned": bool(_geph_owned),
                "port_conflict": bool(_geph_port_conflict),
                "external_detected": bool(_external_geph_detected),
                "restart_recommended": bool(geph_restart["recommended"]),
                "active_sessions": int(geph_sessions),
                "auto_geo_exit": {
                    "enabled": bool(auto_geo_exit["enabled"]),
                    "learned": int(auto_geo_exit["learned"]),
                    "pending": int(auto_geo_exit["pending"]),
                    "last_state": auto_geo_exit["last_state"],
                    "updated_at": float(auto_geo_exit["last_at"] or 0.0),
                },
            },
            "telegram": {
                "state": telegram["telegram_proxy"],
                "suggested": now < _tg_proxy_suggest_until,
            },
        },
        "environment": {
            "pf": _public_pf_status(pf_state),
            "proxy": _public_proxy_status(system_proxy),
            "dns": _public_dns_status(system_dns),
        },
        "recovery": {
            "state": recovery_state,
            "last_action": (
                "pause_private_pf"
                if baseline_guard["state"]
                in {"blocked", "retry", "rollback_failed"}
                or _fd_pressure
                else rearm["last_reason"] or "none"
            ),
            "reason": recovery_reason,
            "updated_at": max(
                float(rearm["last_at"] or 0.0),
                float(geph_restart["last_wake_at"] or 0.0),
                float(geph_restart["last_failure_at"] or 0.0),
                float(_fd_pressure_at or 0.0),
                float(baseline_guard["updated_at"] or 0.0),
            ),
            "count": int(rearm["count"]),
        },
        "canaries": {
            "running": bool(canaries["running"]),
            "total": int(canaries["total"]),
            "ok": int(canaries["ok"]),
            "warnings": int(canaries["warnings"]),
            "degraded": int(canaries["degraded"]),
            "unknown": int(canaries["unknown"]),
            "next_due_in": int(canaries["next_due_in"]),
        },
    }


def startup_status_v2_snapshot(now=None):
    """Build the first lifecycle snapshot without external I/O or probes."""
    now = time.time() if now is None else now
    unknown_route = {"state": HEALTH_UNKNOWN, "updated_at": 0.0}
    return {
        "schema_version": STATUS_SCHEMA_VERSION,
        "daemon": {
            "version": DAEMON_VERSION,
            "state": "dormant",
            "pid": os.getpid(),
            "updated_at": now,
            "connections": _conn_count,
            "hosts_learned": len(_strat_cache),
            "dead_hosts": len(_dead),
        },
        "routes": {
            ROUTE_LOCAL_BYPASS: dict(unknown_route),
            ROUTE_GEO_EXIT: dict(unknown_route),
            ROUTE_DIRECT: dict(unknown_route),
        },
        "backends": {
            "local_engine": {"state": "inactive"},
            "geph": {
                "state": "off",
                "owned": False,
                "port_conflict": False,
                "external_detected": False,
                "restart_recommended": False,
                "active_sessions": 0,
                "auto_geo_exit": {
                    "enabled": False,
                    "learned": 0,
                    "pending": 0,
                    "last_state": "idle",
                    "updated_at": 0.0,
                },
            },
            "telegram": {"state": "unknown", "suggested": False},
        },
        "environment": {
            "pf": {
                "state": "off",
                "applied": False,
                "enabled": False,
                "rules_loaded": False,
                "interceptor_conflict": False,
            },
            "proxy": {
                "state": "unknown",
                "kind": "",
                "managed_by_slipstream": False,
            },
            "dns": {
                "state": "unknown",
                "providers": "",
                "managed_by_slipstream": False,
                "resolution_state": "unknown",
            },
        },
        "recovery": {
            "state": "idle",
            "last_action": "none",
            "reason": "",
            "updated_at": 0.0,
            "count": 0,
        },
        "canaries": {
            "running": False,
            "total": 0,
            "ok": 0,
            "warnings": 0,
            "degraded": 0,
            "unknown": 0,
            "next_due_in": 0,
        },
    }


def status_snapshot_updated_at(status):
    """Return the write timestamp from either supported status schema."""
    if not isinstance(status, dict):
        return 0.0
    value = status.get("ts")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    daemon = status.get("daemon")
    if not isinstance(daemon, dict):
        return 0.0
    value = daemon.get("updated_at")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return 0.0


def status_snapshot_is_terminal_conflict(status):
    """Keep an actionable startup conflict visible after the daemon exits."""
    if not isinstance(status, dict):
        return False
    if status.get("schema_version") == STATUS_SCHEMA_VERSION:
        daemon = status.get("daemon")
        return isinstance(daemon, dict) and daemon.get("state") == "conflict"
    return status.get("state") == "conflict"


def _write_status_snapshot(snapshot):
    with _status_write_lock:
        if _shutdown_started.is_set():
            return
        tmp = STATUS_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(snapshot, f)
        os.chmod(tmp, STATUS_PUBLIC_MODE)
        os.replace(tmp, STATUS_PATH)


def write_startup_status():
    if _shutdown_started.is_set():
        return
    try:
        _write_status_snapshot(startup_status_v2_snapshot())
    except Exception:
        pass


def write_status(state, iface, voice_iface):
    if _shutdown_started.is_set():
        return
    try:
        now = time.time()
        prune_telegram_direct_failures(now)
        prune_auto_geph(now)
        consume_telegram_proxy_acceptance()
        st = status_v2_snapshot(state, iface, voice_iface, now)
        _write_status_snapshot(st)
    except Exception:
        pass


# ---------------------------------------------------------------- pf plumbing
# LaunchDaemons start with an empty PATH, so bare 'pfctl'/'route' aren't
# found and the daemon silently does nothing — force the system dirs onto PATH.
_RUN_ENV = dict(os.environ)
_RUN_ENV["PATH"] = "/sbin:/usr/sbin:/bin:/usr/bin:" + _RUN_ENV.get("PATH", "")


def _run(*args):
    try:
        return subprocess.run(list(args), capture_output=True, text=True, env=_RUN_ENV)
    except FileNotFoundError:
        return subprocess.CompletedProcess(args, 127, "", f"not found: {args[0]}")


def _pf_parent_declarations(text):
    return pf_adapter.parent_declarations(text, PF_PARENT_ANCHOR)


def pf_parent_anchor_available(config_path=PF_CONFIG_PATH):
    return pf_adapter.parent_anchor_available(config_path, PF_PARENT_ANCHOR)


def pf_parent_anchor_loaded():
    return pf_adapter.parent_anchor_loaded(_run, PF_PARENT_ANCHOR)


def _pf_anchor_calls(text, directive):
    return pf_adapter.anchor_calls(text, directive)


def _pf_anchor_child(parent, child):
    return pf_adapter.anchor_child(parent, child)


def _pf_rule_targets_https(line, action):
    return pf_adapter.rule_targets_https(line, action)


def _pf_anchor_has_https_action(anchor, action, directive, visited=None):
    return pf_adapter.anchor_has_https_action(
        _run, anchor, action, directive, visited
    )


def _pf_anchors_before_parent(text, directive):
    return pf_adapter.anchors_before_parent(text, directive, PF_PARENT_ANCHOR)


def pf_preceding_https_interceptors():
    """Return active PF anchors that capture HTTPS before Slipstream's parent.

    PF translation uses the first matching rdr rule. A transparent proxy whose
    anchor appears before ``com.apple/*`` therefore receives the real traffic
    even though Slipstream's own anchor is loaded. Internal canaries do not see
    that ordering, so treating this as an explicit runtime conflict prevents a
    false "Active / OK" state without mutating the other product's rules.
    """
    return pf_adapter.preceding_https_interceptors(_run, PF_PARENT_ANCHOR)


def _pf_token_from_result(result):
    return pf_adapter.token_from_result(result)


def _write_pf_token(token, path=None):
    path = PF_TOKEN_PATH if path is None else path
    pf_adapter.write_token(token, path)


def _read_pf_token(path=None):
    path = PF_TOKEN_PATH if path is None else path
    return pf_adapter.read_token(path)


def _remove_pf_token(path=None):
    path = PF_TOKEN_PATH if path is None else path
    pf_adapter.remove_token(path)


def _read_pf_skip_lease(path=None):
    path = PF_SKIP_LEASE_PATH if path is None else path
    return pf_adapter.read_skip_lease(path)


def _write_pf_skip_lease(path=None):
    path = PF_SKIP_LEASE_PATH if path is None else path
    pf_adapter.write_skip_lease(path, PF_LOOPBACK_INTERFACE, os.getpid())


def _remove_pf_skip_lease(path=None):
    path = PF_SKIP_LEASE_PATH if path is None else path
    pf_adapter.remove_skip_lease(path)


def _pf_loopback_skip_state():
    return pf_adapter.interface_skip_state(_run, PF_LOOPBACK_INTERFACE)


def _restore_pf_loopback_skip():
    """Restore a skip flag that this daemon durably recorded before clearing."""
    try:
        lease = _read_pf_skip_lease()
    except (OSError, ValueError) as error:
        print(f">> invalid PF loopback lease: {error}", file=sys.stderr)
        return False
    if lease is None:
        return True
    state = _pf_loopback_skip_state()
    if state is None:
        return False
    if not state:
        try:
            restored = pf_adapter.set_interface_skip(
                _run,
                PF_LOOPBACK_INTERFACE,
                True,
            )
        except (OSError, ValueError):
            restored = False
        if not restored:
            return False
    try:
        _remove_pf_skip_lease()
    except OSError:
        return False
    return True


def _claim_pf_loopback_skip():
    """Make lo0 PF-visible while preserving external ownership for rollback."""
    try:
        if _read_pf_skip_lease() is not None:
            # A stale lease must be recovered before a new arm. Never overwrite
            # the only durable proof that the external skip flag must return.
            return False
    except (OSError, ValueError):
        return False
    state = _pf_loopback_skip_state()
    if state is None:
        return False
    if not state:
        # Another component already made lo0 PF-visible. Use that state without
        # claiming it and leave it unchanged during teardown.
        return True
    try:
        _write_pf_skip_lease()
        cleared = pf_adapter.set_interface_skip(
            _run,
            PF_LOOPBACK_INTERFACE,
            False,
        )
    except (OSError, ValueError):
        cleared = False
    if cleared:
        return True
    _restore_pf_loopback_skip()
    return False


def _pf_release_enable_token():
    global _pf_enable_token
    token = _pf_enable_token or _read_pf_token()
    if not token:
        _pf_enable_token = None
        _remove_pf_token()
        return None
    result = _run("pfctl", "-X", token)
    if result.returncode == 0:
        _pf_enable_token = None
        _remove_pf_token()
    else:
        # Keep the token recoverable. Overwriting it with a new reference would
        # leak PF ownership and make a later uninstall unable to release it.
        _pf_enable_token = token
    return result


def _pf_enabled_state():
    return pf_adapter.enabled_state(_run)


def _pf_acquire_enable_token():
    global _pf_enable_token
    persisted = _read_pf_token()
    if _pf_enable_token and persisted == _pf_enable_token:
        return True
    stale_memory_token = bool(_pf_enable_token and not persisted)
    if stale_memory_token and _pf_enabled_state() is False:
        # A previous owned recovery can release PF after this daemon has already
        # cached its token. With PF definitively disabled and no durable token,
        # the in-memory reference cannot still be valid; acquire a fresh one.
        _pf_enable_token = None
        _remove_pf_token()
    elif _pf_enable_token or persisted:
        released = _pf_release_enable_token()
        if released is not None and released.returncode != 0:
            return False
    enabled = _run("pfctl", "-E")
    if enabled.returncode != 0:
        return False
    token = _pf_token_from_result(enabled)
    if not token:
        return False
    _pf_enable_token = token
    _write_pf_token(token)
    return True


def _pf_flush():
    return pf_adapter.flush_private_anchor(_run, PF_ANCHOR)


def _flush_private_pf_with_retry(
    attempts=PF_FLUSH_ATTEMPTS,
    delay=PF_FLUSH_RETRY_DELAY,
):
    """Clear only Slipstream's anchor, retrying bounded transient failures."""
    for attempt in range(max(1, int(attempts))):
        result = _pf_flush()
        if result.returncode == 0:
            return True
        if attempt + 1 < attempts and delay > 0:
            time.sleep(delay)
    return False


def fd_pressure_watermarks(soft_limit):
    """Return hysteresis bounds that preserve enough FDs for safe teardown."""
    try:
        limit = int(soft_limit)
    except (TypeError, ValueError, OverflowError):
        limit = 65536
    if limit <= 0 or soft_limit == resource.RLIM_INFINITY:
        limit = 65536
    if limit < 128:
        high = max(1, limit - 8)
        return high, max(1, high // 2)
    high = min(FD_PRESSURE_HIGH_CAP, int(limit * 0.8), limit - 64)
    low = min(FD_PRESSURE_LOW_CAP, int(limit * 0.5), high - 1)
    return max(64, high), max(32, low)


def reduce_fd_pressure(active, open_fds, soft_limit):
    if open_fds is None:
        return bool(active)
    high, low = fd_pressure_watermarks(soft_limit)
    return open_fds > low if active else open_fds >= high


def open_fd_count():
    for path in ("/dev/fd", "/proc/self/fd"):
        try:
            return len(os.listdir(path))
        except OSError:
            continue
    return None


def _release_fd_reserve():
    global _fd_reserve
    reserve, _fd_reserve = _fd_reserve, []
    for fd in reserve:
        try:
            os.close(fd)
        except OSError:
            pass


def _open_fd_reserve():
    if _fd_reserve:
        return
    for _ in range(FD_PRESSURE_RESERVE):
        try:
            _fd_reserve.append(os.open("/dev/null", os.O_RDONLY))
        except OSError:
            break


def mark_fd_pressure(reason):
    """Fail open for native traffic when this process cannot accept safely."""
    global _fd_pressure, _fd_pressure_reason, _fd_pressure_at
    with _fd_pressure_lock:
        first = not _fd_pressure
        _fd_pressure = True
        _fd_pressure_reason = str(reason)[:200]
        _fd_pressure_at = time.time()
    if not first:
        return False
    # Keep enough descriptors in reserve to run the private-anchor cleanup even
    # when accept() has already reported EMFILE.
    _release_fd_reserve()
    print(
        f">> file descriptor pressure -> transparent routing dormant ({_fd_pressure_reason})",
        file=sys.stderr,
    )
    if not pause_private_pf():
        print(
            ">> unable to pause Slipstream's private pf anchor during fd pressure",
            file=sys.stderr,
        )
    return True


def refresh_fd_pressure():
    global _fd_pressure, _fd_pressure_reason
    try:
        soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (ValueError, OSError):
        soft_limit = 65536
    count = open_fd_count()
    next_state = reduce_fd_pressure(_fd_pressure, count, soft_limit)
    if next_state and not _fd_pressure:
        mark_fd_pressure(f"{count} open files")
    elif _fd_pressure and not next_state:
        with _fd_pressure_lock:
            _fd_pressure = False
            _fd_pressure_reason = ""
        _open_fd_reserve()
        print(">> file descriptor pressure cleared -> routing may recover", file=sys.stderr)
    return _fd_pressure


def asyncio_exception_handler(loop, context):
    exc = context.get("exception")
    if isinstance(exc, OSError) and exc.errno in (errno.EMFILE, errno.ENFILE):
        mark_fd_pressure(os.strerror(exc.errno))
        return
    loop.default_exception_handler(context)


def geo_exit_backend_ready(now=None):
    """Whether the optional Geph route may accept a new connection."""
    global _geph_backend_hold_until, _geph_backend_hold_reason
    if not GEPH_ENABLED:
        return False
    now = time.time() if now is None else now
    ready = bool(_geph_up and _geph_port in GEPH_PORTS)
    if not ready or now < _geph_backend_hold_until:
        return False
    if _geph_backend_hold_until:
        _geph_backend_hold_until = 0.0
        _geph_backend_hold_reason = ""
    return True


def baseline_guard_snapshot(now=None):
    now = time.time() if now is None else now
    with _baseline_guard_lock:
        snapshot = dict(_baseline_guard_state)
    retry_at = float(snapshot.get("retry_at", 0.0) or 0.0)
    snapshot["retry_in"] = int(max(0.0, retry_at - now)) if retry_at else 0
    return snapshot


def _set_baseline_guard(state, reason="", *, now=None, retry_at=0.0):
    now = time.time() if now is None else now
    with _baseline_guard_lock:
        failures = int(_baseline_guard_state.get("failures", 0))
        if state in {"blocked", "retry"}:
            failures += 1
        _baseline_guard_state.update({
            "state": state,
            "reason": str(reason or "")[:80],
            "updated_at": now,
            "retry_at": float(retry_at or 0.0),
            "failures": failures,
        })


def reset_baseline_guard(now=None):
    _set_baseline_guard("pending", now=now)


def _baseline_guard_allows_attempt(now=None):
    now = time.time() if now is None else now
    snapshot = baseline_guard_snapshot(now)
    if snapshot["state"] in {"blocked", "rollback_failed"}:
        return False
    return (
        snapshot["state"] != "retry"
        or now >= float(snapshot.get("retry_at", 0.0) or 0.0)
    )


def _console_probe_identity():
    try:
        uid = os.stat("/dev/console").st_uid
        account = pwd.getpwuid(uid)
    except (KeyError, OSError):
        return None
    if uid <= 0 or account.pw_name in {"loginwindow", "_mbsetupuser"}:
        return None
    return (uid, account.pw_gid, account.pw_dir)


def _baseline_probe_command(candidate):
    if getattr(sys, "frozen", False):
        command = [sys.executable]
    else:
        command = [sys.executable, os.path.abspath(__file__)]
    return command + [
        "--baseline-probe",
        "--baseline-host", candidate.host,
        "--baseline-ip", candidate.ip,
        "--baseline-path", candidate.path,
    ]


def _baseline_resolver_command(host):
    if getattr(sys, "frozen", False):
        command = [sys.executable]
    else:
        command = [sys.executable, os.path.abspath(__file__)]
    return command + [
        "--baseline-resolve",
        "--baseline-host", host,
    ]


def _run_baseline_resolver(host, port, identity, *, timeout=BASELINE_RESOLVE_TIMEOUT):
    """Resolve through system DNS in a killable, time-bounded child process."""
    if timeout <= 0:
        return ()
    uid, gid, home = identity
    env = dict(_RUN_ENV)
    env.update({"HOME": home, "TMPDIR": "/tmp"})
    kwargs = {
        "capture_output": True,
        "text": True,
        "timeout": timeout,
        "env": env,
    }
    if os.geteuid() == 0:
        kwargs.update({"user": uid, "group": gid, "extra_groups": ()})
    try:
        result = subprocess.run(_baseline_resolver_command(host), **kwargs)
    except (OSError, subprocess.TimeoutExpired):
        return ()
    if result.returncode != 0:
        return ()
    try:
        addresses = json.loads(result.stdout).get("addresses", ())
    except (AttributeError, json.JSONDecodeError):
        return ()
    if not isinstance(addresses, list):
        return ()
    answers = []
    for address in addresses[: install_guard.MAX_CANDIDATES]:
        if not isinstance(address, str):
            continue
        answers.append((
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            (address, port),
        ))
    return tuple(answers)


def _refresh_system_dns_resolution_checks():
    """Refresh diagnostics without allowing system DNS to occupy a worker."""
    identity = _console_probe_identity()
    if identity is None:
        checks = {"state": "unknown", "checks": []}
    else:
        deadline = time.monotonic() + SYSTEM_DNS_DIAGNOSTIC_BUDGET

        def resolver(host):
            timeout = max(
                0.0,
                min(BASELINE_RESOLVE_TIMEOUT, deadline - time.monotonic()),
            )
            answers = _run_baseline_resolver(host, 443, identity, timeout=timeout)
            return [answer[4][0] for answer in answers]

        checks = system_dns_resolution_checks(resolver)
    _system_dns_cache.update({
        "resolution_ts": time.monotonic(),
        "resolution_checks": dict(checks),
    })
    return checks


def _log_baseline_probe_results(stage, results):
    """Write bounded probe evidence to the private daemon log."""
    for candidate, result in results:
        outcome = "ok" if result.ok else str(result.reason)[:80]
        print(
            f">> HTTPS baseline {stage}: {candidate.host} "
            f"({candidate.ip}) -> {outcome}",
            file=sys.stderr,
        )


def _run_baseline_probe_candidate(
    candidate,
    identity,
    *,
    timeout=install_guard.DEFAULT_TIMEOUT + 1.5,
):
    if timeout <= 0:
        return install_guard.ProbeResult(False, "preflight_budget_exhausted")
    uid, gid, home = identity
    env = dict(_RUN_ENV)
    env.update({"HOME": home, "TMPDIR": "/tmp"})
    kwargs = {
        "capture_output": True,
        "text": True,
        "timeout": timeout,
        "env": env,
    }
    if os.geteuid() == 0:
        kwargs.update({"user": uid, "group": gid, "extra_groups": ()})
    try:
        result = subprocess.run(_baseline_probe_command(candidate), **kwargs)
    except (OSError, subprocess.TimeoutExpired):
        return install_guard.ProbeResult(False, "probe_process_unavailable")
    if result.returncode == 0:
        return install_guard.ProbeResult(True, "ok")
    try:
        reason = json.loads(result.stdout).get("reason", "probe_failed")
    except (AttributeError, json.JSONDecodeError):
        reason = "probe_failed"
    return install_guard.ProbeResult(False, str(reason)[:80])


def _baseline_preflight():
    identity = _console_probe_identity()
    if identity is None:
        return (
            install_guard.QualificationResult(False, "no_console_user"),
            None,
        )
    observed = []
    deadline = time.monotonic() + BASELINE_PREFLIGHT_BUDGET

    def remaining(cap):
        return max(0.0, min(cap, deadline - time.monotonic()))

    def resolver(host, port, **_kwargs):
        return _run_baseline_resolver(
            host,
            port,
            identity,
            timeout=remaining(BASELINE_RESOLVE_TIMEOUT),
        )

    def probe(candidate):
        result = _run_baseline_probe_candidate(
            candidate,
            identity,
            timeout=remaining(install_guard.DEFAULT_TIMEOUT + 1.5),
        )
        observed.append((candidate, result))
        return result

    result = install_guard.qualify_before_arm(probe, resolver=resolver)
    _log_baseline_probe_results("before PF", observed)
    return result, identity


def _baseline_postflight(candidates, identity):
    if identity is None:
        return install_guard.QualificationResult(
            False, BASELINE_GUARD_BLOCK_REASON, tuple(candidates)
        )
    candidates = tuple(candidates)
    with ThreadPoolExecutor(
        max_workers=max(1, len(candidates)),
        thread_name_prefix="baseline-post",
    ) as executor:
        results = dict(zip(
            candidates,
            executor.map(
                lambda candidate: _run_baseline_probe_candidate(candidate, identity),
                candidates,
            ),
        ))
    _log_baseline_probe_results("after PF", results.items())
    return install_guard.qualify_after_arm(
        candidates,
        results.__getitem__,
    )


def transparent_routing_ready():
    """Whether the local transparent engine can safely accept connections."""
    return not _fd_pressure and _baseline_guard_allows_attempt()


def pause_private_pf():
    global _pf_applied
    with _pf_state_lock:
        if not _flush_private_pf_with_retry():
            return False
        _pf_applied = False
        if not _restore_pf_loopback_skip():
            _set_baseline_guard(
                "rollback_failed",
                BASELINE_GUARD_ROLLBACK_REASON,
            )
            return False
    return True


def retry_baseline_rollback():
    """Finish a previously failed post-arm rollback without dropping traffic."""
    snapshot = baseline_guard_snapshot()
    if snapshot["state"] != "rollback_failed":
        return False
    if not pause_private_pf():
        return False
    _pf_release_enable_token()
    _set_baseline_guard("blocked", BASELINE_GUARD_BLOCK_REASON)
    return True


def arm_private_pf_if_ready(port):
    global _pf_applied
    if (
        _shutdown_started.is_set()
        or not transparent_routing_ready()
        or not pf_parent_anchor_loaded()
    ):
        return False
    preflight, identity = _baseline_preflight()
    if not preflight.ok:
        now = time.time()
        _set_baseline_guard(
            "retry",
            preflight.reason,
            now=now,
            retry_at=now + BASELINE_GUARD_RETRY_SECONDS,
        )
        print(
            ">> system HTTPS baseline is not yet provable -> private PF remains dormant",
            file=sys.stderr,
        )
        return False
    with _pf_state_lock:
        if (
            _shutdown_started.is_set()
            or not transparent_routing_ready()
            or not pf_parent_anchor_loaded()
        ):
            return False
        if not _pf_acquire_enable_token():
            return False
        result = _pf_load(port)
        loaded = result.returncode == 0
        loopback_ready = False
        postflight = None
        if loaded:
            # Treat a loaded anchor as potentially active until its private
            # rules are flushed. With lo0 already PF-visible, no lease exists
            # and traffic can start matching immediately.
            _pf_applied = True
            if not _shutdown_started.is_set() and transparent_routing_ready():
                # Load while the external skip is still intact, then clear only
                # PFI_IFLAG_SKIP under a durable lease. This avoids a window
                # where lo0 is globally visible but our rdr rule is absent.
                loopback_ready = _claim_pf_loopback_skip()
            if (
                loopback_ready
                and not _shutdown_started.is_set()
                and transparent_routing_ready()
            ):
                postflight = _baseline_postflight(preflight.candidates, identity)
                if postflight.ok and not _shutdown_started.is_set():
                    _set_baseline_guard("ready")
                    return True

        if _flush_private_pf_with_retry():
            _pf_applied = False
            restored = _restore_pf_loopback_skip()
            if restored:
                _pf_release_enable_token()
            if postflight is not None:
                state = "blocked" if restored else "rollback_failed"
                reason = (
                    BASELINE_GUARD_BLOCK_REASON
                    if restored
                    else BASELINE_GUARD_ROLLBACK_REASON
                )
                _set_baseline_guard(state, reason)
                print(
                    ">> private PF failed the HTTPS baseline -> rolled back and blocked",
                    file=sys.stderr,
                )
            elif loaded and not loopback_ready and not _shutdown_started.is_set():
                now = time.time()
                _set_baseline_guard(
                    "retry" if restored else "rollback_failed",
                    (
                        PF_LOOPBACK_UNAVAILABLE_REASON
                        if restored
                        else BASELINE_GUARD_ROLLBACK_REASON
                    ),
                    now=now,
                    retry_at=now + BASELINE_GUARD_RETRY_SECONDS,
                )
                print(
                    ">> PF loopback qualification failed -> private PF remains dormant",
                    file=sys.stderr,
                )
            if not restored:
                print(
                    ">> PF loopback restoration is incomplete; lease remains recoverable",
                    file=sys.stderr,
                )
        else:
            # Keep the listener alive while the monitor retries only our
            # anchor. Killing it here would turn a PF cleanup failure into a
            # machine-wide HTTPS black hole.
            _pf_applied = loaded or _pf_applied
            _set_baseline_guard("rollback_failed", BASELINE_GUARD_ROLLBACK_REASON)
            print(
                ">> private PF rollback is incomplete; listener remains alive",
                file=sys.stderr,
            )
        return False


def suspend_geo_exit_backend(reason, now=None):
    """Cool down only Geph while local routing remains available."""
    global _geph_up, _geph_backend_hold_until, _geph_backend_hold_reason
    now = time.time() if now is None else now
    _geph_up = False
    _geph_backend_hold_until = max(
        _geph_backend_hold_until,
        now + GEPH_BACKEND_FAILURE_HOLD,
    )
    _geph_backend_hold_reason = str(reason)[:200]
    print(
        ">> geo-exit backend unavailable -> local routing remains active",
        file=sys.stderr,
    )
    return True


def pf_setup_if_ready(port, now=None):
    global _pf_interceptor_conflicts
    if _shutdown_started.is_set():
        return False
    if not transparent_routing_ready():
        print(
            ">> local routing capacity unavailable -> leaving transparent routing dormant",
            file=sys.stderr,
        )
        return False
    if not pf_parent_anchor_available() or not pf_parent_anchor_loaded():
        print(
            f">> pf parent anchor {PF_PARENT_ANCHOR} unavailable -> dormant",
            file=sys.stderr,
        )
        return False
    _pf_interceptor_conflicts = pf_preceding_https_interceptors()
    if _pf_interceptor_conflicts:
        if _pf_applied:
            pause_private_pf()
        print(
            ">> another transparent HTTPS filter is active before Slipstream "
            f"({', '.join(_pf_interceptor_conflicts)}) -> dormant",
            file=sys.stderr,
        )
        return False
    return arm_private_pf_if_ready(port)


def _legacy_global_pf_conflict(port):
    # A killed daemon can leave the private child anchor populated until the
    # next instance starts. Some macOS pfctl listings include those effective
    # child rules in the root view. A matching global signature is therefore a
    # conflict signal, never proof that Slipstream owns or may rewrite it.
    if pf_has_rules(port):
        return False
    nat = _run("pfctl", "-sn")
    rules = _run("pfctl", "-sr")
    if nat.returncode != 0 or rules.returncode != 0:
        return False
    redirect = f"-> 127.0.0.1 port {port}" in nat.stdout
    route = "route-to (lo0 127.0.0.1)" in rules.stdout
    https = re.search(r"\bport\s*(?:=\s*)?443\b", rules.stdout)
    return bool(redirect and route and https)


def _pf_load(port):
    return pf_adapter.load_private_anchor(_run, PF_ANCHOR, PF_RULES, port)


def pf_setup(port):
    """Backward-compatible entry point; every PF arm passes the baseline guard."""
    return pf_setup_if_ready(port)


def pf_has_rules(port):
    """Are our rdr rules still loaded? (sleep/wake or another tool may flush pf)"""
    return pf_adapter.private_rules_loaded(
        _run, PF_ANCHOR, port, pf_parent_anchor_loaded
    )


def pf_state_snapshot(port=PROXY_PORT):
    return pf_adapter.state_snapshot(
        _run,
        PF_ANCHOR,
        port,
        _pf_applied,
        _pf_interceptor_conflicts,
        pf_parent_anchor_loaded,
    )


def pf_teardown():
    global _pf_applied, _pf_interceptor_conflicts
    _shutdown_started.set()
    with _status_write_lock:
        for path in (STATUS_PATH + ".tmp", STATUS_PATH):
            try:
                os.remove(path)      # daemon is going away -> app shows "off"
            except Exception:
                pass
    with _pf_state_lock:
        if _pf_teardown_complete.is_set():
            return True
        flush_result = _pf_flush()
        if flush_result.returncode != 0:
            print(">> unable to clear Slipstream pf anchor; will retry", file=sys.stderr)
            return False
        _pf_applied = False
        if not _restore_pf_loopback_skip():
            print(">> unable to restore PF loopback skip; will retry", file=sys.stderr)
            return False
        release_result = _pf_release_enable_token()
        token_release_failed = (
            release_result is not None and release_result.returncode != 0
        )
        _pf_interceptor_conflicts = []
        _pf_teardown_complete.set()
    print(">> Slipstream pf anchor cleared")
    if token_release_failed:
        # The network-safe boundary is the private anchor, not the enable
        # reference. Keep the token file for a later uninstall/recovery, but do
        # not keep the listener alive after interception has already stopped.
        print(
            ">> Slipstream pf token release deferred; token remains recoverable",
            file=sys.stderr,
        )
    return True


async def wait_for_connections_to_drain(timeout=SHUTDOWN_DRAIN_SECONDS):
    """Give already-accepted streams a bounded chance to finish.

    PF is cleared and the listening socket is closed before this runs, so the
    count can only fall. A deadline keeps launchd stop/uninstall deterministic
    when a browser leaves an idle keep-alive connection open indefinitely.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(0.0, timeout)
    quiet_since = None
    while True:
        now = loop.time()
        if _conn_count == 0:
            quiet_since = now if quiet_since is None else quiet_since
            if (
                timeout <= 0
                or now - quiet_since >= SHUTDOWN_DRAIN_QUIET_SECONDS
            ):
                return True
        else:
            quiet_since = None
        if now >= deadline:
            return False
        await asyncio.sleep(min(0.05, max(0.0, deadline - now)))


async def cancel_active_connections():
    """Cancel and await only connection tasks owned by this daemon."""
    current = asyncio.current_task()
    tasks = [
        task
        for task in tuple(_connection_tasks)
        if task is not current and not task.done()
    ]
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    return len(tasks)


def request_daemon_shutdown(shutdown):
    """Publish terminal intent to worker threads before asyncio starts draining."""
    _shutdown_started.set()
    shutdown.set()


async def serve_until_shutdown(server, shutdown, drain_timeout=SHUTDOWN_DRAIN_SECONDS):
    """Stop new interception before giving accepted streams time to finish."""
    async with server:
        serving = asyncio.create_task(server.serve_forever())
        stopping = asyncio.create_task(shutdown.wait())
        done, _ = await asyncio.wait(
            (serving, stopping),
            return_when=asyncio.FIRST_COMPLETED,
        )
        if serving in done:
            stopping.cancel()
            await asyncio.gather(stopping, return_exceptions=True)
            await serving
            return True

        # Keep the listener alive until the private anchor is definitely gone.
        # Closing it first turns a transient pfctl failure into a TCP/443 black
        # hole for every redirected application.
        while not pf_teardown():
            await asyncio.sleep(0.1)
        server.close()
        await server.wait_closed()
        drained = await wait_for_connections_to_drain(drain_timeout)
        if not drained:
            await cancel_active_connections()
        serving.cancel()
        await asyncio.gather(serving, return_exceptions=True)
        return drained


def running_from_install_dir(file_path=None, executable=None, frozen=None):
    if frozen is None:
        frozen = getattr(sys, "frozen", False)
    if executable is None:
        executable = sys.executable
    if file_path is None:
        file_path = __file__

    if frozen:
        return os.path.dirname(os.path.abspath(executable)) == INSTALL_DIR
    return os.path.abspath(file_path) == os.path.join(INSTALL_DIR, "tproxy.py")


def _same_file_bytes(src, dst):
    try:
        return os.path.exists(dst) and filecmp.cmp(src, dst, shallow=False)
    except Exception:
        return False


def _copy_file_resilient(src, dst, mode=None, attempts=3, delay=0.15):
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if _same_file_bytes(src, dst):
        if mode is not None:
            os.chmod(dst, mode)
        return "unchanged"
    last = None
    for attempt in range(max(1, attempts)):
        tmp = f"{dst}.tmp.{os.getpid()}.{attempt}"
        try:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            shutil.copy2(src, tmp)
            if mode is not None:
                os.chmod(tmp, mode)
            os.replace(tmp, dst)
            return "copied"
        except Exception as e:
            last = e
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            except Exception:
                pass
            if attempt + 1 < attempts:
                time.sleep(delay)
    raise last


def _script_runtime_payload(source_file):
    source_file = os.path.abspath(source_file)
    source_dir = os.path.dirname(source_file)
    payload = (
        (source_file, "tproxy.py"),
        (
            os.path.join(source_dir, "requirements-runtime.txt"),
            "requirements-runtime.txt",
        ),
        (os.path.join(source_dir, "address_attempts.py"), "address_attempts.py"),
        (os.path.join(source_dir, "connection_probe.py"), "connection_probe.py"),
        (os.path.join(source_dir, "connection_race.py"), "connection_race.py"),
        (os.path.join(source_dir, "connection_race_io.py"), "connection_race_io.py"),
        (os.path.join(source_dir, "geph_backend.py"), "geph_backend.py"),
        (os.path.join(source_dir, "install_guard.py"), "install_guard.py"),
        (os.path.join(source_dir, "pf_adapter.py"), "pf_adapter.py"),
        (os.path.join(source_dir, "primes.py"), "primes.py"),
        (os.path.join(source_dir, "route_circuit.py"), "route_circuit.py"),
        (
            os.path.join(source_dir, "route_circuit_registry.py"),
            "route_circuit_registry.py",
        ),
        (
            os.path.join(source_dir, "route_policy_activation.py"),
            "route_policy_activation.py",
        ),
        (
            os.path.join(source_dir, "route_policy_activation_adapter.py"),
            "route_policy_activation_adapter.py",
        ),
        (
            os.path.join(source_dir, "route_policy_bundle.py"),
            "route_policy_bundle.py",
        ),
        (
            os.path.join(source_dir, "route_policy_manifest.py"),
            "route_policy_manifest.py",
        ),
        (os.path.join(source_dir, "routing_policy.py"), "routing_policy.py"),
        (os.path.join(source_dir, "routing_recovery.py"), "routing_recovery.py"),
        (os.path.join(source_dir, "xbox_dns.py"), "xbox_dns.py"),
    )
    missing = [src for src, _ in payload if not os.path.isfile(src)]
    if missing:
        raise FileNotFoundError("missing script runtime: " + ", ".join(missing))
    return payload


def _copy_script_runtime(source_file, install_dir):
    """Copy every local Python module required by the script-mode daemon."""
    payload = _script_runtime_payload(source_file)
    os.makedirs(install_dir, exist_ok=True)
    for src, name in payload:
        _copy_file_resilient(src, os.path.join(install_dir, name), mode=0o644)


def _replace_tree_resilient(src, dst, attempts=3, delay=0.15):
    parent = os.path.dirname(dst)
    os.makedirs(parent, exist_ok=True)
    last = None
    for attempt in range(max(1, attempts)):
        tmp = f"{dst}.tmp.{os.getpid()}.{attempt}"
        backup = f"{dst}.bak.{os.getpid()}.{attempt}"
        try:
            shutil.rmtree(tmp, ignore_errors=True)
            shutil.rmtree(backup, ignore_errors=True)
            shutil.copytree(src, tmp)
            if os.path.exists(dst):
                os.replace(dst, backup)
            os.replace(tmp, dst)
            shutil.rmtree(backup, ignore_errors=True)
            return "replaced"
        except Exception as e:
            last = e
            if not os.path.exists(dst) and os.path.exists(backup):
                try:
                    os.replace(backup, dst)
                except Exception:
                    pass
            shutil.rmtree(tmp, ignore_errors=True)
            shutil.rmtree(backup, ignore_errors=True)
            if attempt + 1 < attempts:
                time.sleep(delay)
    raise last


def cleanup_stale(port=PROXY_PORT):
    """Clear only Slipstream-owned state left by a prior daemon instance."""
    installed = running_from_install_dir()
    legacy_global_conflict = _legacy_global_pf_conflict(port)
    disable_error = ""

    if not installed:
        # A foreground/dev daemon must quiesce an installed KeepAlive job while
        # its listener is still available. Booting it out first can strand the
        # private redirect until this new process reaches the later flush.
        if not _disable_and_cleanup_install(port, remove_runtime=False):
            raise OwnedPfStateError(
                "the installed daemon could not be quiesced safely"
            )
    elif legacy_global_conflict:
        result = _run("launchctl", "disable", _launchd_target())
        if result.returncode != 0:
            disable_error = (result.stderr or result.stdout or "unknown error").strip()

    flush = _pf_flush()
    if flush.returncode != 0:
        raise OwnedPfStateError(
            "Slipstream's private PF anchor could not be cleared"
        )
    if not _restore_pf_loopback_skip():
        raise OwnedPfStateError(
            "Slipstream's PF loopback state could not be restored"
        )
    _pf_release_enable_token()

    if legacy_global_conflict:
        detail = (
            f"; unable to disable owned launchd label: {disable_error[:240]}"
            if disable_error
            else ""
        )
        raise LegacyGlobalPfConflict(
            "global HTTPS PF rules target Slipstream's listener, but their "
            "ownership cannot be proven; refusing to reload /etc/pf.conf" + detail
        )


def orig_dst(sock):
    peer = sock.getpeername()
    local = sock.getsockname()
    buf = bytearray(84)
    buf[0:4] = socket.inet_aton(peer[0])
    buf[16:20] = socket.inet_aton(local[0])
    struct.pack_into("!H", buf, 64, peer[1])
    struct.pack_into("!H", buf, 68, local[1])
    buf[80] = socket.AF_INET
    buf[81] = socket.IPPROTO_TCP
    buf[83] = PF_OUT
    fcntl.ioctl(_pf_fd, DIOCNATLOOK, buf, True)
    return socket.inet_ntoa(bytes(buf[48:52])), struct.unpack_from("!H", buf, 76)[0]


# ------------------------------------------------------------- TLS / desync
def parse_sni(body: bytes):
    try:
        p = 4 + 2 + 32
        p += 1 + body[p]
        p += 2 + struct.unpack_from("!H", body, p)[0]
        p += 1 + body[p]
        ext_end = p + 2 + struct.unpack_from("!H", body, p)[0]
        p += 2
        while p + 4 <= ext_end:
            etype, elen = struct.unpack_from("!HH", body, p)
            p += 4
            if etype == 0:
                np = p + 2 + 1
                nlen = struct.unpack_from("!H", body, np)[0]
                return body[np + 2:np + 2 + nlen].decode("ascii", "replace")
            p += elen
    except Exception:
        pass
    return None


def make_blob(head: bytes, body: bytes, host, cap):
    """Build the first-flight bytes for one strategy.

    cap=None -> plain (no desync, for unblocked hosts). Otherwise split the
    ClientHello into TLS records with a tiny first record (<=cap) plus a cut
    inside the SNI hostname, which defeats this TSPU's first-record SNI check."""
    if cap is None:
        return head + body
    typ, ver = head[0:1], head[1:3]
    n = len(body)
    i = body.find(host.encode()) if host else -1
    if i < 0:
        i = max(2, n // 3)
    c1 = min(cap, max(1, i - 1))
    c2 = min(n - 1, i + (max(1, len(host) // 2) if host else 8))
    cuts = sorted(c for c in {c1, c2} if 0 < c < n)
    parts, prev = [], 0
    for c in cuts:
        if c > prev:
            parts.append(body[prev:c])
            prev = c
    parts.append(body[prev:])
    mk = lambda p: typ + ver + struct.pack("!H", len(p)) + p
    return b"".join(mk(p) for p in parts)


# --------------------------------------------------- adaptive strategy ladder
# Tried in order, cached winner first. The first that completes TLS is cached
# per host; when the TSPU changes and the cached one stops working, connections
# climb the ladder to the next working strategy and re-cache it. Self-tuning,
# no manual re-tuning, survives strategy decay.
STRATEGIES = [
    {"name": "split64",      "cap": 64,   "fake": False},
    {"name": "split64+fake", "cap": 64,   "fake": True},
    {"name": "split16",      "cap": 16,   "fake": False},
    {"name": "split16+fake", "cap": 16,   "fake": True},
    {"name": "fake5",        "cap": 5,    "fake": True},
    {"name": "plain",        "cap": None, "fake": False},
]
STRAT_BY_NAME = {s["name"]: s for s in STRATEGIES}
_STRAT_PATH = "/var/run/slipstream-strat.json"
STRAT_CACHE_MAX = 2048
STRAT_CACHE_VERSION = 4             # bump on strategy-logic changes -> discard stale
                                    # v4: Discord uses decoy fake; video uses poison fake
_strat_cache = OrderedDict()       # host -> winning strategy name
STRAT_SCORE_MAX_HOSTS = 2048
STRAT_SCORE_Z = 1.0                # light Wilson lower bound; avoids overreacting
STRAT_SCORE_CACHED_BONUS = 0.12
STRAT_SCORE_AGE_BONUS_MAX = 0.05
STRAT_SCORE_AGE_BONUS_AFTER = 3600.0
_strat_scores = OrderedDict()      # host -> strategy -> {ok, fail, last}


def load_strat_cache():
    global _strat_cache
    try:
        with open(_STRAT_PATH) as f:
            data = json.load(f)
        if data.get("__v__") != STRAT_CACHE_VERSION:
            data = {}                # logic changed -> old winners may be wrong
        data.pop("__v__", None)
        _strat_cache = OrderedDict(data)
    except Exception:
        _strat_cache = OrderedDict()


def remember_strategy(host, name):
    _strat_cache[host] = name
    _strat_cache.move_to_end(host)
    while len(_strat_cache) > STRAT_CACHE_MAX:
        _strat_cache.popitem(last=False)
    save_strat_cache()


def save_strat_cache():
    try:
        d = dict(_strat_cache)
        d["__v__"] = STRAT_CACHE_VERSION
        with open(_STRAT_PATH, "w") as f:
            json.dump(d, f)
    except Exception:
        pass


def _strategy_wilson_score(ok, total):
    if total <= 0:
        return 0.5
    z = STRAT_SCORE_Z
    p = ok / total
    denom = 1.0 + (z * z / total)
    center = p + (z * z / (2.0 * total))
    margin = z * math.sqrt((p * (1.0 - p) + z * z / (4.0 * total)) / total)
    return max(0.0, min(1.0, (center - margin) / denom))


def _record_strategy_result(host, name, ok, now=None):
    host = normalize_host(host)
    if not host or name not in STRAT_BY_NAME:
        return
    now = time.time() if now is None else now
    per_host = _strat_scores.setdefault(host, {})
    item = per_host.setdefault(name, {"ok": 0, "fail": 0, "last": 0.0})
    item["ok" if ok else "fail"] += 1
    item["last"] = now
    _strat_scores.move_to_end(host)
    while len(_strat_scores) > STRAT_SCORE_MAX_HOSTS:
        _strat_scores.popitem(last=False)


def _strategy_score_bucket():
    return {"hosts": 0, "ok": 0, "fail": 0, "last_seen": 0.0}


def _add_strategy_score(bucket, ok, fail, last):
    bucket["hosts"] += 1
    bucket["ok"] += int(ok or 0)
    bucket["fail"] += int(fail or 0)
    bucket["last_seen"] = max(float(bucket["last_seen"]), float(last or 0.0))


def strategy_score_snapshot():
    """Privacy-safe strategy telemetry.

    `_strat_scores` is keyed by host for routing decisions. Status must not
    expose those hostnames, so diagnostics only publish aggregate counts by
    service group and strategy name.
    """
    groups = {}
    strategies = {}
    for host, per_host in _strat_scores.items():
        policy = route_policy(host)
        group_name = policy["service_group"]
        group = groups.setdefault(group_name, {"hosts": 0, "strategies": {}})
        group["hosts"] += 1
        for name, item in per_host.items():
            if name not in STRAT_BY_NAME:
                continue
            ok = item.get("ok", 0)
            fail = item.get("fail", 0)
            last = item.get("last", 0.0)
            _add_strategy_score(
                group["strategies"].setdefault(name, _strategy_score_bucket()),
                ok,
                fail,
                last,
            )
            _add_strategy_score(
                strategies.setdefault(name, _strategy_score_bucket()),
                ok,
                fail,
                last,
            )
    return {
        "hosts": len(_strat_scores),
        "groups": groups,
        "strategies": strategies,
    }


def _strategy_rank(host, name, base_index, cached, now):
    item = _strat_scores.get(host, {}).get(name)
    if item:
        total = item.get("ok", 0) + item.get("fail", 0)
        score = _strategy_wilson_score(item.get("ok", 0), total)
        age = max(0.0, now - item.get("last", now))
        age_ratio = age / STRAT_SCORE_AGE_BONUS_AFTER
        score += min(STRAT_SCORE_AGE_BONUS_MAX, age_ratio * STRAT_SCORE_AGE_BONUS_MAX)
    else:
        score = 0.5
    if name == cached:
        score += STRAT_SCORE_CACHED_BONUS
    return (-score, base_index)


def _rank_strategy_names(host, names, now=None):
    host = normalize_host(host)
    cached = _strat_cache.get(host)
    now = time.time() if now is None else now
    base_indexes = {name: index for index, name in enumerate(names)}
    return sorted(
        names,
        key=lambda name: _strategy_rank(host, name, base_indexes[name], cached, now),
    )


DISCORD_STRATS = ["split64+fake", "split16+fake", "fake5"]   # fake-ONLY
# YouTube/googlevideo video edges are hard-blocked by SNI like Discord. The TLS probe
# can PASS on a non-fake split (record-splitting alone completes the handshake to the
# CDN), so the adaptive cache happily pins these hosts to "split64" — yet real video
# traffic still stalls (infinite load) because only the fake decoy hides the SNI from
# the TSPU. So force fake-ONLY here and ignore any stale non-fake cache winner. Matches
# Windows zapret "general (ALT)", which always fakes google/youtube instead of probing.
# Session edges rotate (rrN---sn-XXXX.googlevideo.com, *.c.youtube.com) so match by suffix.
GOOGLE_VIDEO_STRATS = ["split64+fake", "split16+fake", "fake5"]   # fake-ONLY
# Default order is FAKE-FIRST for every host: the TSPU throttles many services by
# SNI (Discord, Anthropic, Shopify stores, ...) even when the block is beaten, and
# the TLS probe can't see the throttle — so try fake first everywhere (the decoy
# hides the SNI from the throttler). Non-fake variants remain as fallbacks for the
# rare host the decoy upsets. Inject is cheap (not DoH); the pool absorbs it.
GENERAL_STRATS = ["split64+fake", "split16+fake", "fake5", "split64", "split16", "plain"]


def strategy_order(host):
    policy = route_policy(host)
    strategy_set = policy["strategy_set"]
    if strategy_set == STRATEGY_DIRECT:
        return [STRAT_BY_NAME["plain"]]
    h = normalize_host(host)
    if strategy_set == STRATEGY_DIRECT_FIRST:
        cached = _strat_cache.get(h)
        fallback_names = [name for name in GENERAL_STRATS if name != "plain"]
        if cached in fallback_names:
            fallback_names = [cached] + [
                name for name in fallback_names if name != cached
            ]
        return [STRAT_BY_NAME["plain"]] + [
            STRAT_BY_NAME[name] for name in fallback_names
        ]
    if strategy_set == STRATEGY_FAKE_ONLY:
        # Protected local-bypass routes never fall through to a non-fake TLS
        # strategy, regardless of any stale cached winner.
        names = (
            DISCORD_STRATS
            if policy["service_group"] == SERVICE_DISCORD
            else GOOGLE_VIDEO_STRATS
        )
        names = _rank_strategy_names(h, names)
        return [STRAT_BY_NAME[n] for n in names]
    win = _strat_cache.get(h)
    if win in STRAT_BY_NAME:
        names = [win] + [n for n in GENERAL_STRATS if n != win]
    else:
        names = GENERAL_STRATS
    return [STRAT_BY_NAME[n] for n in _rank_strategy_names(h, names)]


# --------------------------------------------------- fake ClientHello (decoy)
FAKE_DECOY_SNI = "vk.com"   # RU whitelisted host the TSPU never blocks


def build_fake_clienthello(sni: str) -> bytes:
    """Minimal but parseable TLS1.2 ClientHello carrying a decoy SNI. Sent at a
    low TTL so it dies before the server but the in-country DPI ingests it and
    whitelists the flow, letting the real (hard-blocked-SNI) ClientHello pass."""
    name = sni.encode()
    server_name = b"\x00" + struct.pack("!H", len(name)) + name      # host_name entry
    sni_list = struct.pack("!H", len(server_name)) + server_name
    sni_ext = b"\x00\x00" + struct.pack("!H", len(sni_list)) + sni_list
    ext_block = struct.pack("!H", len(sni_ext)) + sni_ext
    ciphers = b"\x00\x2f"
    cl_body = (b"\x03\x03" + os.urandom(32) + b"\x00"
               + struct.pack("!H", len(ciphers)) + ciphers
               + b"\x01\x00" + ext_block)
    hs = b"\x01" + struct.pack("!I", len(cl_body))[1:] + cl_body      # 3-byte length
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


_FAKE_CH = build_fake_clienthello(FAKE_DECOY_SNI)

# zapret-style "fake"/disorder POISON. Proven on this TSPU (2026-07-07): a fake
# TLS-record-shaped GARBAGE segment injected at the connection's REAL next-seq
# (isn+1) with a fooling that makes the SERVER drop it (ttl=4 dies in transit)
# poisons the DPI's TCP reassembly so it never reads the (hard-blocked)
# googlevideo SNI -> the real ClientHello passes and the handshake completes.
# Whitelist-by-decoy-SNI (real google/vk ClientHello) did NOT work here; only the
# GARBAGE poison at the CORRECT seq did (100% on manifest/rr/youtube/redirector;
# seq=1 or any wrong offset -> ignored by the DPI). This is why the old ttl/ts
# decoy with seq=1 never beat googlevideo.
_FAKE_POISON = b"\x16\x03\x01\x02\x00" + b"\x00" * 512
FAKE_TTL = 4

# (local_sport, remote_ip) -> {"isn":.., "sisn":..} filled by the network_monitor
# sniffer (outbound SYN + inbound SYN-ACK). inject_fake needs the real ISN to place
# the poison at isn+1 exactly — macOS has no getsockopt for a socket's TCP seq.
_syn_map = OrderedDict()
_syn_lock = threading.Lock()
SYN_MAP_MAX = 4096


def syn_record(sport, remote_ip, isn=None, sisn=None):
    with _syn_lock:
        k = (sport, remote_ip)
        ent = _syn_map.get(k) or {"isn": None, "sisn": None}
        if isn is not None:
            ent["isn"] = isn
        if sisn is not None:
            ent["sisn"] = sisn
        _syn_map[k] = ent
        _syn_map.move_to_end(k)
        while len(_syn_map) > SYN_MAP_MAX:
            _syn_map.popitem(last=False)


def syn_lookup(sport, remote_ip, wait=0.03):
    # SYN is on the wire before we inject (connection already opened), so this is
    # almost always a hit; the short retry only covers the sniffer-thread race.
    deadline = time.monotonic() + wait
    while True:
        with _syn_lock:
            ent = _syn_map.get((sport, remote_ip))
        if ent and ent.get("isn") is not None:
            return ent
        if time.monotonic() >= deadline:
            return ent
        time.sleep(0.005)


# Reuse ONE scapy L3 socket per thread instead of send()-per-packet. scapy's
# send() opens (and under load leaks) a socket each call, and the voice plane
# primes 6x per packet -> FD exhaustion ("Too many open files"). A thread-local
# socket is safe across the sniffer thread and the asyncio executor workers.
_l3_tls = threading.local()


def _l3send(pkt):
    from scapy.all import conf
    conf.verb = 0
    s = getattr(_l3_tls, "sock", None)
    if s is None:
        s = _l3_tls.sock = conf.L3socket()
    try:
        s.send(pkt)
    except OSError:
        # The cached raw socket goes stale after sleep/wake or an interface change
        # (each worker thread caches its own), so sends silently fail and desync
        # stops working. Reopen once and retry — self-heals without a daemon restart.
        try:
            s.close()
        except Exception:
            pass
        try:
            s = _l3_tls.sock = conf.L3socket()
            s.send(pkt)
        except OSError:
            _l3_tls.sock = None


def inject_fake_poison(src_ip, src_port, dst_ip, dst_port, ttl=FAKE_TTL, repeats=6):
    """Inject a fake GARBAGE TLS-record segment at the connection's REAL next-seq
    (isn+1, from the SYN-sniffed syn_map) with a low TTL so the SERVER drops it in
    transit but the in-country DPI ingests it and poisons its reassembly — the real
    (hard-blocked-SNI) ClientHello that follows then passes. Verified vs googlevideo
    on this TSPU. No-ops if the ISN isn't known yet (real CH still sent unpoisoned;
    better a miss than the old seq=1 dud). Needs scapy (bundled in the frozen)."""
    try:
        from scapy.all import IP, TCP, Raw
    except Exception:
        print("  fake-mode needs scapy: run with sudo .venv/bin/python tproxy.py",
              file=sys.stderr)
        return
    ent = syn_lookup(src_port, dst_ip)
    if not ent or ent.get("isn") is None:
        return                       # unknown seq -> skip (seq=1 is ignored by DPI)
    seq = (ent["isn"] + 1) & 0xffffffff
    ack = ((ent.get("sisn") or 0) + 1) & 0xffffffff
    pkt = (IP(src=src_ip, dst=dst_ip, ttl=ttl)
           / TCP(sport=src_port, dport=dst_port, flags="PA",
                 seq=seq, ack=ack, window=64240)
           / Raw(_FAKE_POISON))
    for _ in range(repeats):
        _l3send(pkt)


def inject_fake_decoy(src_ip, src_port, dst_ip, dst_port, ttl=FAKE_TTL, repeats=6):
    """Inject a low-TTL decoy ClientHello on the same tuple.

    This mirrors the zapret/Flowseal fake mode for Discord-family traffic: the DPI
    sees a harmless SNI first, while the server never receives the decoy because
    the TTL expires in transit.
    """
    try:
        from scapy.all import IP, TCP, Raw
    except Exception:
        print("  fake-mode needs scapy: run with sudo .venv/bin/python tproxy.py",
              file=sys.stderr)
        return
    pkt = (IP(src=src_ip, dst=dst_ip, ttl=ttl)
           / TCP(sport=src_port, dport=dst_port, flags="PA",
                 seq=1, ack=1, window=64240)
           / Raw(_FAKE_CH))
    for _ in range(repeats):
        _l3send(pkt)


def inject_fake_for_host(host, src_ip, src_port, dst_ip, dst_port):
    if is_discord_host(host):
        inject_fake_decoy(src_ip, src_port, dst_ip, dst_port)
        return
    inject_fake_poison(src_ip, src_port, dst_ip, dst_port)


def inject_fake(src_ip, src_port, dst_ip, dst_port, ttl=FAKE_TTL, repeats=6):
    inject_fake_poison(src_ip, src_port, dst_ip, dst_port, ttl=ttl, repeats=repeats)


# ------------------------------------------------------- UDP voice plane
VOICE_LO, VOICE_HI = 50000, 65535   # Discord voice server UDP port range
VOICE_SETUP_LO, VOICE_SETUP_HI = 19294, 19344
VOICE_PORT_RANGES = ((VOICE_SETUP_LO, VOICE_SETUP_HI), (VOICE_LO, VOICE_HI))
VOICE_TTL = 4
VOICE_REPEAT = 6
VOICE_CUTOFF = 5                    # prime the first N datagrams of each flow
VOICE_FLOWS_MAX = 8192             # bound the per-flow table (re-priming is harmless)
VOICE_FLOW_IDLE_TTL = 5 * 60.0


def _fake_stun(txn=b"\x00" * 12):
    return build_fake_stun(txn)


def prune_voice_flows(flows, now, max_flows=VOICE_FLOWS_MAX, idle_ttl=VOICE_FLOW_IDLE_TTL):
    """Drop idle voice flows first, then only the oldest overflow entries."""
    cutoff = now - idle_ttl
    for key, (_, last_seen) in list(flows.items()):
        if last_seen >= cutoff:
            break
        del flows[key]
    while len(flows) > max_flows:
        flows.popitem(last=False)


def observe_voice_flow(flows, key, now=None):
    now = time.time() if now is None else now
    prune_voice_flows(flows, now)
    count, _ = flows.get(key, (0, 0.0))
    should_prime = count < VOICE_CUTOFF
    flows[key] = (min(count + 1, VOICE_CUTOFF), now)
    flows.move_to_end(key)
    return should_prime, count


def _voice_port_filter():
    return " or ".join(
        f"dst portrange {lo}-{hi}" for lo, hi in VOICE_PORT_RANGES
    )


def _voice_port_ranges_label():
    return ", ".join(f"{lo}-{hi}" for lo, hi in VOICE_PORT_RANGES)


def should_prime_voice_payload(dst_port, payload):
    if VOICE_LO <= dst_port <= VOICE_HI:
        return True
    if VOICE_SETUP_LO <= dst_port <= VOICE_SETUP_HI:
        return classify_voice_payload(payload) != "other"
    return False


def default_iface():
    for line in _run("route", "get", "default").stdout.splitlines():
        line = line.strip()
        if line.startswith("interface:"):
            return line.split()[1]
    return None


def _voice_bpf(localip):
    return (f"udp and src host {localip} and ({_voice_port_filter()}) "
            "and not dst net 192.168.0.0/16 and not dst net 10.0.0.0/8 "
            "and not dst net 172.16.0.0/12 and not dst net 169.254.0.0/16 "
            "and not dst net 224.0.0.0/4 and not dst host 255.255.255.255")


def _syn_bpf(localip):
    # Capture outbound SYN (our ISN) + inbound SYN-ACK (server ISN) on :443 so
    # inject_fake can place the poison at the connection's real seq. SYN-flagged
    # only -> volume is bounded to handshakes, not every data packet.
    return f"tcp and host {localip} and port 443 and (tcp[13] & 2 != 0)"


def reduce_geph_probe_state(previous_up, strikes, probe_ok, port, conflict=False):
    """Apply hysteresis without inventing readiness on a cold start."""
    if probe_ok and port is not None:
        return True, 0
    next_strikes = 3 if conflict else strikes + 1
    keep_previous = bool(
        previous_up
        and port is not None
        and not conflict
        and next_strikes < 3
    )
    return keep_previous, next_strikes


def network_monitor(port, voice=True):
    """Long-running guard thread. (1) Keeps the voice sniffer bound to the CURRENT
    default interface so voice survives Wi-Fi/Ethernet/sleep changes. (2) Re-applies
    pf if it ever gets flushed (sleep/wake or another tool). Voice itself: Discord
    RTP is UDP to *.discord.media:50000-65535, with some setup paths observed on
    19294-19344, bypassing the TCP pf-rdr. We BPF-observe it and raw-inject
    low-TTL decoy STUN primes on the 5-tuple, leaving the real flow untouched."""
    global _pf_applied, _geph_up, _pf_interceptor_conflicts
    AsyncSniffer = send = IP = UDP = TCP = Raw = get_if_addr = None
    if voice:
        try:
            from scapy.all import (AsyncSniffer, send, IP, UDP, TCP, Raw,
                                   get_if_addr, conf)
            conf.verb = 0
        except Exception as e:
            print(f">> voice disabled (scapy: {e})", file=sys.stderr)
    fake = _fake_stun()
    flows = OrderedDict()
    sniffer = None
    cur_iface = None

    def on_pkt(p):
        # TCP SYN / SYN-ACK on :443 -> record the connection's ISNs for inject_fake.
        if TCP is not None and p.haslayer(TCP) and p.haslayer(IP):
            t = p[TCP]
            f = int(t.flags)
            if t.dport == 443 and (f & 0x02) and not (f & 0x10):
                syn_record(t.sport, p[IP].dst, isn=t.seq)          # outbound SYN
            elif t.sport == 443 and (f & 0x02) and (f & 0x10):
                syn_record(t.dport, p[IP].src, sisn=t.seq)         # inbound SYN-ACK
            return
        if not (p.haslayer(IP) and p.haslayer(UDP)):
            return
        ip, udp = p[IP], p[UDP]
        if not should_prime_voice_payload(udp.dport, bytes(udp.payload)):
            return
        key = (ip.src, udp.sport, ip.dst, udp.dport)
        should_prime, n = observe_voice_flow(flows, key)
        if not should_prime:
            return
        pkt = (IP(src=ip.src, dst=ip.dst, ttl=VOICE_TTL)
               / UDP(sport=udp.sport, dport=udp.dport) / Raw(fake))
        for _ in range(VOICE_REPEAT):
            _l3send(pkt)
        if VERBOSE and n == 0:
            print(f"  voice: priming {ip.dst}:{udp.dport}", file=sys.stderr)

    geph_strikes = 0
    last_tick = time.time()
    last_iface = None
    first_tick = True
    last_conflict_check = time.time()
    while not _shutdown_started.is_set():
        now = time.time()
        handled_rearms = set()
        if now - last_tick > RUNTIME_WAKE_GAP_SECONDS:
            # macOS slept: our 5s cadence jumped, so the scapy sniffer/send socket
            # and possibly pf are stale. Force a sniffer rebuild (cur_iface=None);
            # _l3send self-heals, and the pf/geph checks below re-arm the rest.
            gap = now - last_tick
            print(f">> woke from sleep (gap {gap:.0f}s) -> re-arming",
                  file=sys.stderr)
            cur_iface = None
            _apply_runtime_rearm(
                "wake", now=now, gap=gap, iface=last_iface or "")
            handled_rearms.add("wake")
        last_tick = now
        iface = default_iface()
        if iface != last_iface:
            if last_iface is not None:
                _apply_runtime_rearm(
                    "network_change", now=now, iface=iface or "")
                handled_rearms.add("network_change")
            last_iface = iface
        for reason in _drain_runtime_rearms():
            if reason in handled_rearms:
                continue
            print(
                f">> lifecycle qualification requested ({reason}) -> re-arming",
                file=sys.stderr,
            )
            cur_iface = None
            _apply_runtime_rearm(
                reason, now=now, iface=iface or last_iface or "")
        if _shutdown_started.is_set():
            break
        restart_state = execute_owned_geph_restart(now=now)
        if restart_state == "restarted":
            _geph_up = False
            geph_strikes = 0
            _finish_geph_restart_drain()
        # Hysteresis: a few missed probes (Geph busy under load, or briefly
        # re-establishing its tunnel) must not flap the route-health state.
        # Only geo-exit selection changes; local routing remains available.
        probe_ok = probe_geph()
        if _shutdown_started.is_set():
            break
        was_geph = _geph_up
        _geph_up, geph_strikes = reduce_geph_probe_state(
            previous_up=was_geph,
            strikes=geph_strikes,
            probe_ok=probe_ok,
            port=_geph_port,
            conflict=_geph_port_conflict,
        )
        if _geph_up != was_geph:
            print(f">> geph SOCKS {'up' if _geph_up else 'down'} "
                  f"(:{_geph_port if _geph_up else GEPH_PORTS}) — geo-exit hosts "
                  f"{'tunnelled' if _geph_up else 'using system-route fallback'}",
                  file=sys.stderr)
            if not first_tick:
                start_canaries_if_due("geph_up" if _geph_up else "geph_down", force=True)
        # Coexist with the user's own VPN: when a full-tunnel VPN owns the default
        # route (utun*) it already bypasses DPI, so drop our pf rules to avoid any
        # conflict; re-arm automatically when the VPN drops.
        vpn = bool(iface) and iface.startswith("utun")
        if now - last_conflict_check >= PF_CONFLICT_CHECK_INTERVAL:
            conflicts = pf_preceding_https_interceptors()
            last_conflict_check = now
        else:
            conflicts = list(_pf_interceptor_conflicts)
        if _shutdown_started.is_set():
            break
        if conflicts != _pf_interceptor_conflicts:
            if conflicts:
                print(
                    ">> another transparent HTTPS filter became active before "
                    f"Slipstream ({', '.join(conflicts)}) -> pausing",
                    file=sys.stderr,
                )
            elif _pf_interceptor_conflicts:
                print(">> transparent HTTPS filter conflict cleared -> re-arming")
            _pf_interceptor_conflicts = conflicts
        refresh_fd_pressure()
        backend_ready = transparent_routing_ready()
        if vpn:
            if _pf_applied:
                print(f">> VPN up (default via {iface}) -> Slipstream dormant",
                      file=sys.stderr)
                pause_private_pf()
        elif conflicts:
            if _pf_applied:
                pause_private_pf()
        elif not backend_ready:
            if baseline_guard_snapshot(now)["state"] == "rollback_failed":
                if retry_baseline_rollback():
                    print(
                        ">> private PF rollback completed; system connection restored",
                        file=sys.stderr,
                    )
            elif _pf_applied:
                print(
                    ">> local routing capacity unavailable -> Slipstream dormant",
                    file=sys.stderr,
                )
                pause_private_pf()
        else:
            if not _pf_applied:
                print(">> local routing ready -> Slipstream active", file=sys.stderr)
                if arm_private_pf_if_ready(port):
                    start_canaries_if_due("pf_reapply", force=True)
                elif not pf_parent_anchor_loaded():
                    print(
                        f">> pf parent anchor {PF_PARENT_ANCHOR} unavailable; "
                        "leaving external rules untouched",
                        file=sys.stderr,
                    )
                else:
                    print(">> routing backend changed before PF could be armed", file=sys.stderr)
            elif _pf_loopback_skip_state() is not False:
                parent_loaded = pf_parent_anchor_loaded()
                print(
                    ">> PF loopback visibility changed — pausing",
                    file=sys.stderr,
                )
                paused = pause_private_pf()
                if parent_loaded and paused:
                    print(">> PF loopback cleanup complete — re-applying", file=sys.stderr)
                    if arm_private_pf_if_ready(port):
                        start_canaries_if_due("pf_reapply", force=True)
                elif not parent_loaded:
                    print(
                        f">> pf parent anchor {PF_PARENT_ANCHOR} vanished; "
                        "leaving external rules untouched",
                        file=sys.stderr,
                    )
            elif not pf_has_rules(port):
                parent_loaded = pf_parent_anchor_loaded()
                print(">> Slipstream pf anchor vanished — pausing", file=sys.stderr)
                paused = pause_private_pf()
                if parent_loaded and paused:
                    print(">> private PF cleanup complete — re-applying", file=sys.stderr)
                    if arm_private_pf_if_ready(port):
                        start_canaries_if_due("pf_reapply", force=True)
                elif not parent_loaded:
                    print(
                        f">> pf parent anchor {PF_PARENT_ANCHOR} vanished; "
                        "leaving external rules untouched",
                        file=sys.stderr,
                    )
        if send is not None:                       # scapy available
            if iface and iface != cur_iface:
                if sniffer is not None:
                    try:
                        sniffer.stop()
                    except Exception:
                        pass
                    sniffer = None
                try:
                    localip = get_if_addr(iface)
                    bpf = f"({_voice_bpf(localip)}) or ({_syn_bpf(localip)})"
                    sniffer = AsyncSniffer(iface=iface, filter=bpf,
                                           prn=on_pkt, store=0)
                    sniffer.start()
                    cur_iface = iface
                    print(f">> voice plane: priming UDP {_voice_port_ranges_label()} "
                          f"+ SYN-seq capture on {iface}")
                except Exception as e:
                    print(f">> voice sniffer unavailable on {iface}: {e}", file=sys.stderr)
                    cur_iface = None
        runtime_state = (
            "conflict" if conflicts
            else "dormant" if vpn or not backend_ready or not _pf_applied
            else "active"
        )
        write_status(runtime_state, iface, cur_iface)
        if first_tick:
            if runtime_state == "active":
                start_canaries_if_due("startup", force=True)
            start_route_policy_remote_update_if_due("startup")
            first_tick = False
        else:
            if runtime_state == "active":
                start_canaries_if_due("periodic")
            start_route_policy_remote_update_if_due("periodic")
        if _shutdown_started.wait(5):
            break


# ------------------------------------------------------------- DoH (blocking)
def _doh_ssl_context():
    return ssl.create_default_context()


def _doh_request(host, doh_sni):
    query = urlencode({"name": host, "type": "A"})
    return (f"GET /dns-query?{query} HTTP/1.1\r\n"
            f"Host: {doh_sni}\r\naccept: application/dns-json\r\n"
            f"connection: close\r\n\r\n").encode("ascii")


def _doh_query(doh_ip, doh_sni, host, timeout=3):
    ctx = _doh_ssl_context()
    inbio, outbio = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inbio, outbio, server_hostname=doh_sni)
    s = socket.create_connection((doh_ip, 443), timeout=timeout)
    s.settimeout(timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sent = [False]
    try:
        while True:                                   # handshake (tlsrec first flight)
            try:
                obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                out = outbio.read()
                if out:
                    if not sent[0]:
                        s.sendall(make_blob(out[:5], out[5:], doh_sni, FIRST_REC_CAP)
                                  if out[:1] == b"\x16" else out)
                        sent[0] = True
                    else:
                        s.sendall(out)
                data = s.recv(65536)
                if not data:
                    raise IOError("eof in handshake")
                inbio.write(data)
        req = _doh_request(host, doh_sni)
        obj.write(req)
        while True:
            out = outbio.read()
            if not out:
                break
            s.sendall(out)
        buf = b""
        while True:
            try:
                data = s.recv(65536)
            except socket.timeout:
                break
            if data:
                inbio.write(data)
            while True:
                try:
                    dec = obj.read(65536)
                except ssl.SSLWantReadError:
                    break
                except ssl.SSLError:
                    dec = b""
                if not dec:
                    break
                buf += dec
            if not data:
                break
        s.close()
        j = buf.find(b"{")
        doc = json.loads(buf[j:buf.rfind(b"}") + 1])
        ips = [a["data"] for a in doc.get("Answer", []) if a.get("type") == 1]
        if ips:
            return ips
    except Exception:
        try:
            s.close()
        except Exception:
            pass
    return None


DOH_TTL = 300.0          # re-resolve every 5 min — Cloudflare rotates IPs, a
                         # forever-cache silently breaks over hours (the sneaky one)
DOH_TTL_NEG = 30.0       # short negative cache so failures don't hammer the resolver
DOH_CACHE_MAX = 1024
_doh_lock = threading.Lock()


def doh_resolve(host):
    """Return a LIST of real A-record IPs (try several — some specific Cloudflare
    IPs are IP-blocked while others aren't). TTL'd + bounded so stale rotated IPs
    don't silently break it, and the cache can't grow without limit."""
    now = time.monotonic()
    with _doh_lock:
        ent = _doh_cache.get(host)
        if ent and ent[1] > now:
            _doh_cache.move_to_end(host)
            return ent[0]
    ips = []
    for ip, sni in DOH:
        r = _doh_query(ip, sni, host)
        if r:
            ips = r
            break
    with _doh_lock:
        _doh_cache[host] = (ips, now + (DOH_TTL if ips else DOH_TTL_NEG))
        _doh_cache.move_to_end(host)
        while len(_doh_cache) > DOH_CACHE_MAX:
            _doh_cache.popitem(last=False)
    return ips


async def doh_resolve_async(host):
    """Resolve on the dedicated pool, collapsing concurrent first-time lookups
    for the same host into a single query (no await between get+set -> race-free
    on the single-threaded loop)."""
    fut = _doh_inflight.get(host)
    if fut is not None:
        return await fut
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    _doh_inflight[host] = fut
    try:
        ips = await loop.run_in_executor(_POOL, doh_resolve, host)
    except Exception:
        ips = []
    finally:
        _doh_inflight.pop(host, None)
        if not fut.done():
            fut.set_result(ips)
    return ips


async def xbox_dns_resolve_async(host):
    """Resolve one fallback host through app-owned Xbox DNS without system DNS."""
    host = normalize_host(host)
    if not host:
        return []
    fut = _xbox_dns_inflight.get(host)
    if fut is not None:
        return await fut
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    _xbox_dns_inflight[host] = fut
    try:
        ips = await loop.run_in_executor(_POOL, xbox_dns_resolve, host)
    except Exception:
        ips = []
    finally:
        _xbox_dns_inflight.pop(host, None)
        if not fut.done():
            fut.set_result(ips)
    return ips


def system_resolve(host, port=443):
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return []
    ips = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    return ips


async def system_resolve_async(host):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_POOL, system_resolve, host)


def _dedupe_ips(ips):
    out = []
    for ip in ips:
        if ip and ip not in out:
            out.append(ip)
    return out


async def resolve_connection_ips(host, fallback_ip):
    if not host:
        return [fallback_ip] if fallback_ip else []
    ips = []
    doh_ips = await doh_resolve_async(host)
    ips.extend(doh_ips)
    # Local-bypass/CDN domains often have one dead edge and several working ones.
    # When DoH is empty or this is a zapret-scoped host, include system DNS too
    # so the strategy ladder can roll to a different edge without using Geph.
    if not doh_ips or is_local_bypass_host(host):
        ips.extend(await system_resolve_async(host))
    ips.append(fallback_ip)
    return _dedupe_ips(ips)


def ip_attempt_limit(host):
    policy = route_policy(host)
    limits = route_policy_manifest().get("attempt_limits", {})
    return limits.get(
        policy["route_class"],
        limits.get("default", DEFAULT_IP_ATTEMPT_LIMIT),
    )


# ------------------------------------------------------------- relay
@dataclass
class _RelayActivity:
    last_downstream_at: float
    client_end_at: float = 0.0
    server_end_at: float = 0.0
    client_eof: bool = False
    client_half_closed: bool = False
    client_read_failed: bool = False
    downstream_write_failed: bool = False
    client_ended_first: bool = False
    server_ended_first: bool = False
    first_downstream_seen: bool = False
    on_first_downstream: object = None


def _local_stream_stalled(activity, now=None):
    """Return true when a client gives up after a real downstream silence.

    TLS is opaque here, so byte count alone cannot prove that an HTTP response
    completed. A quiet keep-alive connection can be closed normally by the
    client, so only an abnormal client read error or a failed downstream write
    after a long lack of server progress can trigger recovery.
    """
    now = time.monotonic() if now is None else now
    if not activity.client_end_at:
        return False
    return (
        (activity.client_read_failed or activity.downstream_write_failed)
        and now - activity.last_downstream_at >= LOCAL_STREAM_IDLE
    )


def _clean_eof_stream_stalled(activity, now=None):
    """Return true for a client-first orderly EOF after downstream silence.

    A single orderly EOF can be an ordinary keep-alive close, so callers must
    require a repeated exact-host signal before changing the next retry.  The
    The relay records which direction completed first. A server-first EOF is a
    normal completion signal and must not be learned as a stall; cancellation
    of the still-pending direction must not look like an upstream EOF.
    """
    now = time.monotonic() if now is None else now
    if not (
        activity.client_eof
        and activity.client_end_at
        and activity.client_ended_first
    ):
        return False
    if (
        activity.server_ended_first
        or activity.client_read_failed
        or activity.downstream_write_failed
    ):
        return False
    return now - activity.last_downstream_at >= LOCAL_STREAM_IDLE


def _prune_clean_eof_stalls(now):
    cutoff = now - CLEAN_EOF_STALL_WINDOW
    for stale, events in list(_clean_eof_stalls.items()):
        while events and events[0] <= cutoff:
            events.popleft()
        if not events:
            _clean_eof_stalls.pop(stale, None)
    while len(_clean_eof_stalls) > CLEAN_EOF_STALL_STATE_MAX:
        _clean_eof_stalls.pop(next(iter(_clean_eof_stalls)))


def _clear_clean_eof_stalls(host):
    _clean_eof_stalls.pop(normalize_host(host), None)


def _repeated_clean_eof_stream_stall(host, activity, now=None):
    """Record a clean stall and return true only after the bounded threshold."""
    h = normalize_host(host)
    now = time.monotonic() if now is None else now
    if (
        not h
        or route_policy(h)["route_class"] != ROUTE_UNKNOWN
        or not _clean_eof_stream_stalled(activity, now)
    ):
        return False
    _prune_clean_eof_stalls(now)
    events = _clean_eof_stalls.setdefault(h, deque())
    events.append(now)
    _prune_clean_eof_stalls(now)
    if len(events) < CLEAN_EOF_STALL_STORM:
        return False
    _clear_clean_eof_stalls(h)
    return True


def note_clean_eof_stream_stall(
    host,
    strategy_name,
    activity,
    *,
    via_xbox_dns=False,
    now=None,
):
    """Handle repeated client-first clean EOF stalls without a route escape.

    This is deliberately narrower than an abnormal transport failure: it needs
    two exact-host observations in a bounded window and can only select the
    app-owned Xbox DNS/plain-TLS retry for a generic unknown host.  An Xbox
    retry needs the same repeated signal before it is cleared, so one ordinary
    keep-alive EOF cannot discard a recovery that may have worked.  This never
    learns a Geph route.
    """
    h = normalize_host(host)
    if (
        not h
        or strategy_name not in STRAT_BY_NAME
    ):
        return False
    if not _repeated_clean_eof_stream_stall(h, activity, now):
        return False
    if via_xbox_dns:
        _record_strategy_result(h, strategy_name, False)
        if _strat_cache.get(h) == strategy_name:
            _strat_cache.pop(h, None)
        _clear_xbox_dns_candidate(h)
        return True
    return note_local_stream_stall(h, strategy_name)


def _mark_xbox_dns_candidate(host, now=None):
    h = normalize_host(host)
    if not h or route_policy(h)["route_class"] != ROUTE_UNKNOWN:
        return False
    now = time.monotonic() if now is None else now
    _xbox_dns_candidates[h] = now + XBOX_DNS_CANDIDATE_TTL
    _prune_xbox_dns_state(_xbox_dns_candidates, now)
    return True


def _note_xbox_dns_attempt(host, now=None):
    h = normalize_host(host)
    if not h or route_policy(h)["route_class"] != ROUTE_UNKNOWN:
        return False
    now = time.monotonic() if now is None else now
    _xbox_dns_attempts[h] = now + XBOX_DNS_ATTEMPT_TTL
    _prune_xbox_dns_state(_xbox_dns_attempts, now)
    return True


def _prune_xbox_dns_state(state, now):
    for stale, expiry in list(state.items()):
        if expiry <= now:
            state.pop(stale, None)
    while len(state) > XBOX_DNS_STATE_MAX:
        state.pop(next(iter(state)))


def _xbox_dns_attempted_recently(host, now=None):
    h = normalize_host(host)
    now = time.monotonic() if now is None else now
    expiry = _xbox_dns_attempts.get(h, 0.0)
    if expiry > now:
        return True
    _xbox_dns_attempts.pop(h, None)
    return False


def _xbox_dns_candidate_active(host, now=None):
    h = normalize_host(host)
    now = time.monotonic() if now is None else now
    expiry = _xbox_dns_candidates.get(h, 0.0)
    if expiry > now:
        return True
    _xbox_dns_candidates.pop(h, None)
    return False


def _clear_xbox_dns_candidate(host):
    _xbox_dns_candidates.pop(normalize_host(host), None)


def note_local_stream_stall(host, strategy_name):
    """Demote only the exact generic strategy after a partial stream stall.

    A partial TLS response is not proof that a service needs a foreign exit.
    On the next connection, use an app-owned Xbox DNS lookup before the normal
    local ladder. Protected local groups stay entirely outside this recovery
    path, and no host is learned for Geph here.
    """
    h = normalize_host(host)
    if not h or route_policy(h)["route_class"] != ROUTE_UNKNOWN:
        return False
    if strategy_name not in STRAT_BY_NAME:
        return False
    _record_strategy_result(h, strategy_name, False)
    if _strat_cache.get(h) == strategy_name:
        _strat_cache.pop(h, None)
    _mark_xbox_dns_candidate(h)
    return True


async def _close_stream_writer(writer):
    try:
        writer.close()
    except Exception:
        return
    wait_closed = getattr(writer, "wait_closed", None)
    if not callable(wait_closed):
        return
    try:
        await asyncio.wait_for(wait_closed(), timeout=1.0)
    except (asyncio.TimeoutError, ConnectionError, OSError, RuntimeError, TypeError):
        pass


async def _half_close_stream_writer(writer):
    """Propagate an orderly read EOF without discarding the peer response."""
    can_write_eof = getattr(writer, "can_write_eof", None)
    write_eof = getattr(writer, "write_eof", None)
    if not callable(can_write_eof) or not callable(write_eof):
        return False
    try:
        if not can_write_eof():
            return False
        write_eof()
        drain = getattr(writer, "drain", None)
        if callable(drain):
            await drain()
        return True
    except (ConnectionError, NotImplementedError, OSError, RuntimeError, TypeError):
        return False


async def splice(src, dst, activity=None):
    total = 0
    try:
        while True:
            try:
                data = await src.read(65536)
            except (ConnectionResetError, BrokenPipeError, OSError):
                break
            if not data:
                break
            total += len(data)
            try:
                dst.write(data)
                await dst.drain()
            except (ConnectionResetError, BrokenPipeError, OSError):
                if activity is not None:
                    activity.downstream_write_failed = True
                break
            if activity is not None:
                activity.last_downstream_at = time.monotonic()
                if not activity.first_downstream_seen:
                    activity.first_downstream_seen = True
                    if activity.on_first_downstream is not None:
                        activity.on_first_downstream()
    finally:
        if activity is not None:
            activity.server_end_at = time.monotonic()
        await _close_stream_writer(dst)
    return total


async def pump(reader, up_w, activity=None):
    total = 0
    half_closed = False
    try:
        while True:
            try:
                data = await reader.read(65536)
            except (ConnectionResetError, BrokenPipeError, OSError):
                if activity is not None:
                    activity.client_read_failed = True
                break
            if not data:
                if activity is not None:
                    activity.client_eof = True
                half_closed = await _half_close_stream_writer(up_w)
                if activity is not None:
                    activity.client_half_closed = half_closed
                break
            total += len(data)
            try:
                up_w.write(data)
                await up_w.drain()
            except (ConnectionResetError, BrokenPipeError, OSError):
                break
    finally:
        if activity is not None:
            activity.client_end_at = time.monotonic()
        if not half_closed:
            await _close_stream_writer(up_w)
    return total


async def relay_local_stream(reader, up_w, up_r, writer, activity=None):
    """Relay both directions with bounded support for an orderly half-close.

    A client EOF is propagated upstream when the transport supports TCP
    half-close, preserving delayed responses for request-then-EOF protocols.
    The server direction then gets one downstream-idle interval to finish.
    Unsupported half-close, transport errors, and server-first completion keep
    the bounded cancellation behavior so no pair of FDs remains indefinitely.
    """
    relay_activity = activity or _RelayActivity(last_downstream_at=time.monotonic())
    client_task = asyncio.create_task(pump(reader, up_w, relay_activity))
    server_task = asyncio.create_task(splice(up_r, writer, relay_activity))
    tasks = (client_task, server_task)
    try:
        done, pending = await asyncio.wait(
            tasks,
            return_when=asyncio.FIRST_COMPLETED,
        )
        relay_activity.client_ended_first = (
            client_task in done and server_task not in done
        )
        relay_activity.server_ended_first = (
            server_task in done and client_task not in done
        )
        if relay_activity.client_ended_first and relay_activity.client_half_closed:
            while not server_task.done():
                last_progress_at = max(
                    relay_activity.client_end_at,
                    relay_activity.last_downstream_at,
                )
                idle_left = (
                    last_progress_at
                    + LOCAL_STREAM_IDLE
                    - time.monotonic()
                )
                if idle_left <= 0:
                    server_task.cancel()
                    break
                try:
                    await asyncio.wait_for(
                        asyncio.shield(server_task),
                        timeout=idle_left,
                    )
                except asyncio.TimeoutError:
                    continue
            pending = {task for task in tasks if not task.done()}
        for task in pending:
            task.cancel()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        totals = []
        for result in results:
            if isinstance(result, BaseException):
                if not isinstance(result, asyncio.CancelledError):
                    raise result
                totals.append(0)
            else:
                totals.append(result)
        return tuple(totals)
    except BaseException:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
    finally:
        if relay_activity.client_half_closed:
            await _close_stream_writer(up_w)


# Control-RPC port paired with each SOCKS port. The external mapping is used only
# when SLIP_GEPH_PORT explicitly opts into the user's separately-running Geph.
GEPH_CONTROL = {9954: 9955, 9909: 12222}


def _console_user_home():
    try:
        uid = os.stat("/dev/console").st_uid
        if uid == 0:
            return None
        return pwd.getpwuid(uid).pw_dir
    except (OSError, KeyError):
        return None


def geph_ownership_path(home=None):
    home = _console_user_home() if home is None else home
    return geph_backend.ownership_path(home, GEPH_OWNERSHIP_FILE)


def _read_geph_ownership(path=None):
    path = geph_ownership_path() if path is None else path
    return geph_backend.read_ownership(path)


def _geph_listener_pid(port):
    return geph_backend.listener_pid(_run, port)


def _geph_process_command(pid):
    return geph_backend.process_command(_run, pid)


def _geph_state_matches(state, listener_pid, command):
    return geph_backend.state_matches(state, listener_pid, command)


def geph_listener_owned(port=GEPH_OWNED_PORT, state=None, listener_pid=None, command=None):
    state = _read_geph_ownership() if state is None else state
    return geph_backend.listener_owned(
        _run,
        port,
        state,
        listener_process_id=listener_pid,
        command=command,
    )


def _tcp_listener_present(port, timeout=0.25):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=timeout).close()
        return True
    except OSError:
        return False


def probe_geph():
    """Is a geph tunnel actually carrying sessions right now? (monitor, every 5s).
    Liveness comes from the control RPC (conn_info reports ESTABLISHED sessions
    without opening a new stream), NOT a fresh SOCKS5-CONNECT — that stream probe
    intermittently failed under normal tunnel load, mis-reporting geph "down",
    which fired fail-closed and dropped live app connections (the Claude/Codex
    reconnects). geph's own process was stable throughout; only our probe flapped."""
    global _geph_port, _geph_owned, _geph_port_conflict, _external_geph_detected
    if not GEPH_ENABLED:
        _geph_port = None
        _geph_owned = False
        _geph_port_conflict = False
        _external_geph_detected = False
        return False
    _external_geph_detected = _tcp_listener_present(GEPH_EXTERNAL_PORT)
    _geph_port_conflict = False
    # Sticky re-check is retained only for an explicit port override. The default
    # path has one owned port and can never drift to the user's external Geph.
    order = GEPH_PORTS
    if _geph_port in GEPH_PORTS and _geph_port != GEPH_PORTS[0]:
        order = [_geph_port] + [p for p in GEPH_PORTS if p != _geph_port]
    for p in order:
        owned = p == GEPH_OWNED_PORT and geph_listener_owned(p)
        if _env_geph_port is None and not owned:
            if _tcp_listener_present(p):
                _geph_port_conflict = True
                _geph_port = None
            _geph_owned = False
            continue
        if _geph_live(p):
            _geph_port = p
            _geph_owned = owned
            return True
    _geph_owned = False
    if _geph_port_conflict:
        _geph_port = None
    return False    # transient miss -> keep last good _geph_port; hysteresis decides


def _geph_conn_info_sessions(control_port, timeout=3):
    """Active-session count from geph's control RPC conn_info, or None if the
    control listener is unreachable."""
    try:
        s = socket.create_connection(("127.0.0.1", control_port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(b'{"jsonrpc":"2.0","id":1,"method":"conn_info","params":[]}\n')
        buf = b""
        while b"\n" not in buf:
            d = s.recv(65536)
            if not d:
                break
            buf += d
        s.close()
        return len(json.loads(buf.decode()).get("result", {}).get("sessions", []))
    except Exception:
        return None


def _geph_live(socks_port, timeout=3):
    """Liveness for a geph SOCKS port via conn_info — no stream opened, so no
    false-down under load. If conn_info doesn't answer in time we do NOT fall back
    to the SOCKS-CONNECT probe: that fresh-stream open false-fails under load and
    was the whole reason for moving off it (it caused the residual flap). Instead,
    if the control port still accepts a TCP connection geph is alive and merely
    busy -> up; only a refused control port is a real "down"."""
    ctl = GEPH_CONTROL.get(socks_port)
    if ctl is None:
        return _geph_socks_works(socks_port, timeout)  # env port override, no control mapping
    n = _geph_conn_info_sessions(ctl, timeout)
    if n is not None:
        return n > 0
    try:
        socket.create_connection(("127.0.0.1", ctl), timeout=1).close()
        return True   # control bound + reachable, conn_info just slow -> alive
    except OSError:
        return False  # control refused -> geph really down


def _geph_socks_works(port, timeout=2.5):
    """Fallback liveness (used only when the control RPC is unreachable):
    SOCKS5-CONNECT to 1.1.1.1:443 through this geph, proving it reaches an exit."""
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00")
        if s.recv(2)[:2] != b"\x05\x00":
            s.close()
            return False
        s.sendall(b"\x05\x01\x00\x01\x01\x01\x01\x01\x01\xbb")   # CONNECT 1.1.1.1:443
        rep = s.recv(4)
        s.close()
        return len(rep) >= 2 and rep[1] == 0                     # REP==0 == reached exit
    except Exception:
        return False


async def dial_via_geph(host, port, first_flight):
    """Open a SOCKS5 CONNECT to host:port through geph's local listener and send
    the buffered first flight PLAIN (the tunnel handles censorship — no desync).
    CONNECT-by-domain lets geph resolve + exit abroad, sidestepping RU DNS poison
    and the geo-block entirely. Returns (reader, writer) to geph or None on any
    failure (caller then falls back to local desync)."""
    port_socks = _geph_port
    if not port_socks:
        return None
    try:
        gr, gw = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port_socks), timeout=3)
    except Exception:
        return None
    connected = False
    try:
        gw.write(b"\x05\x01\x00")                      # VER5, 1 method, no-auth
        await gw.drain()
        greet = await asyncio.wait_for(gr.readexactly(2), 3)
        if greet[0] != 0x05 or greet[1] != 0x00:
            raise IOError("socks5 no-auth refused")
        hb = host.encode("ascii", "ignore")[:255]
        gw.write(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack("!H", port))
        await gw.drain()
        rep = await asyncio.wait_for(gr.readexactly(4), 8)   # VER REP RSV ATYP
        if rep[1] != 0x00:
            raise IOError(f"socks5 connect rep={rep[1]}")
        atyp = rep[3]
        if atyp == 0x01:
            await gr.readexactly(4)
        elif atyp == 0x03:
            ln = await gr.readexactly(1)
            await gr.readexactly(ln[0])
        elif atyp == 0x04:
            await gr.readexactly(16)
        await gr.readexactly(2)                        # bound port
        gw.write(first_flight)                         # original ClientHello, plain
        await gw.drain()
        connected = True
        return gr, gw
    except asyncio.CancelledError:
        raise
    except Exception:
        return None
    finally:
        if not connected:
            await _close_stream_writer(gw)


async def dial_plain(ip, port, first_flight):
    """Open an exact direct stream with no DNS rewrite, desync, or tunnel.

    The buffered first flight is sent verbatim. This is used for transparent
    system-route preservation as well as Telegram MTProto safety passthrough.
    Returns ``(reader, writer)`` or ``None``.
    """
    w = None
    connected = False
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=6)
        w.write(first_flight)
        await w.drain()
        connected = True
        return r, w
    except asyncio.CancelledError:
        raise
    except Exception as error:
        if VERBOSE:
            print(
                f"  exact system dial {ip}:{port} failed: "
                f"{type(error).__name__}: {str(error)[:160]}",
                file=sys.stderr,
            )
        return None
    finally:
        if w is not None and not connected:
            await _close_stream_writer(w)


async def dial_and_probe(real_ip, port, first_blob, probe_timeout=2.5):
    """Connect, send the (split) first flight, wait for the first server bytes.
    Returns (up_r, up_w, server_first) or None if no response in time."""
    try:
        up_r, up_w = await asyncio.wait_for(
            asyncio.open_connection(real_ip, port, family=socket.AF_INET), timeout=5)
    except Exception:
        return None
    connected = False
    try:
        up_w.write(first_blob)
        await up_w.drain()
        data = await asyncio.wait_for(up_r.read(65536), probe_timeout)
        if data:
            connected = True
            return up_r, up_w, data
    except (asyncio.TimeoutError, OSError):
        pass
    finally:
        if not connected:
            await _close_stream_writer(up_w)
    return None


async def dial_and_probe_fake(real_ip, port, first_blob, host=None, probe_timeout=3.0):
    """Like dial_and_probe but injects a low-TTL decoy ClientHello on the real
    4-tuple BEFORE the real flight (zapret 'fake' — for deep-reassembly SNIs)."""
    connected = False
    try:
        up_r, up_w = await asyncio.wait_for(
            asyncio.open_connection(real_ip, port, family=socket.AF_INET), timeout=5)
    except Exception:
        return None
    try:
        s = up_w.get_extra_info("socket")
        src_ip, src_port = s.getsockname()
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            _POOL, inject_fake_for_host, host, src_ip, src_port, real_ip, port
        )
        up_w.write(first_blob)
        await up_w.drain()
        data = await asyncio.wait_for(up_r.read(65536), probe_timeout)
        if data:
            connected = True
            return up_r, up_w, data
    except (asyncio.TimeoutError, OSError):
        pass
    finally:
        if not connected:
            await _close_stream_writer(up_w)
    return None


async def dial_strategy(ip, port, head, body, host, strat):
    blob = make_blob(head, body, host, strat["cap"])
    if strat["fake"]:
        return await dial_and_probe_fake(ip, port, blob, host=host)
    return await dial_and_probe(ip, port, blob)


async def _race_probe_addresses(
    host,
    port,
    addresses,
    dial_candidate,
    *,
    policy,
    backend,
):
    """Race complete first-payload probes within one preselected route."""
    candidates = tuple(addresses)
    if not candidates:
        return None, 0
    raced = await connection_probe.race_probe_dials(
        host or candidates[0],
        port,
        candidates,
        dial_candidate,
        service_group=policy.get("service_group") or SERVICE_GENERIC,
        route_class=policy.get("route_class") or ROUTE_UNKNOWN,
        backend_id=backend,
        timeout_ms=ADDRESS_RACE_TIMEOUT_MS,
        stagger_ms=ADDRESS_RACE_STAGGER_MS,
        max_concurrent=ADDRESS_RACE_MAX_CONCURRENT,
    )
    attempted = raced.attempted_count
    if raced.connection is None:
        return None, attempted
    return (
        raced.address,
        (
            raced.connection.reader,
            raced.connection.writer,
            raced.server_first,
        ),
    ), attempted


async def _try_xbox_dns_local_connect(host, port, head, body):
    """Try the app-owned Xbox DNS answer locally, never through Geph."""
    if route_policy(host)["route_class"] != ROUTE_UNKNOWN:
        return None
    _note_xbox_dns_attempt(host)
    ips = await xbox_dns_resolve_async(host)
    plain = STRAT_BY_NAME["plain"]
    raced, _attempted = await _race_probe_addresses(
        host,
        port,
        ips[:DEFAULT_IP_ATTEMPT_LIMIT],
        lambda ip: dial_strategy(ip, port, head, body, host, plain),
        policy=route_policy(host),
        backend=BACKEND_LOCAL_ENGINE,
    )
    return raced


async def _try_exact_system_passthrough(
    host,
    dst_ip,
    port,
    first_flight,
    reader,
    writer,
    *,
    track_unknown=False,
):
    """Relay the PF-selected destination without changing route semantics.

    This is the transparent baseline for direct, unknown, and no-SNI traffic:
    no alternate DNS lookup, no desync strategy, and no first-payload gate.
    Unknown-host recovery is learned only after this stream has finished; the
    already-sent first flight is never replayed through another route.
    """
    direct = await dial_plain(dst_ip, port, first_flight)
    if not direct:
        return False
    up_r, up_w = direct
    started_at = time.monotonic()
    activity = _RelayActivity(last_downstream_at=started_at)
    result = await relay_local_stream(reader, up_w, up_r, writer, activity)
    duration = time.monotonic() - started_at
    if track_unknown and host:
        if _local_stream_stalled(activity, now=started_at + duration):
            note_local_stream_stall(host, "plain")
        elif _clean_eof_stream_stalled(activity, now=started_at + duration):
            note_clean_eof_stream_stall(
                host,
                "plain",
                activity,
                now=started_at + duration,
            )
        elif activity.server_ended_first:
            _clear_clean_eof_stalls(host)
            if not activity.first_downstream_seen and not (result[1] or 0):
                note_local_stream_stall(host, "plain")
    return True


async def _try_system_geo_connect(host, dst_ip, port, first_flight, reader, writer):
    """Keep the system-selected route usable when no app-owned exit is ready.

    ``dst_ip`` is the destination selected before PF redirected the socket, so
    this preserves the user's DNS, VPN, and routing decisions. It relays as
    soon as the exact destination accepts the connection; long-lived streams
    must not be gated on a server-first payload.
    """
    direct = await dial_plain(dst_ip, port, first_flight)
    if direct is None:
        return False
    up_r, up_w = direct
    policy = route_policy(host)
    payload_recorded = False

    def record_first_payload():
        nonlocal payload_recorded
        if payload_recorded:
            return
        route_health_event(
            policy["service_group"],
            ROUTE_GEO_EXIT,
            host,
            True,
            backend=BACKEND_DIRECT,
        )
        payload_recorded = True

    if VERBOSE:
        print(f"OK {host}:{port} via system route {dst_ip}", file=sys.stderr)
    activity = _RelayActivity(
        last_downstream_at=time.monotonic(),
        on_first_downstream=record_first_payload,
    )
    result = await relay_local_stream(reader, up_w, up_r, writer, activity)
    if not payload_recorded and not (result[1] or 0):
        route_health_event(
            policy["service_group"],
            ROUTE_GEO_EXIT,
            host,
            False,
            "system route closed before payload",
            backend=BACKEND_DIRECT,
        )
    return True


async def handle(reader, writer):
    global _conn_count
    task = asyncio.current_task()
    if task is not None:
        _connection_tasks.add(task)
    _conn_count += 1
    try:
        await _handle_impl(reader, writer)
    finally:
        await _close_stream_writer(writer)
        _conn_count -= 1
        if task is not None:
            _connection_tasks.discard(task)


async def _handle_impl(reader, writer):
    sock = writer.get_extra_info("socket")
    try:
        dst_ip, dst_port = orig_dst(sock)
    except OSError as e:
        if VERBOSE:
            print(f"  DIOCNATLOOK failed: {e}", file=sys.stderr)
        writer.close()
        return
    if VERBOSE:
        print(f"  accepted PF stream -> {dst_ip}:{dst_port}", file=sys.stderr)
    if dst_port == PROXY_PORT and dst_ip.startswith("127."):
        if VERBOSE:
            print("  rejected recursive PF destination", file=sys.stderr)
        writer.close()
        return

    # read the client's first flight to learn the SNI BEFORE dialing upstream
    host = None
    is_tls = False
    head = body = b""
    try:
        head = await asyncio.wait_for(reader.readexactly(5), timeout=15)
        if head[0] == 0x16:
            is_tls = True
            body = await reader.readexactly(struct.unpack("!H", head[3:5])[0])
            host = parse_sni(body)
        else:
            body = await reader.read(65536)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
        writer.close()
        return

    # Telegram MTProto to its DC IPs: no SNI, nothing like TLS — our desync
    # corrupts the handshake. Pass DIRECT (untouched) so we never make Telegram
    # worse than baseline. The DPI-bypass for Telegram is the bundled tg-ws-proxy
    # (local MTProto proxy on :1443); once Telegram points at it, these direct DC
    # connections stop happening at all.
    if _ip_in_nets(dst_ip, TELEGRAM_NETS):
        up = await dial_plain(dst_ip, dst_port, head + body)
        if up is None:
            note_telegram_direct_failure("connect failed")
            writer.close()
            return
        ur, uw = up
        t0 = time.monotonic()
        res = await relay_local_stream(reader, uw, ur, writer)
        down_b = res[1] or 0
        dur = time.monotonic() - t0
        if down_b > 0:
            note_telegram_direct_success()
        elif dur < 20:
            note_telegram_direct_failure("empty direct response")
        return

    # Split-tunnel: a reviewed geo-exit service can use a proven Smart DNS path
    # or the verified owned Geph tunnel. Both are optional. If neither is ready,
    # preserve the destination chosen by the user's own DNS/VPN/system route;
    # never move the host into the local desync ladder and never disarm the
    # independent Discord/YouTube path.
    if is_tls and is_geo_exit_route(host):
        policy = route_policy(host)
        geph_owned = bool(_geph_owned)
        if smart_dns_route_enabled(host) and runtime_route_circuit_allows(
            policy,
            GEO_BACKEND_SMART_DNS,
        ):
            smart = await _try_smart_dns_geo_connect(host, dst_port, head + body)
            if smart:
                runtime_route_circuit_record_result(
                    policy,
                    GEO_BACKEND_SMART_DNS,
                    True,
                )
                smart_ip, smart_result = smart
                up_r, up_w, server_first = smart_result
                route_health_event(
                    policy["service_group"],
                    ROUTE_GEO_EXIT,
                    host,
                    True,
                    backend=GEO_BACKEND_SMART_DNS,
                )
                if VERBOSE:
                    print(f"OK {host}:{dst_port} via smart DNS {smart_ip}", file=sys.stderr)
                try:
                    writer.write(server_first)
                    await writer.drain()
                except OSError:
                    await _close_stream_writer(up_w)
                    writer.close()
                    return
                await relay_local_stream(reader, up_w, up_r, writer)
                return
            runtime_route_circuit_record_result(
                policy,
                GEO_BACKEND_SMART_DNS,
                False,
            )
            _smart_dns_mark_failure(
                host,
                "smart dns runtime probe failed",
                policy["service_group"],
            )
        geph_expected = bool(GEPH_ENABLED and (_geph_up or _geph_port or _geph_owned))
        geph_now = time.time()
        geph_cooling = geph_now < _geph_backend_hold_until
        geph_ready = geo_exit_backend_ready(now=geph_now)
        geph_failure = "tunnel down"
        geph_suspend = "geo-exit tunnel down"
        if geph_ready and _geph_session_started():
            try:
                if runtime_route_circuit_allows(
                    policy,
                    GEO_BACKEND_GEPH,
                    owned=geph_owned,
                ):
                    g = await dial_via_geph(host, dst_port, head + body)
                    if g:
                        gr, gw = g
                        if VERBOSE:
                            print(f"OK {host}:{dst_port} via geph tunnel", file=sys.stderr)
                        t0 = time.monotonic()
                        geph_result_recorded = False

                        def record_first_geph_payload():
                            nonlocal geph_result_recorded
                            if geph_result_recorded:
                                return
                            runtime_route_circuit_record_result(
                                policy,
                                GEO_BACKEND_GEPH,
                                True,
                                owned=geph_owned,
                            )
                            clear_geph_route_failure()
                            geph_result_recorded = True

                        activity = _RelayActivity(
                            last_downstream_at=t0,
                            on_first_downstream=record_first_geph_payload,
                        )
                        res = await relay_local_stream(
                            reader,
                            gw,
                            gr,
                            writer,
                            activity,
                        )
                        down_b = res[1] or 0
                        if down_b == 0 and time.monotonic() - t0 < 10:
                            runtime_route_circuit_record_result(
                                policy,
                                GEO_BACKEND_GEPH,
                                False,
                                owned=geph_owned,
                            )
                            log_geph_route_failure(host, "remote closed without response")
                            # The current client stream cannot be replayed after a
                            # zero-byte close. Cool down only Geph; the next client
                            # retry can use the preserved system route.
                            suspend_geo_exit_backend(
                                "geo-exit remote close before payload"
                            )
                        elif not geph_result_recorded:
                            runtime_route_circuit_record_result(
                                policy,
                                GEO_BACKEND_GEPH,
                                True,
                                owned=geph_owned,
                            )
                            clear_geph_route_failure()
                        return
                    runtime_route_circuit_record_result(
                        policy,
                        GEO_BACKEND_GEPH,
                        False,
                        owned=geph_owned,
                    )
                    geph_failure = "SOCKS connect failed"
                    geph_suspend = "geo-exit SOCKS connect unavailable"
                else:
                    geph_failure = "backend cooling down"
                    geph_suspend = "geo-exit backend cooling down"
            finally:
                _geph_session_finished()
        elif geph_expected and not geph_cooling and runtime_route_circuit_allows(
            policy,
            GEO_BACKEND_GEPH,
            owned=geph_owned,
        ):
            runtime_route_circuit_record_result(
                policy,
                GEO_BACKEND_GEPH,
                False,
                owned=geph_owned,
            )

        if geph_expected and not geph_cooling:
            suspend_geo_exit_backend(geph_suspend)
        if await _try_system_geo_connect(
            host,
            dst_ip,
            dst_port,
            head + body,
            reader,
            writer,
        ):
            return
        if geph_expected:
            log_geph_route_failure(host, geph_failure)
        else:
            route_health_event(
                policy["service_group"],
                ROUTE_GEO_EXIT,
                host,
                False,
                "system route unavailable; Geph not configured",
                backend=BACKEND_DIRECT,
            )
        if VERBOSE:
            print(
                f"  no usable route for geo-host {host}; "
                "local Discord/YouTube routing remains active",
                file=sys.stderr,
            )
        writer.close()
        return

    policy = route_policy(host)
    route_class = policy["route_class"]
    unknown_recovery_ready = bool(
        is_tls
        and host
        and route_class == ROUTE_UNKNOWN
        and _xbox_dns_candidate_active(host)
    )
    preserve_system_route = (
        not is_tls
        or route_class == ROUTE_DIRECT
        or (route_class == ROUTE_UNKNOWN and not unknown_recovery_ready)
    )
    if preserve_system_route:
        if await _try_exact_system_passthrough(
            host,
            dst_ip,
            dst_port,
            head + body,
            reader,
            writer,
            track_unknown=bool(is_tls and host and route_class == ROUTE_UNKNOWN),
        ):
            return
        if is_tls and host and route_class == ROUTE_UNKNOWN:
            _mark_xbox_dns_candidate(host)
        writer.close()
        return

    # de-poison: resolve the SNI over DoH/system DNS -> LIST of real IPs
    # (fallback dst_ip). Some CDN edges are bad while neighbors work.
    if not runtime_route_circuit_allows(policy, BACKEND_LOCAL_ENGINE):
        if VERBOSE:
            print(
                f"  {host or dst_ip} local backend cooling down",
                file=sys.stderr,
            )
        writer.close()
        return
    real_ips = await resolve_connection_ips(host, dst_ip)
    ip_limit = ip_attempt_limit(host)

    # Adaptive strategy ladder (auto-sweep / self-tuning). Try strategies in
    # order — cached winner for this host first — across up to a couple of real
    # IPs (some Cloudflare IPs are IP-blocked while others work). First success
    # is cached per host so a decayed strategy auto-rolls to the next that works.
    result = None
    chosen = real_ips[0]
    chosen_name = None
    via_xbox_dns = False
    if is_tls and host and _xbox_dns_candidate_active(host):
        xbox = await _try_xbox_dns_local_connect(host, dst_port, head, body)
        if xbox:
            chosen, result = xbox
            chosen_name = "plain"
            via_xbox_dns = True
            _record_strategy_result(host, chosen_name, True)
        else:
            _clear_xbox_dns_candidate(host)

    if result is None and not is_tls:
        raced, _attempted = await _race_probe_addresses(
            host,
            dst_port,
            real_ips[:ip_limit],
            lambda ip: dial_and_probe(ip, dst_port, head + body),
            policy=policy,
            backend=BACKEND_LOCAL_ENGINE,
        )
        if raced:
            chosen, result = raced
    elif result is None:
        now = time.monotonic()
        # known-dead host -> 1 fast-fail attempt instead of the full 7-attempt ladder
        max_attempts = 1 if (host and _dead.get(host, 0) > now) else 7
        attempts = 0
        for strat in strategy_order(host):
            strat_ok = False
            remaining = max_attempts - attempts
            candidates = real_ips[:min(ip_limit, remaining)]
            raced, attempted = await _race_probe_addresses(
                host,
                dst_port,
                candidates,
                lambda ip: dial_strategy(
                    ip,
                    dst_port,
                    head,
                    body,
                    host,
                    strat,
                ),
                policy=policy,
                backend=BACKEND_LOCAL_ENGINE,
            )
            attempts += max(1, attempted) if candidates else 0
            if raced:
                chosen, result = raced
                chosen_name = strat["name"]
                strat_ok = True
                _record_strategy_result(host, strat["name"], True)
            if not strat_ok:
                _record_strategy_result(host, strat["name"], False)
            if result or attempts >= max_attempts:
                break
        if result:
            if host:
                _dead.pop(host, None)
                if _strat_cache.get(host) != chosen_name:
                    remember_strategy(host, chosen_name)
        elif host:
            _dead[host] = now + DEAD_TTL        # arm the negative cache
            if len(_dead) > 4096:
                _dead.clear()

    # A full local ladder miss can still recover this intercepted connection
    # through Xbox DNS, using its answer locally with plain TLS. This never
    # opens Geph and does not modify macOS DNS.
    if (
        result is None
        and is_tls
        and host
        and policy["route_class"] == ROUTE_UNKNOWN
    ):
        xbox = await _try_xbox_dns_local_connect(host, dst_port, head, body)
        if xbox:
            chosen, result = xbox
            chosen_name = "plain"
            via_xbox_dns = True
            _mark_xbox_dns_candidate(host)
            _record_strategy_result(host, chosen_name, True)
            _dead.pop(host, None)
            if _strat_cache.get(host) != chosen_name:
                remember_strategy(host, chosen_name)

    if not result:
        runtime_route_circuit_record_result(
            policy,
            BACKEND_LOCAL_ENGINE,
            False,
        )
        if policy["route_class"] == ROUTE_LOCAL_BYPASS:
            note_local_bypass_runtime_result(
                host,
                False,
                "runtime strategy probe failed",
            )
        if VERBOSE:
            print(f"  {host or dst_ip} NO RESPONSE ({len(real_ips)} ips)",
                  file=sys.stderr)
        writer.close()
        return

    runtime_route_circuit_record_result(
        policy,
        BACKEND_LOCAL_ENGINE,
        True,
    )
    if policy["route_class"] == ROUTE_LOCAL_BYPASS:
        note_local_bypass_runtime_result(host, True)

    up_r, up_w, server_first = result
    if VERBOSE:
        tag = f" [{chosen_name}]" if chosen_name else ""
        tag += " de-poisoned" if host and chosen != dst_ip else ""
        print(f"OK {host or dst_ip}:{dst_port} via {chosen}{tag}", file=sys.stderr)

    try:
        writer.write(server_first)
        await writer.drain()
    except OSError:
        await _close_stream_writer(up_w)
        writer.close()
        return
    t0 = time.monotonic()
    activity = _RelayActivity(last_downstream_at=t0)
    res = await relay_local_stream(reader, up_w, up_r, writer, activity)
    duration = time.monotonic() - t0
    # A partial local stream stall demotes only the exact generic strategy. It
    # teaches the next client retry to use app-owned Xbox DNS locally; protected
    # local groups never enter this path and no host is learned for Geph here.
    if is_tls and host:
        if _local_stream_stalled(activity, now=t0 + duration):
            if via_xbox_dns:
                _record_strategy_result(host, chosen_name, False)
                if _strat_cache.get(host) == chosen_name:
                    _strat_cache.pop(host, None)
                _clear_xbox_dns_candidate(host)
            else:
                note_local_stream_stall(host, chosen_name)
        elif _clean_eof_stream_stalled(activity, now=t0 + duration):
            note_clean_eof_stream_stall(
                host,
                chosen_name,
                activity,
                via_xbox_dns=via_xbox_dns,
                now=t0 + duration,
            )
        elif activity.server_ended_first:
            _clear_clean_eof_stalls(host)
        note_local_result(
            host,
            len(server_first) + (res[1] or 0),
            duration,
        )
    if VERBOSE and is_discord_host(host):
        up_b, down_b = res[0] or 0, len(server_first) + (res[1] or 0)
        print(f"  closed {host}: up={up_b} down={down_b} "
              f"dur={duration:.1f}s", file=sys.stderr)


LAUNCHD_LABEL = "dev.slipstream.tproxy"
LAUNCHD_PLIST = f"/Library/LaunchDaemons/{LAUNCHD_LABEL}.plist"
LOG_PATH = "/var/log/slipstream.log"
OBSOLETE_NEWSYSLOG_CONFIG_PATH = f"/etc/newsyslog.d/{LAUNCHD_LABEL}.conf"
INSTALL_DIR = "/usr/local/slipstream"   # NOT under ~/Documents (TCC-protected)
LOG_MAX_BYTES = 1024 * 1024
LOG_BACKUPS = 5


def _harden_log_fd(fd, path):
    mode = os.fstat(fd).st_mode
    if not stat.S_ISREG(mode):
        raise OSError(f"refusing non-regular log path: {path}")
    os.fchmod(fd, 0o600)
    try:
        os.fchown(fd, 0, 0)
    except (AttributeError, PermissionError, OSError):
        # Source-mode development and unit tests may run without root. The
        # installed LaunchDaemon runs as root and normalizes ownership too.
        pass


def _open_private_log(path):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags, 0o600)
    try:
        _harden_log_fd(fd, path)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _harden_existing_log(path):
    if not os.path.lexists(path):
        return False
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        # The running daemon may rotate an archive between lexists() and open()
        # during reinstall. A vanished archive is already safely absent.
        return False
    try:
        _harden_log_fd(fd, path)
    finally:
        os.close(fd)
    return True


def ensure_private_log_files(path=LOG_PATH, backups=LOG_BACKUPS):
    """Create or migrate the raw daemon log and retained archives."""
    fd = _open_private_log(path)
    os.close(fd)
    for index in range(1, backups + 1):
        _harden_existing_log(f"{path}.{index}")


class RotatingLogWriter:
    def __init__(
        self,
        path,
        max_bytes=LOG_MAX_BYTES,
        backups=LOG_BACKUPS,
        redirect_fds=False,
        timestamp=False,
        clock=None,
    ):
        self.path = path
        self.max_bytes = max_bytes
        self.backups = backups
        self.redirect_fds = redirect_fds
        self.timestamp = timestamp
        self.clock = clock or time.time
        self._line_start = True
        self._lock = threading.RLock()
        self._file = None
        for index in range(1, self.backups + 1):
            _harden_existing_log(self._archive_path(index))
        self._open()
        if os.fstat(self._file.fileno()).st_size >= self.max_bytes:
            self._rotate()

    def _open(self):
        fd = _open_private_log(self.path)
        self._file = os.fdopen(fd, "a", buffering=1)
        if self.redirect_fds:
            os.dup2(self._file.fileno(), 1)
            os.dup2(self._file.fileno(), 2)

    def _archive_path(self, index):
        return f"{self.path}.{index}"

    def _rotate(self):
        if self._file:
            self._file.flush()
            self._file.close()
        oldest = self._archive_path(self.backups)
        if os.path.exists(oldest):
            os.remove(oldest)
        for index in range(self.backups - 1, 0, -1):
            src = self._archive_path(index)
            if os.path.exists(src):
                os.replace(src, self._archive_path(index + 1))
        if os.path.exists(self.path):
            os.replace(self.path, self._archive_path(1))
        self._open()

    def _timestamp(self):
        return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(self.clock()))

    def _format(self, data):
        if not self.timestamp:
            return data
        out = []
        for part in data.splitlines(keepends=True):
            if self._line_start:
                out.append(self._timestamp())
                out.append(" ")
            out.append(part)
            self._line_start = part.endswith("\n")
        return "".join(out)

    def write(self, data):
        if not data:
            return 0
        with self._lock:
            data = self._format(data)
            size = os.path.getsize(self.path) if os.path.exists(self.path) else 0
            incoming = len(data.encode("utf-8", errors="replace"))
            if size and size + incoming > self.max_bytes:
                self._rotate()
            written = self._file.write(data)
            self._file.flush()
            return written

    def flush(self):
        with self._lock:
            self._file.flush()

    def isatty(self):
        return False


def setup_rotating_logs():
    writer = RotatingLogWriter(LOG_PATH, redirect_fds=True, timestamp=True)
    sys.stdout = writer
    sys.stderr = writer
    return writer


def remove_obsolete_newsyslog_config():
    try:
        os.remove(OBSOLETE_NEWSYSLOG_CONFIG_PATH)
    except FileNotFoundError:
        pass
    except Exception:
        pass


def launchd_plist_text(prog_args, workdir):
    prog_xml = "".join(f"<string>{a}</string>" for a in prog_args)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0"><dict>\n'
        f'  <key>Label</key><string>{LAUNCHD_LABEL}</string>\n'
        f'  <key>ProgramArguments</key><array>{prog_xml}</array>\n'
        '  <key>RunAtLoad</key><true/>\n'
        '  <key>KeepAlive</key><true/>\n'
        '  <key>EnvironmentVariables</key><dict>'
        '<key>PATH</key><string>/sbin:/usr/sbin:/bin:/usr/bin</string>'
        '<key>PYTHONUNBUFFERED</key><string>1</string></dict>\n'
        '  <key>SoftResourceLimits</key><dict>'
        '<key>NumberOfFiles</key><integer>16384</integer></dict>\n'
        '  <key>HardResourceLimits</key><dict>'
        '<key>NumberOfFiles</key><integer>16384</integer></dict>\n'
        f'  <key>WorkingDirectory</key><string>{workdir}</string>\n'
        '  <key>StandardOutPath</key><string>/dev/null</string>\n'
        '  <key>StandardErrorPath</key><string>/dev/null</string>\n'
        '</dict></plist>\n'
    )


def _launchd_target():
    return f"system/{LAUNCHD_LABEL}"


def _launchd_job_absent(result):
    if result.returncode == 0:
        return False
    detail = f"{result.stdout or ''}\n{result.stderr or ''}".lower()
    return "could not find service" in detail


def _command_failure(action, result):
    detail = (result.stderr or result.stdout or "command returned an error").strip()
    raise RuntimeError(f"{action}: {detail[:400]}")


def _require_command(action, *args):
    result = _run(*args)
    if result.returncode != 0:
        _command_failure(action, result)
    return result


def _daemon_status_record():
    try:
        with open(STATUS_PATH) as handle:
            status = json.load(handle)
    except Exception:
        return None
    if not isinstance(status, dict):
        return None
    if status.get("schema_version") == STATUS_SCHEMA_VERSION:
        status = status.get("daemon")
    return status if isinstance(status, dict) else None


def _daemon_recovery_record():
    try:
        with open(STATUS_PATH) as handle:
            status = json.load(handle)
    except Exception:
        return None
    if not isinstance(status, dict) or status.get("schema_version") != STATUS_SCHEMA_VERSION:
        return None
    recovery = status.get("recovery")
    return recovery if isinstance(recovery, dict) else None


def _process_command_for_pid(pid):
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return None
    result = _run("/bin/ps", "-ww", "-p", str(pid), "-o", "command=")
    if result.returncode != 0:
        return None
    command = result.stdout.strip()
    return command or None


def _installed_daemon_command_owned(command):
    if not command:
        return False
    try:
        parts = shlex.split(command)
    except ValueError:
        return False
    if not parts:
        return False
    install_dir = os.path.realpath(INSTALL_DIR)
    executable = os.path.realpath(parts[0])
    frozen = os.path.join(install_dir, os.path.basename(sys.executable))
    if executable == frozen:
        return True
    script = os.path.join(install_dir, "tproxy.py")
    python = os.path.realpath(
        os.path.join(install_dir, "venv", "bin", "python3")
    )
    python_app = os.path.realpath(os.path.join(
        os.path.dirname(os.path.dirname(python)),
        "Resources", "Python.app", "Contents", "MacOS", "Python",
    ))
    return executable in {python, python_app} and any(
        os.path.realpath(arg) == script for arg in parts[1:3]
    )


def _listener_pids(port):
    result = _run(
        "/usr/sbin/lsof",
        "-nP",
        "-a",
        f"-iTCP:{port}",
        "-sTCP:LISTEN",
        "-t",
    )
    if result.returncode not in {0, 1}:
        return []
    return sorted({
        int(line)
        for line in result.stdout.splitlines()
        if line.strip().isdigit() and int(line) > 0
    })


def _owned_listener_pids(port):
    return [
        pid for pid in _listener_pids(port)
        if _installed_daemon_command_owned(_process_command_for_pid(pid))
    ]


def _stop_owned_daemon_pid(pid, timeout=SHUTDOWN_DRAIN_SECONDS + 2.0):
    command = _process_command_for_pid(pid)
    if not _installed_daemon_command_owned(command):
        return False
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _process_command_for_pid(pid) is None:
            return True
        time.sleep(0.1)
    # Never force-stop the only listener while our private anchor may still
    # redirect HTTPS to it. The supervising root process can clear the same
    # owned anchor, then give the daemon one last chance to finish naturally.
    if not _flush_private_pf_with_retry(attempts=10, delay=0.2):
        return False
    if not _restore_pf_loopback_skip():
        return False
    grace_deadline = time.monotonic() + 1.0
    while time.monotonic() < grace_deadline:
        if _process_command_for_pid(pid) is None:
            return True
        time.sleep(0.1)
    # Revalidate immediately before SIGKILL so a recycled PID is never touched.
    if _installed_daemon_command_owned(_process_command_for_pid(pid)):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            return False
    return _process_command_for_pid(pid) is None


def _wait_for_listener_state(port, present, timeout=8.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _tcp_listener_present(port) == present:
            return True
        time.sleep(0.1)
    return _tcp_listener_present(port) == present


def _installed_daemon_readiness(port):
    status = _daemon_status_record()
    if not status:
        return False, "status missing"
    updated_at = status.get("updated_at", status.get("ts", 0))
    if not isinstance(updated_at, (int, float)) or time.time() - updated_at > 15:
        return False, "status stale"
    if status.get("state") not in {"active", "dormant"}:
        return False, f"unexpected state {status.get('state')!r}"
    recovery = _daemon_recovery_record() or {}
    if recovery.get("reason") == BASELINE_GUARD_BLOCK_REASON:
        return False, "daemon rolled back after baseline HTTPS qualification failed"
    if recovery.get("reason") == BASELINE_GUARD_ROLLBACK_REASON:
        return False, "daemon is still restoring the system HTTPS path"
    if recovery.get("reason") == PF_LOOPBACK_UNAVAILABLE_REASON:
        return False, "daemon could not qualify the PF loopback path"
    pid = status.get("pid")
    if not _installed_daemon_command_owned(_process_command_for_pid(pid)):
        return False, "status pid is not the installed daemon"
    listener_pids = _listener_pids(port)
    if listener_pids != [pid]:
        return False, (
            f"listener 127.0.0.1:{port} is not owned exclusively by "
            "the status pid"
        )
    rules_loaded = bool(pf_state_snapshot(port).get("rules_loaded"))
    if rules_loaded != (status.get("state") == "active"):
        return False, "PF state does not match daemon state"
    return True, "ready"


def _installed_daemon_ready(port):
    return _installed_daemon_readiness(port)[0]


def _wait_for_installed_daemon(port, timeout=30.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, reason = _installed_daemon_readiness(port)
        if ready:
            return True
        if "baseline HTTPS qualification failed" in reason:
            return False
        time.sleep(0.25)
    return _installed_daemon_ready(port)


def _write_launchd_plist_atomic(text):
    tmp = f"{LAUNCHD_PLIST}.tmp.{os.getpid()}"
    try:
        with open(tmp, "w") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, LAUNCHD_PLIST)
    finally:
        try:
            os.remove(tmp)
        except FileNotFoundError:
            pass


def _remove_install_runtime_artifacts():
    shutil.rmtree(INSTALL_DIR, ignore_errors=True)
    for path in (_STRAT_PATH, STATUS_PATH, TGWS_LINK_PATH):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _cleanup_install_incomplete(reason):
    print(f"cleanup incomplete: {reason}", file=sys.stderr)
    return False


def _remove_daemon_status_artifacts():
    for path in (STATUS_PATH + ".tmp", STATUS_PATH):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        except OSError:
            return False
    return True


def _disable_and_cleanup_install(port=PROXY_PORT, remove_runtime=True):
    status = _daemon_status_record() or {}
    pid = status.get("pid")
    disable_result = _run("/bin/launchctl", "disable", _launchd_target())
    if disable_result.returncode != 0:
        return _cleanup_install_incomplete("launchd label could not be disabled")
    if not _flush_private_pf_with_retry(attempts=10, delay=0.2):
        # Keep the already-running listener and its runtime in place. Removing
        # either while our anchor still redirects HTTPS would be less safe than
        # returning an explicit incomplete rollback.
        return _cleanup_install_incomplete("private PF anchor could not be cleared")
    if not _restore_pf_loopback_skip():
        return _cleanup_install_incomplete("PF loopback skip could not be restored")

    # KeepAlive must be quiesced before signalling the process. Stopping the
    # daemon first leaves a window where launchd can replace it while cleanup is
    # still inspecting the old PID, which presents as a process that keeps
    # coming back and can leave the listener behind.
    owned_pids = set(_owned_listener_pids(port))
    if (
        isinstance(pid, int)
        and not isinstance(pid, bool)
        and _installed_daemon_command_owned(_process_command_for_pid(pid))
    ):
        owned_pids.add(pid)
    bootout_result = _run("/bin/launchctl", "bootout", "system", LAUNCHD_PLIST)
    if bootout_result.returncode != 0:
        retry = _run("/bin/launchctl", "bootout", "system", LAUNCHD_PLIST)
        if retry.returncode != 0:
            loaded = _run("/bin/launchctl", "print", _launchd_target())
            if not _launchd_job_absent(loaded):
                # The loaded KeepAlive job may have re-armed after the first
                # cleanup. Restore the network boundary again, but do not
                # signal its process until launchd is proven quiescent.
                _flush_private_pf_with_retry(attempts=10, delay=0.2)
                _restore_pf_loopback_skip()
                reason = (
                    "launchd job remains loaded"
                    if loaded.returncode == 0
                    else "launchd job absence could not be verified"
                )
                return _cleanup_install_incomplete(reason)
    owned_pids.update(_owned_listener_pids(port))
    process_results = []
    for owned_pid in sorted(owned_pids):
        command = _process_command_for_pid(owned_pid)
        if command is None:
            continue
        if not _installed_daemon_command_owned(command):
            continue
        process_results.append(_stop_owned_daemon_pid(owned_pid))
    processes_clean = all(process_results)
    # The first cleanup happens while the listener is still available. Repeat it
    # after launchd and every verified survivor are quiescent so a final monitor
    # tick cannot leave a re-armed anchor behind during uninstall.
    if not _flush_private_pf_with_retry(attempts=10, delay=0.2):
        return _cleanup_install_incomplete("private PF anchor reappeared during shutdown")
    if not _restore_pf_loopback_skip():
        return _cleanup_install_incomplete("PF loopback skip reappeared during shutdown")
    if not processes_clean:
        return _cleanup_install_incomplete("owned daemon process did not stop")
    pf_release_result = _pf_release_enable_token()
    if pf_release_result is not None and pf_release_result.returncode != 0:
        return _cleanup_install_incomplete("owned PF enable token was not released")
    if not _remove_daemon_status_artifacts():
        return _cleanup_install_incomplete("daemon status could not be removed")
    listener_clean = _wait_for_listener_state(port, False, timeout=3.0)
    if not listener_clean:
        return _cleanup_install_incomplete("listener remains on TCP/1080")
    if not remove_runtime:
        return True
    try:
        os.remove(LAUNCHD_PLIST)
    except FileNotFoundError:
        pass
    except OSError:
        return _cleanup_install_incomplete("LaunchDaemon plist could not be removed")
    remove_obsolete_newsyslog_config()
    _remove_install_runtime_artifacts()
    runtime_clean = not any(os.path.lexists(path) for path in (
        INSTALL_DIR,
        LAUNCHD_PLIST,
        _STRAT_PATH,
        STATUS_PATH,
        TGWS_LINK_PATH,
        PF_SKIP_LEASE_PATH,
    ))
    clean = all((
        disable_result.returncode == 0,
        processes_clean,
        runtime_clean,
    ))
    if not clean:
        return _cleanup_install_incomplete("installed runtime artifacts remain")
    return True


def do_install(port):
    # Install a self-contained copy under /usr/local (a root LaunchDaemon has NO
    # TCC access to ~/Documents). Two modes:
    #  - frozen (PyInstaller onedir): copy the self-contained bundle, run the binary
    #  - script (dev): copy local runtime modules + build a venv with dependencies
    frozen = getattr(sys, "frozen", False)
    try:
        if not frozen:
            # Validate before stopping a working installed daemon.
            _script_runtime_payload(__file__)
        elif not os.path.isfile(sys.executable) or not os.access(sys.executable, os.X_OK):
            raise RuntimeError("frozen daemon payload is not executable")
    except Exception as error:
        print(f"install preflight failed: {error}", file=sys.stderr)
        return False
    # The daemon owns log creation; launchd is pointed at /dev/null below so it
    # can never recreate a deleted log with a process-default mode. Pre-create
    # and migrate here so install/reinstall also fixes retained archives.
    mutated = False
    try:
        ensure_private_log_files()
        secret_path = os.path.join(INSTALL_DIR, "tgws-secret")
        try:
            with open(secret_path) as handle:
                tgws_secret_backup = handle.read()
        except Exception:
            tgws_secret_backup = None
        mutated = True
        if not _disable_and_cleanup_install(port, remove_runtime=False):
            raise RuntimeError("existing daemon could not be quiesced safely")
        if frozen:
            src = os.path.dirname(os.path.abspath(sys.executable))
            _replace_tree_resilient(src, INSTALL_DIR)
            binary = os.path.join(INSTALL_DIR, os.path.basename(sys.executable))
            prog_args = [binary, "--port", str(port)]
            uninstall_hint = f"sudo {binary} --uninstall"
        else:
            script = os.path.join(INSTALL_DIR, "tproxy.py")
            _copy_script_runtime(__file__, INSTALL_DIR)
        # Copy the vendored tg-ws-proxy module next to it so start_tgws_proxy finds
        # it (otherwise Telegram falls back to plain MTProto passthrough).
            _here = os.path.dirname(os.path.abspath(__file__))
            _src_proxy = os.path.join(_here, "..", "vendor", "tg-ws-proxy", "proxy")
            if os.path.isdir(_src_proxy):
                _replace_tree_resilient(_src_proxy, os.path.join(INSTALL_DIR, "proxy"))
            venv = os.path.join(INSTALL_DIR, "venv")
            py = os.path.join(venv, "bin", "python3")
            if not os.path.exists(py):
                base = getattr(sys, "_base_executable", None) or sys.executable
                print(">> building self-contained venv (needs network, ~20s)...")
                _require_command("venv create failed", base, "-m", "venv", venv)
            # cryptography is REQUIRED too: the vendored tg-ws-proxy's _aes.py falls
            # back to a ctypes libcrypto shim without it, which macOS aborts ("loading
            # libcrypto in an unsafe way") -> the daemon crash-loops. certifi gives
            # the GitHub CF-domain refresh a CA bundle in frozen/script installs.
            # Use the reviewed runtime lock so this legacy source install resolves
            # the same distributions as release builds.
            _require_command(
                "scapy/cryptography/certifi install failed",
                py, "-m", "pip", "install", "--quiet",
                "--disable-pip-version-check",
                "--only-binary=:all:",
                "--require-hashes",
                "-r", os.path.join(_here, "requirements-runtime.txt"),
            )
            prog_args = [py, script, "--port", str(port)]
            uninstall_hint = f"sudo {py} {script} --uninstall"
        if tgws_secret_backup:
            with open(secret_path, "w") as handle:
                handle.write(tgws_secret_backup.strip())
            os.chmod(secret_path, 0o600)
        plist = launchd_plist_text(prog_args, INSTALL_DIR)
        _write_launchd_plist_atomic(plist)
        remove_obsolete_newsyslog_config()
        _require_command(
            "launchd label enable failed",
            "/bin/launchctl", "enable", _launchd_target(),
        )
        _require_command(
            "launchd bootstrap failed",
            "/bin/launchctl", "bootstrap", "system", LAUNCHD_PLIST,
        )
        if not _wait_for_installed_daemon(port):
            _, reason = _installed_daemon_readiness(port)
            raise RuntimeError(
                "daemon did not publish a healthy active/dormant state: "
                f"{reason}"
            )
    except Exception as error:
        rollback_clean = True
        if mutated:
            rollback_clean = _disable_and_cleanup_install(port)
        if rollback_clean:
            print(f"install failed safely: {error}", file=sys.stderr)
        else:
            print(f"install failed; rollback incomplete: {error}", file=sys.stderr)
        return False
    print(f"installed -> {LAUNCHD_PLIST}")
    print(f"runs now + at every boot as root, auto-restarts on crash.")
    print(f"logs:      tail -f {LOG_PATH}")
    print(f"uninstall: {uninstall_hint}")
    return True


def do_uninstall():
    clean = _disable_and_cleanup_install(PROXY_PORT)
    if clean:
        print("uninstalled + Slipstream pf anchor cleared")
    else:
        print("warning: Slipstream cleanup incomplete; inspect launchd, PF token, and TCP/1080",
              file=sys.stderr)
    return clean


def recover_owned_network_state():
    """Recover only durable PF state after launchd has been quiesced."""
    if not _flush_private_pf_with_retry(attempts=10, delay=0.2):
        return _cleanup_install_incomplete("private PF anchor could not be cleared")
    if not _restore_pf_loopback_skip():
        return _cleanup_install_incomplete("PF loopback skip could not be restored")
    released = _pf_release_enable_token()
    if released is not None and released.returncode != 0:
        return _cleanup_install_incomplete("owned PF enable token was not released")
    if not _remove_daemon_status_artifacts():
        return _cleanup_install_incomplete("daemon status could not be removed")
    return True


def _start_network_monitor(port, voice):
    threading.Thread(
        target=network_monitor,
        args=(port,),
        kwargs={"voice": voice},
        daemon=True,
    ).start()


async def amain(port, voice=True):
    global _geph_up
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(asyncio_exception_handler)
    shutdown = asyncio.Event()
    shutdown_signals = (
        signal.SIGTERM,
        signal.SIGINT,
        signal.SIGHUP,
        signal.SIGTSTP,
    )

    for shutdown_signal in shutdown_signals:
        loop.add_signal_handler(
            shutdown_signal,
            request_daemon_shutdown,
            shutdown,
        )
    try:
        server = await asyncio.start_server(
            handle, "127.0.0.1", port, reuse_address=True)
    except OSError as e:
        if e.errno == 48:
            print(f"\nport {port} already in use — another tproxy is still running.\n"
                  f"kill it and retry:\n  sudo lsof -ti tcp:{port} | xargs sudo kill\n",
                  file=sys.stderr)
        raise
    # Publishing a safe state must not depend on DNS, Geph, or PF. This also
    # gives the installer an exact listener/status ownership proof while the
    # bounded startup qualification is still running.
    write_startup_status()
    # Local routing is independent of the optional Geph backend. A clean install
    # must activate Discord/YouTube bypass even before Geph is configured.
    probe_ok = probe_geph()
    _geph_up, _ = reduce_geph_probe_state(
        previous_up=False,
        strikes=0,
        probe_ok=probe_ok,
        port=_geph_port,
        conflict=_geph_port_conflict,
    )
    startup_iface = default_iface()
    # A user full-tunnel VPN already owns the route. Do not arm even briefly:
    # the monitor will qualify Slipstream only after that default route leaves.
    if not (startup_iface and startup_iface.startswith("utun")):
        # The post-arm probe is redirected back into this asyncio server. Run
        # the blocking transaction off-loop so the listener can service it.
        await asyncio.to_thread(pf_setup_if_ready, port)
    startup_state = (
        "conflict" if _pf_interceptor_conflicts
        else "active" if _pf_applied
        else "dormant"
    )
    write_status(startup_state, startup_iface, None)
    # The monitor owns later pause/re-arm decisions after the cold-start gate.
    _start_network_monitor(port, voice)
    print(f">> transparent tlsrec+DoH proxy on 127.0.0.1:{port}  (root)")
    print(">> quit + reopen Discord normally; its updater is captured too")
    print(">> Ctrl-C (or close terminal) to stop and restore pf")
    try:
        drained = await serve_until_shutdown(server, shutdown)
        if not drained:
            print(
                f">> shutdown drain expired with {_conn_count} active connection(s)",
                file=sys.stderr,
            )
    finally:
        for shutdown_signal in shutdown_signals:
            loop.remove_signal_handler(shutdown_signal)


# ---- Telegram: bundled Flowseal/tg-ws-proxy (vendored proxy/ module) ----------
TGWS_PORT = 1443
TGWS_SECRET_PATH = "/usr/local/slipstream/tgws-secret"
# World-readable so the (non-root) tray can read the tg://proxy link and offer a
# one-click "Open in Telegram" — the secret file itself stays root-only 0600.
TGWS_LINK_PATH = "/var/run/slipstream-tgws.link"


def _tgws_secret():
    """Stable 32-hex MTProto secret so the user's Telegram proxy entry keeps
    working across restarts. Prefers the standalone TG WS Proxy app's secret (if
    the user already runs it) so quitting that app and letting our embedded proxy
    take over :1443 needs NO Telegram reconfigure; else our own persisted secret;
    else a fresh one."""
    import glob
    for cfg in glob.glob("/Users/*/Library/Application Support/TgWsProxy/config.json"):
        try:
            s = json.load(open(cfg)).get("secret", "").strip().lower()
            if len(s) == 32 and all(c in "0123456789abcdef" for c in s):
                return s
        except Exception:
            pass
    try:
        s = open(TGWS_SECRET_PATH).read().strip()
        if len(s) == 32 and all(c in "0123456789abcdef" for c in s):
            return s
    except Exception:
        pass
    s = os.urandom(16).hex()
    try:
        with open(TGWS_SECRET_PATH, "w") as f:
            f.write(s)
        os.chmod(TGWS_SECRET_PATH, 0o600)
    except Exception:
        pass
    return s


def _close_asyncio_loop(loop):
    """Cancel loop-owned tasks and release its selector descriptor."""
    if loop is None or loop.is_closed():
        return
    try:
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.run_until_complete(loop.shutdown_asyncgens())
    except Exception:
        pass
    finally:
        loop.close()


def start_tgws_proxy():
    """Run the vendored tg-ws-proxy — a local MTProto proxy on 127.0.0.1:1443 — in
    a daemon thread. Telegram Desktop points at it (tg://proxy?...) and its MTProto
    rides WSS to Telegram's Cloudflare-fronted WS endpoints, bypassing the DC-IP
    block. Its outbound runs as root, so our own pf rdr (user != root) leaves it
    alone: it goes out direct, no desync, no loop back into us."""
    set_tgws_state("starting")
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in (here, os.path.join(here, "..", "vendor", "tg-ws-proxy")):
        if os.path.isdir(os.path.join(cand, "proxy")):
            p = os.path.abspath(cand)
            if p not in sys.path:
                sys.path.insert(0, p)
            break
    try:
        from proxy.tg_ws_proxy import _run as _tgws_run
        from proxy.config import proxy_config
    except Exception as e:
        set_tgws_state("unavailable", repr(e))
        print(f">> tg-ws-proxy unavailable ({e!r}); Telegram gets MTProto "
              f"passthrough only", file=sys.stderr)
        return
    proxy_config.host = "127.0.0.1"
    proxy_config.port = TGWS_PORT
    proxy_config.secret = _tgws_secret()
    link = f"tg://proxy?server=127.0.0.1&port={TGWS_PORT}&secret=dd{proxy_config.secret}"
    # publish the link world-readable so the tray's "Open in Telegram" works
    try:
        with open(TGWS_LINK_PATH, "w") as f:
            f.write(link)
        os.chmod(TGWS_LINK_PATH, 0o644)
    except Exception:
        pass

    def _loop():
        warned_inuse = False
        while True:
            loop = None
            delay = 1
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                set_tgws_state("ready")
                loop.run_until_complete(_tgws_run())
            except OSError as e:
                if getattr(e, "errno", None) == 48:   # EADDRINUSE
                    set_tgws_state("in_use", "127.0.0.1:1443 is already in use")
                    if not warned_inuse:
                        print(">> tg-ws-proxy: :1443 held by the standalone TG WS "
                              "Proxy app; the embedded proxy takes over when you "
                              "quit it (same secret, no Telegram reconfigure)",
                              file=sys.stderr)
                        warned_inuse = True
                    delay = 15
                else:
                    set_tgws_state("error", repr(e))
                    print(f">> tg-ws-proxy crashed: {e!r} -> restart in 5s",
                          file=sys.stderr)
                    delay = 5
            except Exception as e:
                set_tgws_state("error", repr(e))
                print(f">> tg-ws-proxy crashed: {e!r} -> restart in 5s",
                      file=sys.stderr)
                delay = 5
            finally:
                _close_asyncio_loop(loop)
            time.sleep(delay)

    threading.Thread(target=_loop, daemon=True, name="tg-ws-proxy").start()
    print(f">> tg-ws-proxy ready on 127.0.0.1:{TGWS_PORT}", file=sys.stderr)


def main():
    global VERBOSE, _pf_fd
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=PROXY_PORT)
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--no-voice", action="store_true",
                    help="disable the UDP voice plane")
    ap.add_argument("--install", action="store_true",
                    help="install as a LaunchDaemon (starts at boot, auto-restarts)")
    ap.add_argument("--uninstall", action="store_true",
                    help="remove the LaunchDaemon and clear private pf state")
    ap.add_argument("--recover-network", action="store_true",
                    help=argparse.SUPPRESS)
    ap.add_argument("--status", action="store_true",
                    help="print daemon status JSON and exit (no root needed)")
    ap.add_argument("--baseline-resolve", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--baseline-probe", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--baseline-host", default="", help=argparse.SUPPRESS)
    ap.add_argument("--baseline-ip", default="", help=argparse.SUPPRESS)
    ap.add_argument("--baseline-path", default="/", help=argparse.SUPPRESS)
    args = ap.parse_args()
    VERBOSE = args.verbose

    if args.baseline_resolve:
        candidates = install_guard.resolve_candidates(
            ((args.baseline_host, "/"),),
        )
        addresses = list(dict.fromkeys(candidate.ip for candidate in candidates))
        print(json.dumps({"addresses": addresses}))
        sys.exit(0 if addresses else 2)

    if args.baseline_probe:
        candidate = install_guard.BaselineCandidate(
            host=args.baseline_host,
            ip=args.baseline_ip,
            path=args.baseline_path,
        )
        result = install_guard.probe_https(candidate)
        print(json.dumps({
            "ok": result.ok,
            "reason": result.reason,
            "status_code": result.status_code,
            "bytes_received": result.bytes_received,
        }))
        sys.exit(0 if result.ok else 2)

    if args.status:
        try:
            with open(STATUS_PATH) as f:
                line = f.read().strip()
            # Live states expire because the daemon writes every 5s. A startup
            # conflict is terminal and must remain visible after that daemon
            # deliberately exits instead of refreshing the snapshot.
            st = json.loads(line)
            if (
                time.time() - status_snapshot_updated_at(st) > 15
                and not status_snapshot_is_terminal_conflict(st)
            ):
                line = '{"state": "off"}'
            print(line)
        except Exception:
            print('{"state": "off"}')
        return

    if os.geteuid() != 0:
        print("must run as root:  sudo python3 tproxy.py", file=sys.stderr)
        sys.exit(1)

    if args.install:
        sys.exit(0 if do_install(args.port) else 1)
    if args.uninstall:
        sys.exit(0 if do_uninstall() else 1)
    if args.recover_network:
        sys.exit(0 if recover_owned_network_state() else 1)

    # A transparent proxy carries ALL system TCP/443 — hundreds of concurrent FDs.
    # The default 256-fd soft limit is far too low ("Too many open files"); raise it.
    try:
        _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        for target in (65536, 32768, 16384, 10240, 8192):
            cap = target if hard == resource.RLIM_INFINITY else min(target, hard)
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (cap, hard))
                break
            except (ValueError, OSError):
                continue
    except Exception:
        pass
    _open_fd_reserve()

    try:
        cleanup_stale()    # release only state owned by the previous daemon
    except (LegacyGlobalPfConflict, OwnedPfStateError) as exc:
        write_status("conflict", "", "")
        print(f">> {exc}", file=sys.stderr)
        _release_fd_reserve()
        sys.exit(1)
    setup_rotating_logs()   # keep launchd stdout/stderr bounded across long runs
    print(f">> daemon session start v{DAEMON_VERSION} pid={os.getpid()}")
    load_strat_cache()     # remember per-host winning strategies across restarts
    load_auto_geph()       # remember hosts learned to need the geph tunnel
    try:
        trusted_policy_keys = load_trusted_route_policy_keys()
    except Exception as exc:
        trusted_policy_keys = dict(TRUSTED_ROUTE_POLICY_KEYS)
        _set_route_policy_remote("key_error", error=str(exc))
        print(f">> route policy keys unavailable: {exc}", file=sys.stderr)
    load_persisted_route_policy(trusted_policy_keys)

    # bundled Telegram MTProto proxy (tg-ws-proxy) — local :1443, points Telegram
    # past the DC-IP block via WSS. Best-effort; never blocks daemon startup.
    start_tgws_proxy()

    atexit.register(
        lambda: None if _pf_teardown_complete.is_set() else pf_teardown()
    )
    # amain owns graceful SIGTERM/SIGINT/SIGHUP/SIGTSTP handling so launchd
    # stop and uninstall clear PF immediately without os._exit() tearing down
    # every in-flight browser stream.
    # Disposable lifecycle qualification may request the same network-change
    # rearm path without mutating the runner's real interfaces. The handler only
    # queues work; the monitor thread performs every PF/backend operation.
    signal.signal(_RUNTIME_REARM_SIGNAL, _runtime_rearm_signal_handler)

    _pf_fd = os.open("/dev/pf", os.O_RDWR)
    try:
        asyncio.run(amain(args.port, voice=not args.no_voice))
    except KeyboardInterrupt:
        pass
    finally:
        _release_fd_reserve()
        if not _pf_teardown_complete.is_set():
            pf_teardown()


if __name__ == "__main__":
    main()
