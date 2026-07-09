#!/usr/bin/env python3
"""tproxy — TRANSPARENT tlsrec proxy + DoH via pf rdr (Spike 4, needs root).

Two blocks were found on the target network:
  1. SNI DPI  -> beaten by tlsrec (tiny first TLS record).
  2. DNS poisoning -> blocked domains resolve to a stub IP (87.228.47.x) with no
     real server, so desync is useless. Beaten by re-resolving the SNI over DoH
     (DNS-over-HTTPS) and connecting to the REAL IP.

A transparent pf redirect captures ALL local TCP/443 (browser, Discord, the
updater) with no per-app config and blocks QUIC. For each connection we read the
ClientHello, parse the SNI, DoH-resolve it to the real IP, then forward a
tlsrec-split ClientHello to that real IP.

Run:   sudo python3 tproxy.py [--verbose]
Stop:  Ctrl-C  (auto-restores pf + connectivity)
ESCAPE HATCH if connectivity breaks (other terminal):
    sudo pfctl -f /etc/pf.conf ; sudo pfctl -d
"""
import argparse
import asyncio
import atexit
import base64
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
import resource
import signal
import socket
import ssl
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlencode, urlparse
import urllib.request

from primes import build_fake_stun, classify as classify_voice_payload


class _ScapyMacNoiseFilter(logging.Filter):
    def filter(self, record):
        return "MAC address to reach destination not found" not in record.getMessage()


logging.getLogger("scapy.runtime").addFilter(_ScapyMacNoiseFilter())

PROXY_PORT = 1080
DIOCNATLOOK = 0xC0544417
PF_OUT = 2
FIRST_REC_CAP = 64
VERBOSE = False

# DoH resolvers (connect by IP, no bootstrap DNS needed). SNI may itself be
# DPI-blocked -> we tlsrec its ClientHello too.
DOH = [("1.1.1.1", "cloudflare-dns.com"), ("8.8.8.8", "dns.google")]

PF_RULES = """\
table <slipstream_quic_block> persist
rdr pass on lo0 inet proto tcp from any to any port 443 -> 127.0.0.1 port {port}
pass out route-to (lo0 127.0.0.1) inet proto tcp from any to any port 443 user != root
"""
# NOTE: QUIC (UDP/443) is intentionally NOT blocked. YouTube/googlevideo video runs
# over QUIC/HTTP3, and QUIC to those hosts WORKS on this TSPU (verified 2026-07-07:
# Version-Negotiation replies in ~0.04s). The old QUIC block (Codex #11-#15) forced
# the browser onto TCP, which IS DPI-dropped for googlevideo -> video died. Leaving
# QUIC alone restores native HTTP3 playback. The <slipstream_quic_block> table is
# kept (empty, unreferenced) so the legacy note_quic_block_ips() calls don't error.

_pf_applied = False
_pf_fd = None
QUIC_BLOCK_TABLE = "slipstream_quic_block"
QUIC_BLOCK_MAX = 4096
_quic_block_ips = OrderedDict()
_doh_cache = OrderedDict()      # host -> (ips, expiry_monotonic)
# Dedicated pool for the blocking off-loop work (DoH resolves, fake injection).
# The default asyncio executor is tiny (~cpu+4); a browser opening many new hosts
# floods it with slow DoH queries and the whole proxy stalls. 64 workers + DoH
# de-dup keeps the app responsive under a browser's connection burst.
_POOL = ThreadPoolExecutor(max_workers=64, thread_name_prefix="slip")
_doh_inflight = {}             # host -> asyncio.Future (collapse concurrent DoH)
# Negative cache: a host that failed the whole ladder is "dead" for a cooldown,
# during which it gets ONE fast-fail attempt instead of 7 — stops retry-storms
# from a persistently-blocked host (e.g. Telegram DC sockets hammering forever).
DEAD_TTL = 60.0
_dead = {}                     # host -> expiry_monotonic

# Status the menu-bar app polls (atomic write; ts lets the app detect a dead daemon).
STATUS_PATH = "/var/run/slipstream.status"
DAEMON_VERSION = "0.1.5"
_conn_count = 0                # live proxied connections

# --------------------------------------------------- Geph split-tunnel (hybrid)
# The elegant hybrid (not a blunt VPN toggle): MOST traffic uses our local desync;
# only the handful of services that hard-block Russian IPs server-side (OpenAI,
# Anthropic, ...) are tunnelled through geph's local SOCKS5 — and ONLY when geph is
# actually running. Russian services are split-tunnel-EXCLUDED: they must never
# enter the tunnel (privacy + they'd break, geph exits abroad). geph absent ->
# _geph_up stays False -> this whole path is inert and behaviour is unchanged.
GEPH_ENABLED = os.environ.get("SLIP_GEPH", "1") != "0"
# Prefer Slipstream's OWN bundled geph5-client (:9954, started by the menu-bar app
# with the user's account secret); fall back to a separately-running Geph.app
# (:9909). SLIP_GEPH_PORT overrides with a single explicit port.
_env_geph_port = os.environ.get("SLIP_GEPH_PORT")
GEPH_PORTS = [int(_env_geph_port)] if _env_geph_port else [9954, 9909]
_geph_up = False               # set by network_monitor's periodic probe
_geph_port = None              # the live SOCKS port (set by probe_geph)
_system_dns_cache = {
    "ts": 0.0,
    "status": None,
    "resolution_ts": 0.0,
    "resolution_checks": None,
}
SYSTEM_DNS_STATUS_TTL = 30.0
SYSTEM_DNS_RESOLUTION_TTL = 5 * 60.0

ROUTE_LOCAL_BYPASS = "local_bypass"
ROUTE_GEO_EXIT = "geo_exit"
ROUTE_DIRECT = "direct_passthrough"
ROUTE_UNKNOWN = "unknown"

SERVICE_DISCORD = "discord"
SERVICE_YOUTUBE = "youtube_video"
SERVICE_OPENAI = "openai"
SERVICE_ANTHROPIC = "anthropic"
SERVICE_TELEGRAM = "telegram"
SERVICE_STEAM_STORE = "steam_store"
SERVICE_GITHUB = "github"
SERVICE_GENERIC = "generic"

STRATEGY_FAKE_ONLY = "fake_only"
STRATEGY_GEPH = "geph"
STRATEGY_DIRECT = "direct"
STRATEGY_GENERAL = "general"

DEFAULT_IP_ATTEMPT_LIMIT = 2
LOCAL_BYPASS_IP_ATTEMPT_LIMIT = 4
IP_ATTEMPT_LIMIT_BY_ROUTE = {
    ROUTE_LOCAL_BYPASS: LOCAL_BYPASS_IP_ATTEMPT_LIMIT,
}
ROUTE_POLICY_VERSION = 1
ROUTE_POLICY_SOURCE = "bundled"
ROUTE_POLICY_SCHEMA_VERSION = 1

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
POLICY_PROTECTED_LOCAL_BYPASS_GROUPS = frozenset((SERVICE_DISCORD, SERVICE_YOUTUBE))
POLICY_ALLOWED_SERVICE_GROUPS = frozenset((
    SERVICE_DISCORD,
    SERVICE_YOUTUBE,
    SERVICE_OPENAI,
    SERVICE_ANTHROPIC,
    SERVICE_TELEGRAM,
    SERVICE_STEAM_STORE,
    SERVICE_GITHUB,
    SERVICE_GENERIC,
))
POLICY_ALLOWED_STRATEGY_BY_ROUTE = {
    ROUTE_DIRECT: frozenset((STRATEGY_DIRECT,)),
    ROUTE_LOCAL_BYPASS: frozenset((STRATEGY_FAKE_ONLY,)),
    ROUTE_GEO_EXIT: frozenset((STRATEGY_GEPH,)),
}
POLICY_STATE_DIR = "/var/db/slipstream"
ROUTE_POLICY_STATE_PATH = os.path.join(POLICY_STATE_DIR, "route-policy.json")
ROUTE_POLICY_PREVIOUS_PATH = os.path.join(POLICY_STATE_DIR, "route-policy.previous.json")
ROUTE_POLICY_KEYS_PATH = os.path.join(POLICY_STATE_DIR, "route-policy-keys.json")
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

CANARY_INTERVAL = 10 * 60.0
CANARY_JITTER = 90.0
CANARY_FORCE_MIN_GAP = 60.0
CANARY_FAILURE_WINDOW = 5 * 60.0
LOCAL_PAYLOAD_CANARY_TIMEOUT = 4.0
LOCAL_PAYLOAD_CANARY_MIN_BYTES = 64
LOCAL_PAYLOAD_DEGRADE_AFTER = 3
LOCAL_BYPASS_RUNTIME_DEGRADE_AFTER = 3
GEO_PAYLOAD_CANARY_TIMEOUT = 6.0
QUIC_CANARY_TIMEOUT = 1.5
QUIC_UNSUPPORTED_VERSION = b"\x0a\x0a\x0a\x0a"
QUIC_MIN_INITIAL_SIZE = 1200
GEO_EXIT_RUNTIME_DEGRADE_AFTER = 3
SMART_DNS_OK_TTL = 10 * 60.0
SMART_DNS_GROUPS = (SERVICE_OPENAI, SERVICE_ANTHROPIC)
_smart_dns_ok_until = {}
_smart_dns_last_failure = {"host": "", "reason": "", "ts": 0.0}


def _host_matches(host, domains):
    if not host:
        return False
    h = host.lower().rstrip(".")
    return any(h == d or h.endswith("." + d) for d in domains)


def is_discord_host(host):
    return _host_matches(host, DISCORD_HOSTS)


def is_google_video_host(host):
    return _host_matches(host, GOOGLE_VIDEO)


def normalize_host(host):
    return host.lower().rstrip(".") if host else ""


def _policy_result(host, route_class, service_group, strategy_set):
    return {
        "host": host,
        "route_class": route_class,
        "service_group": service_group,
        "strategy_set": strategy_set,
    }


def _match_policy(host, policies):
    for policy in policies:
        if _host_matches(host, policy["domains"]):
            return policy
    return None


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


def _normalize_policy_domains(domains, name):
    if not isinstance(domains, (list, tuple)) or not domains:
        raise ValueError(f"{name}.domains must be a non-empty list")
    normalized = []
    seen = set()
    for domain in domains:
        if not isinstance(domain, str):
            raise ValueError(f"{name}.domains entries must be strings")
        host = normalize_host(domain)
        if (
            not host
            or "*" in host
            or "/" in host
            or ":" in host
            or any(part == "" for part in host.split("."))
        ):
            raise ValueError(f"{name}.domains contains invalid host {domain!r}")
        if host not in seen:
            normalized.append(host)
            seen.add(host)
    return normalized


def _normalize_policy_entry(
    entry, name, *, default_route_class=None, default_strategy_set=None,
):
    if not isinstance(entry, dict):
        raise ValueError(f"{name} must be an object")
    group = entry.get("service_group")
    if group not in POLICY_ALLOWED_SERVICE_GROUPS:
        raise ValueError(f"{name}.service_group is not supported")
    route_class = entry.get("route_class", default_route_class)
    if route_class not in POLICY_ALLOWED_STRATEGY_BY_ROUTE:
        raise ValueError(f"{name}.route_class is not supported")
    strategy_set = entry.get("strategy_set", default_strategy_set)
    if strategy_set not in POLICY_ALLOWED_STRATEGY_BY_ROUTE[route_class]:
        raise ValueError(f"{name}.strategy_set does not match route_class")
    if group in POLICY_PROTECTED_LOCAL_BYPASS_GROUPS and (
        route_class != ROUTE_LOCAL_BYPASS or strategy_set != STRATEGY_FAKE_ONLY
    ):
        raise ValueError(f"{group} must stay local_bypass/fake_only")
    return {
        "domains": _normalize_policy_domains(entry.get("domains"), name),
        "route_class": route_class,
        "service_group": group,
        "strategy_set": strategy_set,
    }


def validate_route_policy_manifest(manifest):
    if not isinstance(manifest, dict):
        raise ValueError("policy manifest must be an object")
    normalized = {
        "version": _require_policy_int(
            manifest.get("version"),
            "version",
            min_value=1,
            max_value=1_000_000,
        ),
        "source": manifest.get("source"),
        "static_routes": [],
        "geo_exit_routes": [],
        "attempt_limits": {},
    }
    if not isinstance(normalized["source"], str) or not normalized["source"].strip():
        raise ValueError("source must be a non-empty string")

    static_routes = manifest.get("static_routes")
    geo_exit_routes = manifest.get("geo_exit_routes")
    if not isinstance(static_routes, list) or not static_routes:
        raise ValueError("static_routes must be a non-empty list")
    if not isinstance(geo_exit_routes, list):
        raise ValueError("geo_exit_routes must be a list")

    protected_seen = set()
    for index, entry in enumerate(static_routes):
        item = _normalize_policy_entry(entry, f"static_routes[{index}]")
        normalized["static_routes"].append(item)
        if item["service_group"] in POLICY_PROTECTED_LOCAL_BYPASS_GROUPS:
            protected_seen.add(item["service_group"])
    missing = POLICY_PROTECTED_LOCAL_BYPASS_GROUPS - protected_seen
    if missing:
        raise ValueError(f"protected local-bypass groups missing: {', '.join(sorted(missing))}")

    for index, entry in enumerate(geo_exit_routes):
        item = _normalize_policy_entry(
            entry,
            f"geo_exit_routes[{index}]",
            default_route_class=ROUTE_GEO_EXIT,
            default_strategy_set=STRATEGY_GEPH,
        )
        if item["route_class"] != ROUTE_GEO_EXIT:
            raise ValueError(f"geo_exit_routes[{index}] must be geo_exit")
        normalized["geo_exit_routes"].append(item)

    attempt_limits = manifest.get("attempt_limits")
    if not isinstance(attempt_limits, dict):
        raise ValueError("attempt_limits must be an object")
    for route_class, value in attempt_limits.items():
        if route_class != "default" and route_class not in POLICY_ALLOWED_STRATEGY_BY_ROUTE:
            raise ValueError(f"attempt_limits has unsupported route {route_class!r}")
        normalized["attempt_limits"][route_class] = _require_policy_int(
            value,
            f"attempt_limits[{route_class}]",
            min_value=1,
            max_value=8,
        )
    if "default" not in normalized["attempt_limits"]:
        raise ValueError("attempt_limits.default is required")
    return normalized


def route_policy_canonical_bytes(manifest=None):
    manifest = route_policy_manifest() if manifest is None else manifest
    normalized = validate_route_policy_manifest(manifest)
    return json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")


def route_policy_hash(manifest=None):
    return hashlib.sha256(route_policy_canonical_bytes(manifest)).hexdigest()


def verify_signed_route_policy_bundle(bundle, public_keys):
    if not isinstance(bundle, dict):
        raise ValueError("signed policy bundle must be an object")
    if not isinstance(public_keys, dict) or not public_keys:
        raise ValueError("trusted policy keys are required")
    schema = _require_policy_int(
        bundle.get("schema"),
        "schema",
        min_value=ROUTE_POLICY_SCHEMA_VERSION,
        max_value=ROUTE_POLICY_SCHEMA_VERSION,
    )
    if schema != ROUTE_POLICY_SCHEMA_VERSION:
        raise ValueError("unsupported policy bundle schema")
    key_id = bundle.get("key_id")
    if not isinstance(key_id, str) or key_id not in public_keys:
        raise ValueError("unknown policy key")
    signature = bundle.get("signature")
    if not isinstance(signature, str):
        raise ValueError("policy signature must be base64")
    try:
        signature_bytes = base64.b64decode(signature, validate=True)
        public_key_bytes = base64.b64decode(public_keys[key_id], validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("policy signature or key is not valid base64") from exc

    manifest = validate_route_policy_manifest(bundle.get("manifest"))
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise ValueError("policy signature support unavailable") from exc
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            signature_bytes,
            route_policy_canonical_bytes(manifest),
        )
    except InvalidSignature as exc:
        raise ValueError("policy signature verification failed") from exc
    return manifest


def apply_route_policy_manifest(manifest):
    """Activate a validated route policy manifest in memory.

    Remote fetch/persistence is deliberately outside this function. This keeps
    policy updates staged: verify first, activate atomically, then expose the
    active hash in status for diagnostics/rollback decisions.
    """
    global _active_route_policy_manifest
    normalized = validate_route_policy_manifest(manifest)
    _active_route_policy_manifest = _copy_route_policy_manifest(normalized)
    return route_policy_status_snapshot()


def apply_signed_route_policy_bundle(bundle, public_keys):
    manifest = verify_signed_route_policy_bundle(bundle, public_keys)
    return apply_route_policy_manifest(manifest)


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


def load_trusted_route_policy_keys(
    *,
    path=None,
    embedded_keys=None,
):
    keys = dict(TRUSTED_ROUTE_POLICY_KEYS if embedded_keys is None else embedded_keys)
    if path is None:
        path = os.environ.get(ROUTE_POLICY_KEYS_PATH_ENV, ROUTE_POLICY_KEYS_PATH)
    if path and os.path.exists(path):
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, dict) and "keys" in data:
            data = data["keys"]
        keys.update(_validate_route_policy_key_map(data))
    return _validate_route_policy_key_map(keys)


def validate_route_policy_remote_url(url):
    if not isinstance(url, str) or not url.strip():
        raise ValueError("remote policy url is empty")
    parsed = urlparse(url.strip())
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("remote policy url must use https")
    return url.strip()


def fetch_signed_route_policy_bundle(
    url,
    *,
    fetcher=None,
    timeout=ROUTE_POLICY_FETCH_TIMEOUT,
    max_bytes=ROUTE_POLICY_MAX_BYTES,
):
    url = validate_route_policy_remote_url(url)
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
        return data
    if isinstance(data, str):
        data = data.encode("utf-8")
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("remote policy response must be JSON")
    if len(data) > max_bytes:
        raise ValueError("remote policy response is too large")
    return json.loads(bytes(data).decode("utf-8"))


def _route_policy_health_gate_passed(result):
    if result is True:
        return True, ""
    if result is False:
        return False, "health gate failed"
    if isinstance(result, (list, tuple)) and len(result) >= 2:
        ok, degraded = result[0], result[1]
        try:
            ok_count = int(ok)
            degraded_count = int(degraded)
        except (TypeError, ValueError):
            return False, "health gate returned invalid counters"
        if degraded_count == 0 and ok_count > 0:
            return True, ""
        return False, f"health gate degraded={degraded_count} ok={ok_count}"
    if isinstance(result, dict):
        degraded = int(result.get("degraded") or 0)
        blocked = int(result.get("blocked") or 0)
        ok = int(result.get("ok") or 0)
        if degraded == 0 and blocked == 0 and ok > 0:
            return True, ""
        return False, f"health gate degraded={degraded} blocked={blocked} ok={ok}"
    return False, "health gate did not run"


def apply_signed_route_policy_bundle_with_health_gate(
    bundle,
    public_keys,
    health_runner,
    *,
    policy_path=ROUTE_POLICY_STATE_PATH,
    previous_path=ROUTE_POLICY_PREVIOUS_PATH,
    now=None,
):
    previous_manifest = route_policy_manifest()
    previous_storage = route_policy_storage_snapshot()
    manifest = verify_signed_route_policy_bundle(bundle, public_keys)
    apply_route_policy_manifest(manifest)
    try:
        gate_ok, gate_error = _route_policy_health_gate_passed(health_runner())
    except Exception as exc:
        gate_ok, gate_error = False, f"health gate error: {exc}"
    if not gate_ok:
        if previous_manifest.get("source") == ROUTE_POLICY_SOURCE:
            reset_route_policy_manifest()
        else:
            apply_route_policy_manifest(previous_manifest)
        _set_route_policy_storage(
            "rejected",
            source=previous_storage.get("source") or previous_manifest.get("source"),
            sha256=previous_storage.get("sha256") or route_policy_hash(previous_manifest),
            error=gate_error,
            path=policy_path,
        )
        return None
    return save_signed_route_policy_bundle(
        bundle,
        public_keys,
        policy_path=policy_path,
        previous_path=previous_path,
        now=now,
    )


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


def _atomic_write_json(path, data, *, mode=0o600):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(data, f, sort_keys=True, separators=(",", ":"))
            f.write("\n")
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        try:
            os.remove(tmp)
        except FileNotFoundError:
            pass
        except Exception:
            pass


def signed_route_policy_state(bundle, public_keys, now=None):
    manifest = verify_signed_route_policy_bundle(bundle, public_keys)
    return {
        "schema": ROUTE_POLICY_SCHEMA_VERSION,
        "saved_at": time.time() if now is None else now,
        "sha256": route_policy_hash(manifest),
        "source": manifest["source"],
        "bundle": bundle,
    }


def save_signed_route_policy_bundle(
    bundle,
    public_keys,
    *,
    policy_path=ROUTE_POLICY_STATE_PATH,
    previous_path=ROUTE_POLICY_PREVIOUS_PATH,
    now=None,
):
    state = signed_route_policy_state(bundle, public_keys, now=now)
    if os.path.exists(policy_path):
        os.makedirs(os.path.dirname(previous_path), exist_ok=True)
        shutil.copy2(policy_path, previous_path)
    _atomic_write_json(policy_path, state)
    apply_signed_route_policy_bundle(bundle, public_keys)
    _set_route_policy_storage(
        "saved",
        source=state["source"],
        sha256=state["sha256"],
        path=policy_path,
    )
    return route_policy_status_snapshot()


def load_persisted_route_policy(
    public_keys,
    *,
    policy_path=ROUTE_POLICY_STATE_PATH,
):
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
        with open(policy_path) as f:
            state = json.load(f)
        if state.get("schema") != ROUTE_POLICY_SCHEMA_VERSION:
            raise ValueError("unsupported persisted policy schema")
        manifest = verify_signed_route_policy_bundle(state.get("bundle"), public_keys)
        expected_hash = state.get("sha256")
        actual_hash = route_policy_hash(manifest)
        if expected_hash != actual_hash:
            raise ValueError("persisted policy hash mismatch")
        apply_route_policy_manifest(manifest)
        _set_route_policy_storage(
            "loaded",
            source=manifest["source"],
            sha256=actual_hash,
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


def rollback_route_policy(
    public_keys,
    *,
    policy_path=ROUTE_POLICY_STATE_PATH,
    previous_path=ROUTE_POLICY_PREVIOUS_PATH,
):
    if os.path.exists(previous_path):
        os.replace(previous_path, policy_path)
        loaded = load_persisted_route_policy(public_keys, policy_path=policy_path)
        if loaded:
            _route_policy_storage["state"] = "rolled_back"
        return loaded
    try:
        os.remove(policy_path)
    except FileNotFoundError:
        pass
    reset_route_policy_manifest()
    _set_route_policy_storage(
        "rolled_back_bundled",
        source=ROUTE_POLICY_SOURCE,
        sha256=route_policy_hash(),
        path=policy_path,
    )
    return True


def reset_route_policy_manifest():
    global _active_route_policy_manifest
    _active_route_policy_manifest = None
    _set_route_policy_storage(
        "bundled",
        source=ROUTE_POLICY_SOURCE,
        sha256=route_policy_hash(),
    )
    return route_policy_status_snapshot()


def route_policy_status_snapshot():
    manifest = route_policy_manifest()
    domains = {ROUTE_DIRECT: 0, ROUTE_LOCAL_BYPASS: 0, ROUTE_GEO_EXIT: 0}
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
    h = normalize_host(host)
    if not h:
        return _policy_result("", ROUTE_UNKNOWN, SERVICE_GENERIC, STRATEGY_GENERAL)
    static_routes, geo_exit_routes = route_policy_tables()
    policy = _match_policy(h, static_routes)
    if policy:
        return _policy_result(
            h,
            policy["route_class"],
            policy["service_group"],
            policy["strategy_set"],
        )
    if is_russian(h):
        return _policy_result(h, ROUTE_DIRECT, SERVICE_GENERIC, STRATEGY_DIRECT)
    wall_now = time.time() if now is None else now
    geo_policy = _match_policy(h, geo_exit_routes)
    if geo_policy or _auto_geph.get(h, 0) > wall_now:
        group = (geo_policy or {}).get("service_group", SERVICE_GENERIC)
        return _policy_result(h, ROUTE_GEO_EXIT, group, STRATEGY_GEPH)
    return _policy_result(h, ROUTE_UNKNOWN, SERVICE_GENERIC, STRATEGY_GENERAL)


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
_canary_health = {}
_canary_failure_windows = {}
_canary_state = {
    "running": False,
    "last_run": 0.0,
    "last_started": 0.0,
    "next_due": 0.0,
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

# Russian services — NEVER tunnelled (split-tunnel exclusion "for the VPN").
# Primary rule is the national TLDs; the set covers big RU services on .com/.net.
RU_TLDS = (".ru", ".su", ".xn--p1ai", ".moscow", ".tatar", ".xn--80adxhks")
RU_HOSTS = (
    "vk.com", "vk.cc", "vkvideo.ru", "userapi.com", "vk-cdn.net", "vkuser.net",
    "yandex.com", "yandex.net", "yastatic.net", "yandexcloud.net", "ya.ru",
    "mail.ru", "mycdn.me", "imgsmail.ru",
    "sberbank.com", "sber.ru", "sberdevices.ru",
    "ozon.com", "ozon.ru", "wildberries.ru", "wb.ru", "avito.ru",
    "gosuslugi.ru", "nalog.ru", "gov.ru",
    "tinkoff.ru", "tbank.ru", "gazprombank.ru", "vtb.ru", "alfabank.ru",
    "rutube.ru", "ok.ru", "dzen.ru", "kinopoisk.ru", "2gis.com", "2gis.ru",
    "kaspersky.com", "kaspersky.ru", "aliexpress.ru",
)


def is_russian(host):
    """True for any Russian service — excluded from the geph tunnel."""
    if not host:
        return False
    h = host.lower().rstrip(".")
    if h.endswith(RU_TLDS):
        return True
    return _host_matches(h, RU_HOSTS)


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
AUTO_GEPH_NET_BAD = 5         # this many hosts failing at once = network problem
AUTO_GEPH_TTL = 7 * 86400.0   # remember a learned host for a week
AUTO_GEPH_CONFIRM_COOLDOWN = 120.0
AUTO_GEPH_CONFIRM_TIMEOUT = 6.0
AUTO_GEPH_CONFIRM_MIN_BYTES = 64
_auto_fail = {}               # host -> list[monotonic] recent stuck closes
_auto_geph = {}               # host -> wall-clock expiry (learned geph hosts)
_auto_geph_confirming = {}    # host -> monotonic start time
_auto_geph_last_probe = {}    # host -> monotonic last proof attempt
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

# geph's own broker-fronting domains — NEVER desync/auto-route these (our daemon
# would otherwise mangle geph's broker access or route geph through itself).
GEPH_INFRA = ("kubernetes.io", "cdn77.org", "cdn77.com", "netlify.app", "vuejs.org")


def _is_geph_infra(host):
    return _host_matches(host, GEPH_INFRA)


def geph_route(host):
    """Should this host go through geph's tunnel? Geo-blocked (listed OR learned)
    AND not Russian."""
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
    policy = route_policy(host, now=now)
    if policy["route_class"] != ROUTE_LOCAL_BYPASS:
        return None
    group = policy["service_group"]
    if ok:
        return route_health_event(
            group,
            ROUTE_LOCAL_BYPASS,
            host,
            True,
            now=now,
        )

    clear_route_strategy_cache(group=group)
    item = route_health_event(
        group,
        ROUTE_LOCAL_BYPASS,
        host,
        False,
        reason or "runtime local bypass failed",
        now=now,
        degrade_after=LOCAL_BYPASS_RUNTIME_DEGRADE_AFTER,
    )
    start_canaries_if_due(
        f"runtime:{group}",
        force=True,
        now=canary_now,
        runner=canary_runner,
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
    return {
        "state": "active" if kinds else "off",
        "kind": ",".join(kinds),
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
    checks = system_dns_resolution_checks()
    _system_dns_cache.update({
        "resolution_ts": now,
        "resolution_checks": dict(checks),
    })
    return checks


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
    _geph_last_failure.update({
        "host": normalize_host(host),
        "reason": reason[:200],
        "ts": time.time(),
    })
    policy = route_policy(host)
    route_health_event(
        policy["service_group"], ROUTE_GEO_EXIT, host,
        ok=False,
        reason=reason,
        state=HEALTH_BLOCKED if reason == "tunnel down" else HEALTH_DEGRADED,
        degrade_after=1 if reason == "tunnel down" else GEO_EXIT_RUNTIME_DEGRADE_AFTER,
    )
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
    print(f">> geph route failed for {host}: {reason}", file=sys.stderr)


def clear_geph_route_failure():
    _geph_last_failure.update({"host": "", "reason": "", "ts": 0.0})


def prune_auto_geph(now=None):
    now = time.time() if now is None else now
    expired = [
        host for host, expiry in list(_auto_geph.items())
        if not isinstance(expiry, (int, float)) or expiry <= now
    ]
    for host in expired:
        _auto_geph.pop(host, None)
    if expired:
        save_auto_geph()


def load_auto_geph():
    global _auto_geph
    try:
        with open(_AUTO_GEPH_PATH) as f:
            data = json.load(f)
        now = time.time()
        _auto_geph = {h: e for h, e in data.items()
                      if isinstance(e, (int, float)) and e > now}
    except Exception:
        _auto_geph = {}


def save_auto_geph():
    try:
        with open(_AUTO_GEPH_PATH, "w") as f:
            json.dump(_auto_geph, f)
    except Exception:
        pass


# Adaptive auto-routing is on by default, but promotion is proof-gated: local
# low-content hangs only schedule a candidate, and Geph must return HTTPS payload
# before the exact host is learned. SLIP_AUTOGEPH=0 disables this learning layer.
AUTO_GEPH_ENABLED = os.environ.get("SLIP_AUTOGEPH", "1") != "0"


def _auto_geph_candidate_allowed(host):
    h = normalize_host(host)
    if not h:
        return False
    if is_russian(h) or _is_geph_infra(h):
        return False
    policy = route_policy(h)
    return policy["route_class"] == ROUTE_UNKNOWN


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


def _geph_payload_probe(host, timeout=AUTO_GEPH_CONFIRM_TIMEOUT):
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
    bytes_read = _geph_payload_probe(h)
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
    """Called after a NON-geph local-desync close. A "stuck" close — the
    connection was held a long time but returned no real content (the
    "reconnecting…" hang) — is the candidate signal. A storm of them for one host
    schedules a Geph payload proof; only that proof learns the host. Fast
    low-content closes (redirects / 204 / beacons, e.g. google) are normal and
    must not count. Real content resets the host's failure noise."""
    if not AUTO_GEPH_ENABLED:
        return
    h = normalize_host(host)
    if not _auto_geph_candidate_allowed(h):
        return                                  # RU, already tunnelled, or geph's own
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
    if len(q) < AUTO_GEPH_STORM or not _geph_up:
        return
    # network-fine guard: if many DISTINCT hosts are failing at once it's the
    # network, not a per-host geo-block — don't sweep everything into the tunnel.
    # (Count hosts with >=2 recent low-content closes; this accumulates before any
    # single host crosses the storm threshold, so a network-wide outage is caught.)
    failing = sum(1 for v in _auto_fail.values()
                  if sum(1 for t in v if t >= cutoff) >= 2)
    if failing >= AUTO_GEPH_NET_BAD:
        return
    _schedule_auto_geph_confirmation(h, now=now, runner=confirmation_runner)


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
    {
        "name": "openai_billing",
        "group": SERVICE_OPENAI,
        "host": "billing.openai.com",
        "degrade_after": GEO_EXIT_RUNTIME_DEGRADE_AFTER,
    },
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
    for ip in ips[:DEFAULT_IP_ATTEMPT_LIMIT]:
        result = await dial_and_probe(ip, port, first_flight, probe_timeout=probe_timeout)
        if result:
            return ip, result
    return None


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
    head, body = _canary_client_hello(host)
    payload_failed = False
    payload_short = False
    min_payload_bytes = _local_payload_min_bytes(spec)
    for strat in strategy_order(host):
        strat_ok = False
        if not strat.get("fake"):
            continue
        for ip in ips[:ip_attempt_limit(host)]:
            result = await dial_strategy(ip, 443, head, body, host, strat)
            if result:
                _close_probe_result(result)
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
    _canary_state["running"] = False
    _canary_state["next_due"] = now + _canary_delay(now)


def _canary_thread_main(reason):
    try:
        asyncio.run(run_route_canaries(reason))
    except Exception as e:
        print(f">> route canaries failed: {e}", file=sys.stderr)
    finally:
        finish_canaries()


def start_canaries_if_due(reason="periodic", force=False, now=None, runner=None):
    now = time.monotonic() if now is None else now
    if _canary_state["running"]:
        return False
    if force and _canary_state["last_started"] and now - _canary_state["last_started"] < CANARY_FORCE_MIN_GAP:
        return False
    if not force and _canary_state["next_due"] and now < _canary_state["next_due"]:
        return False
    _canary_state["running"] = True
    _canary_state["last_started"] = now
    if runner is not None:
        try:
            runner(reason)
        finally:
            finish_canaries(now)
        return True
    threading.Thread(target=_canary_thread_main, args=(reason,), daemon=True).start()
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


def write_status(state, iface, voice_iface):
    try:
        now = time.time()
        prune_telegram_direct_failures(now)
        prune_auto_geph(now)
        consume_telegram_proxy_acceptance()
        st = {
            "state": state,            # "active" | "dormant"
            "version": DAEMON_VERSION,
            "pid": os.getpid(),
            "ts": now,
            "conns": _conn_count,
            "iface": iface or "",
            "voice": voice_iface or "",
            "hosts_learned": len(_strat_cache),
            "dead": len(_dead),
            "geph": "up" if _geph_up else ("off" if not GEPH_ENABLED else "down"),
            "geph_learned": len(_auto_geph),
            "auto_geo_exit": auto_geo_exit_status_snapshot(now),
            "routing_policy": route_policy_status_snapshot(),
            "routing_policy_storage": route_policy_storage_snapshot(),
            "routing_policy_remote": route_policy_remote_snapshot(),
            "strategy_scores": strategy_score_snapshot(),
            "telegram_proxy_suggest": now < _tg_proxy_suggest_until,
            "telegram_direct_failures": len(_tg_direct_failures),
            "route_health": route_health_snapshot(now),
            "system_proxy": current_system_proxy_status(),
            "system_dns": current_system_dns_status(),
            "smart_dns": smart_dns_status_snapshot(now),
            "pf_state": pf_state_snapshot(PROXY_PORT),
            "geph_detail": {
                "port": _geph_port or 0,
                "failure_reason": _geph_last_failure["reason"],
                "last_failure_host": _geph_last_failure["host"],
                "last_failure_at": _geph_last_failure["ts"],
            },
            "canaries": canary_status_snapshot(),
        }
        st.update(tgws_status(now))
        tmp = STATUS_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(st, f)
        os.replace(tmp, STATUS_PATH)
    except Exception:
        pass


# ---------------------------------------------------------------- pf plumbing
# LaunchDaemons start with an empty PATH, so bare 'pfctl'/'route'/'pgrep' aren't
# found and the daemon silently does nothing — force the system dirs onto PATH.
_RUN_ENV = dict(os.environ)
_RUN_ENV["PATH"] = "/sbin:/usr/sbin:/bin:/usr/bin:" + _RUN_ENV.get("PATH", "")


def _run(*args):
    try:
        return subprocess.run(list(args), capture_output=True, text=True, env=_RUN_ENV)
    except FileNotFoundError:
        return subprocess.CompletedProcess(args, 127, "", f"not found: {args[0]}")


def _quic_blockable_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        addr.version == 4
        and not addr.is_loopback
        and not addr.is_link_local
        and not addr.is_multicast
        and not addr.is_private
        and not _ip_in_nets(ip, TELEGRAM_NETS)
    )


def sync_quic_block_table():
    ips = list(_quic_block_ips)
    if ips:
        _run("pfctl", "-t", QUIC_BLOCK_TABLE, "-T", "replace", *ips)
    else:
        _run("pfctl", "-t", QUIC_BLOCK_TABLE, "-T", "flush")


def note_quic_block_ips(ips, max_ips=QUIC_BLOCK_MAX):
    new_ips = []
    for ip in ips:
        if not _quic_blockable_ip(ip):
            continue
        exists = ip in _quic_block_ips
        _quic_block_ips[ip] = time.monotonic()
        _quic_block_ips.move_to_end(ip)
        if not exists:
            new_ips.append(ip)
    evicted = False
    while len(_quic_block_ips) > max_ips:
        _quic_block_ips.popitem(last=False)
        evicted = True
    if _pf_applied and evicted:
        sync_quic_block_table()
    elif _pf_applied and new_ips:
        _run("pfctl", "-t", QUIC_BLOCK_TABLE, "-T", "add", *new_ips)


def _pf_load(port):
    f = tempfile.NamedTemporaryFile("w", suffix=".slipstream.pf.conf", delete=False)
    f.write(PF_RULES.format(port=port))
    f.close()
    r = _run("pfctl", "-f", f.name)
    if r.returncode == 0:
        sync_quic_block_table()
    try:
        os.unlink(f.name)
    except Exception:
        pass
    return r


def pf_setup(port):
    global _pf_applied
    _run("pfctl", "-f", "/etc/pf.conf")
    _run("pfctl", "-E")                 # enable pf (ref-counted) — once
    r = _pf_load(port)
    if r.returncode != 0:
        print("pfctl load failed:\n" + r.stderr, file=sys.stderr)
        sys.exit(1)
    _pf_applied = True
    print(f">> pf active: all TCP/443 -> 127.0.0.1:{port}; QUIC scoped by table")


def pf_has_rules(port):
    """Are our rdr rules still loaded? (sleep/wake or another tool may flush pf)"""
    return f"port {port}" in _run("pfctl", "-sn").stdout


def pf_state_snapshot(port=PROXY_PORT):
    info = _run("pfctl", "-s", "info")
    rules = _run("pfctl", "-sn")
    return {
        "applied": bool(_pf_applied),
        "enabled": info.returncode == 0 and "Status: Enabled" in info.stdout,
        "rules_loaded": rules.returncode == 0 and f"port {port}" in rules.stdout,
    }


def pf_teardown():
    global _pf_applied
    try:
        os.remove(STATUS_PATH)        # daemon is going away -> app shows "off"
    except Exception:
        pass
    if not _pf_applied:
        return
    _run("pfctl", "-f", "/etc/pf.conf")
    _run("pfctl", "-d")
    _pf_applied = False
    print(">> pf restored")


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


def cleanup_stale():
    """Self-heal: kill any leftover tproxy instances (e.g. a Ctrl+Z-suspended
    one still holding the port) and reset pf to the clean default, so a fresh
    start always works without manual lsof/kill/escape."""
    me, parent = os.getpid(), os.getppid()
    # A MANUAL run (from the repo, not the installed daemon) must stop the daemon
    # first: launchd KeepAlive would instantly restart a kill-9'd daemon and
    # re-grab :1080. PyInstaller sets __file__ under _internal, so frozen daemons
    # must be identified by sys.executable instead.
    if not running_from_install_dir():
        _run("launchctl", "bootout", "system", LAUNCHD_PLIST)
    killed = 0
    for pattern in ("tproxy.py", "slipstreamd"):
        res = _run("pgrep", "-f", pattern)
        for line in res.stdout.split():
            try:
                pid = int(line)
            except ValueError:
                continue
            if pid not in (me, parent):
                _run("kill", "-9", str(pid))
                killed += 1
    _run("pfctl", "-f", "/etc/pf.conf")     # drop any stale rules from a crash
    if killed:
        print(f">> self-heal: killed {killed} stale tproxy instance(s), reset pf")


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
    if policy["route_class"] == ROUTE_DIRECT:
        return [STRAT_BY_NAME["plain"]]
    # Discord must NEVER fall to a non-fake strategy (its throttle is relentless),
    # so it uses the fake-only set and ignores any stale non-fake cache entry.
    if policy["service_group"] == SERVICE_DISCORD:
        names = _rank_strategy_names(host, DISCORD_STRATS)
        return [STRAT_BY_NAME[n] for n in names]
    # YouTube/googlevideo: same fake-only discipline (see GOOGLE_VIDEO note above).
    if policy["service_group"] == SERVICE_YOUTUBE:
        names = _rank_strategy_names(host, GOOGLE_VIDEO_STRATS)
        return [STRAT_BY_NAME[n] for n in names]
    host = normalize_host(host)
    win = _strat_cache.get(host)
    if win in STRAT_BY_NAME:
        names = [win] + [n for n in GENERAL_STRATS if n != win]
    else:
        names = GENERAL_STRATS
    return [STRAT_BY_NAME[n] for n in _rank_strategy_names(host, names)]


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


def network_monitor(port, voice=True):
    """Long-running guard thread. (1) Keeps the voice sniffer bound to the CURRENT
    default interface so voice survives Wi-Fi/Ethernet/sleep changes. (2) Re-applies
    pf if it ever gets flushed (sleep/wake or another tool). Voice itself: Discord
    RTP is UDP to *.discord.media:50000-65535, with some setup paths observed on
    19294-19344, bypassing the TCP pf-rdr. We BPF-observe it and raw-inject
    low-TTL decoy STUN primes on the 5-tuple, leaving the real flow untouched."""
    global _pf_applied, _geph_up
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
    while True:
        now = time.time()
        if now - last_tick > 30:
            # macOS slept: our 5s cadence jumped, so the scapy sniffer/send socket
            # and possibly pf are stale. Force a sniffer rebuild (cur_iface=None);
            # _l3send self-heals, and the pf/geph checks below re-arm the rest.
            print(f">> woke from sleep (gap {now - last_tick:.0f}s) -> re-arming",
                  file=sys.stderr)
            cur_iface = None
            start_canaries_if_due("wake", force=True)
        last_tick = now
        iface = default_iface()
        if iface != last_iface:
            if last_iface is not None:
                start_canaries_if_due("network_change", force=True)
            last_iface = iface
        # Hysteresis: a few failed probes (geph busy under load, or briefly
        # re-establishing its tunnel) must NOT flip us to "down" — that drops
        # geo-blocked hosts to local desync (RU exit IP -> Anthropic/CF 403).
        # Only declare down after 3 consecutive misses (~15s of real outage).
        if probe_geph():
            geph_strikes = 0
            up = True
        else:
            geph_strikes += 1
            up = geph_strikes < 3
        was_geph, _geph_up = _geph_up, up
        if _geph_up != was_geph:
            print(f">> geph SOCKS {'up' if _geph_up else 'down'} "
                  f"(:{_geph_port if _geph_up else GEPH_PORTS}) — geo-blocked hosts "
                  f"{'tunnelled' if _geph_up else 'on local desync'}", file=sys.stderr)
            if not first_tick:
                start_canaries_if_due("geph_up" if _geph_up else "geph_down", force=True)
        # Coexist with the user's own VPN: when a full-tunnel VPN owns the default
        # route (utun*) it already bypasses DPI, so drop our pf rules to avoid any
        # conflict; re-arm automatically when the VPN drops.
        vpn = bool(iface) and iface.startswith("utun")
        if vpn:
            if _pf_applied:
                print(f">> VPN up (default via {iface}) -> Slipstream dormant",
                      file=sys.stderr)
                _run("pfctl", "-f", "/etc/pf.conf")
                _pf_applied = False
        else:
            if not _pf_applied:
                print(">> no VPN -> Slipstream active", file=sys.stderr)
                _pf_load(port)
                _pf_applied = True
                start_canaries_if_due("pf_reapply", force=True)
            elif not pf_has_rules(port):
                print(">> pf rules vanished — re-applying", file=sys.stderr)
                _pf_load(port)
                start_canaries_if_due("pf_reapply", force=True)
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
                    print(f">> voice sniffer failed on {iface}: {e}", file=sys.stderr)
                    cur_iface = None
        write_status("dormant" if vpn else "active", iface, cur_iface)
        if first_tick:
            start_canaries_if_due("startup", force=True)
            start_route_policy_remote_update_if_due("startup")
            first_tick = False
        else:
            start_canaries_if_due("periodic")
            start_route_policy_remote_update_if_due("periodic")
        time.sleep(5)


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
async def splice(src, dst):
    total = 0
    try:
        while True:
            data = await src.read(65536)
            if not data:
                break
            total += len(data)
            dst.write(data)
            await dst.drain()
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        try:
            dst.close()
        except Exception:
            pass
    return total


async def pump(reader, up_w):
    total = 0
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            total += len(data)
            up_w.write(data)
            await up_w.drain()
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        try:
            up_w.close()
        except Exception:
            pass
    return total


# Control-RPC port paired with each SOCKS port (ours :9955 / the GUI's :12222).
GEPH_CONTROL = {9954: 9955, 9909: 12222}


def probe_geph():
    """Is a geph tunnel actually carrying sessions right now? (monitor, every 5s).
    Liveness comes from the control RPC (conn_info reports ESTABLISHED sessions
    without opening a new stream), NOT a fresh SOCKS5-CONNECT — that stream probe
    intermittently failed under normal tunnel load, mis-reporting geph "down",
    which fired fail-closed and dropped live app connections (the Claude/Codex
    reconnects). geph's own process was stable throughout; only our probe flapped."""
    global _geph_port
    if not GEPH_ENABLED:
        _geph_port = None
        return False
    # Sticky: re-check the LAST-GOOD port first, only then the rest. Stops the
    # daemon oscillating 9954<->9909 (ours vs the user's GUI) when both are up —
    # port churn mid-session breaks live connections and spams up/down logs.
    order = GEPH_PORTS
    if _geph_port in GEPH_PORTS and _geph_port != GEPH_PORTS[0]:
        order = [_geph_port] + [p for p in GEPH_PORTS if p != _geph_port]
    for p in order:
        if _geph_live(p):
            _geph_port = p
            return True
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
        return gr, gw
    except Exception:
        try:
            gw.close()
        except Exception:
            pass
        return None


async def dial_plain(ip, port, first_flight):
    """Plain direct dial (no desync, no tunnel) for traffic we must not tamper
    with — Telegram MTProto. Sends the buffered first flight verbatim; returns
    (reader, writer) or None."""
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=6)
        w.write(first_flight)
        await w.drain()
        return r, w
    except Exception:
        return None


async def dial_and_probe(real_ip, port, first_blob, probe_timeout=2.5):
    """Connect, send the (split) first flight, wait for the first server bytes.
    Returns (up_r, up_w, server_first) or None if no response in time."""
    try:
        up_r, up_w = await asyncio.wait_for(
            asyncio.open_connection(real_ip, port, family=socket.AF_INET), timeout=5)
    except Exception:
        return None
    try:
        up_w.write(first_blob)
        await up_w.drain()
        data = await asyncio.wait_for(up_r.read(65536), probe_timeout)
        if data:
            return up_r, up_w, data
    except (asyncio.TimeoutError, OSError):
        pass
    try:
        up_w.close()
    except Exception:
        pass
    return None


async def dial_and_probe_fake(real_ip, port, first_blob, host=None, probe_timeout=3.0):
    """Like dial_and_probe but injects a low-TTL decoy ClientHello on the real
    4-tuple BEFORE the real flight (zapret 'fake' — for deep-reassembly SNIs)."""
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
            return up_r, up_w, data
    except (asyncio.TimeoutError, OSError):
        pass
    try:
        up_w.close()
    except Exception:
        pass
    return None


async def dial_strategy(ip, port, head, body, host, strat):
    blob = make_blob(head, body, host, strat["cap"])
    if strat["fake"]:
        return await dial_and_probe_fake(ip, port, blob, host=host)
    return await dial_and_probe(ip, port, blob)


async def handle(reader, writer):
    global _conn_count
    _conn_count += 1
    try:
        await _handle_impl(reader, writer)
    finally:
        _conn_count -= 1


async def _handle_impl(reader, writer):
    sock = writer.get_extra_info("socket")
    try:
        dst_ip, dst_port = orig_dst(sock)
    except OSError as e:
        if VERBOSE:
            print(f"  DIOCNATLOOK failed: {e}", file=sys.stderr)
        writer.close()
        return
    if dst_port == PROXY_PORT and dst_ip.startswith("127."):
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
        res = await asyncio.gather(pump(reader, uw), splice(ur, writer))
        down_b = res[1] or 0
        dur = time.monotonic() - t0
        if down_b > 0:
            note_telegram_direct_success()
        elif dur < 20:
            note_telegram_direct_failure("empty direct response")
        return

    # Split-tunnel: a geo-blocked service (refuses RU IPs) goes through geph's
    # SOCKS5 tunnel. geph is the ONLY honest path for these hosts — local desync
    # would exit on the Russian IP and earn a hard 403 ("Request not allowed")
    # that makes apps like Claude DROP their session (forcing a manual re-login).
    # So FAIL CLOSED on any geph trouble (down during a ~20-30s respawn, or the
    # CONNECT failed): close the connection so the client retries until geph is
    # back, instead of leaking the geo-host to an RU exit. (Russian services are
    # excluded by geph_route and fall through to desync as normal.) A user-owned
    # Smart DNS can take this branch first, but only after canaries have proven
    # that the DNS-provided path is live; any runtime miss falls back to Geph.
    if is_tls and geph_route(host):
        policy = route_policy(host)
        note_quic_block_ips([dst_ip])
        if smart_dns_route_enabled(host):
            smart = await _try_smart_dns_geo_connect(host, dst_port, head + body)
            if smart:
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
                    try:
                        up_w.close()
                    except Exception:
                        pass
                    writer.close()
                    return
                await asyncio.gather(pump(reader, up_w), splice(up_r, writer))
                return
            _smart_dns_mark_failure(
                host,
                "smart dns runtime probe failed",
                policy["service_group"],
            )
        if _geph_up:
            g = await dial_via_geph(host, dst_port, head + body)
            if g:
                gr, gw = g
                if VERBOSE:
                    print(f"OK {host}:{dst_port} via geph tunnel", file=sys.stderr)
                t0 = time.monotonic()
                res = await asyncio.gather(pump(reader, gw), splice(gr, writer))
                down_b = res[1] or 0
                if down_b == 0 and time.monotonic() - t0 < 10:
                    log_geph_route_failure(host, "remote closed without response")
                else:
                    clear_geph_route_failure()
                return
            log_geph_route_failure(host, "SOCKS connect failed")
        else:
            log_geph_route_failure(host, "tunnel down")
        if VERBOSE:
            print(f"  geph unavailable for geo-host {host} -> fail closed "
                  f"(no RU leak, client will retry)", file=sys.stderr)
        writer.close()
        return

    # de-poison: resolve the SNI over DoH/system DNS -> LIST of real IPs
    # (fallback dst_ip). Some CDN edges are bad while neighbors work.
    policy = route_policy(host)
    real_ips = await resolve_connection_ips(host, dst_ip)
    ip_limit = ip_attempt_limit(host)

    # Adaptive strategy ladder (auto-sweep / self-tuning). Try strategies in
    # order — cached winner for this host first — across up to a couple of real
    # IPs (some Cloudflare IPs are IP-blocked while others work). First success
    # is cached per host so a decayed strategy auto-rolls to the next that works.
    result = None
    chosen = real_ips[0]
    chosen_name = None
    if not is_tls:
        for ip in real_ips[:ip_limit]:
            result = await dial_and_probe(ip, dst_port, head + body)
            if result:
                chosen = ip
                break
    else:
        now = time.monotonic()
        # known-dead host -> 1 fast-fail attempt instead of the full 7-attempt ladder
        max_attempts = 1 if (host and _dead.get(host, 0) > now) else 7
        attempts = 0
        for strat in strategy_order(host):
            strat_ok = False
            for ip in real_ips[:ip_limit]:
                attempts += 1
                result = await dial_strategy(ip, dst_port, head, body, host, strat)
                if result:
                    chosen, chosen_name = ip, strat["name"]
                    strat_ok = True
                    _record_strategy_result(host, strat["name"], True)
                    break
                if attempts >= max_attempts:
                    break
            if not strat_ok:
                _record_strategy_result(host, strat["name"], False)
            if result or attempts >= max_attempts:
                break
        if result:
            if host:
                _dead.pop(host, None)
                if _strat_cache.get(host) != chosen_name:
                    remember_strategy(host, chosen_name)
                if chosen_name != "plain":
                    note_quic_block_ips([dst_ip, chosen, *real_ips[:ip_limit]])
        elif host:
            _dead[host] = now + DEAD_TTL        # arm the negative cache
            if len(_dead) > 4096:
                _dead.clear()

    if not result:
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
        try:
            up_w.close()
        except Exception:
            pass
        writer.close()
        return
    t0 = time.monotonic()
    res = await asyncio.gather(pump(reader, up_w), splice(up_r, writer))
    # adaptive: a host that keeps closing with no real content is geo-blocked ->
    # learn it for the geph tunnel (this connection went local; the next routes).
    if is_tls and host:
        note_local_result(host, len(server_first) + (res[1] or 0),
                          time.monotonic() - t0)
    if VERBOSE and is_discord_host(host):
        up_b, down_b = res[0] or 0, len(server_first) + (res[1] or 0)
        print(f"  closed {host}: up={up_b} down={down_b} "
              f"dur={time.monotonic() - t0:.1f}s", file=sys.stderr)


LAUNCHD_LABEL = "dev.slipstream.tproxy"
LAUNCHD_PLIST = f"/Library/LaunchDaemons/{LAUNCHD_LABEL}.plist"
LOG_PATH = "/var/log/slipstream.log"
OBSOLETE_NEWSYSLOG_CONFIG_PATH = f"/etc/newsyslog.d/{LAUNCHD_LABEL}.conf"
INSTALL_DIR = "/usr/local/slipstream"   # NOT under ~/Documents (TCC-protected)
LOG_MAX_BYTES = 1024 * 1024
LOG_BACKUPS = 5


def active_console_gid(console_path="/dev/console"):
    try:
        uid = os.stat(console_path).st_uid
        if uid:
            return pwd.getpwuid(uid).pw_gid
    except (AttributeError, KeyError, OSError):
        pass
    return 0


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
        if os.path.exists(self.path) and os.path.getsize(self.path) >= self.max_bytes:
            self._rotate()
        else:
            self._open()

    def _open(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._file = open(self.path, "a", buffering=1)
        try:
            os.chown(self.path, 0, active_console_gid())
        except (AttributeError, PermissionError, OSError):
            pass
        os.chmod(self.path, 0o640)
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


def do_install(port):
    # Install a self-contained copy under /usr/local (a root LaunchDaemon has NO
    # TCC access to ~/Documents). Two modes:
    #  - frozen (PyInstaller onedir): copy the self-contained bundle, run the binary
    #  - script (dev): copy tproxy.py + build a venv with scapy
    secret_path = os.path.join(INSTALL_DIR, "tgws-secret")
    try:
        tgws_secret_backup = open(secret_path).read()
    except Exception:
        tgws_secret_backup = None
    _run("launchctl", "bootout", "system", LAUNCHD_PLIST)      # stop old daemon before replacing files
    if getattr(sys, "frozen", False):
        src = os.path.dirname(os.path.abspath(sys.executable))
        _replace_tree_resilient(src, INSTALL_DIR)
        binary = os.path.join(INSTALL_DIR, os.path.basename(sys.executable))
        prog_args = [binary, "--port", str(port)]
        uninstall_hint = f"sudo {binary} --uninstall"
    else:
        os.makedirs(INSTALL_DIR, exist_ok=True)
        script = os.path.join(INSTALL_DIR, "tproxy.py")
        _copy_file_resilient(os.path.abspath(__file__), script, mode=0o644)
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
            print(">> building self-contained venv + scapy (needs network, ~20s)...")
            if _run(base, "-m", "venv", venv).returncode != 0:
                print("venv create failed", file=sys.stderr)
                return
            # cryptography is REQUIRED too: the vendored tg-ws-proxy's _aes.py falls
            # back to a ctypes libcrypto shim without it, which macOS aborts ("loading
            # libcrypto in an unsafe way") -> the daemon crash-loops. certifi gives
            # the GitHub CF-domain refresh a CA bundle in frozen/script installs.
            r = _run(py, "-m", "pip", "install", "--quiet",
                     "--disable-pip-version-check", "scapy", "cryptography", "certifi")
            if r.returncode != 0:
                print("scapy/cryptography/certifi install failed (pypi reachable?):\n"
                      + r.stderr[-400:], file=sys.stderr)
                return
        prog_args = [py, script, "--port", str(port)]
        uninstall_hint = f"sudo {py} {script} --uninstall"
    if tgws_secret_backup:
        try:
            with open(secret_path, "w") as f:
                f.write(tgws_secret_backup.strip())
            os.chmod(secret_path, 0o600)
        except Exception:
            pass
    workdir = INSTALL_DIR
    prog_xml = "".join(f"<string>{a}</string>" for a in prog_args)
    plist = (
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
        f'  <key>StandardOutPath</key><string>{LOG_PATH}</string>\n'
        f'  <key>StandardErrorPath</key><string>{LOG_PATH}</string>\n'
        '</dict></plist>\n'
    )
    with open(LAUNCHD_PLIST, "w") as f:
        f.write(plist)
    os.chmod(LAUNCHD_PLIST, 0o644)
    remove_obsolete_newsyslog_config()
    _run("launchctl", "bootout", "system", LAUNCHD_PLIST)      # if already loaded
    r = _run("launchctl", "bootstrap", "system", LAUNCHD_PLIST)
    if r.returncode != 0:
        _run("launchctl", "load", "-w", LAUNCHD_PLIST)         # older macOS fallback
    print(f"installed -> {LAUNCHD_PLIST}")
    print(f"runs now + at every boot as root, auto-restarts on crash.")
    print(f"logs:      tail -f {LOG_PATH}")
    print(f"uninstall: {uninstall_hint}")


def do_uninstall():
    _run("launchctl", "bootout", "system", LAUNCHD_PLIST)
    _run("launchctl", "unload", "-w", LAUNCHD_PLIST)
    try:
        os.remove(LAUNCHD_PLIST)
    except Exception:
        pass
    remove_obsolete_newsyslog_config()
    _run("pfctl", "-f", "/etc/pf.conf")
    _run("pfctl", "-d")
    shutil.rmtree(INSTALL_DIR, ignore_errors=True)
    try:
        os.remove(_STRAT_PATH)             # drop any stale strategy cache
    except Exception:
        pass
    print("uninstalled + pf restored")


async def amain(port):
    try:
        server = await asyncio.start_server(
            handle, "127.0.0.1", port, reuse_address=True)
    except OSError as e:
        if e.errno == 48:
            print(f"\nport {port} already in use — another tproxy is still running.\n"
                  f"kill it and retry:\n  sudo lsof -ti tcp:{port} | xargs sudo kill\n",
                  file=sys.stderr)
        raise
    pf_setup(port)                       # grab pf only AFTER we hold the port
    print(f">> transparent tlsrec+DoH proxy on 127.0.0.1:{port}  (root)")
    print(">> quit + reopen Discord normally; its updater is captured too")
    print(">> Ctrl-C (or close terminal) to stop and restore pf")
    async with server:
        await server.serve_forever()


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
                    time.sleep(15)
                    continue
                set_tgws_state("error", repr(e))
                print(f">> tg-ws-proxy crashed: {e!r} -> restart in 5s",
                      file=sys.stderr)
                time.sleep(5)
            except Exception as e:
                set_tgws_state("error", repr(e))
                print(f">> tg-ws-proxy crashed: {e!r} -> restart in 5s",
                      file=sys.stderr)
                time.sleep(5)

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
                    help="remove the LaunchDaemon and restore pf")
    ap.add_argument("--status", action="store_true",
                    help="print daemon status JSON and exit (no root needed)")
    args = ap.parse_args()
    VERBOSE = args.verbose

    if args.status:
        try:
            with open(STATUS_PATH) as f:
                line = f.read().strip()
            # treat a stale file (>15s) as off — the daemon writes every 5s
            st = json.loads(line)
            if time.time() - st.get("ts", 0) > 15:
                line = '{"state": "off"}'
            print(line)
        except Exception:
            print('{"state": "off"}')
        return

    if os.geteuid() != 0:
        print("must run as root:  sudo python3 tproxy.py", file=sys.stderr)
        sys.exit(1)

    if args.install:
        do_install(args.port)
        return
    if args.uninstall:
        do_uninstall()
        return

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

    cleanup_stale()        # kill leftover instances + reset pf before we start
    setup_rotating_logs()   # keep launchd stdout/stderr bounded across long runs
    load_strat_cache()     # remember per-host winning strategies across restarts
    load_auto_geph()       # remember hosts learned to need the geph tunnel
    try:
        trusted_policy_keys = load_trusted_route_policy_keys()
    except Exception as exc:
        trusted_policy_keys = dict(TRUSTED_ROUTE_POLICY_KEYS)
        _set_route_policy_remote("key_error", error=str(exc))
        print(f">> route policy keys unavailable: {exc}", file=sys.stderr)
    load_persisted_route_policy(trusted_policy_keys)

    # guard thread: voice sniffer follows the default iface + pf self-heal
    threading.Thread(target=network_monitor, args=(args.port,),
                     kwargs={"voice": not args.no_voice}, daemon=True).start()

    # bundled Telegram MTProto proxy (tg-ws-proxy) — local :1443, points Telegram
    # past the DC-IP block via WSS. Best-effort; never blocks daemon startup.
    start_tgws_proxy()

    atexit.register(pf_teardown)
    # Catch close-terminal (SIGHUP) and suspend (SIGTSTP, i.e. Ctrl+Z) too — a
    # network tool holding pf must never be left half-alive in the background.
    for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGTSTP):
        signal.signal(s, lambda *_: (pf_teardown(), os._exit(0)))

    _pf_fd = os.open("/dev/pf", os.O_RDWR)
    try:
        asyncio.run(amain(args.port))
    except KeyboardInterrupt:
        pass
    finally:
        pf_teardown()


if __name__ == "__main__":
    main()
