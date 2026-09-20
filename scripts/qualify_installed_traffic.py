"""Bounded public-payload checks; process/status readiness is not traffic proof."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib


URL = "https://media.discordapp.net/stickers/1228092333061443654.png"
URLS = (URL, "https://cdn.discordapp.com/stickers/1228092333061443654.png")
MIN_BYTES = 64 * 1024
MAX_BYTES = 2 * 1024 * 1024


def complete_png(body):
    """Require full chunk framing, CRCs and terminal IEND, not just a PNG prefix."""
    if not body.startswith(b"\x89PNG\r\n\x1a\n") or len(body) > MAX_BYTES:
        return False
    offset, chunks, has_data = 8, 0, False
    while offset + 12 <= len(body):
        size = struct.unpack_from("!I", body, offset)[0]
        end = offset + 12 + size
        if end > len(body):
            return False
        kind = body[offset + 4:offset + 8]
        data = body[offset + 8:end - 4]
        crc = struct.unpack_from("!I", body, end - 4)[0]
        if zlib.crc32(kind + data) & 0xffffffff != crc:
            return False
        if chunks == 0 and (kind != b"IHDR" or size != 13):
            return False
        has_data |= kind == b"IDAT" and size > 0
        if kind == b"IEND":
            return size == 0 and end == len(body) and has_data
        offset, chunks = end, chunks + 1
    return False


def probe(path, runner=subprocess.run, url=URL):
    routes = {
        "proxy_ipv4": ["--noproxy", "", "--proxy", "http://127.0.0.1:1080"],
        "proxy_ipv6": ["--noproxy", "", "--proxy", "http://[::1]:1080"],
        "transparent": ["--noproxy", "*"],
    }
    with tempfile.TemporaryDirectory(prefix="slipstream-traffic-") as directory:
        body_path = Path(directory) / "payload"
        command = ["/usr/bin/curl", "-q", "--silent", "--show-error",
                   "--connect-timeout", "3", "--max-time", "10",
                   "--max-filesize", str(MAX_BYTES), "--proto", "=https",
                   *routes[path], "--output", str(body_path),
                   "--write-out", "%{http_code}", url]
        try:
            result = runner(command, capture_output=True, text=True, timeout=12)
            body = body_path.read_bytes() if body_path.exists() else b""
            valid = result.returncode == 0 and result.stdout.strip() == "200" and len(body) >= MIN_BYTES and complete_png(body)
            return {"path": path, "url": url, "pass": valid, "exit_code": result.returncode,
                    "http_status": result.stdout.strip(), "bytes": len(body)}
        except (OSError, subprocess.TimeoutExpired):
            return {"path": path, "url": url, "pass": False, "error": "probe_unavailable_or_timed_out"}


def qualify(runner=subprocess.run):
    paths = ("proxy_ipv4", "proxy_ipv6", "transparent")
    # One bounded request per delivery host and route; no retry loop and no
    # unrelated neutral host that could hide a broken Discord media route.
    with ThreadPoolExecutor(max_workers=6) as pool:
        attempts = list(pool.map(lambda pair: probe(pair[0], runner, pair[1]),
                                 ((path, url) for path in paths for url in URLS)))
    results = []
    for path in paths:
        route = [item for item in attempts if item["path"] == path]
        chosen = next((item for item in route if item["pass"]), route[0])
        results.append({**chosen, "attempts": route})
    return {"status": "pass" if all(item["pass"] for item in results) else "fail",
            "scope": "public_complete_png_tcp", "results": results}


if __name__ == "__main__":
    report = qualify()
    print(json.dumps(report))
    raise SystemExit(0 if report["status"] == "pass" else 1)
