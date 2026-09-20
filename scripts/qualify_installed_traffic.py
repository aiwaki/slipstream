"""Bounded public-payload checks; process/status readiness is not traffic proof."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib


URL = "https://media.discordapp.net/stickers/1228092333061443654.png"
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


def probe(path, runner=subprocess.run):
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
                   "--write-out", "%{http_code}", URL]
        try:
            result = runner(command, capture_output=True, text=True, timeout=12)
            body = body_path.read_bytes() if body_path.exists() else b""
            valid = result.returncode == 0 and result.stdout.strip() == "200" and complete_png(body)
            return {"path": path, "pass": valid, "exit_code": result.returncode,
                    "http_status": result.stdout.strip(), "bytes": len(body)}
        except (OSError, subprocess.TimeoutExpired):
            return {"path": path, "pass": False, "error": "probe_unavailable_or_timed_out"}


def qualify(runner=subprocess.run):
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda path: probe(path, runner),
                                ("proxy_ipv4", "proxy_ipv6", "transparent")))
    return {"status": "pass" if all(item["pass"] for item in results) else "fail",
            "scope": "public_complete_png_tcp", "results": results}


if __name__ == "__main__":
    report = qualify()
    print(json.dumps(report))
    raise SystemExit(0 if report["status"] == "pass" else 1)
