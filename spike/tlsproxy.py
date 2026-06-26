#!/usr/bin/env python3
"""tlsproxy — local SOCKS5 proxy that applies TLS-record desync (Spike 2).

The tcpsweep probe proved `tlsrec_sni` (splitting the ClientHello into two TLS
records at the SNI) beats this network's DPI for Discord + YouTube, with NO root.
This turns that winning strategy into a usable local SOCKS5 proxy so Discord and
browsers can route through it and actually connect.

NOT production. Becomes the Rust `bypassd` TCP plane. No root, no VPN, no pf.

Run (rootless):
    python3 tlsproxy.py            # listens on 127.0.0.1:1080

Steer Discord desktop through it (no root, no system change — fully quit Discord first):
    open -a Discord --args --proxy-server=socks5://127.0.0.1:1080

Steer a browser: point its SOCKS5 proxy at 127.0.0.1:1080 (Firefox: Settings ->
Network -> Manual -> SOCKS v5 host 127.0.0.1 port 1080, "proxy DNS when using SOCKS5").
"""
import argparse
import asyncio
import ipaddress
import socket
import struct
import sys

LISTEN_HOST, LISTEN_PORT = "127.0.0.1", 1080
DESYNC = True   # set False via --no-desync to A/B test passthrough vs tlsrec
VERBOSE = False  # --verbose: log every connection (diagnostics)


FIRST_REC_CAP = 64  # keep the FIRST TLS record tiny — see note below


def tlsrec_split(record_head: bytes, body: bytes, host: str) -> list[bytes]:
    """Re-frame one ClientHello record into 2-3 records.

    Empirically (user's TSPU): the desync works only when the FIRST TLS record
    is SMALL. Browsers send large ClientHellos (~1700-2300B) with the SNI at a
    randomised offset; a single `find(SNI)+len/2` cut makes record1 large when
    the SNI sits late -> DPI parses it -> re-blocks. So: always emit a tiny first
    record (<= FIRST_REC_CAP), plus a cut inside the SNI hostname to break SNI
    matching even on a reassembling parser. record1 stays tiny regardless of
    where the SNI is.
    """
    typ, ver = record_head[0:1], record_head[1:3]
    n = len(body)
    i = body.find(host.encode())
    if i < 0:
        i = max(1, n // 2)
    c1 = min(FIRST_REC_CAP, max(1, i - 1))          # tiny first record
    c2 = min(n - 1, i + max(1, len(host) // 2))     # cut inside the SNI hostname
    cuts = sorted(c for c in {c1, c2} if 0 < c < n)

    parts, prev = [], 0
    for c in cuts:
        if c > prev:
            parts.append(body[prev:c])
            prev = c
    parts.append(body[prev:])

    def mk(payload: bytes) -> bytes:
        return typ + ver + struct.pack("!H", len(payload)) + payload

    return [mk(p) for p in parts]


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    try:
        # --- SOCKS5 greeting ---
        ver, nmethods = struct.unpack("!BB", await reader.readexactly(2))
        if ver != 5:
            writer.close()
            return
        await reader.readexactly(nmethods)
        writer.write(b"\x05\x00")                 # no-auth
        await writer.drain()

        # --- SOCKS5 request ---
        ver, cmd, _rsv, atyp = struct.unpack("!BBBB", await reader.readexactly(4))
        if atyp == 1:                              # IPv4
            host = str(ipaddress.IPv4Address(await reader.readexactly(4)))
        elif atyp == 3:                            # domain
            ln = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(ln)).decode("ascii", "replace")
        elif atyp == 4:                            # IPv6
            host = str(ipaddress.IPv6Address(await reader.readexactly(16)))
        else:
            writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain(); writer.close(); return
        port = struct.unpack("!H", await reader.readexactly(2))[0]

        if cmd != 1:                               # only CONNECT
            writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain(); writer.close(); return

        if VERBOSE:
            print(f"CONNECT {host}:{port}", file=sys.stderr)

        # --- connect upstream ---
        try:
            # Force IPv4: the DPI/desync path is validated on v4, and IPv6
            # paths to Cloudflare-fronted hosts behave differently (different
            # block behaviour + data-path stalls). DPI-bypass tools target v4.
            up_r, up_w = await asyncio.wait_for(
                asyncio.open_connection(host, port, family=socket.AF_INET),
                timeout=10)
        except Exception as e:
            print(f"[upstream {host}:{port}] connect failed: {e!r}", file=sys.stderr)
            writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")  # refused
            await writer.drain(); writer.close(); return

        writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")      # success
        await writer.drain()

        # --- relay: tlsrec on the first client flight (443), then splice ---
        results = await asyncio.gather(
            _client_to_upstream(reader, up_w, host, port),
            _splice(up_r, writer),
        )
        if VERBOSE:
            srv = results[1] or 0
            print(f"  {host}:{port} server_bytes={srv} "
                  f"{'OK' if srv > 0 else 'NO RESPONSE (blocked?)'}",
                  file=sys.stderr)
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        print(f"[{peer}] error: {e!r}", file=sys.stderr)
    finally:
        writer.close()


async def _client_to_upstream(reader, up_w, host, port):
    try:
        if port == 443 and DESYNC:
            head = await reader.readexactly(5)
            if head[0] == 0x16:                    # TLS handshake record
                rec_len = struct.unpack("!H", head[3:5])[0]
                body = await reader.readexactly(rec_len)
                frags = tlsrec_split(head, body, host)
                if VERBOSE:
                    print(f"  tlsrec {host}: CH={rec_len} -> recs="
                          f"{[len(f) for f in frags]}", file=sys.stderr)
                # CRITICAL: emit both records in ONE write == ONE TCP segment.
                # Sending them as two writes (two segments) lets a TCP-reassembling
                # DPI concatenate the handshake across records and recover the SNI,
                # which re-blocks (empirically: two writes fail on Discord's path,
                # one write succeeds). Matches the validated tcpsweep behaviour.
                up_w.write(b"".join(frags))
                await up_w.drain()
            else:
                up_w.write(head)
                await up_w.drain()
        while True:
            data = await reader.read(65536)
            if not data:
                break
            up_w.write(data)
            await up_w.drain()
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try:
            up_w.close()
        except Exception:
            pass


async def _splice(src, dst):
    total = 0
    try:
        while True:
            data = await src.read(65536)
            if not data:
                break
            total += len(data)
            dst.write(data)
            await dst.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try:
            dst.close()
        except Exception:
            pass
    return total


async def amain(host, port):
    server = await asyncio.start_server(handle_client, host, port)
    addr = server.sockets[0].getsockname()
    print(f"tlsproxy (tlsrec) listening on socks5://{addr[0]}:{addr[1]}  (no root)")
    print("Discord:  open -a Discord --args --proxy-server=socks5://"
          f"{addr[0]}:{addr[1]}   (quit Discord fully first)")
    async with server:
        await server.serve_forever()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=LISTEN_HOST)
    ap.add_argument("--port", type=int, default=LISTEN_PORT)
    ap.add_argument("--no-desync", action="store_true",
                    help="passthrough (no tlsrec) — for A/B testing")
    ap.add_argument("--verbose", action="store_true",
                    help="log every connection (diagnostics)")
    args = ap.parse_args()
    global DESYNC, VERBOSE
    DESYNC = not args.no_desync
    VERBOSE = args.verbose
    try:
        asyncio.run(amain(args.host, args.port))
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
