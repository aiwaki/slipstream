"""Bounded loopback HTTPS CONNECT admission; never decrypts browser TLS.

CONNECT authority belongs to this stream, not an IP cache or outer ECH SNI.
Only public DNS names on 443 are accepted. The caller owns stream cleanup.
"""
import asyncio
import ipaddress
import re


MAX_HEADER_BYTES = 8192
HEADER_TIMEOUT = 10
DNS_TIMEOUT = 5
PAC_PATH = '/slipstream-https.pac'


def pac_script(port):
    # Keep non-HTTPS, non-443 and intranet traffic on its original route. DNS
    # here uses the browser/system resolver; no resolver setting is changed.
    return ('''function FindProxyForURL(url, host) {
  if (!/^https:\\/\\/[^/:]+(?::443)?\\//i.test(url) ||
      isPlainHostName(host) || shExpMatch(host, "*.local") ||
      /^[0-9.]+$/.test(host) || host.indexOf(":") >= 0) return "DIRECT";
  var ip = dnsResolve(host);
  if (!ip || isInNet(ip, "127.0.0.0", "255.0.0.0") ||
      isInNet(ip, "10.0.0.0", "255.0.0.0") ||
      isInNet(ip, "172.16.0.0", "255.240.0.0") ||
      isInNet(ip, "192.168.0.0", "255.255.0.0") ||
      isInNet(ip, "169.254.0.0", "255.255.0.0")) return "DIRECT";
  return "PROXY 127.0.0.1:PORT";
}
'''.replace('PORT', str(port))).encode('ascii')
_NAME = re.compile(r"(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\Z")


def parse_authority(header):
    text = header.decode("ascii")
    lines = text.split("\r\n")
    if lines[-2:] != ["", ""]:
        raise ValueError("incomplete header")
    parts = lines[0].split(" ")
    if len(parts) != 3 or parts[0] != "CONNECT" or parts[2] not in (
        "HTTP/1.0", "HTTP/1.1"
    ):
        raise ValueError("CONNECT required")
    authority = parts[1].lower()
    if not authority.endswith(":443"):
        raise ValueError("HTTPS port required")
    host = authority[:-4]
    if not _NAME.fullmatch(host) or "." not in host:
        raise ValueError("DNS name required")
    if any(not label or len(label) > 63 or label.startswith("-")
           or label.endswith("-") for label in host.split(".")):
        raise ValueError("invalid DNS label")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("numeric authority forbidden")
    seen = set()
    for line in lines[1:-2]:
        if not line or line[0].isspace() or ":" not in line:
            raise ValueError("invalid header")
        name, value = line.split(":", 1)
        name = name.lower()
        if not re.fullmatch(r"[a-z0-9!#$%&'*+.^_`|~-]+", name):
            raise ValueError("invalid field name")
        if any(ord(char) < 32 and char != "\t" or ord(char) == 127 for char in value):
            raise ValueError("invalid field value")
        if name in {"content-length", "transfer-encoding"}:
            raise ValueError("CONNECT body forbidden")
        if name == "host" and (name in seen or value.strip().lower() != authority):
            raise ValueError("conflicting authority")
        seen.add(name)
    return host


async def admit(reader, writer, resolve, prefix=b""):
    """Return (hostname, public address, 443), leaving tunnel bytes unread."""
    peer = writer.get_extra_info("peername")
    if not peer or not ipaddress.ip_address(peer[0]).is_loopback:
        raise ValueError("loopback clients only")

    async def read_header():
        data = bytearray(prefix)
        while not data.endswith(b"\r\n\r\n"):
            if len(data) >= MAX_HEADER_BYTES:
                raise ValueError("header too large")
            data.extend(await reader.readexactly(1))
        return bytes(data)

    try:
        header = await asyncio.wait_for(read_header(), HEADER_TIMEOUT)
        if header.split(b'\r\n', 1)[0] in (
            b'GET /slipstream-https.pac HTTP/1.1',
            b'GET /slipstream-https.pac HTTP/1.0',
        ):
            endpoint = writer.get_extra_info('sockname')
            payload = pac_script(endpoint[1])
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\n'
                         b'Cache-Control: no-store\r\nConnection: close\r\nContent-Length: '
                         + str(len(payload)).encode('ascii') + b'\r\n\r\n' + payload)
            await writer.drain()
            return None
        host = parse_authority(header)
    except (ValueError, UnicodeError, asyncio.IncompleteReadError, asyncio.TimeoutError):
        writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
        await writer.drain()
        raise ValueError("invalid CONNECT") from None
    try:
        addresses = await asyncio.wait_for(resolve(host), DNS_TIMEOUT)
        # Reject mixed private/public answers, rather than turning this root
        # process into an access path to a local or link-local service.
        if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
            raise ValueError("non-public destination")
    except (OSError, ValueError, asyncio.TimeoutError):
        writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
        await writer.drain()
        raise ValueError("CONNECT resolution failed") from None
    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await writer.drain()
    return host, addresses[0], 443
