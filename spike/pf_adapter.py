"""Low-level macOS PF operations for Slipstream's private anchor."""

import ctypes
import fcntl
import json
import os
import re
import stat
import struct
import tempfile


PFI_IFLAG_SKIP = 0x0100
DIOCSETIFFLAG = 0xC0284459
DIOCCLRIFFLAG = 0xC028445A
SKIP_LEASE_SCHEMA_VERSION = 1


class PfiocIface(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * 16),
        ("buffer", ctypes.c_void_p),
        ("esize", ctypes.c_int),
        ("size", ctypes.c_int),
        ("nzero", ctypes.c_int),
        ("flags", ctypes.c_int),
    ]


if ctypes.sizeof(PfiocIface) != 40:
    raise RuntimeError(f"unexpected macOS pfioc_iface size: {ctypes.sizeof(PfiocIface)}")


def parent_declarations(text, parent_anchor):
    rdr = re.search(
        rf'^\s*rdr-anchor\s+"{re.escape(parent_anchor)}"(?:\s+.*)?$',
        text,
        re.MULTILINE,
    )
    rules = re.search(
        rf'^\s*anchor\s+"{re.escape(parent_anchor)}"(?:\s+.*)?$',
        text,
        re.MULTILINE,
    )
    return bool(rdr and rules)


def parent_anchor_available(config_path, parent_anchor):
    try:
        with open(config_path, encoding="utf-8") as handle:
            return parent_declarations(handle.read(), parent_anchor)
    except OSError:
        return False


def parent_anchor_loaded(runner, parent_anchor):
    nat = runner("pfctl", "-sn")
    rules = runner("pfctl", "-sr")
    if nat.returncode != 0 or rules.returncode != 0:
        return False
    return parent_declarations(nat.stdout + "\n" + rules.stdout, parent_anchor)


def anchor_calls(text, directive):
    pattern = re.compile(
        rf'^\s*{re.escape(directive)}\s+"([^"]+)"', re.MULTILINE
    )
    return pattern.findall(text)


def anchor_child(parent, child):
    if child.startswith("/"):
        return child.lstrip("/")
    if not parent:
        return child
    return f"{parent}/{child}"


def rule_targets_https(line, action):
    action_match = (
        re.search(r"^\s*rdr\b", line)
        if action == "rdr"
        else re.search(r"\broute-to\b", line)
    )
    return bool(
        action_match and re.search(r"\bport\b[^\n]*\b443\b", line)
    )


def anchor_has_https_action(
    runner,
    anchor,
    action,
    directive,
    visited=None,
):
    visited = set() if visited is None else visited
    anchor = anchor.lstrip("/")
    if not anchor or anchor in visited:
        return False
    visited.add(anchor)
    flag = "-sn" if action == "rdr" else "-sr"
    result = runner("pfctl", "-a", anchor, flag)
    if result.returncode != 0:
        return False
    if any(rule_targets_https(line, action) for line in result.stdout.splitlines()):
        return True
    return any(
        anchor_has_https_action(
            runner,
            anchor_child(anchor, child),
            action,
            directive,
            visited,
        )
        for child in anchor_calls(result.stdout, directive)
    )


def anchors_before_parent(text, directive, parent_anchor):
    anchors = []
    for anchor in anchor_calls(text, directive):
        if anchor == parent_anchor:
            break
        anchors.append(anchor.lstrip("/"))
    return anchors


def preceding_https_interceptors(runner, parent_anchor):
    nat = runner("pfctl", "-sn")
    rules = runner("pfctl", "-sr")
    if nat.returncode != 0 or rules.returncode != 0:
        return []
    redirects = {
        anchor
        for anchor in anchors_before_parent(nat.stdout, "rdr-anchor", parent_anchor)
        if anchor_has_https_action(runner, anchor, "rdr", "rdr-anchor")
    }
    routes = {
        anchor
        for anchor in anchors_before_parent(rules.stdout, "anchor", parent_anchor)
        if anchor_has_https_action(runner, anchor, "route-to", "anchor")
    }
    return sorted(redirects & routes)


def token_from_result(result):
    output = f"{result.stdout}\n{result.stderr}"
    match = re.search(r"Token\s*:\s*([0-9]+)", output, re.IGNORECASE)
    return match.group(1) if match else None


def write_token(token, path):
    tmp = f"{path}.tmp.{os.getpid()}"
    try:
        with open(tmp, "w", encoding="ascii") as handle:
            handle.write(token + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def read_token(path):
    try:
        with open(path, encoding="ascii") as handle:
            token = handle.read().strip()
    except OSError:
        return None
    return token if token.isdigit() else None


def remove_token(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def enabled_state(runner):
    """Return PF's enabled state, or None when it cannot be inspected."""
    info = runner("pfctl", "-s", "info")
    if info.returncode != 0:
        return None
    return "Status: Enabled" in info.stdout


def interface_skip_state(runner, interface):
    """Return whether PF skips an interface, or None when not provable."""
    result = runner("pfctl", "-v", "-s", "Interfaces")
    if result.returncode != 0:
        return None
    plain = interface
    skipped = f"{interface} (skip)"
    for line in result.stdout.splitlines():
        value = line.strip()
        if value == skipped:
            return True
        if value == plain:
            return False
    return None


def set_interface_skip(
    runner,
    interface,
    enabled,
    device_path="/dev/pf",
    opener=None,
    ioctl_fn=None,
):
    """Set only PFI_IFLAG_SKIP and prove the resulting kernel state."""
    if not isinstance(enabled, bool):
        raise ValueError("PF interface skip state must be boolean")
    encoded = interface.encode("ascii")
    if not encoded or len(encoded) >= 16:
        raise ValueError(f"invalid PF interface name: {interface!r}")
    request = PfiocIface()
    request.name = encoded
    request.flags = PFI_IFLAG_SKIP
    payload = bytearray(
        ctypes.string_at(ctypes.addressof(request), ctypes.sizeof(request))
    )
    command = DIOCSETIFFLAG if enabled else DIOCCLRIFFLAG
    opener = open if opener is None else opener
    ioctl_fn = fcntl.ioctl if ioctl_fn is None else ioctl_fn
    with opener(device_path, "r+b", buffering=0) as device:
        ioctl_fn(device.fileno(), command, payload, True)
    return interface_skip_state(runner, interface) == enabled


def _fsync_parent(path):
    parent = os.path.dirname(os.fspath(path)) or "."
    directory = os.open(parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def write_skip_lease(path, interface, owner_pid):
    """Persist ownership before clearing an externally supplied skip flag."""
    if interface != "lo0":
        raise ValueError("PF skip lease may own only lo0")
    if (
        not isinstance(owner_pid, int)
        or isinstance(owner_pid, bool)
        or owner_pid <= 0
    ):
        raise ValueError("invalid PF skip lease owner")
    payload = {
        "interface": interface,
        "owner_pid": owner_pid,
        "restore_skip": True,
        "schema_version": SKIP_LEASE_SCHEMA_VERSION,
    }
    parent = os.path.dirname(os.fspath(path)) or "."
    prefix = f".{os.path.basename(os.fspath(path))}."
    descriptor, tmp = tempfile.mkstemp(prefix=prefix, dir=parent, text=True)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            descriptor = -1
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        _fsync_parent(path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def read_skip_lease(path):
    try:
        metadata = os.lstat(path)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.geteuid()
        ):
            raise ValueError("invalid PF skip lease")
        with open(path, encoding="ascii") as handle:
            payload = json.load(handle)
    except FileNotFoundError:
        return None
    if not isinstance(payload, dict):
        raise ValueError("invalid PF skip lease")
    if (
        payload.get("schema_version") != SKIP_LEASE_SCHEMA_VERSION
        or payload.get("interface") != "lo0"
        or payload.get("restore_skip") is not True
        or not isinstance(payload.get("owner_pid"), int)
        or isinstance(payload.get("owner_pid"), bool)
        or payload["owner_pid"] <= 0
    ):
        raise ValueError("invalid PF skip lease")
    return payload


def remove_skip_lease(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        return
    _fsync_parent(path)


def flush_private_anchor(runner, anchor):
    # `pfctl -F all` includes global state even when -a is present on macOS.
    rules = runner("pfctl", "-a", anchor, "-F", "rules")
    nat = runner("pfctl", "-a", anchor, "-F", "nat")
    return rules if rules.returncode != 0 else nat


# Darwin PF ABI address families: AF_INET=2, AF_INET6=30.
class PfAddrWrap(ctypes.Structure):
    # Darwin pfvar.h: 32-byte address/mask union, aligned pointer union, type.
    _fields_ = [("address_mask", ctypes.c_ubyte * 32),
                ("pointer", ctypes.c_uint64), ("type", ctypes.c_uint8),
                ("iflags", ctypes.c_uint8)]


class PfStateAddrKill(ctypes.Structure):
    _fields_ = [("address", PfAddrWrap), ("reserved", ctypes.c_uint8 * 3),
                ("neg", ctypes.c_uint8), ("ports", ctypes.c_uint16 * 2),
                ("op", ctypes.c_uint8), ("xport_padding", ctypes.c_uint8 * 3)]


class PfiocStateKill(ctypes.Structure):
    _fields_ = [("af", ctypes.c_uint8), ("proto", ctypes.c_uint8),
                ("variant", ctypes.c_uint8), ("pad", ctypes.c_uint8),
                ("src", PfStateAddrKill), ("dst", PfStateAddrKill),
                ("ifname", ctypes.c_char * 16), ("owner", ctypes.c_char * 64)]


def _loopback_state_kill_request(family, port, reverse=False):
    """Darwin exact loopback endpoints + TCP + one exact service port only."""
    if family not in (2, 30) or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid loopback state selector")
    if (ctypes.sizeof(PfAddrWrap), ctypes.sizeof(PfStateAddrKill),
            ctypes.sizeof(PfiocStateKill)) != (48, 64, 216):
        raise RuntimeError("unsupported Darwin PF state-kill ABI")
    request = PfiocStateKill()
    request.af, request.proto = family, 6
    address = (b"\x7f\x00\x00\x01" if family == 2 else b"\x00" * 15 + b"\x01")
    for endpoint in (request.src, request.dst):
        endpoint.address.address_mask[:len(address)] = address
        endpoint.address.address_mask[16:16 + len(address)] = b"\xff" * len(address)
    endpoint = request.src if reverse else request.dst
    endpoint.ports[0] = endpoint.ports[1] = struct.unpack("=H", struct.pack("!H", port))[0]
    endpoint.op = 2  # PF_OP_EQ
    return bytearray(ctypes.string_at(ctypes.addressof(request), ctypes.sizeof(request)))


def clear_inactive_loopback_proxy_states(runner, port, *, opener=None, ioctl_fn=None):
    """Call only while both exclusive listener sockets are bound, not listening.

    Refuse if any old kernel connection/listener is alive or the snapshot cannot
    be understood. A bound non-listening socket prevents new successful accepts
    during the check. Never clear remote/translated tuples or another port.
    """
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid proxy port")
    result = runner("/usr/sbin/lsof", "-nP", f"-iTCP:{port}", "-FpnT")
    if result.stderr or result.returncode not in (0, 1):
        return False
    if result.returncode == 1:
        if result.stdout.strip():
            return False
    else:
        # lsof emits one f/n/TST record per socket, including our bound CLOSED
        # sockets. Missing state or unfamiliar output is never absence proof.
        records = re.split(r"(?m)^f[^\n]*\n", result.stdout)[1:]
        if not records:
            return False
        for record in records:
            states = re.findall(r"(?m)^TST=(\S+)$", record)
            if not re.search(r"(?m)^n.+$", record) or len(states) != 1:
                return False
            if states[0] not in ("TIME_WAIT", "CLOSED"):
                return False
    opener = open if opener is None else opener
    ioctl_fn = fcntl.ioctl if ioctl_fn is None else ioctl_fn
    with opener("/dev/pf", "r+b", buffering=0) as device:
        for family in (2, 30):
            for reverse in (False, True):
                payload = _loopback_state_kill_request(family, port, reverse)
                command = 0xC0000000 | (len(payload) << 16) | (ord("D") << 8) | 41
                ioctl_fn(device.fileno(), command, payload, True)
    return True


def load_private_anchor(runner, anchor, rules_template, port):
    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".slipstream.pf.conf", delete=False
    )
    handle.write(rules_template.format(port=port))
    handle.close()
    try:
        return runner("pfctl", "-a", anchor, "-f", handle.name)
    finally:
        try:
            os.unlink(handle.name)
        except FileNotFoundError:
            pass


def _dual_stack_private_rules_loaded(nat, rules, port):
    return (
        f"port {port}" in nat
        and "-> 127.0.0.1" in nat
        and "inet6" in nat
        and "-> ::1" in nat
        and "route-to (lo0 127.0.0.1)" in rules
        and "route-to (lo0 ::1)" in rules
        and "inet6" in rules
    )


def private_rules_loaded(runner, anchor, port, parent_loaded):
    if not parent_loaded():
        return False
    nat = runner("pfctl", "-a", anchor, "-sn")
    rules = runner("pfctl", "-a", anchor, "-sr")
    return (
        nat.returncode == 0
        and rules.returncode == 0
        and _dual_stack_private_rules_loaded(nat.stdout, rules.stdout, port)
    )


def state_snapshot(runner, anchor, port, applied, conflicts, parent_loaded):
    info = runner("pfctl", "-s", "info")
    anchor_nat = runner("pfctl", "-a", anchor, "-sn")
    anchor_rules = runner("pfctl", "-a", anchor, "-sr")
    is_parent_loaded = parent_loaded()
    return {
        "applied": bool(applied),
        "enabled": info.returncode == 0 and "Status: Enabled" in info.stdout,
        "anchor": anchor,
        "parent_loaded": is_parent_loaded,
        "interceptor_conflicts": list(conflicts),
        "rules_loaded": (
            is_parent_loaded
            and anchor_nat.returncode == 0
            and anchor_rules.returncode == 0
            and _dual_stack_private_rules_loaded(
                anchor_nat.stdout,
                anchor_rules.stdout,
                port,
            )
        ),
    }
