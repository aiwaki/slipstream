"""Fail-closed macOS provenance for a browser-origin TCP connection.

The module deliberately does not accept a URL or hostname.  Its only input is
the local peer endpoint observed by the transparent relay, and its public
result contains no browsing data.  Exact-host capability binding remains the
caller's responsibility.
"""

from __future__ import annotations

import ipaddress
import os
import re
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import Callable, Protocol, Sequence


LSOF_PATH = "/usr/sbin/lsof"
PS_PATH = "/bin/ps"
CODESIGN_PATH = "/usr/bin/codesign"
LSAPPINFO_PATH = "/usr/bin/lsappinfo"
IOREG_PATH = "/usr/sbin/ioreg"

_CHROME_TEAM_ID = "EQHXZ8M8AV"
_MAX_EXECUTABLE_PATH_BYTES = 4_096


class BrowserFamily(str, Enum):
    SAFARI = "safari"
    CHROME = "chrome"


class AdmissionReason(str, Enum):
    ACCEPTED = "accepted"
    INVALID_PEER = "invalid_peer"
    OWNER_NOT_FOUND = "owner_not_found"
    AMBIGUOUS_OWNER = "ambiguous_owner"
    PROCESS_IDENTITY_FAILED = "process_identity_failed"
    SIGNATURE_FAILED = "signature_failed"
    ANCESTRY_FAILED = "ancestry_failed"
    NOT_FRONTMOST = "not_frontmost"
    INPUT_NOT_RECENT = "input_not_recent"
    OBSERVATION_CHANGED = "observation_changed"
    DEADLINE_EXCEEDED = "deadline_exceeded"


@dataclass(frozen=True)
class BrowserNavigationProvenance:
    accepted: bool
    browser_family: BrowserFamily | None
    pid: int | None
    reason: AdmissionReason


@dataclass(frozen=True)
class AdmissionPolicy:
    total_budget_seconds: float = 1.0
    command_timeout_seconds: float = 0.25
    recent_input_seconds: float = 5.0
    max_ancestry_depth: int = 12
    max_command_output_bytes: int = 16_384
    allow_shared_signed_webkit_with_frontmost_safari: bool = False

    def __post_init__(self) -> None:
        if not 0.0 < self.total_budget_seconds <= 8.0:
            raise ValueError("total_budget_seconds must be in (0, 8]")
        if not 0.0 < self.command_timeout_seconds <= self.total_budget_seconds:
            raise ValueError("command_timeout_seconds must fit the total budget")
        if not 0.0 <= self.recent_input_seconds <= 30.0:
            raise ValueError("recent_input_seconds must be in [0, 30]")
        if not 1 <= self.max_ancestry_depth <= 32:
            raise ValueError("max_ancestry_depth must be in [1, 32]")
        if not 1_024 <= self.max_command_output_bytes <= 65_536:
            raise ValueError("max_command_output_bytes must be in [1024, 65536]")
        if not isinstance(self.allow_shared_signed_webkit_with_frontmost_safari, bool):
            raise ValueError("shared WebKit policy must be a boolean")


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    output: str
    truncated: bool = False


class CommandRunner(Protocol):
    def __call__(
        self,
        argv: Sequence[str],
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> CommandResult: ...


Clock = Callable[[], float]
PathResolver = Callable[[str], str]


@dataclass(frozen=True)
class _LsofRecord:
    pid: int
    uid: int
    command: str
    endpoints: tuple[str, ...]
    established: bool


@dataclass(frozen=True)
class _ProcessSnapshot:
    pid: int
    ppid: int
    uid: int
    executable: str


@dataclass(frozen=True)
class _Signature:
    identifier: str
    team_identifier: str | None
    designated_requirement: str


@dataclass(frozen=True)
class _FrontmostApplication:
    asn: str
    bundle_identifier: str
    pid: int


class _BudgetExpired(Exception):
    pass


class _ObservationFailure(Exception):
    def __init__(self, reason: AdmissionReason) -> None:
        super().__init__(reason.value)
        self.reason = reason


class SystemCommandRunner:
    """Run a fixed argv without a shell and stop reading at a hard byte limit."""

    def __call__(
        self,
        argv: Sequence[str],
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> CommandResult:
        if not argv or timeout_seconds <= 0.0 or max_output_bytes <= 0:
            return CommandResult(126, "")
        if any(not isinstance(part, str) or "\x00" in part for part in argv):
            return CommandResult(126, "")

        try:
            process = subprocess.Popen(
                tuple(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                close_fds=True,
                start_new_session=True,
                env={
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "LANG": "C",
                    "LC_ALL": "C",
                    # macOS ps otherwise ellipsizes long WebKit executable paths.
                    "COLUMNS": "4096",
                },
            )
        except (OSError, ValueError):
            return CommandResult(126, "")

        assert process.stdout is not None
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout_seconds
        output = bytearray()
        pipe_open = True

        try:
            while pipe_open or process.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0.0:
                    self._kill(process)
                    return CommandResult(124, "")

                events = selector.select(min(remaining, 0.05))
                for key, _ in events:
                    try:
                        chunk = os.read(key.fd, min(4_096, max_output_bytes + 1 - len(output)))
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        pipe_open = False
                        continue
                    output.extend(chunk)
                    if len(output) > max_output_bytes:
                        self._kill(process)
                        return CommandResult(125, "", truncated=True)

                if process.poll() is not None and not events and pipe_open:
                    # Give the pipe one final bounded drain after process exit.
                    continue

            returncode = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except (OSError, subprocess.TimeoutExpired):
            self._kill(process)
            return CommandResult(124, "")
        finally:
            selector.close()
            process.stdout.close()

        try:
            decoded = bytes(output).decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return CommandResult(126, "")
        return CommandResult(returncode, decoded)

    @staticmethod
    def _kill(process: subprocess.Popen[bytes]) -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=0.1)
        except subprocess.TimeoutExpired:
            pass


class _BudgetedObserver:
    def __init__(
        self,
        runner: CommandRunner,
        clock: Clock,
        policy: AdmissionPolicy,
    ) -> None:
        self._runner = runner
        self._clock = clock
        self._policy = policy
        self._deadline = clock() + policy.total_budget_seconds

    def run(self, argv: Sequence[str]) -> str:
        remaining = self._deadline - self._clock()
        if remaining <= 0.0:
            raise _BudgetExpired
        result = self._runner(
            tuple(argv),
            min(self._policy.command_timeout_seconds, remaining),
            self._policy.max_command_output_bytes,
        )
        if self._clock() >= self._deadline:
            raise _BudgetExpired
        if result.returncode != 0 or result.truncated:
            raise _ObservationFailure(AdmissionReason.PROCESS_IDENTITY_FAILED)
        if len(result.output.encode("utf-8")) > self._policy.max_command_output_bytes:
            raise _ObservationFailure(AdmissionReason.PROCESS_IDENTITY_FAILED)
        return result.output


def assess_browser_navigation_provenance(
    peer_address: str,
    peer_port: int,
    *,
    runner: CommandRunner | None = None,
    clock: Clock = time.monotonic,
    path_resolver: PathResolver = os.path.realpath,
    policy: AdmissionPolicy = AdmissionPolicy(),
) -> BrowserNavigationProvenance:
    """Verify that a relay peer is a foreground, recently-used Safari/Chrome.

    Rejections intentionally omit the observed PID and browser family.  The
    accepted PID is the socket-owning leaf process, not the application PID.
    Acceptance may admit a bounded local preflight; it is not evidence for
    route learning by itself and cannot identify a particular browser tab.

    The opt-in shared-WebKit policy is intentionally narrower than normal
    ancestry: it binds an Apple-signed WebKit networking XPC to an independently
    verified, stable, frontmost Apple-signed Safari process.  It remains off by
    default because macOS does not expose the originating tab here.
    """

    peer = _validated_peer(peer_address, peer_port)
    if peer is None:
        return _rejected(AdmissionReason.INVALID_PEER)
    normalized_address, normalized_port = peer

    observer = _BudgetedObserver(runner or SystemCommandRunner(), clock, policy)
    try:
        initial_lsof = observer.run(_lsof_argv(normalized_address, normalized_port))
        initial_owners = _matching_lsof_owners(
            initial_lsof,
            normalized_address,
            normalized_port,
        )
        if not initial_owners:
            return _rejected(AdmissionReason.OWNER_NOT_FOUND)
        if len(initial_owners) != 1:
            return _rejected(AdmissionReason.AMBIGUOUS_OWNER)
        owner = initial_owners[0]

        leaf = _read_process(observer, owner.pid)
        if leaf.uid != owner.uid or leaf.uid == 0:
            return _rejected(AdmissionReason.PROCESS_IDENTITY_FAILED)
        leaf_path = _resolved_executable(leaf.executable, path_resolver)
        family = _family_for_leaf_path(leaf_path)
        if family is None:
            return _rejected(AdmissionReason.PROCESS_IDENTITY_FAILED)
        if not _verify_signature(observer, leaf_path, family, root=False):
            return _rejected(AdmissionReason.SIGNATURE_FAILED)

        root = _find_signed_application_ancestor(
            observer,
            leaf,
            leaf_path,
            family,
            path_resolver,
            policy.max_ancestry_depth,
        )
        if root is None:
            if not (
                policy.allow_shared_signed_webkit_with_frontmost_safari
                and family is BrowserFamily.SAFARI
                and _is_webkit_network_path(leaf_path)
            ):
                return _rejected(AdmissionReason.ANCESTRY_FAILED)
            frontmost = _read_frontmost(observer)
            if frontmost.bundle_identifier != "com.apple.Safari":
                return _rejected(AdmissionReason.NOT_FRONTMOST)
            root = _read_process(observer, frontmost.pid)
            root_path = _resolved_executable(root.executable, path_resolver)
            if root.uid != leaf.uid or not _is_root_path(BrowserFamily.SAFARI, root_path):
                return _rejected(AdmissionReason.NOT_FRONTMOST)
            if not _verify_signature(
                observer,
                root_path,
                BrowserFamily.SAFARI,
                root=True,
            ):
                return _rejected(AdmissionReason.SIGNATURE_FAILED)
        else:
            frontmost = _read_frontmost(observer)

        if (
            frontmost.pid != root.pid
            or frontmost.bundle_identifier != _root_bundle_identifier(family)
        ):
            return _rejected(AdmissionReason.NOT_FRONTMOST)

        if _read_hid_idle_seconds(observer) > policy.recent_input_seconds:
            return _rejected(AdmissionReason.INPUT_NOT_RECENT)

        repeated_leaf = _read_process(observer, owner.pid)
        if repeated_leaf != leaf:
            return _rejected(AdmissionReason.OBSERVATION_CHANGED)
        if root.pid != leaf.pid and _read_process(observer, root.pid) != root:
            return _rejected(AdmissionReason.OBSERVATION_CHANGED)

        final_lsof = observer.run(_lsof_argv(normalized_address, normalized_port))
        if _matching_lsof_owners(final_lsof, normalized_address, normalized_port) != [owner]:
            return _rejected(AdmissionReason.OBSERVATION_CHANGED)

        if _read_frontmost(observer) != frontmost:
            return _rejected(AdmissionReason.OBSERVATION_CHANGED)

        return BrowserNavigationProvenance(
            accepted=True,
            browser_family=family,
            pid=owner.pid,
            reason=AdmissionReason.ACCEPTED,
        )
    except _BudgetExpired:
        return _rejected(AdmissionReason.DEADLINE_EXCEEDED)
    except _ObservationFailure as failure:
        return _rejected(failure.reason)
    except (OSError, ValueError, UnicodeError):
        return _rejected(AdmissionReason.PROCESS_IDENTITY_FAILED)


def _rejected(reason: AdmissionReason) -> BrowserNavigationProvenance:
    return BrowserNavigationProvenance(False, None, None, reason)


def _validated_peer(address: str, port: int) -> tuple[str, int] | None:
    if not isinstance(address, str) or not isinstance(port, int) or isinstance(port, bool):
        return None
    if "%" in address or not 1 <= port <= 65_535:
        return None
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    if parsed.is_unspecified or parsed.is_multicast:
        return None
    return parsed.compressed, port


def _lsof_argv(address: str, port: int) -> tuple[str, ...]:
    selector_address = f"[{address}]" if ":" in address else address
    return (
        LSOF_PATH,
        "-nP",
        "-a",
        f"-iTCP@{selector_address}:{port}",
        "-sTCP:ESTABLISHED",
        "-FpcunT",
    )


def _parse_lsof_records(output: str) -> list[_LsofRecord]:
    records: list[_LsofRecord] = []
    current: dict[str, object] | None = None

    def finish() -> None:
        nonlocal current
        if current is None:
            return
        try:
            pid = int(str(current["pid"]), 10)
            uid = int(str(current["uid"]), 10)
            command = str(current.get("command", ""))
            endpoints = tuple(str(value) for value in current.get("endpoints", []))
            established = bool(current.get("established", False))
        except (KeyError, TypeError, ValueError):
            current = None
            return
        if pid > 1 and uid >= 0 and len(command) <= 256 and endpoints:
            records.append(_LsofRecord(pid, uid, command, endpoints, established))
        current = None

    if "\x00" in output:
        return []
    for line in output.splitlines():
        if not line:
            continue
        field, value = line[0], line[1:]
        if field == "p":
            finish()
            current = {"pid": value, "endpoints": []}
        elif current is None:
            continue
        elif field == "c":
            current["command"] = value
        elif field == "u":
            current["uid"] = value
        elif field == "n":
            endpoints = current["endpoints"]
            assert isinstance(endpoints, list)
            if len(endpoints) < 32 and len(value) <= 1_024:
                endpoints.append(value)
        elif field == "T" and value == "ST=ESTABLISHED":
            current["established"] = True
    finish()
    return records


def _matching_lsof_owners(output: str, address: str, port: int) -> list[_LsofRecord]:
    matched: list[_LsofRecord] = []
    for record in _parse_lsof_records(output):
        if record.uid == 0 or not record.established:
            continue
        if any(_endpoint_matches(endpoint, address, port) for endpoint in record.endpoints):
            matched.append(record)
    return matched


def _endpoint_matches(endpoint: str, address: str, port: int) -> bool:
    local = endpoint.split("->", 1)[0]
    if local.startswith("["):
        match = re.fullmatch(r"\[([^]]+)]:(\d{1,5})", local)
        if match is None:
            return False
        endpoint_address, endpoint_port = match.groups()
    else:
        try:
            endpoint_address, endpoint_port = local.rsplit(":", 1)
        except ValueError:
            return False
    try:
        return (
            ipaddress.ip_address(endpoint_address) == ipaddress.ip_address(address)
            and int(endpoint_port, 10) == port
        )
    except ValueError:
        return False


def _read_process(observer: _BudgetedObserver, pid: int) -> _ProcessSnapshot:
    output = observer.run(
        (PS_PATH, "-ww", "-p", str(pid), "-o", "pid=", "-o", "ppid=", "-o", "uid=", "-o", "comm=")
    )
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) != 1:
        raise _ObservationFailure(AdmissionReason.PROCESS_IDENTITY_FAILED)
    parts = lines[0].split(maxsplit=3)
    if len(parts) != 4:
        raise _ObservationFailure(AdmissionReason.PROCESS_IDENTITY_FAILED)
    try:
        observed_pid, ppid, uid = (int(part, 10) for part in parts[:3])
    except ValueError as error:
        raise _ObservationFailure(AdmissionReason.PROCESS_IDENTITY_FAILED) from error
    executable = parts[3]
    if observed_pid != pid or ppid < 0 or uid < 0 or not _safe_absolute_path(executable):
        raise _ObservationFailure(AdmissionReason.PROCESS_IDENTITY_FAILED)
    return _ProcessSnapshot(observed_pid, ppid, uid, executable)


def _safe_absolute_path(path: str) -> bool:
    if (
        not path.startswith("/")
        or "\x00" in path
        or "\n" in path
        or len(path.encode("utf-8")) > _MAX_EXECUTABLE_PATH_BYTES
    ):
        return False
    return ".." not in PurePosixPath(path).parts


def _resolved_executable(path: str, resolver: PathResolver) -> str:
    resolved = resolver(path)
    if not isinstance(resolved, str) or not _safe_absolute_path(resolved):
        raise _ObservationFailure(AdmissionReason.PROCESS_IDENTITY_FAILED)
    return resolved


_SAFARI_ROOT_PATHS = (
    re.compile(r"^/Applications/Safari\.app/Contents/MacOS/Safari$"),
    re.compile(r"^/System/Applications/Safari\.app/Contents/MacOS/Safari$"),
    re.compile(
        r"^/System/Volumes/Preboot/Cryptexes/App/System/Applications/"
        r"Safari\.app/Contents/MacOS/Safari$"
    ),
)
_WEBKIT_NETWORK_PATHS = (
    re.compile(
        r"^/System/Library/Frameworks/WebKit\.framework/Versions/[A-Z]/XPCServices/"
        r"com\.apple\.WebKit\.Networking\.xpc/Contents/MacOS/"
        r"com\.apple\.WebKit\.Networking$"
    ),
    re.compile(
        r"^/System/Volumes/Preboot/Cryptexes/OS/System/Library/Frameworks/"
        r"WebKit\.framework/Versions/[A-Z]/XPCServices/"
        r"com\.apple\.WebKit\.Networking\.xpc/Contents/MacOS/"
        r"com\.apple\.WebKit\.Networking$"
    ),
)
_CHROME_ROOT_PATH = re.compile(
    r"^/Applications/Google Chrome\.app/Contents/MacOS/Google Chrome$"
)
_CHROME_HELPER_PATH = re.compile(
    r"^/Applications/Google Chrome\.app/Contents/Frameworks/"
    r"Google Chrome Framework\.framework/Versions/[^/]+/Helpers/"
    r"Google Chrome Helper(?: \([^)]+\))?\.app/Contents/MacOS/"
    r"Google Chrome Helper(?: \([^)]+\))?$"
)


def _matches_any(path: str, patterns: Sequence[re.Pattern[str]]) -> bool:
    return any(pattern.fullmatch(path) is not None for pattern in patterns)


def _family_for_leaf_path(path: str) -> BrowserFamily | None:
    if _matches_any(path, (*_SAFARI_ROOT_PATHS, *_WEBKIT_NETWORK_PATHS)):
        return BrowserFamily.SAFARI
    if _CHROME_ROOT_PATH.fullmatch(path) or _CHROME_HELPER_PATH.fullmatch(path):
        return BrowserFamily.CHROME
    return None


def _is_root_path(family: BrowserFamily, path: str) -> bool:
    if family is BrowserFamily.SAFARI:
        return _matches_any(path, _SAFARI_ROOT_PATHS)
    return _CHROME_ROOT_PATH.fullmatch(path) is not None


def _is_webkit_network_path(path: str) -> bool:
    return _matches_any(path, _WEBKIT_NETWORK_PATHS)


def _verify_signature(
    observer: _BudgetedObserver,
    path: str,
    family: BrowserFamily,
    *,
    root: bool,
) -> bool:
    try:
        observer.run((CODESIGN_PATH, "--verify", "--strict", "--verbose=2", path))
        output = observer.run(
            (CODESIGN_PATH, "--display", "--verbose=4", "--requirements", "-", path)
        )
    except _ObservationFailure:
        return False
    signature = _parse_signature(output)
    if signature is None:
        return False

    if family is BrowserFamily.SAFARI:
        if _is_root_path(family, path):
            expected_identifier = "com.apple.Safari"
        elif _is_webkit_network_path(path) and not root:
            expected_identifier = "com.apple.WebKit.Networking"
        else:
            return False
        return (
            signature.identifier == expected_identifier
            and "anchor apple" in signature.designated_requirement.lower()
        )

    if _is_root_path(family, path):
        identifier_ok = signature.identifier == "com.google.Chrome"
    elif _CHROME_HELPER_PATH.fullmatch(path) and not root:
        identifier_ok = bool(
            re.fullmatch(
                r"com\.google\.Chrome(?:\.helper(?:\.[A-Za-z0-9_-]+)?)?",
                signature.identifier,
            )
        )
    else:
        return False
    requirement = signature.designated_requirement
    return (
        identifier_ok
        and signature.team_identifier == _CHROME_TEAM_ID
        and "anchor apple generic" in requirement.lower()
        and re.search(
            r"certificate leaf\[subject\.OU]\s*=\s*\"?EQHXZ8M8AV\"?",
            requirement,
        )
        is not None
    )


def _parse_signature(output: str) -> _Signature | None:
    identifiers = re.findall(r"^Identifier=([^\r\n]+)$", output, flags=re.MULTILINE)
    teams = re.findall(r"^TeamIdentifier=([^\r\n]+)$", output, flags=re.MULTILINE)
    requirements = re.findall(r"^designated => (.+)$", output, flags=re.MULTILINE)
    if len(identifiers) != 1 or len(requirements) != 1 or len(teams) > 1:
        return None
    team = teams[0] if teams and teams[0] != "not set" else None
    return _Signature(identifiers[0], team, requirements[0])


def _find_signed_application_ancestor(
    observer: _BudgetedObserver,
    leaf: _ProcessSnapshot,
    leaf_path: str,
    family: BrowserFamily,
    resolver: PathResolver,
    max_depth: int,
) -> _ProcessSnapshot | None:
    current = leaf
    current_path = leaf_path
    seen: set[int] = set()
    for _ in range(max_depth):
        if current.pid in seen or current.uid != leaf.uid:
            return None
        seen.add(current.pid)
        if _is_root_path(family, current_path):
            if _verify_signature(observer, current_path, family, root=True):
                return current
            return None
        if current.ppid <= 1:
            return None
        current = _read_process(observer, current.ppid)
        current_path = _resolved_executable(current.executable, resolver)
    return None


def _root_bundle_identifier(family: BrowserFamily) -> str:
    if family is BrowserFamily.SAFARI:
        return "com.apple.Safari"
    return "com.google.Chrome"


def _read_frontmost(observer: _BudgetedObserver) -> _FrontmostApplication:
    asn = _parse_front_asn(observer.run((LSAPPINFO_PATH, "front")))
    output = observer.run(
        (LSAPPINFO_PATH, "info", "-only", "bundleID", "-only", "pid", asn)
    )
    bundle_ids = re.findall(
        r'^"CFBundleIdentifier"="([^"\r\n]+)"$', output, flags=re.MULTILINE
    )
    pids = re.findall(r'^"pid"=(\d+)$', output, flags=re.MULTILINE)
    if len(bundle_ids) != 1 or len(pids) != 1:
        raise _ObservationFailure(AdmissionReason.NOT_FRONTMOST)
    pid = int(pids[0], 10)
    if pid <= 1:
        raise _ObservationFailure(AdmissionReason.NOT_FRONTMOST)
    return _FrontmostApplication(asn, bundle_ids[0], pid)


def _parse_front_asn(output: str) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) != 1 or re.fullmatch(r"ASN:0x[0-9a-fA-F]+-0x[0-9a-fA-F]+:", lines[0]) is None:
        raise _ObservationFailure(AdmissionReason.NOT_FRONTMOST)
    return lines[0]


def _read_hid_idle_seconds(observer: _BudgetedObserver) -> float:
    output = observer.run(
        (IOREG_PATH, "-c", "IOHIDSystem", "-d", "1", "-r", "-k", "HIDIdleTime")
    )
    values = re.findall(r'"HIDIdleTime"\s*=\s*(\d+)', output)
    if len(values) != 1:
        raise _ObservationFailure(AdmissionReason.INPUT_NOT_RECENT)
    nanoseconds = int(values[0], 10)
    if nanoseconds < 0:
        raise _ObservationFailure(AdmissionReason.INPUT_NOT_RECENT)
    return nanoseconds / 1_000_000_000.0


__all__ = [
    "AdmissionPolicy",
    "AdmissionReason",
    "BrowserFamily",
    "BrowserNavigationProvenance",
    "CommandResult",
    "SystemCommandRunner",
    "assess_browser_navigation_provenance",
]
