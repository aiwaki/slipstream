from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

import pytest

from macos_browser_provenance import (
    AdmissionPolicy,
    AdmissionReason,
    BrowserFamily,
    CommandResult,
    assess_browser_navigation_provenance,
)
from macos_browser_provenance import (
    CODESIGN_PATH,
    IOREG_PATH,
    LSOF_PATH,
    LSAPPINFO_PATH,
    PS_PATH,
    _matching_lsof_owners,
)


SAFARI_PATH = "/Applications/Safari.app/Contents/MacOS/Safari"
WEBKIT_PATH = (
    "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/"
    "com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking"
)
CRYPTEX_SAFARI_PATH = (
    "/System/Volumes/Preboot/Cryptexes/App/System/Applications/"
    "Safari.app/Contents/MacOS/Safari"
)
CRYPTEX_WEBKIT_PATH = (
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library/Frameworks/"
    "WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/"
    "Contents/MacOS/com.apple.WebKit.Networking"
)
CHROME_PATH = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
CHROME_HELPER_PATH = (
    "/Applications/Google Chrome.app/Contents/Frameworks/"
    "Google Chrome Framework.framework/Versions/151.0.7922.77/Helpers/"
    "Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper"
)


@dataclass
class FakeClock:
    value: float = 100.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


@dataclass
class FixtureRunner:
    clock: FakeClock
    owner_pid: int = 201
    owner_uid: int = 501
    endpoint: str = "127.0.0.1:54321->93.184.216.34:443"
    processes: dict[int, tuple[int, int, str]] = field(
        default_factory=lambda: {
            201: (200, 501, WEBKIT_PATH),
            200: (1, 501, SAFARI_PATH),
        }
    )
    front_bundle: str = "com.apple.Safari"
    front_pid: int = 200
    idle_nanoseconds: int = 250_000_000
    advance_per_call: float = 0.0
    lsof_outputs: list[str] = field(default_factory=list)
    signature_overrides: dict[str, str] = field(default_factory=dict)
    verify_failures: set[str] = field(default_factory=set)
    calls: list[tuple[tuple[str, ...], float, int]] = field(default_factory=list)
    _lsof_index: int = 0

    def __call__(
        self,
        argv: Sequence[str],
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> CommandResult:
        command = tuple(argv)
        self.calls.append((command, timeout_seconds, max_output_bytes))
        self.clock.advance(self.advance_per_call)
        assert timeout_seconds > 0
        assert 1_024 <= max_output_bytes <= 65_536

        if command[0] == LSOF_PATH:
            if self.lsof_outputs:
                index = min(self._lsof_index, len(self.lsof_outputs) - 1)
                output = self.lsof_outputs[index]
                self._lsof_index += 1
            else:
                output = self._lsof(self.owner_pid, self.owner_uid, self.endpoint)
            return CommandResult(0, output)

        if command[0] == PS_PATH:
            pid = int(command[command.index("-p") + 1])
            process = self.processes.get(pid)
            if process is None:
                return CommandResult(1, "")
            ppid, uid, path = process
            return CommandResult(0, f"{pid} {ppid} {uid} {path}\n")

        if command[0] == CODESIGN_PATH:
            path = command[-1]
            if "--verify" in command:
                return CommandResult(1 if path in self.verify_failures else 0, "")
            return CommandResult(0, self.signature_overrides.get(path, self._signature(path)))

        if command == (LSAPPINFO_PATH, "front"):
            return CommandResult(0, "ASN:0x0-0xabc:\n")
        if command[:2] == (LSAPPINFO_PATH, "info"):
            return CommandResult(
                0,
                f'"CFBundleIdentifier"="{self.front_bundle}"\n"pid"={self.front_pid}\n',
            )
        if command[0] == IOREG_PATH:
            return CommandResult(0, f'    "HIDIdleTime" = {self.idle_nanoseconds}\n')
        raise AssertionError(f"unexpected command: {command!r}")

    @staticmethod
    def _lsof(pid: int, uid: int, endpoint: str) -> str:
        return (
            f"p{pid}\n"
            "cBrowserNet\n"
            f"u{uid}\n"
            f"n{endpoint}\n"
            "TST=ESTABLISHED\n"
        )

    @staticmethod
    def _signature(path: str) -> str:
        if path in {WEBKIT_PATH, CRYPTEX_WEBKIT_PATH}:
            identifier = "com.apple.WebKit.Networking"
            return (
                f"Executable={path}\nIdentifier={identifier}\nTeamIdentifier=not set\n"
                f'designated => identifier "{identifier}" and anchor apple\n'
            )
        if path in {SAFARI_PATH, CRYPTEX_SAFARI_PATH}:
            identifier = "com.apple.Safari"
            return (
                f"Executable={path}\nIdentifier={identifier}\nTeamIdentifier=not set\n"
                f'designated => identifier "{identifier}" and anchor apple\n'
            )
        if path == CHROME_HELPER_PATH:
            identifier = "com.google.Chrome.helper"
        elif path == CHROME_PATH:
            identifier = "com.google.Chrome"
        else:
            identifier = "invalid"
        return (
            f"Executable={path}\nIdentifier={identifier}\nTeamIdentifier=EQHXZ8M8AV\n"
            f'designated => identifier "{identifier}" and anchor apple generic and '
            'certificate leaf[subject.OU] = "EQHXZ8M8AV"\n'
        )


def assess(runner: FixtureRunner, **kwargs):
    return assess_browser_navigation_provenance(
        "127.0.0.1",
        54321,
        runner=runner,
        clock=runner.clock,
        path_resolver=lambda path: path,
        **kwargs,
    )


def test_structured_lsof_parser_matches_only_exact_local_endpoint() -> None:
    output = (
        FixtureRunner._lsof(201, 501, "127.0.0.1:54321->93.184.216.34:443")
        + FixtureRunner._lsof(202, 501, "127.0.0.1:54322->93.184.216.34:443")
    )

    records = _matching_lsof_owners(output, "127.0.0.1", 54321)

    assert [record.pid for record in records] == [201]


def test_structured_lsof_parser_handles_ipv6_without_substring_matching() -> None:
    output = FixtureRunner._lsof(301, 501, "[::1]:54321->[2606:4700::1111]:443")

    assert [record.pid for record in _matching_lsof_owners(output, "::1", 54321)] == [301]
    assert not _matching_lsof_owners(output, "::1", 5432)


def test_accepts_signed_foreground_safari_network_process_after_recent_input() -> None:
    clock = FakeClock()
    runner = FixtureRunner(clock)

    result = assess(runner)

    assert result.accepted is True
    assert result.browser_family is BrowserFamily.SAFARI
    assert result.pid == 201
    assert result.reason is AdmissionReason.ACCEPTED
    assert all(call[0][0].startswith("/") for call in runner.calls)
    assert all(call[2] == AdmissionPolicy().max_command_output_bytes for call in runner.calls)


def test_accepts_safari_paths_resolved_into_signed_system_cryptexes() -> None:
    clock = FakeClock()
    runner = FixtureRunner(clock)
    resolved = {WEBKIT_PATH: CRYPTEX_WEBKIT_PATH, SAFARI_PATH: CRYPTEX_SAFARI_PATH}

    result = assess_browser_navigation_provenance(
        "127.0.0.1",
        54321,
        runner=runner,
        clock=clock,
        path_resolver=lambda path: resolved.get(path, path),
    )

    assert result.accepted is True
    assert result.browser_family is BrowserFamily.SAFARI


def test_accepts_only_official_google_chrome_helper_and_signed_root() -> None:
    clock = FakeClock()
    runner = FixtureRunner(
        clock,
        processes={
            301: (300, 501, CHROME_HELPER_PATH),
            300: (1, 501, CHROME_PATH),
        },
        owner_pid=301,
        front_bundle="com.google.Chrome",
        front_pid=300,
    )

    result = assess(runner)

    assert result.accepted is True
    assert result.browser_family is BrowserFamily.CHROME
    assert result.pid == 301


def test_rejects_background_browser_even_when_socket_and_signatures_match() -> None:
    clock = FakeClock()
    runner = FixtureRunner(clock, front_bundle="com.openai.codex", front_pid=999)

    result = assess(runner)

    assert result == result.__class__(False, None, None, AdmissionReason.NOT_FRONTMOST)


def test_rejects_idle_mac() -> None:
    clock = FakeClock()
    runner = FixtureRunner(clock, idle_nanoseconds=6_000_000_000)

    result = assess(runner)

    assert result.accepted is False
    assert result.reason is AdmissionReason.INPUT_NOT_RECENT
    assert result.pid is None


def test_rejects_spoofed_lsof_owner_with_arbitrary_chromium_executable() -> None:
    clock = FakeClock()
    runner = FixtureRunner(
        clock,
        processes={201: (200, 501, "/Applications/Chromium.app/Contents/MacOS/Chromium")},
    )

    result = assess(runner)

    assert result.reason is AdmissionReason.PROCESS_IDENTITY_FAILED
    assert not any(call[0][0] == CODESIGN_PATH for call in runner.calls)


def test_rejects_google_named_helper_signed_by_wrong_team() -> None:
    clock = FakeClock()
    runner = FixtureRunner(
        clock,
        processes={
            301: (300, 501, CHROME_HELPER_PATH),
            300: (1, 501, CHROME_PATH),
        },
        owner_pid=301,
        front_bundle="com.google.Chrome",
        front_pid=300,
    )
    runner.signature_overrides[CHROME_HELPER_PATH] = (
        "Identifier=com.google.Chrome.helper\n"
        "TeamIdentifier=ATTACKER01\n"
        'designated => identifier "com.google.Chrome.helper" and anchor apple generic and '
        'certificate leaf[subject.OU] = "ATTACKER01"\n'
    )

    result = assess(runner)

    assert result.reason is AdmissionReason.SIGNATURE_FAILED
    assert result.browser_family is None


def test_rejects_shared_webkit_helper_without_safari_parent_ancestry() -> None:
    clock = FakeClock()
    runner = FixtureRunner(clock, processes={201: (1, 501, WEBKIT_PATH)})

    result = assess(runner)

    assert result.reason is AdmissionReason.ANCESTRY_FAILED


def test_opt_in_accepts_stable_shared_webkit_only_with_signed_frontmost_safari() -> None:
    clock = FakeClock()
    runner = FixtureRunner(
        clock,
        processes={
            201: (1, 501, WEBKIT_PATH),
            200: (1, 501, SAFARI_PATH),
        },
    )
    policy = AdmissionPolicy(allow_shared_signed_webkit_with_frontmost_safari=True)

    result = assess(runner, policy=policy)

    assert result.accepted is True
    assert result.browser_family is BrowserFamily.SAFARI
    assert result.pid == 201
    assert sum(call[0][0] == LSOF_PATH for call in runner.calls) == 2
    assert sum(call[0] == (LSAPPINFO_PATH, "front") for call in runner.calls) == 2


def test_opt_in_shared_webkit_rejects_unsigned_frontmost_safari() -> None:
    clock = FakeClock()
    runner = FixtureRunner(
        clock,
        processes={
            201: (1, 501, WEBKIT_PATH),
            200: (1, 501, SAFARI_PATH),
        },
    )
    runner.signature_overrides[SAFARI_PATH] = (
        "Identifier=com.apple.Safari\n"
        "TeamIdentifier=ATTACKER01\n"
        'designated => identifier "com.apple.Safari" and anchor attacker\n'
    )
    policy = AdmissionPolicy(allow_shared_signed_webkit_with_frontmost_safari=True)

    result = assess(runner, policy=policy)

    assert result.reason is AdmissionReason.SIGNATURE_FAILED


def test_opt_in_shared_webkit_rejects_non_safari_frontmost_application() -> None:
    clock = FakeClock()
    runner = FixtureRunner(
        clock,
        processes={201: (1, 501, WEBKIT_PATH)},
        front_bundle="com.openai.codex",
        front_pid=999,
    )
    policy = AdmissionPolicy(allow_shared_signed_webkit_with_frontmost_safari=True)

    result = assess(runner, policy=policy)

    assert result.reason is AdmissionReason.NOT_FRONTMOST


def test_rejects_ambiguous_socket_ownership() -> None:
    clock = FakeClock()
    runner = FixtureRunner(clock)
    runner.lsof_outputs = [
        FixtureRunner._lsof(201, 501, runner.endpoint)
        + FixtureRunner._lsof(202, 501, runner.endpoint)
    ]

    result = assess(runner)

    assert result.reason is AdmissionReason.AMBIGUOUS_OWNER
    assert not any(call[0][0] == PS_PATH for call in runner.calls)


def test_rejects_when_socket_owner_changes_during_admission() -> None:
    clock = FakeClock()
    runner = FixtureRunner(clock)
    runner.lsof_outputs = [
        FixtureRunner._lsof(201, 501, runner.endpoint),
        FixtureRunner._lsof(202, 501, runner.endpoint),
    ]

    result = assess(runner)

    assert result.reason is AdmissionReason.OBSERVATION_CHANGED


def test_rejects_when_signed_application_process_changes_during_admission() -> None:
    clock = FakeClock()
    runner = FixtureRunner(clock)
    root_reads = 0
    base_call = runner.__call__

    def changing_root(argv: Sequence[str], timeout: float, maximum: int) -> CommandResult:
        nonlocal root_reads
        command = tuple(argv)
        if command[0] == PS_PATH and command[command.index("-p") + 1] == "200":
            root_reads += 1
            if root_reads == 2:
                runner.calls.append((command, timeout, maximum))
                return CommandResult(0, f"200 1 502 {SAFARI_PATH}\n")
        return base_call(argv, timeout, maximum)

    result = assess_browser_navigation_provenance(
        "127.0.0.1",
        54321,
        runner=changing_root,
        clock=clock,
        path_resolver=lambda path: path,
    )

    assert result.reason is AdmissionReason.OBSERVATION_CHANGED


def test_rejects_when_frontmost_application_changes_during_admission() -> None:
    clock = FakeClock()
    runner = FixtureRunner(clock)
    front_calls = 0
    base_call = runner.__call__

    def changing_front(argv: Sequence[str], timeout: float, maximum: int) -> CommandResult:
        nonlocal front_calls
        if tuple(argv) == (LSAPPINFO_PATH, "front"):
            front_calls += 1
            runner.calls.append((tuple(argv), timeout, maximum))
            if front_calls == 2:
                return CommandResult(0, "ASN:0x0-0xdef:\n")
        return base_call(argv, timeout, maximum)

    result = assess_browser_navigation_provenance(
        "127.0.0.1",
        54321,
        runner=changing_front,
        clock=clock,
        path_resolver=lambda path: path,
    )

    assert result.reason is AdmissionReason.OBSERVATION_CHANGED


def test_total_deadline_bounds_all_subprocess_observations() -> None:
    clock = FakeClock()
    runner = FixtureRunner(clock, advance_per_call=0.26)
    policy = AdmissionPolicy(total_budget_seconds=0.5, command_timeout_seconds=0.25)

    result = assess(runner, policy=policy)

    assert result.reason is AdmissionReason.DEADLINE_EXCEEDED
    assert len(runner.calls) == 2


@pytest.mark.parametrize(
    ("address", "port"),
    [
        ("not-an-address", 54321),
        ("127.0.0.1", 0),
        ("127.0.0.1", 65_536),
        ("::1%lo0", 54321),
        ("0.0.0.0", 54321),
    ],
)
def test_invalid_peer_fails_without_running_commands(address: str, port: int) -> None:
    clock = FakeClock()
    runner = FixtureRunner(clock)

    result = assess_browser_navigation_provenance(
        address,
        port,
        runner=runner,
        clock=clock,
        path_resolver=lambda path: path,
    )

    assert result.reason is AdmissionReason.INVALID_PEER
    assert runner.calls == []
