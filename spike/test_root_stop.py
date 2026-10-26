"""Preserving root stop, with all OS effects replaced by owned fixtures."""
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import signal
import os

import pytest
import tproxy


def result(code=0, stdout='', stderr=''):
    return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)


@pytest.fixture
def stopped_runtime(monkeypatch, tmp_path):
    install = tmp_path / 'install'
    install.mkdir()
    paths = {
        'INSTALL_DIR': install,
        'LAUNCHD_PLIST': tmp_path / 'daemon.plist',
        'STATUS_PATH': tmp_path / 'status.json',
        '_STRAT_PATH': tmp_path / 'strategies.json',
        '_AUTO_GEPH_PATH': tmp_path / 'auto-geph.json',
    }
    (install / 'slipstreamd').write_text('runtime')
    (install / 'tgws-secret').write_text('fixture-secret')
    for name, path in paths.items():
        monkeypatch.setattr(tproxy, name, str(path))
        if name != 'INSTALL_DIR':
            path.write_text('retained')
    state = SimpleNamespace(loaded=True, alive=True, disabled=False, calls=[], kill=[],
                            ps_error=False, lsof_error=False, bootout_error=False,
                            disable_error=False, pf_error=False, disable_readback=True,
                            final_job_unknown=False, survive=False, listener=True)
    command = '/fixture/slipstreamd --port 1080'
    monkeypatch.setattr(tproxy, '_daemon_status_record', lambda: {'pid': 4242})
    monkeypatch.setattr(tproxy, '_installed_daemon_command_owned', lambda c: c == command)
    monkeypatch.setattr(tproxy.time, 'sleep', lambda _: None)

    def run(*args):
        state.calls.append(args)
        if args[0] == '/usr/bin/env':
            assert args[1:3] == ('LC_ALL=C', 'LANG=C')
            args = args[3:]
        if args[:2] == ('/bin/launchctl', 'print'):
            assert args[2] == 'system/dev.slipstream.tproxy'
            if state.final_job_unknown and not state.loaded:
                return result(1, stderr='Permission denied')
            return (result(stdout='system/dev.slipstream.tproxy = {\n pid = 4242\n}')
                    if state.loaded else result(113, stderr='Bad request.\nCould not find service "dev.slipstream.tproxy" in domain for system\n'))
        if args[:2] == ('/bin/launchctl', 'print-disabled'):
            return result(stdout='disabled services = {\n "dev.slipstream.tproxy" => '
                          + ('true' if state.disabled and state.disable_readback else 'false') + '\n}')
        if args[:2] == ('/bin/launchctl', 'disable'):
            if state.disable_error:
                return result(1, stderr='denied')
            state.disabled = True
            return result()
        if args[:2] == ('/bin/launchctl', 'bootout'):
            assert args == ('/bin/launchctl', 'bootout', 'system/dev.slipstream.tproxy')
            if state.bootout_error:
                return result(1, stderr='busy')
            state.loaded = False
            if not state.survive:
                state.alive = False
            return result()
        if args[0] == '/usr/sbin/lsof':
            if state.lsof_error:
                return result(1, stderr='permission denied')
            return result(stdout='4242\n') if state.alive and state.listener else result(1)
        if args[0] == '/bin/ps':
            if state.ps_error:
                return result(124, stderr='timed out')
            if '-axww' in args:
                rows = f'{os.geteuid()} {os.getpid()} S /fixture/slipstreamd --stop\n'
                if state.alive:
                    rows += '0 4242 S ' + command + '\n'
                return result(stdout=rows)
            return result(stdout='0 S ' + command) if state.alive else result(1)
        raise AssertionError(f'unexpected OS command type: {args[0]}')

    def kill(pid, sig):
        assert pid == 4242
        state.kill.append(sig)
        state.alive = False

    monkeypatch.setattr(tproxy, '_run', run)
    monkeypatch.setattr(tproxy.os, 'kill', kill)
    monkeypatch.setattr(tproxy, '_flush_private_pf_with_retry', lambda **_: not state.pf_error)
    monkeypatch.setattr(tproxy, '_restore_pf_loopback_skip', lambda: True)
    monkeypatch.setattr(tproxy, '_pf_release_enable_token', lambda: None)
    monkeypatch.setattr(tproxy, '_remove_daemon_status_artifacts', lambda: paths['STATUS_PATH'].unlink(missing_ok=True) or True)
    monkeypatch.setattr(tproxy, '_wait_for_listener_state', lambda *_, **__: not state.alive)
    monkeypatch.setattr(tproxy, '_remove_install_runtime_artifacts', lambda: pytest.fail('stop removed runtime'))
    return state, paths


def test_stop_preserves_installed_runtime_settings_and_learning(stopped_runtime):
    state, paths = stopped_runtime
    before = {str(p): p.read_bytes() for p in paths['INSTALL_DIR'].iterdir()}
    before.update({str(p): p.read_bytes() for name, p in paths.items() if name not in {'INSTALL_DIR', 'STATUS_PATH'}})
    assert tproxy.do_stop()
    assert not state.loaded and not state.alive and state.disabled
    assert state.kill == []  # launchd already stopped the process
    assert not paths['STATUS_PATH'].exists()
    assert {p: Path(p).read_bytes() for p in before} == before


def test_stop_revalidates_and_stops_owned_survivor(stopped_runtime):
    state, _ = stopped_runtime
    state.survive = True
    assert tproxy.do_stop()
    assert state.kill == [signal.SIGTERM]


@pytest.mark.parametrize('failure', ['ps_error', 'lsof_error', 'disable_error', 'pf_error', 'bootout_error'])
def test_stop_failure_never_claims_success_or_removes_runtime(stopped_runtime, failure):
    state, paths = stopped_runtime
    setattr(state, failure, True)
    assert not tproxy.do_stop()
    assert paths['INSTALL_DIR'].exists() and paths['STATUS_PATH'].exists()
    assert state.kill == []
    if failure in {'ps_error', 'lsof_error'}:
        assert not state.disabled


def test_stop_requires_disabled_readback(stopped_runtime):
    state, paths = stopped_runtime
    state.disable_readback = False
    assert not tproxy.do_stop()
    assert paths['STATUS_PATH'].exists()


def test_stop_rejects_unknown_after_bootout(stopped_runtime):
    state, paths = stopped_runtime
    state.final_job_unknown = True
    assert not tproxy.do_stop()
    assert paths['STATUS_PATH'].exists()
    assert state.kill == []


@pytest.mark.parametrize('reply', [
    result(113, stderr='Could not find service "foreign" in domain for system'),
    result(113, stderr='Could not find service "dev.slipstream.tproxy" in domain for user gui: 502'),
    result(1, stderr='Could not find service "dev.slipstream.tproxy" in domain for system\nPermission denied'),
    result(0, stdout='system/foreign = {\n pid = 4242\n}'),
    result(-9, stderr='Could not find service "dev.slipstream.tproxy" in domain for system'),
])
def test_stop_exact_root_absence_never_accepts_unknown(monkeypatch, reply):
    monkeypatch.setattr(tproxy, '_run', lambda *_: reply)
    assert tproxy._stop_launchd_observation() == ('unknown', None)


@pytest.mark.parametrize('reply', [result(124, stderr='timed out'), result(0), result(1, stderr='denied')])
def test_stop_process_unknown_is_not_absent(monkeypatch, reply):
    answers = iter([result(stdout='0 S /owned'), reply])
    signals = []
    monkeypatch.setattr(tproxy, '_run', lambda *_: next(answers))
    monkeypatch.setattr(tproxy, '_installed_daemon_command_owned', lambda c: c == '/owned')
    monkeypatch.setattr(tproxy.os, 'kill', lambda *args: signals.append(args))
    assert not tproxy._stop_owned_daemon_pid(4242, strict_observation=True)
    assert signals == [(4242, signal.SIGTERM)]


def test_stop_never_signals_reused_pid(monkeypatch):
    monkeypatch.setattr(tproxy, '_run', lambda *_: result(stdout='0 S /external/app'))
    monkeypatch.setattr(tproxy, '_installed_daemon_command_owned', lambda _: False)
    monkeypatch.setattr(tproxy.os, 'kill', lambda *_: pytest.fail('signalled external process'))
    assert tproxy._stop_owned_daemon_pid(4242, strict_observation=True)


@pytest.mark.parametrize('allowed, succeeds, code', [(True, True, 0), (True, False, 1), (False, True, 1)])
def test_stop_cli_runs_under_lock_and_propagates_failure(monkeypatch, allowed, succeeds, code):
    events = []
    @contextmanager
    def lock():
        events.append('lock')
        if not allowed:
            raise RuntimeError('active update')
        try:
            yield
        finally:
            events.append('unlock')
    def stop():
        events.append('stop')
        return succeeds
    monkeypatch.setattr(tproxy.sys, 'argv', ['slipstreamd', '--stop'])
    monkeypatch.setattr(tproxy.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(tproxy, '_installer_operation_lock', lock)
    monkeypatch.setattr(tproxy, 'do_stop', stop)
    with pytest.raises(SystemExit) as error:
        tproxy.main()
    assert error.value.code == code
    assert events == (['lock', 'stop', 'unlock'] if allowed else ['lock'])


def test_stop_cli_rejects_conflicting_action_before_effects(monkeypatch):
    monkeypatch.setattr(tproxy.sys, 'argv', ['slipstreamd', '--stop', '--uninstall'])
    monkeypatch.setattr(tproxy, 'do_uninstall', lambda **_: pytest.fail('uninstall called'))
    with pytest.raises(SystemExit) as error:
        tproxy.main()
    assert error.value.code == 2


@pytest.mark.parametrize('row, expected', [
    ('0 S (slipstreamd)', 'unknown'),
    ('0 S slipstreamd', 'unknown'),
    ('0 Z (slipstreamd)', 'absent'),
    ('0 E (slipstreamd)', 'absent'),
    ('502 S /fixture/slipstreamd', 'foreign'),
    ('bad S /fixture/slipstreamd', 'unknown'),
])
def test_stop_pid_observation_preserves_ambiguous_identity(monkeypatch, row, expected):
    monkeypatch.setattr(tproxy, '_run', lambda *_: result(stdout=row))
    assert tproxy._stop_process_observation(4242)[0] == expected


def test_stop_never_signals_user_process_running_same_binary(monkeypatch):
    monkeypatch.setattr(tproxy, '_run', lambda *_: result(stdout='502 S /fixture/slipstreamd'))
    monkeypatch.setattr(tproxy, '_installed_daemon_command_owned', lambda _: True)
    monkeypatch.setattr(tproxy.os, 'kill', lambda *_: pytest.fail('signalled user process'))
    assert tproxy._stop_owned_daemon_pid(4242, strict_observation=True)


def test_stop_reports_surviving_owned_pid(monkeypatch):
    signals = []
    clock = iter(range(0, 30, 2))
    monkeypatch.setattr(tproxy.time, 'monotonic', lambda: next(clock))
    monkeypatch.setattr(tproxy, '_run', lambda *_: result(stdout='0 S /owned'))
    monkeypatch.setattr(tproxy, '_installed_daemon_command_owned', lambda c: c == '/owned')
    monkeypatch.setattr(tproxy.os, 'kill', lambda pid, sig: signals.append(sig))
    monkeypatch.setattr(tproxy, '_flush_private_pf_with_retry', lambda **_: True)
    monkeypatch.setattr(tproxy, '_restore_pf_loopback_skip', lambda: True)
    assert not tproxy._stop_owned_daemon_pid(4242, timeout=0, strict_observation=True)
    assert signals == [signal.SIGTERM, signal.SIGKILL]


def test_stop_preserves_evidence_when_final_listener_query_fails(stopped_runtime, monkeypatch):
    _, paths = stopped_runtime
    answers = iter([[4242], [], None])
    monkeypatch.setattr(tproxy, '_stop_listener_pids', lambda _: next(answers))
    assert not tproxy.do_stop()
    assert paths['STATUS_PATH'].exists()


def test_stop_initial_unknown_job_never_mutates(stopped_runtime, monkeypatch):
    state, paths = stopped_runtime
    monkeypatch.setattr(tproxy, '_stop_launchd_observation', lambda: ('unknown', None))
    assert not tproxy.do_stop()
    assert state.calls == []
    assert paths['STATUS_PATH'].exists()


def test_stop_cli_requires_root_before_lock(monkeypatch):
    monkeypatch.setattr(tproxy.sys, 'argv', ['slipstreamd', '--stop'])
    monkeypatch.setattr(tproxy.os, 'geteuid', lambda: 502)
    monkeypatch.setattr(tproxy, '_installer_operation_lock', lambda: pytest.fail('lock reached'))
    with pytest.raises(SystemExit) as error:
        tproxy.main()
    assert error.value.code == 1


def test_stop_confirms_delayed_exit_after_sigkill(monkeypatch):
    signals = []
    clock = iter(range(0, 30, 2))
    after_kill = iter([('present', '/owned'), ('absent', None)])
    def observe(_):
        return next(after_kill) if signal.SIGKILL in signals else ('present', '/owned')
    monkeypatch.setattr(tproxy.time, 'monotonic', lambda: next(clock))
    monkeypatch.setattr(tproxy.time, 'sleep', lambda _: None)
    monkeypatch.setattr(tproxy, '_stop_process_observation', observe)
    monkeypatch.setattr(tproxy, '_installed_daemon_command_owned', lambda c: c == '/owned')
    monkeypatch.setattr(tproxy.os, 'kill', lambda pid, sig: signals.append(sig))
    monkeypatch.setattr(tproxy, '_flush_private_pf_with_retry', lambda **_: True)
    monkeypatch.setattr(tproxy, '_restore_pf_loopback_skip', lambda: True)
    assert tproxy._stop_owned_daemon_pid(4242, timeout=0, strict_observation=True)
    assert signals == [signal.SIGTERM, signal.SIGKILL]


def test_stop_finds_owned_orphan_before_listener_and_status(stopped_runtime, monkeypatch):
    state, _ = stopped_runtime
    state.loaded = False
    state.listener = False
    monkeypatch.setattr(tproxy, '_daemon_status_record', lambda: None)
    monkeypatch.setattr(tproxy, '_wait_for_listener_state', lambda *_, **__: True)
    assert tproxy.do_stop()
    assert not state.alive
    assert state.kill == [signal.SIGTERM]


@pytest.mark.parametrize('unknown_stage', ['initial', 'after_bootout', 'final'])
def test_stop_never_claims_success_with_incomplete_census(stopped_runtime, monkeypatch, unknown_stage):
    state, paths = stopped_runtime
    replies = {
        'initial': [None],
        'after_bootout': [{4242}, None],
        'final': [{4242}, set(), None],
    }
    census = iter(replies[unknown_stage])
    monkeypatch.setattr(tproxy, '_stop_owned_process_census', lambda: next(census))
    assert not tproxy.do_stop()
    assert paths['STATUS_PATH'].exists()
    assert state.kill == []
    if unknown_stage == 'initial':
        assert not state.disabled


def test_stop_final_census_requires_no_surviving_runtime(stopped_runtime, monkeypatch):
    _, paths = stopped_runtime
    census = iter([{4242}, set(), {4243}])
    monkeypatch.setattr(tproxy, '_stop_owned_process_census', lambda: next(census))
    assert not tproxy.do_stop()
    assert paths['STATUS_PATH'].exists()


def test_stop_unknown_after_sigkill_has_no_extra_signal(monkeypatch):
    signals = []
    clock = iter(range(0, 30, 2))
    monkeypatch.setattr(tproxy.time, 'monotonic', lambda: next(clock))
    monkeypatch.setattr(tproxy, '_stop_process_observation', lambda _: (
        ('unknown', None) if signal.SIGKILL in signals else ('present', '/owned')))
    monkeypatch.setattr(tproxy, '_installed_daemon_command_owned', lambda c: c == '/owned')
    monkeypatch.setattr(tproxy.os, 'kill', lambda pid, sig: signals.append(sig))
    monkeypatch.setattr(tproxy, '_flush_private_pf_with_retry', lambda **_: True)
    monkeypatch.setattr(tproxy, '_restore_pf_loopback_skip', lambda: True)
    assert not tproxy._stop_owned_daemon_pid(4242, timeout=0, strict_observation=True)
    assert signals == [signal.SIGTERM, signal.SIGKILL]


SELF = '0 10 S /fixture/slipstreamd --stop\n'


@pytest.mark.parametrize('reply, expected', [
    (result(stdout=SELF + '0 4242 S /fixture/slipstreamd --port 1080\n'), {4242}),
    (result(stdout=SELF + '0 4242 S /fixture/slipstreamd --status\n'), set()),
    (result(stdout=SELF + '0 4242 S /fixture/slipstreamd --update-worker fixture\n'), set()),
    (result(stdout=SELF + '502 4242 S /fixture/slipstreamd --port 1080\n'), set()),
    (result(stdout=SELF + '-2 4242 S /system/process\n'), set()),
    (result(stdout=SELF + '0 4242 S /external/slipstreamd\n'), set()),
    (result(stdout=SELF + '0 4242 Z (slipstreamd)\n'), set()),
    (result(stdout=SELF + '0 4242 S (slipstreamd)\n'), None),
    (result(stdout=SELF + '0 4242 S slipstreamd --port 1080\n'), None),
    (result(stdout=SELF.rstrip()), None),
    (result(stdout=SELF + 'unparseable\n'), None),
    (result(stdout=SELF + '0 10 S /other/process\n'), None),
    (result(stdout='0 4242 S /fixture/slipstreamd\n'), None),
    (result(stdout='502 10 S /fixture/slipstreamd --stop\n'), None),
    (result(stdout=SELF + '-4294967296 4242 S /system/process\n'), None),
    (result(stdout=SELF, stderr='partial output'), None),
    (result(124, stdout=SELF, stderr='timeout'), None),
    (result(), None),
])
def test_stop_census_requires_complete_owned_identity(monkeypatch, reply, expected):
    monkeypatch.setattr(tproxy.os, 'getpid', lambda: 10)
    monkeypatch.setattr(tproxy.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(tproxy, '_installed_daemon_command_owned', lambda c: c.startswith('/fixture/slipstreamd'))
    def run(*args):
        assert args == ('/usr/bin/env', 'LC_ALL=C', 'LANG=C', '/bin/ps', '-axww',
                        '-o', 'uid=,pid=,stat=,command=')
        return reply
    monkeypatch.setattr(tproxy, '_run', run)
    assert tproxy._stop_owned_process_census() == expected


@pytest.mark.parametrize('arguments, owned', [
    ('', True), ('--port=1080 --no-voice --verbose', True),
    ('--port 1080', True), ('--port 65536', False),
    ('--install', False), ('--uninstall', False), ('--stop', False),
    ('--recover-network', False), ('--baseline-probe --baseline-host fixture', False),
    ('--classify-host fixture', False), ('--transport-mechanics-selftest', False),
])
def test_stop_runtime_identity_excludes_control_processes(monkeypatch, arguments, owned):
    monkeypatch.setattr(tproxy, '_installed_daemon_command_owned', lambda _: True)
    assert tproxy._stop_runtime_command_owned('/fixture/slipstreamd ' + arguments) is owned


@pytest.mark.parametrize('row, expected', [
    ('0 ? /fixture/slipstreamd', ('present', '/fixture/slipstreamd')),
    ('0 ?N+ /fixture/slipstreamd', ('present', '/fixture/slipstreamd')),
    ('502 ?s /fixture/slipstreamd', ('foreign', None)),
    ('0 ? (slipstreamd)', ('unknown', None)),
    ('0 S? /fixture/slipstreamd', ('unknown', None)),
    ('0 ?? /fixture/slipstreamd', ('unknown', None)),
])
def test_stop_pid_unknown_scheduling_state_preserves_identity(monkeypatch, row, expected):
    monkeypatch.setattr(tproxy, '_run', lambda *_: result(stdout=row))
    assert tproxy._stop_process_observation(4242) == expected


@pytest.mark.parametrize('rows, expected', [
    ('0 10 ? /fixture/slipstreamd --stop\n', set()),
    (SELF + '502 4242 ? /unrelated/application\n', set()),
    (SELF + '0 4242 ?N+ /fixture/slipstreamd --port 1080\n', {4242}),
    (SELF + '0 4242 ?s /external/slipstreamd\n', set()),
])
def test_stop_census_accepts_darwin_unknown_scheduling_state(monkeypatch, rows, expected):
    monkeypatch.setattr(tproxy.os, 'getpid', lambda: 10)
    monkeypatch.setattr(tproxy.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(tproxy, '_installed_daemon_command_owned', lambda c: c.startswith('/fixture/slipstreamd'))
    monkeypatch.setattr(tproxy, '_run', lambda *_: result(stdout=rows))
    monkeypatch.setattr(tproxy.time, 'sleep', lambda _: pytest.fail('valid state must not retry'))
    assert tproxy._stop_owned_process_census() == expected


@pytest.mark.parametrize('fresh_rows, expected', [
    (SELF, set()),
    (SELF + '0 4243 ? /fixture/slipstreamd --port 1080\n', {4243}),
    (SELF + '502 4242 ? /fixture/slipstreamd --port 1080\n', set()),
])
def test_stop_census_retries_only_complete_ambiguous_snapshot(monkeypatch, capsys, fresh_rows, expected):
    calls, sleeps = [], []
    replies = iter([
        result(stdout=SELF + '0 4241 S /fixture/slipstreamd --port 1080\n0 4242 S (slipstreamd)\n'),
        result(stdout=fresh_rows),
    ])
    monkeypatch.setattr(tproxy.os, 'getpid', lambda: 10)
    monkeypatch.setattr(tproxy.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(tproxy, '_installed_daemon_command_owned', lambda c: c.startswith('/fixture/slipstreamd'))
    monkeypatch.setattr(tproxy, '_run', lambda *args: calls.append(args) or next(replies))
    monkeypatch.setattr(tproxy.time, 'sleep', sleeps.append)
    monkeypatch.setattr(tproxy.os, 'kill', lambda *_: pytest.fail('census must never signal'))
    assert tproxy._stop_owned_process_census() == expected
    assert len(calls) == 2 and calls[0] == calls[1]
    assert sleeps == [0.1]
    assert capsys.readouterr().err == 'stop_census_error=ambiguous_root_basename sample=1\n'


def test_stop_census_persistent_ambiguity_is_bounded_and_never_empty(monkeypatch, capsys):
    calls, sleeps = [], []
    monkeypatch.setattr(tproxy.os, 'getpid', lambda: 10)
    monkeypatch.setattr(tproxy.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(tproxy, '_run', lambda *args: calls.append(args) or result(stdout=SELF + '0 4242 S (slipstreamd) private-argv\n'))
    monkeypatch.setattr(tproxy.time, 'sleep', sleeps.append)
    assert tproxy._stop_owned_process_census() is None
    assert len(calls) == 2 and sleeps == [0.1]
    assert capsys.readouterr().err == ('stop_census_error=ambiguous_root_basename sample=1\n'
                                     'stop_census_error=ambiguous_root_basename sample=2\n')


@pytest.mark.parametrize('reply, reason', [
    (result(124, stderr='private-timeout'), 'command_timeout'),
    (result(1, stderr='private-permission'), 'command_failed'),
    (result(stdout=SELF, stderr='private-stderr'), 'command_stderr'),
    (result(), 'empty_output'),
    (result(stdout=SELF.rstrip()), 'truncated_output'),
    (result(stdout=SELF + 'private-malformed\n'), 'malformed_row'),
    (result(stdout=SELF + '0 4242 S? /private-command\n'), 'invalid_state'),
    (result(stdout=SELF + '0 10 S /private-command\n'), 'duplicate_pid'),
    (result(stdout='502 10 S /private-command\n'), 'self_identity'),
    (result(stdout='0 4242 S /private-command\n'), 'missing_self'),
    (result(stdout=SELF + '0 4242 S (slipstreamd)\nprivate-malformed\n'), 'malformed_row'),
    (result(stdout=SELF + '0 4242 S (slipstreamd)\n0 10 S /private-command\n'), 'duplicate_pid'),
    (result(stdout='0 4242 S (slipstreamd)\n'), 'missing_self'),
])
def test_stop_census_other_unknown_reasons_fail_immediately_and_privately(monkeypatch, capsys, reply, reason):
    calls = []
    monkeypatch.setattr(tproxy.os, 'getpid', lambda: 10)
    monkeypatch.setattr(tproxy.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(tproxy, '_run', lambda *args: calls.append(args) or reply)
    monkeypatch.setattr(tproxy.time, 'sleep', lambda _: pytest.fail('non-identity failure must not retry'))
    assert tproxy._stop_owned_process_census() is None
    assert len(calls) == 1
    assert capsys.readouterr().err == f'stop_census_error={reason} sample=1\n'


def test_stop_waits_for_fresh_census_before_effects_and_revalidates_survivor(stopped_runtime, monkeypatch):
    state, _ = stopped_runtime
    state.survive = True
    original_run, original_kill = tproxy._run, tproxy.os.kill
    census_calls, sleep_calls, pid_checks = [], [], []
    def run(*args):
        if '-axww' in args:
            census_calls.append(args)
            if len(census_calls) == 1:
                return result(stdout=f'{os.geteuid()} {os.getpid()} S /fixture/slipstreamd --stop\n0 4242 S (slipstreamd)\n')
        if '-p' in args:
            pid_checks.append(args)
        return original_run(*args)
    def sleep(seconds):
        sleep_calls.append(seconds)
        assert not state.disabled and not state.kill
    def kill(pid, sig):
        assert len(census_calls) >= 3  # initial retry plus fresh post-bootout census
        assert len(pid_checks) >= 2  # initial observation and pre-signal revalidation
        original_kill(pid, sig)
    monkeypatch.setattr(tproxy, '_run', run)
    monkeypatch.setattr(tproxy.time, 'sleep', sleep)
    monkeypatch.setattr(tproxy.os, 'kill', kill)
    assert tproxy.do_stop()
    assert sleep_calls == [0.1]
    assert state.kill == [signal.SIGTERM]


def test_stop_question_state_never_authorizes_a_reused_pid(monkeypatch):
    monkeypatch.setattr(tproxy, '_run', lambda *_: result(stdout='0 ? /external/app'))
    monkeypatch.setattr(tproxy, '_installed_daemon_command_owned', lambda _: False)
    monkeypatch.setattr(tproxy.os, 'kill', lambda *_: pytest.fail('signalled reused PID'))
    assert tproxy._stop_owned_daemon_pid(4242, strict_observation=True)
