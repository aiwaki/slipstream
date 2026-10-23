"""Hermetic pre-ACK fault fixtures. No real signals, subprocesses or installers."""
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
import packaged_update_preack as fault
import packaged_update_observer as observer
import qualify_packaged_update_commit as driver

assert Path(observer.__file__).parent == REPO / "scripts"
assert Path(driver.__file__).parent == REPO / "scripts"


@pytest.fixture(autouse=True)
def no_native(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("native execution/signal forbidden")
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "kill", forbidden)


def write_private(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))
    path.chmod(0o600)


@pytest.fixture
def window(tmp_path):
    backend = object.__new__(fault.PreAckObserver)
    backend.uid = os.getuid()
    backend.target = tmp_path / "Slipstream.app"
    executable = backend.target / "Contents/MacOS/slipstream"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"inert fixture, never executable")
    backend.journal_path, backend.ack_path = tmp_path / "journal.json", tmp_path / "journal.ack.json"
    backend.expected = {"new": {"app_executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest()}}
    backend.fault_process = None
    backend.watchdog = {"pid": 333}
    backend.deadline = 1000
    backend.events = []
    backend.record = lambda name, value: backend.events.append((name, copy.deepcopy(value)))
    identity = {"nonce": "a" * 32, "uid": backend.uid}
    journal = {"phase": "successor_launched", "successor_pid": 222, "uid": backend.uid,
        "successor_started": "Mon Oct 19 12:00:00 2026", "successor_deadline_unix": 9999,
        "initiator_pid": 111, "target": str(backend.target), "daemon_update": {"identity": identity}}
    write_private(backend.journal_path, journal)
    root = {**identity, "phase": "ready", "decision": None, "writer_quiescent": True, "deadline_unix": 9999}
    backend.bind = lambda value: setattr(backend, "last_journal", copy.deepcopy(value))
    backend.status = lambda: copy.deepcopy(root)
    process = {"pid": 222, "uid": backend.uid, "started": journal["successor_started"],
        "command": str(executable), "state": "S"}
    backend.process_snapshot = lambda pid: copy.deepcopy(process)
    signals = []
    def send(pid, kind):
        signals.append((pid, kind))
        if kind == signal.SIGSTOP:
            process["state"] = "T"
    return backend, journal, root, process, signals, send


def inject(backend, send, **kwargs):
    return backend.inject_pre_ack_exit(send=send, clock=lambda: 0, wallclock=lambda: 100, **kwargs)


def test_stop_then_reread_then_exact_kill(window):
    backend, journal, root, process, signals, send = window
    inject(backend, send)
    assert signals == [(222, signal.SIGSTOP), (222, signal.SIGKILL)]
    assert [name for name, _ in backend.events] == ["fault_stop_sent", "fault_stopped_window", "fault_kill_sent"]
    assert backend.events[1][1]["process"]["state"] == "T"
    assert backend.fault_process["pid"] == 222
    with pytest.raises(fault.Refused, match="once"):
        inject(backend, send)
    assert len(signals) == 2


@pytest.mark.parametrize("change", ["ack", "commit", "abort", "journal_phase", "journal_pid", "uid", "birth", "command", "zombie", "deadline"])
def test_window_change_after_stop_never_kills(window, change):
    backend, journal, root, process, signals, send = window
    def changing_send(pid, kind):
        send(pid, kind)
        if change == "ack": write_private(backend.ack_path, {"arrived": True})
        elif change in {"commit", "abort"}: root.update(decision=change, phase="committing" if change == "commit" else "aborting")
        elif change == "journal_phase": journal["phase"] = "daemon_commit_requested"
        elif change == "journal_pid": journal["successor_pid"] = 444
        elif change == "uid": process["uid"] += 1
        elif change == "birth": process["started"] = "Tue Oct 20 12:00:00 2026"
        elif change == "command": process["command"] = "/unrelated"
        elif change == "zombie": process["state"] = "Z"
        elif change == "deadline": journal["successor_deadline_unix"] = 10
        write_private(backend.journal_path, journal)
    with pytest.raises(fault.Refused): inject(backend, changing_send)
    assert signals == [(222, signal.SIGSTOP)]
    assert backend.fault_process is None


@pytest.mark.parametrize("change", ["ack", "commit", "pid", "uid", "birth", "command", "stopped", "payload", "deadline"])
def test_closed_or_changed_initial_window_never_signals(window, change):
    backend, journal, root, process, signals, send = window
    if change == "ack": write_private(backend.ack_path, {"arrived": True})
    elif change == "commit": root.update(phase="committed", decision="commit")
    elif change == "pid": process["pid"] = 444
    elif change == "uid": process["uid"] += 1
    elif change == "birth": process["started"] = "Tue Oct 20 12:00:00 2026"
    elif change == "command": process["command"] = "/unrelated"
    elif change == "stopped": process["state"] = "T"
    elif change == "payload": (backend.target / "Contents/MacOS/slipstream").write_bytes(b"changed")
    elif change == "deadline": journal["successor_deadline_unix"] = 10
    write_private(backend.journal_path, journal)
    with pytest.raises(fault.Refused): inject(backend, send)
    assert signals == []


def test_stop_confirmation_is_bounded_and_never_escalates(window):
    backend, journal, root, process, signals, _send = window
    ticks = iter([0, 0, 0, 3])
    with pytest.raises(fault.Refused, match="STOP confirmation"):
        backend.inject_pre_ack_exit(send=lambda *a: signals.append(a), clock=lambda: next(ticks),
                                    wallclock=lambda: 100, sleep=lambda _: None)
    assert signals == [(222, signal.SIGSTOP)]


def test_final_ack_reread_catches_arrival_after_root_read(window):
    backend, journal, root, process, signals, send = window
    original = backend.process_snapshot
    def snapshot(pid):
        if len(signals) and process["state"] == "T":
            snapshot.stopped_calls += 1
            if snapshot.stopped_calls == 2:
                write_private(backend.ack_path, {"late": True})
        return original(pid)
    snapshot.stopped_calls = 0
    backend.process_snapshot = snapshot
    with pytest.raises(fault.Refused, match="ACK appeared"):
        inject(backend, send)
    assert signals == [(222, signal.SIGSTOP)]


@pytest.mark.parametrize("field,value", [("pid",222),("pid",111),("uid",99999),("state","T"),("state","Z"),("command","/unrelated")])
def test_old_tray_is_not_failed_new_or_initiator(window, field, value):
    backend, journal, root, process, signals, send = window
    old = {**process, "pid": 555, "started": "Mon Oct 19 12:01:00 2026"}
    assert fault.exact_old_tray(old, journal, backend.uid, 222)
    old[field] = value
    assert not fault.exact_old_tray(old, journal, backend.uid, 222)


def terminal_backend(window):
    backend, journal, root, process, signals, send = window
    backend.fault_process = copy.deepcopy(process)
    backend.args = SimpleNamespace(mode=fault.MODE)
    backend.root_status = {"phase":"aborted", "decision":"abort", "writer_quiescent":True}
    backend.ack = None; backend.receipt = {"prepared":True}; backend.initiator = {**process,"pid":111}
    backend.watchdog_finished = lambda: True
    backend.process_snapshot = lambda pid: None
    backend.observe_once = lambda: None
    backend.final_old_app = lambda **kw: backend.events.append(("old-tree-tray", {}))
    backend.prove = lambda side, **kw: backend.events.append(("daemon-proof", {"side":side, **kw}))
    return backend


def test_rollback_requires_old_app_and_exact_snapshot_daemon(window):
    backend = terminal_backend(window)
    result = backend.qualify_app(clock=lambda:0)
    assert result["side"] == "old" and result["successor_exit_before_ack_rollback_qualified"] is True
    assert result["public_pair_qualified"] is False
    assert backend.events == [("old-tree-tray",{}),("daemon-proof",{"side":"old","exact_snapshot":True}),("old-tree-tray",{})]


@pytest.mark.parametrize("failure", ["old-tree", "old-daemon", "old-tray-died", "unexpected-ack", "root-commit"])
def test_rollback_proof_failure_cannot_qualify(window, failure):
    backend = terminal_backend(window)
    def reject(**kw): raise fault.Refused("proof missing")
    if failure == "old-tree": backend.final_old_app = reject
    elif failure == "old-daemon": backend.prove = lambda *a, **kw: reject()
    elif failure == "old-tray-died":
        count = [0]
        def final(**kw):
            count[0] += 1
            if count[0] == 2: reject()
        backend.final_old_app = final
    elif failure == "unexpected-ack": backend.ack = {"arrived":True}
    elif failure == "root-commit": backend.root_status.update(phase="committed",decision="commit")
    with pytest.raises(fault.Refused): backend.qualify_app(clock=lambda:0)


def test_missing_rollback_proof_has_finite_deadline(window):
    backend = terminal_backend(window)
    backend.root_status.update(phase="aborting", writer_quiescent=False)
    ticks = iter([0, 911])
    with pytest.raises(fault.Refused, match="deadline exhausted"):
        backend.qualify_app(clock=lambda:next(ticks), sleep=lambda _:None)


def test_commit_driver_default_cleanup_remains_commit_only(tmp_path, monkeypatch):
    events=[]
    monkeypatch.setattr(driver,"install_old",lambda _:None)
    monkeypatch.setattr(driver,"cleanup_committed",lambda _:events.append("commit-cleanup"))
    for key in ("CI","GITHUB_ACTIONS","SLIPSTREAM_DISPOSABLE_CI","RUNNER_OS","RUNNER_TEMP"):
        monkeypatch.setenv(key,"fixture")
    backend=SimpleNamespace(args=SimpleNamespace(mode="commit",trigger_dir=tmp_path),binary=tmp_path/'inert',env={},
        setup_observation=lambda:events.append("observer-ready"),qualify_app=lambda:{"side":"new"},
        cleanup_rollback=lambda:pytest.fail("commit must not use rollback cleanup"))
    result=driver.drive(backend,start=lambda *a,**kw:SimpleNamespace(wait=lambda **kw:0))
    assert result=={"side":"new"} and events==["observer-ready","commit-cleanup"]


def test_unknown_fault_outcome_never_runs_cleanup(tmp_path, monkeypatch):
    monkeypatch.setattr(driver,"install_old",lambda _:None)
    for key in ("CI","GITHUB_ACTIONS","SLIPSTREAM_DISPOSABLE_CI","RUNNER_OS","RUNNER_TEMP"):
        monkeypatch.setenv(key,"fixture")
    def fail(): raise fault.Refused("missed window")
    backend=SimpleNamespace(args=SimpleNamespace(mode=fault.MODE,trigger_dir=tmp_path),binary=tmp_path/'inert',env={},
        setup_observation=lambda:None,qualify_app=fail,cleanup_rollback=lambda:pytest.fail("unknown cleanup"))
    with pytest.raises(fault.Refused,match="missed window"):
        driver.drive(backend,start=lambda *a,**kw:SimpleNamespace(wait=lambda **kw:0))
    assert backend.trigger_started and not getattr(backend,'transaction_observed',False)


def test_root_lease_expired_never_signals(window):
    backend, journal, root, process, signals, send = window
    root['deadline_unix'] = 100
    with pytest.raises(fault.Refused, match='deadline'):
        inject(backend, send)
    assert signals == []


def test_kill_crossing_deadline_is_incomplete_not_pass(window):
    backend, journal, root, process, signals, send = window
    ticks = iter([100, 100, 10000])
    with pytest.raises(fault.Refused, match='causal result incomplete'):
        backend.inject_pre_ack_exit(send=send, clock=lambda:0, wallclock=lambda:next(ticks))
    assert signals == [(222, signal.SIGSTOP), (222, signal.SIGKILL)]


@pytest.fixture
def restored(tmp_path,monkeypatch):
    monkeypatch.setattr(Path,"home",lambda:tmp_path/"home")
    fixture=json.loads((REPO/'contracts/update-daemon-status-v1.json').read_text())
    prepared=next(v['status'] for v in fixture['vectors'] if v['name']=='prepared')
    identity={k:v for k,v in prepared.items() if k not in {
        'manifest_sha256','phase','decision','accepted_sequence','deadline_unix','worker_pid',
        'daemon_pid','daemon_sha256','heartbeat_seq','install_attestation_sha256','writer_quiescent','error'}}
    identity['uid']=os.getuid()
    expected={side:{'version':identity[side+'_version'], 'archive_sha256':identity['archive_sha256'],
        **{key:identity[side+'_'+key] for key in ('app_executable_sha256','daemon_sha256','bundle_tree_sha256')}}
        for side in ('old','new')}
    backend=object.__new__(fault.PreAckObserver)
    backend.uid=os.getuid(); backend.identity=identity; backend.expected=expected
    backend.target=tmp_path/'Applications/Slipstream.app'; backend.target.mkdir(parents=True)
    backend.state=tmp_path/'state'; backend.manifest=prepared['manifest_sha256']; backend.watchdog_hash='9'*64
    backend.journal_path=backend.state/observer.JOURNAL; backend.ack_path=backend.journal_path.with_suffix('.ack.json')
    backend.stage=backend.target.parent/('.Slipstream.app.slipstream-stage-'+identity['nonce'])
    backend.agent=Path.home()/'Library/LaunchAgents'/(observer.WATCHDOG+'.plist')
    start='Mon Oct 19 12:00:00 2026'
    receipt={'schema_version':2,'nonce':identity['nonce'],'uid':backend.uid,'initiator_pid':111,
        'target':str(backend.target),'backup':str(backend.target.parent/('.Slipstream.app.slipstream-backup-'+identity['nonce'])),
        'stage':str(backend.stage),'helper':str(backend.state/'runtime/slipstream-update-watchdog'),
        'launch_agent':str(backend.agent),'current_version':expected['old']['version'],
        'expected_version':expected['new']['version'],'archive_sha256':identity['archive_sha256'],
        'watchdog_sha256':backend.watchdog_hash,'old_executable_sha256':identity['old_app_executable_sha256'],
        'new_executable_sha256':identity['new_app_executable_sha256'],'phase':'old_relaunched',
        'successor_pid':222,'successor_started':start,'successor_deadline_unix':9999,'last_error':None,
        'daemon_update':{'identity':identity,'manifest_sha256':backend.manifest,'sequence':2,
                         'action':'abort','authorization_started':True}}
    path=backend.state/('app-update-transaction-failed-'+identity['nonce']+'.json')
    write_private(path,receipt)
    backend.fault_process={'pid':222,'uid':backend.uid,'started':start,'state':'S',
        'command':str(backend.target/'Contents/MacOS/slipstream')}
    old={**backend.fault_process,'pid':555,'started':'Mon Oct 19 12:01:00 2026'}
    backend.tray=backend.rollback_receipt=None; backend.events=[]
    backend.record=lambda name,value:backend.events.append((name,copy.deepcopy(value)))
    backend.process_snapshot=lambda pid:copy.deepcopy(old) if pid==555 else None
    backend.watchdog_finished=lambda:True
    def query(argv, **kwargs):
        if argv[0] == "/bin/ps":
            assert argv == ["/bin/ps", "-p", "555", "-o", "pid=,pgid=,uid=,state=,lstart="]
            assert kwargs == {"check": False, "timeout": 1}
            return SimpleNamespace(returncode=0,
                stdout=f"555 333 {backend.uid} S {old['started']}\n".encode())
        assert argv == ["/usr/bin/pgrep", "-x", "slipstream"]
        return SimpleNamespace(returncode=0, stdout=b"555\n")
    backend.run=query
    backend.tproxy=SimpleNamespace(_daemon_update_tree=lambda *a,**kw:expected['old']['bundle_tree_sha256'],
        _DAEMON_UPDATE_REQUESTS=str(tmp_path/'requests'))
    backend.status=lambda:{'phase':'aborted','decision':'abort','writer_quiescent':True}
    backend.deadline=time.monotonic()+1000
    info=backend.target.lstat()
    backend.created=[{'path':backend.target,'sha256':expected['old']['bundle_tree_sha256'],
                      'inode':(info.st_dev,info.st_ino),'complete':True}]
    return backend,receipt,path,old


def test_actual_private_failed_receipt_and_independent_old_tray_proof(restored):
    backend,receipt,path,old=restored
    backend.final_old_app()
    assert backend.rollback_receipt['successor_pid']==222
    assert backend.tray==old and backend.tray['pid']==555
    assert [name for name,_ in backend.events]==[
        'rollback_receipt','final_tray_query','final_tray_processes','final_old_app']
    assert backend.events[2][1]["processes"] == [
        {"pid": 555, "pgid": 333, "uid": backend.uid, "state": "S", "started": old["started"]}]


@pytest.mark.parametrize("returncode,stdout,outcome", [
    (1, b"", "no_candidates"),
    (0, b"555\n556\n", "multiple_candidates"),
    (2, b"", "query_error"),
])
def test_old_tray_refusal_keeps_sanitized_query_diagnostic(restored, returncode, stdout, outcome):
    backend, receipt, path, old = restored
    def query(argv, **kwargs):
        if argv[0] == "/bin/ps":
            raise fault.Refused("inert optional process diagnostic failure")
        return SimpleNamespace(returncode=returncode, stdout=stdout)
    backend.run = query
    with pytest.raises(fault.Refused, match="one independently observed OLD tray must be alive"):
        backend.final_old_app()
    diagnostic = next(value for kind, value in backend.events if kind == "final_tray_query")
    assert diagnostic["side"] == "old"
    assert diagnostic["returncode"] == returncode and diagnostic["outcome"] == outcome


@pytest.mark.parametrize('change',['phase','new_pid','new_birth','manifest','decision','nonce','archive','private_mode',
    'old_tree','new_alive','multiple_old','old_absent','old_zombie','old_stopped','watchdog','active_journal','stage','backup'])
def test_incomplete_actual_rollback_proof_rejected(restored,change):
    backend,receipt,path,old=restored
    if change=='phase': receipt['phase']='rolled_back'
    elif change=='new_pid': receipt['successor_pid']=444
    elif change=='new_birth': receipt['successor_started']='Tue Oct 20 12:00:00 2026'
    elif change=='manifest': receipt['daemon_update']['manifest_sha256']='f'*64
    elif change=='decision': receipt['daemon_update']['action']='commit'
    elif change=='nonce': receipt['nonce']='f'*32
    elif change=='archive': receipt['archive_sha256']='f'*64
    elif change=='old_tree': backend.tproxy._daemon_update_tree=lambda *a,**kw:backend.expected['new']['bundle_tree_sha256']
    elif change=='new_alive': backend.process_snapshot=lambda pid:backend.fault_process if pid==222 else old
    elif change=='multiple_old': backend.run=lambda *a,**kw:SimpleNamespace(returncode=0,stdout=b'555\n556\n')
    elif change=='old_absent': backend.run=lambda *a,**kw:SimpleNamespace(returncode=1,stdout=b'')
    elif change=='old_zombie': old['state']='Z'
    elif change=='old_stopped': old['state']='T'
    elif change=='watchdog':
        backend.watchdog_finished=lambda:False
        backend.deadline=90.05
    elif change=='active_journal': write_private(backend.journal_path,receipt)
    elif change=='stage': backend.stage.mkdir()
    elif change=='backup': Path(receipt['backup']).mkdir()
    write_private(path,receipt)
    if change=='private_mode': path.chmod(0o644)
    now = [0.0]
    with pytest.raises(fault.Refused):
        backend.final_old_app(clock=lambda: now[0], sleep=lambda seconds: now.__setitem__(0, now[0]+seconds))


def test_rollback_receipt_and_relaunched_old_identity_must_remain_stable(restored):
    backend,receipt,path,old=restored
    backend.final_old_app()
    old['started']='Tue Oct 20 12:01:00 2026'
    with pytest.raises(fault.Refused,match='OLD tray changed'): backend.final_old_app()
    receipt['last_error']='changed'
    write_private(path,receipt)
    with pytest.raises(fault.Refused,match='receipt changed'): backend.final_old_app()


def test_cleanup_requires_old_stop_and_preserves_initial_restored_inode(restored,monkeypatch):
    backend,receipt,path,old=restored
    calls=[]
    def send(pid,sig):
        calls.append(('signal',pid,sig))
        backend.process_snapshot=lambda pid:None
        backend.run=lambda *a,**kw:SimpleNamespace(returncode=1,stdout=b'')
    def teardown(value):
        calls.append(('teardown',copy.deepcopy(value.created)))
    monkeypatch.setattr(fault.Native,'teardown',teardown)
    backend.cleanup_rollback(send=send,clock=lambda:0)
    info=backend.target.lstat()
    assert calls[0]==('signal',555,signal.SIGTERM)
    assert calls[1]==('teardown',[{'path':backend.target,'sha256':backend.expected['old']['bundle_tree_sha256'],
        'inode':(info.st_dev,info.st_ino),'complete':True}])


def restored_with_real_terminal_watchdog(restored):
    """Only the OS flock is real; launchd, processes and payloads stay inert."""
    backend, receipt, path, old = restored
    helper = Path(receipt['helper'])
    helper.parent.mkdir(parents=True)
    helper.write_bytes(b'inert watchdog fixture')
    backend.watchdog_hash = receipt['watchdog_sha256'] = observer.digest(helper)
    write_private(path, receipt)
    backend.last_journal = copy.deepcopy(receipt)
    backend.watchdog = {'pid': 333}
    backend.observed_watchdog_policy = {
        'Label': observer.WATCHDOG,
        'ProgramArguments': [str(helper), '--journal', str(backend.journal_path)],
        'RunAtLoad': True, 'KeepAlive': {'SuccessfulExit': False}, 'ProcessType': 'Background',
        'StandardOutPath': str(backend.state / 'update-watchdog.stdout.log'),
        'StandardErrorPath': str(backend.state / 'update-watchdog.stderr.log')}
    job = (f'gui/{backend.uid}/{observer.WATCHDOG} = {{\n'
        f'\tactive count = 0\n\tprogram = {helper}\n\targuments = {{\n'
        f'\t\t{helper}\n\t\t--journal\n\t\t{backend.journal_path}\n\t}}\n'
        '\tstate = not running\n\truns = 1\n\tlast exit code = 0\n}\n').encode()
    original_run = backend.run
    backend.run = lambda argv, **kw: (SimpleNamespace(returncode=0, stdout=job, stderr=b'')
        if argv[0] == '/bin/launchctl' else original_run(argv, **kw))
    del backend.watchdog_finished
    write_private(backend.journal_path.with_suffix('.lock'), {})
    backend.deadline = time.monotonic() + 1000
    backend.final_old_app()  # A successful earlier qualifier does not remove OLD's startup lock use.
    return backend, receipt, path, old


def test_cleanup_waits_for_restored_old_startup_lock_after_qualification(restored, monkeypatch):
    backend, receipt, path, old = restored_with_real_terminal_watchdog(restored)
    calls, now = [], [0.0]
    backend.deadline = 0.05
    monkeypatch.setattr(fault.Native, 'teardown', lambda _: calls.append('teardown'))
    def send(pid, sig):
        calls.append((pid, sig))
        backend.process_snapshot = lambda _: None
        backend.run = lambda *a, **kw: SimpleNamespace(returncode=1, stdout=b'')
    with backend.journal_path.with_suffix('.lock').open('rb') as held:
        observer.fcntl.flock(held, observer.fcntl.LOCK_EX | observer.fcntl.LOCK_NB)
        def release_after_observation(seconds):
            assert calls == []
            # Preserve the failed observation, even though the next snapshot will succeed.
            diagnostic = [value for kind, value in backend.events if kind == 'completion_diagnostic'][-1]
            assert diagnostic['lock'] == 'busy'
            assert diagnostic['watchdog_process'] is None
            assert not any(diagnostic['paths_present'].values())
            observer.fcntl.flock(held, observer.fcntl.LOCK_UN)
            now[0] += seconds
        backend.cleanup_rollback(send=send, clock=lambda: now[0], sleep=release_after_observation)
    assert calls == [(555, signal.SIGTERM), 'teardown']
    assert 0 < now[0] < backend.deadline
    diagnostics = [value for kind, value in backend.events if kind == 'completion_diagnostic']
    assert diagnostics[-1]['lock'] == 'busy'
    assert backend.completion_diagnostic['lock'] == 'available'


@pytest.mark.parametrize('release_at_deadline', [False, True])
def test_cleanup_busy_lock_uses_original_deadline_and_exact_false_diagnostic(restored, monkeypatch, release_at_deadline):
    backend, receipt, path, old = restored_with_real_terminal_watchdog(restored)
    now, observations = [0.0], []
    backend.deadline = 0.05
    original_run = backend.run
    def run(argv, **kw):
        if argv[0] == '/bin/launchctl':
            observations.append(now[0])
        return original_run(argv, **kw)
    backend.run = run
    monkeypatch.setattr(fault.Native, 'teardown', lambda _: pytest.fail('unsafe teardown'))
    with backend.journal_path.with_suffix('.lock').open('rb') as held:
        observer.fcntl.flock(held, observer.fcntl.LOCK_EX | observer.fcntl.LOCK_NB)
        def sleep(seconds):
            now[0] += seconds
            assert now[0] <= backend.deadline
            if release_at_deadline and now[0] == backend.deadline:
                observer.fcntl.flock(held, observer.fcntl.LOCK_UN)
        with pytest.raises(fault.Refused, match='terminal watchdog deadline exhausted'):
            backend.cleanup_rollback(clock=lambda: now[0], sleep=sleep)
    assert now[0] == backend.deadline == 0.05
    assert observations == [0.0, 0.02, 0.04]  # No timeout resample or renewed budget.
    diagnostics = [value for kind, value in backend.events if kind == 'completion_diagnostic']
    assert diagnostics[-1]['lock'] == 'busy'
    assert backend.completion_diagnostic == diagnostics[-1]


@pytest.mark.parametrize('change', ['tree', 'receipt', 'ack', 'new_alive', 'old_identity', 'root_commit', 'policy'])
def test_cleanup_revalidates_rollback_after_startup_lock_wait(restored, monkeypatch, change):
    backend, receipt, path, old = restored_with_real_terminal_watchdog(restored)
    now = [0.0]
    backend.deadline = 0.05
    monkeypatch.setattr(fault.Native, 'teardown', lambda _: pytest.fail('unsafe teardown'))
    with backend.journal_path.with_suffix('.lock').open('rb') as held:
        observer.fcntl.flock(held, observer.fcntl.LOCK_EX | observer.fcntl.LOCK_NB)
        def release_and_change(seconds):
            observer.fcntl.flock(held, observer.fcntl.LOCK_UN)
            now[0] += seconds
            if change == 'tree':
                backend.tproxy._daemon_update_tree = lambda *a, **kw: 'f' * 64
            elif change == 'receipt':
                receipt['last_error'] = 'receipt changed during wait'
                write_private(path, receipt)
            elif change == 'ack':
                write_private(backend.ack_path, {'unexpected': 'ACK'})
            elif change == 'new_alive':
                backend.process_snapshot = lambda pid: backend.fault_process if pid == 222 else old if pid == 555 else None
            elif change == 'old_identity':
                old['started'] = 'Tue Oct 20 12:00:00 2026'
            elif change == 'root_commit':
                backend.status = lambda: {'phase': 'committed', 'decision': 'commit', 'writer_quiescent': True}
            elif change == 'policy':
                backend.observed_watchdog_policy['KeepAlive'] = True
        with pytest.raises(fault.Refused):
            backend.cleanup_rollback(clock=lambda: now[0], sleep=release_and_change)
    assert now[0] > 0


@pytest.mark.parametrize('phase', ['watchdog', 'app'])
def test_cleanup_rejects_proof_finishing_at_original_deadline(restored, monkeypatch, phase):
    backend, receipt, path, old = restored_with_real_terminal_watchdog(restored)
    now = [0.0]
    backend.deadline = 0.05
    if phase == 'watchdog':
        original = backend.run
        def run(argv, **kw):
            value = original(argv, **kw)
            if argv[0] == '/bin/launchctl':
                now[0] = backend.deadline
            return value
        backend.run = run
    else:
        original = backend.tproxy._daemon_update_tree
        def tree(*a, **kw):
            now[0] = backend.deadline
            return original(*a, **kw)
        backend.tproxy._daemon_update_tree = tree
    monkeypatch.setattr(fault.Native, 'teardown', lambda _: pytest.fail('unsafe teardown'))
    with pytest.raises(fault.Refused, match='deadline exhausted'):
        backend.cleanup_rollback(clock=lambda: now[0], sleep=lambda _: pytest.fail('expired wait'))


@pytest.mark.parametrize('change',['root_commit','root_undecided','root_busy','new_alive','old_stopped','old_reused','replaced_inode'])
def test_unknown_cleanup_state_cannot_signal_or_teardown(restored,monkeypatch,change):
    backend,receipt,path,old=restored
    backend.final_old_app()
    if change=='root_commit': backend.status=lambda:{'phase':'committed','decision':'commit','writer_quiescent':True}
    elif change=='root_undecided': backend.status=lambda:{'phase':'ready','decision':None,'writer_quiescent':True}
    elif change=='root_busy': backend.status=lambda:{'phase':'aborted','decision':'abort','writer_quiescent':False}
    elif change=='new_alive': backend.process_snapshot=lambda pid:backend.fault_process if pid==222 else old
    elif change=='old_stopped': old['state']='T'
    elif change=='old_reused': old['started']='Tue Oct 20 12:00:00 2026'
    elif change=='replaced_inode': backend.created[0]['inode']=(0,0)
    monkeypatch.setattr(fault.Native,'teardown',lambda _:pytest.fail('unsafe cleanup'))
    with pytest.raises(fault.Refused):
        backend.cleanup_rollback(send=lambda *a:pytest.fail('unsafe signal'),clock=lambda:0)


def test_cleanup_pid_reuse_after_sigterm_cannot_teardown(restored,monkeypatch):
    backend,receipt,path,old=restored
    signals=[]
    def send(*args):
        signals.append(args)
        old['started']='Tue Oct 20 12:00:00 2026'
    monkeypatch.setattr(fault.Native,'teardown',lambda _:pytest.fail('unsafe teardown'))
    with pytest.raises(fault.Refused,match='reused'):
        backend.cleanup_rollback(send=send,clock=lambda:0)
    assert signals==[(555,signal.SIGTERM)]


def test_old_stop_timeout_never_forces_teardown(restored,monkeypatch):
    backend,receipt,path,old=restored
    signals=[]
    now=[0]
    monkeypatch.setattr(fault.Native,'teardown',lambda _:pytest.fail('unsafe teardown'))
    with pytest.raises(fault.Refused,match='no forced cleanup'):
        backend.cleanup_rollback(send=lambda *a:signals.append(a),clock=lambda:now[0],
            sleep=lambda _:now.__setitem__(0,16))
    assert signals==[(555,signal.SIGTERM)]


def test_rollback_driver_selects_cleanup_only_after_successful_observation(tmp_path,monkeypatch):
    events=[]
    monkeypatch.setattr(driver,'install_old',lambda _:None)
    monkeypatch.setattr(driver,'cleanup_committed',lambda _:pytest.fail('wrong cleanup'))
    for key in ('CI','GITHUB_ACTIONS','SLIPSTREAM_DISPOSABLE_CI','RUNNER_OS','RUNNER_TEMP'):
        monkeypatch.setenv(key,'fixture')
    backend=SimpleNamespace(args=SimpleNamespace(mode=fault.MODE,trigger_dir=tmp_path),binary=tmp_path/'inert',env={},
        setup_observation=lambda:events.append('ready'),qualify_app=lambda:{'side':'old'},
        cleanup_rollback=lambda:events.append(('rollback-cleanup',backend.transaction_observed)))
    assert driver.drive(backend,start=lambda *a,**kw:SimpleNamespace(wait=lambda **kw:0))=={'side':'old'}
    assert events==['ready',('rollback-cleanup',True)]
