"""Source-side contracts for the existing frozen self-test; no network or build."""
import ast
import argparse
import asyncio
from collections import OrderedDict
import importlib
import json
from pathlib import Path
import shlex
import socket
import subprocess
import sys
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_IMPORTS = (
    'proxy.cf_h2', 'proxy.h2_transport', 'httpx', 'httpcore',
    'h2.config', 'h2.connection', 'hpack', 'hyperframe.frame',
)


@pytest.fixture(autouse=True)
def offline_only(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Frozen import check must not perform external I/O')

    for name in ('connect', 'connect_ex', 'bind', 'listen'):
        monkeypatch.setattr(socket.socket, name, forbidden)
    for name in ('create_connection', 'getaddrinfo'):
        monkeypatch.setattr(socket, name, forbidden)
    for name in ('open_connection', 'start_server',
                 'create_subprocess_exec', 'create_subprocess_shell'):
        monkeypatch.setattr(asyncio, name, forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.syspath_prepend(str(ROOT / 'vendor/tg-ws-proxy'))


def load_selftest():
    # Execute actual self-test definitions without importing daemon startup or
    # running its unchanged QUIC implementation. These substitutes are only the
    # existing matrix's collaborators, not the new Telegram import boundary.
    source = ast.parse((ROOT / 'spike/tproxy.py').read_text())
    names = {'_telegram_frozen_import_selftest', 'transport_mechanics_selftest'}
    functions = [node for node in source.body
                 if isinstance(node, ast.FunctionDef) and node.name in names]

    def fallback(initials, fallbacks, flow, initial, *, now):
        if initial[1] != 'www.xpersonatoy.com' or flow in fallbacks:
            return None
        fallbacks[flow] = True
        return b'fixture'

    namespace = {
        'OrderedDict': OrderedDict, 'QUIC_V1': 'v1', 'QUIC_V2': 'v2',
        '_pf_applied': False, 'GEPH_ENABLED': False, '_geph_up': False,
        '_geph_owned': False, '_geph_port': 0, 'GEPH_OWNED_PORT': 12345,
        'transparent_routing_ready': lambda: False,
        '_transport_selftest_quic_initial': lambda version, host: (version, host),
        '_quic_initial_crypto_fragments': lambda initial: ({'version': initial[0]}, []),
        '_observe_quic_initial_sni': lambda flows, flow, initial, **kw: initial[1],
        '_quic_initial_tcp_fallback_response': fallback,
    }
    exec(compile(ast.Module(body=functions, type_ignores=[]), 'selftest-definitions', 'exec'), namespace)
    return namespace


@pytest.mark.parametrize('missing_module', REQUIRED_IMPORTS)
def test_transport_selftest_refuses_missing_telegram_closure(monkeypatch, missing_module):
    original_import = importlib.import_module

    def resolve(name, *args, **kwargs):
        if name == missing_module:
            raise ModuleNotFoundError(missing_module)
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(importlib, 'import_module', resolve)
    namespace = load_selftest()
    with pytest.raises(ModuleNotFoundError, match=missing_module):
        namespace['transport_mechanics_selftest']()
    assert namespace['_pf_applied'] is False
    assert namespace['GEPH_ENABLED'] is False


def test_actual_h2_import_initialization_and_close_preserves_report(monkeypatch):
    httpx = importlib.import_module('httpx')
    h2_transport = importlib.import_module('proxy.h2_transport')
    assert Path(h2_transport.__file__).resolve() == (
        ROOT / 'vendor/tg-ws-proxy/proxy/h2_transport.py').resolve()
    clients, transports = [], []
    real_client, real_transport = httpx.AsyncClient, h2_transport.H2Transport

    def capture_transport(*args, **kwargs):
        transport = real_transport(*args, **kwargs)
        transports.append(transport)
        return transport

    def capture_client(*args, **kwargs):
        client = real_client(*args, **kwargs)
        clients.append(client)
        return client

    monkeypatch.setattr(h2_transport, 'H2Transport', capture_transport)
    monkeypatch.setattr(httpx, 'AsyncClient', capture_client)
    report = load_selftest()['transport_mechanics_selftest']()
    assert report == {
        'schema_version': 1, 'result': 'passed', 'versions': ['v1', 'v2'],
        'families': ['inet', 'inet6'], 'exact_host_fallback': True,
        'protected_routes_isolation': True, 'network_mutated': False,
    }
    assert len(clients) == len(transports) == 1
    assert clients[0].is_closed
    assert transports[0].closed and transports[0].connection is None


def test_transport_initialization_failure_cannot_pass(monkeypatch):
    transport = importlib.import_module('proxy.h2_transport')

    def broken_transport(*args, **kwargs):
        raise RuntimeError('Missing bundled SSL data')

    monkeypatch.setattr(transport, 'H2Transport', broken_transport)
    with pytest.raises(RuntimeError, match='Missing bundled SSL data'):
        load_selftest()['transport_mechanics_selftest']()


def test_packaged_workflow_command_satisfies_actual_selftest_capability(monkeypatch, capsys):
    workflow = (ROOT / '.github/workflows/ci.yml').read_text()
    start = workflow.index('      - name: Verify packaged resources\n')
    gate = workflow[start:workflow.index('\n      - ', start + 1)]
    commands = [line for line in gate.replace('\\\n', '').splitlines()
                if '--transport-mechanics-selftest' in line]
    assert len(commands) == 1
    argv = shlex.split(commands[0])

    # Interpret only this fixed command's sudo/env prefix, without a shell or
    # subprocess. No inherited environment may accidentally grant capability.
    euid = 501
    if argv[0] == 'sudo':
        euid = 0
        argv.pop(0)
    if argv[0] == 'env':
        argv.pop(0)
    environment = {}
    while argv and '=' in argv[0]:
        key, value = argv.pop(0).split('=', 1)
        environment[key] = value
    assert argv == ['$daemon', '--transport-mechanics-selftest']

    source = ast.parse((ROOT / 'spike/tproxy.py').read_text())
    main = next(node for node in source.body
                if isinstance(node, ast.FunctionDef) and node.name == 'main')
    calls = []
    report = {'result': 'passed', 'fixture': 'capability-only'}

    def checked_selftest():
        calls.append(True)
        return report

    namespace = {
        'argparse': argparse, 'json': json, 'sys': sys, 'PROXY_PORT': 7777,
        'os': SimpleNamespace(geteuid=lambda: euid, environ=environment),
        'transport_mechanics_selftest': checked_selftest,
    }
    exec(compile(ast.Module(body=[main], type_ignores=[]), 'selftest-main', 'exec'), namespace)
    monkeypatch.setattr(sys, 'argv', argv)
    assert namespace['main']() is None
    assert calls == [True]
    assert json.loads(capsys.readouterr().out) == report
