# -*- mode: python ; coding: utf-8 -*-
import os
import sys
from PyInstaller.utils.hooks import collect_all, collect_submodules

# Resolve inputs from the spec location, not the caller's working directory.
# Release CI, local scripts, and direct PyInstaller invocations must bundle the
# same daemon and vendored Telegram proxy.
_HERE = os.path.abspath(SPECPATH)
_ROOT = os.path.dirname(_HERE)
_TGWS = os.path.join(_ROOT, 'vendor', 'tg-ws-proxy')
if _TGWS not in sys.path:
    sys.path.insert(0, _TGWS)

datas = []
binaries = []
hiddenimports = []
_POLICY_KEYS = os.path.join(_HERE, 'route-policy-keys.json')
if os.path.exists(_POLICY_KEYS):
    datas.append((_POLICY_KEYS, '.'))
# scapy (fake-mode raw packets + voice) and cryptography (tg-ws-proxy AES) must be
# fully bundled — the frozen daemon has no system Python/venv to fall back on.
for _pkg in ('scapy', 'cryptography'):
    _d, _b, _h = collect_all(_pkg)
    datas += _d; binaries += _b; hiddenimports += _h
# The vendored tg-ws-proxy is imported dynamically (sys.path at runtime), so
# PyInstaller can't see it statically — pull its whole `proxy` package in by name.
hiddenimports += collect_submodules('proxy')


a = Analysis(
    [os.path.join(_HERE, 'tproxy.py')],
    pathex=[_TGWS],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='slipstreamd',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='slipstreamd',
)
