#!/bin/bash
# Freeze the daemon (tproxy.py) into a self-contained binary with PyInstaller, so
# the shipped .app needs NO Python/venv on the end user's machine. Run on a Mac
# with network (pulls pyinstaller + runtime deps from PyPI). Output: dist/slipstreamd/.
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
echo ">> build venv + pyinstaller + runtime deps ..."
rm -rf .buildvenv
"$PY" -m venv .buildvenv
.buildvenv/bin/python -m pip install --quiet --upgrade pip
.buildvenv/bin/python -m pip install --quiet pyinstaller scapy cryptography certifi

echo ">> freezing tproxy.py via slipstreamd.spec ..."
rm -rf build dist
.buildvenv/bin/pyinstaller --noconfirm --clean slipstreamd.spec

echo
echo "built dist/slipstreamd/  (self-contained, no Python needed)"
echo
echo "1) validate the freeze (no root — checks scapy import + status path):"
echo "     ./dist/slipstreamd/slipstreamd --status"
echo "2) install from the frozen binary (replaces the venv daemon):"
echo "     sudo ./dist/slipstreamd/slipstreamd --install"
