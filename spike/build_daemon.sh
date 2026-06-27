#!/bin/bash
# Freeze the daemon (tproxy.py) into a self-contained binary with PyInstaller, so
# the shipped .app needs NO Python/venv on the end user's machine. Run on a Mac
# with network (pulls pyinstaller + scapy from PyPI). Output: dist/slipstreamd/.
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
echo ">> build venv + pyinstaller + scapy ..."
rm -rf .buildvenv
"$PY" -m venv .buildvenv
.buildvenv/bin/python -m pip install --quiet --upgrade pip
.buildvenv/bin/python -m pip install --quiet pyinstaller scapy

echo ">> freezing tproxy.py (scapy collected whole — it imports submodules at runtime) ..."
rm -rf build dist slipstreamd.spec
.buildvenv/bin/pyinstaller --noconfirm --clean \
  --onedir --name slipstreamd \
  --collect-all scapy \
  tproxy.py

echo
echo "built dist/slipstreamd/  (self-contained, no Python needed)"
echo
echo "1) validate the freeze (no root — checks scapy import + status path):"
echo "     ./dist/slipstreamd/slipstreamd --status"
echo "2) install from the frozen binary (replaces the venv daemon):"
echo "     sudo ./dist/slipstreamd/slipstreamd --install"
