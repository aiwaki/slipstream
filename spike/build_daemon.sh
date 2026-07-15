#!/bin/bash
# Freeze the daemon (tproxy.py) into a self-contained binary with PyInstaller, so
# the shipped .app needs NO Python/venv on the end user's machine. Run on a Mac
# with network (pulls pyinstaller + runtime deps from PyPI). Output: dist/slipstreamd/.
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
PY_MINOR="$($PY -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
if [[ "$PY_MINOR" != "3.13" ]]; then
  echo "Python 3.13 is required to build slipstreamd (found $PY_MINOR)" >&2
  exit 1
fi
echo ">> build venv + pyinstaller + runtime deps ..."
rm -rf .buildvenv
"$PY" -m venv .buildvenv
.buildvenv/bin/python -m pip install \
  --quiet \
  --disable-pip-version-check \
  --only-binary=:all: \
  --require-hashes \
  -r requirements-build.txt

echo ">> freezing tproxy.py via slipstreamd.spec ..."
rm -rf build dist
.buildvenv/bin/pyinstaller --noconfirm --clean slipstreamd.spec

echo
echo "built dist/slipstreamd/  (self-contained, no Python needed)"
echo
echo "1) validate the freeze (no root — checks scapy import + status path):"
echo "     ./dist/slipstreamd/slipstreamd --status"
echo "2) qualify privileged lifecycle only on disposable CI/test machines:"
echo "     see ../DEVELOPMENT.md"
