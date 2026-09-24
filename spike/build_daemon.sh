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

# Packaged CI needs an ephemeral verification key embedded in the exact daemon
# that PyInstaller freezes. Generate it only after the locked build environment
# exists, so the policy tool uses the same pinned runtime dependencies and no
# second preparation/freeze path can drift from the bundled daemon.
if [[ -n "${SLIPSTREAM_EPHEMERAL_ROUTE_POLICY_KEY_ID:-}" ]]; then
  policy_key_dir="$(mktemp -d "${TMPDIR:-/tmp}/slipstream-route-policy-key.XXXXXX")"
  policy_private_key="$policy_key_dir/private.key"
  policy_public_keys="$policy_key_dir/public.json"
  trap 'rm -f "$policy_private_key" "$policy_public_keys"; rmdir "$policy_key_dir" 2>/dev/null || true' EXIT
  .buildvenv/bin/python ../scripts/make_route_policy_bundle.py \
    --generate-keypair \
    --key-id "$SLIPSTREAM_EPHEMERAL_ROUTE_POLICY_KEY_ID" \
    --private-key-output "$policy_private_key" \
    --public-keys-output "$policy_public_keys"
  mv -f "$policy_public_keys" route-policy-keys.json
  rm -f "$policy_private_key"
  rmdir "$policy_key_dir"
  trap - EXIT
fi

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
