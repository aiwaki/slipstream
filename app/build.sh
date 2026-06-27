#!/bin/bash
# Build Slipstream.app from Sources/main.swift — no Xcode project needed.
# Requires the Swift toolchain (comes with Xcode or the Command Line Tools).
set -euo pipefail
cd "$(dirname "$0")"

APP="Slipstream.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp Info.plist "$APP/Contents/Info.plist"

[ -f Resources/Slipstream.icns ] || ./make_icns.sh
cp Resources/*.svg Resources/Slipstream.icns "$APP/Contents/Resources/"

swiftc -O Sources/main.swift \
  -o "$APP/Contents/MacOS/Slipstream" \
  -framework AppKit -framework Foundation \
  -target "$(uname -m)-apple-macos13.0"

# ad-hoc sign so Gatekeeper lets it run locally
codesign --force --deep --sign - "$APP" >/dev/null 2>&1 || true

echo "built ./$APP"
echo "run:  open ./$APP   (look for the bolt icon in the menu bar)"
echo "note: the daemon must be installed once — sudo .venv/bin/python ../spike/tproxy.py --install"
