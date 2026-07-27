#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="${1:?usage: build_safari_companion.sh OUTPUT_DIRECTORY}"
APP_NAME="Slipstream Safari Companion"
BUNDLE_ID="dev.slipstream.Slipstream-Safari-Companion"
PROJECT_ROOT="$OUTPUT/$APP_NAME"
APP="$OUTPUT/DerivedData/Build/Products/Release/$APP_NAME.app"
APPEX="$APP/Contents/PlugIns/$APP_NAME Extension.appex"
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Versions/Current/Frameworks/LaunchServices.framework/Versions/Current/Support/lsregister"

if [[ ! -x "$LSREGISTER" ]]; then
  echo "LaunchServices registration tool is unavailable" >&2
  exit 1
fi

if xcrun --find safari-web-extension-packager >/dev/null 2>&1; then
  SAFARI_PACKAGER="safari-web-extension-packager"
elif xcrun --find safari-web-extension-converter >/dev/null 2>&1; then
  SAFARI_PACKAGER="safari-web-extension-converter"
else
  echo "Apple Safari WebExtension packaging tool is unavailable" >&2
  exit 1
fi

if [[ -e "$OUTPUT" ]]; then
  echo "refusing to replace existing output: $OUTPUT" >&2
  exit 1
fi

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/slipstream-safari-extension.XXXXXX")"

cleanup() {
  local status=$?
  local cleanup_status=0
  local real_app=""
  local registration_present=0

  trap - EXIT
  rm -rf "$STAGE"
  if [[ -x "$LSREGISTER" && -d "$APP" ]]; then
    real_app="$(realpath "$APP")"
    "$LSREGISTER" -u "$real_app" >/dev/null 2>&1 \
      || cleanup_status=1
    for _ in 1 2 3; do
      sleep 1
      if ! "$LSREGISTER" -dump | grep -F "$real_app" >/dev/null; then
        registration_present=0
        break
      fi
      registration_present=1
    done
    (( registration_present == 0 )) || cleanup_status=1
  fi

  if (( status == 0 && cleanup_status != 0 )); then
    echo "failed to unregister temporary Safari build products" >&2
    exit "$cleanup_status"
  fi
  exit "$status"
}
trap cleanup EXIT

cp "$ROOT/browser-companion/safari/manifest.json" "$STAGE/manifest.json"
cp "$ROOT/browser-companion/safari/service-worker.js" "$STAGE/service-worker.js"
cp "$ROOT/browser-companion/chromium/service-worker-core.js" \
  "$STAGE/service-worker-core.js"
cp "$ROOT/browser-companion/chromium/detector.js" "$STAGE/detector.js"
cp "$ROOT/browser-companion/chromium/content.js" "$STAGE/content.js"
cp "$ROOT/app-tauri/src-tauri/icons/32x32.png" "$STAGE/icon-32.png"
cp "$ROOT/app-tauri/src-tauri/icons/64x64.png" "$STAGE/icon-64.png"
cp "$ROOT/app-tauri/src-tauri/icons/128x128.png" "$STAGE/icon-128.png"

xcrun "$SAFARI_PACKAGER" \
  --project-location "$OUTPUT" \
  --app-name "$APP_NAME" \
  --bundle-identifier "$BUNDLE_ID" \
  --swift \
  --macos-only \
  --copy-resources \
  --no-open \
  --no-prompt \
  "$STAGE"

HANDLER="$PROJECT_ROOT/$APP_NAME Extension/SafariWebExtensionHandler.swift"
cat \
  "$ROOT/browser-companion/safari/Sources/SemanticBridge.swift" \
  "$ROOT/browser-companion/safari/Sources/SafariWebExtensionHandler.swift" \
  > "$HANDLER"

xcodebuild \
  -quiet \
  -project "$PROJECT_ROOT/$APP_NAME.xcodeproj" \
  -scheme "$APP_NAME" \
  -configuration Release \
  -destination "platform=macOS,arch=arm64" \
  -derivedDataPath "$OUTPUT/DerivedData" \
  MACOSX_DEPLOYMENT_TARGET=13.0 \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  build

test -x "$APP/Contents/MacOS/$APP_NAME"
test -x "$APPEX/Contents/MacOS/$APP_NAME Extension"
test -f "$APPEX/Contents/Resources/manifest.json"

echo "$APP"
