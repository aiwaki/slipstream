#!/bin/bash
# Render Resources/slip-appicon.svg into Resources/Slipstream.icns using AppKit
# (NSImage loads SVG on macOS 13+) + iconutil. No external SVG toolchain needed.
set -euo pipefail
cd "$(dirname "$0")"
SVG="Resources/slip-appicon.svg"
ICONSET="Slipstream.iconset"
rm -rf "$ICONSET"; mkdir -p "$ICONSET"

cat > /tmp/svg2png.swift <<'EOF'
import AppKit
let a = CommandLine.arguments
guard a.count == 4, let px = Int(a[3]), let img = NSImage(contentsOfFile: a[1]) else { exit(1) }
let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px,
  bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
  colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
rep.size = NSSize(width: px, height: px)
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
img.draw(in: NSRect(x: 0, y: 0, width: px, height: px))
NSGraphicsContext.restoreGraphicsState()
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: a[2]))
EOF
swiftc -O /tmp/svg2png.swift -o /tmp/svg2png -framework AppKit

gen() { /tmp/svg2png "$SVG" "$ICONSET/$2" "$1"; }
gen 16   icon_16x16.png
gen 32   icon_16x16@2x.png
gen 32   icon_32x32.png
gen 64   icon_32x32@2x.png
gen 128  icon_128x128.png
gen 256  icon_128x128@2x.png
gen 256  icon_256x256.png
gen 512  icon_256x256@2x.png
gen 512  icon_512x512.png
gen 1024 icon_512x512@2x.png

iconutil -c icns "$ICONSET" -o Resources/Slipstream.icns
rm -rf "$ICONSET"
echo "built Resources/Slipstream.icns"
