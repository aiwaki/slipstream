#!/bin/bash
# Render the SVG marks into the assets Tauri needs:
#   icons/slip-menubar-mark.png       (tray, template image)
#   icons/slip-menubar-mark-off.png   (tray, off state)
#   icons/icon.icns                   (app bundle icon)
# Uses AppKit (NSImage loads SVG on macOS 13+) — no external SVG toolchain.
set -euo pipefail
cd "$(dirname "$0")/src-tauri/icons"

cat > /tmp/slip_svg2png.swift <<'EOF'
import AppKit
let a = CommandLine.arguments
guard a.count == 5, let w = Int(a[3]), let h = Int(a[4]),
      let img = NSImage(contentsOfFile: a[1]) else { exit(1) }
let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: w, pixelsHigh: h,
  bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
  colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
rep.size = NSSize(width: w, height: h)
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
img.draw(in: NSRect(x: 0, y: 0, width: w, height: h))
NSGraphicsContext.restoreGraphicsState()
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: a[2]))
EOF
swiftc -O /tmp/slip_svg2png.swift -o /tmp/slip_svg2png -framework AppKit

# menu-bar marks: 56x32 aspect -> render at 2x (mac tints the template)
/tmp/slip_svg2png slip-menubar-mark.svg     slip-menubar-mark.png     72 40
/tmp/slip_svg2png slip-menubar-mark-off.svg slip-menubar-mark-off.png 72 40

# app icon -> icns
ICONSET=Slipstream.iconset
rm -rf "$ICONSET"; mkdir -p "$ICONSET"
gen() { /tmp/slip_svg2png slip-appicon.svg "$ICONSET/$2" "$1" "$1"; }
gen 16 icon_16x16.png;     gen 32 icon_16x16@2x.png
gen 32 icon_32x32.png;     gen 64 icon_32x32@2x.png
gen 128 icon_128x128.png;  gen 256 icon_128x128@2x.png
gen 256 icon_256x256.png;  gen 512 icon_256x256@2x.png
gen 512 icon_512x512.png;  gen 1024 icon_512x512@2x.png
iconutil -c icns "$ICONSET" -o icon.icns
rm -rf "$ICONSET"
echo "built icons/: slip-menubar-mark{,-off}.png, icon.icns"
