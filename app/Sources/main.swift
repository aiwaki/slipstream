// Slipstream — menu-bar app (AppKit NSStatusItem).
// Unprivileged UI over the root LaunchDaemon (tproxy.py). Reads the daemon's
// status file; toggles it via launchctl with a one-time admin prompt.

import AppKit
import Foundation

let LAUNCHD_LABEL = "dev.slipstream.tproxy"
let PLIST = "/Library/LaunchDaemons/\(LAUNCHD_LABEL).plist"
let STATUS_PATH = "/var/run/slipstream.status"
let LOG_PATH = "/var/log/slipstream.log"
let APP_VERSION = "0.1"

final class Controller: NSObject, NSApplicationDelegate {
    let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    let menu = NSMenu()
    let stateItem = NSMenuItem(title: "…", action: nil, keyEquivalent: "")
    let detailItem = NSMenuItem(title: "", action: nil, keyEquivalent: "")
    let toggleItem = NSMenuItem(title: "Enable", action: #selector(toggle), keyEquivalent: "")
    var timer: Timer?
    var lastState = "off"

    func applicationDidFinishLaunching(_ note: Notification) {
        stateItem.isEnabled = false
        detailItem.isEnabled = false
        menu.addItem(stateItem)
        menu.addItem(detailItem)
        menu.addItem(.separator())
        toggleItem.target = self
        menu.addItem(toggleItem)
        let restart = NSMenuItem(title: "Restart Proxy", action: #selector(restartProxy), keyEquivalent: "")
        restart.target = self
        menu.addItem(restart)
        let log = NSMenuItem(title: "Open Log", action: #selector(openLog), keyEquivalent: "")
        log.target = self
        menu.addItem(log)
        menu.addItem(.separator())
        let ver = NSMenuItem(title: "Version \(APP_VERSION)", action: nil, keyEquivalent: "")
        ver.isEnabled = false
        menu.addItem(ver)
        menu.addItem(NSMenuItem(title: "Quit Slipstream",
                                action: #selector(NSApplication.terminate(_:)),
                                keyEquivalent: "q"))
        statusItem.menu = menu
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { _ in self.refresh() }
    }

    func readStatus() -> [String: Any]? {
        guard let data = FileManager.default.contents(atPath: STATUS_PATH),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        if let ts = obj["ts"] as? Double,
           Date().timeIntervalSince1970 - ts > 15 { return nil }   // stale -> off
        return obj
    }

    func refresh() {
        let st = readStatus()
        let state = (st?["state"] as? String) ?? "off"
        lastState = state
        let conns = (st?["conns"] as? Int) ?? 0
        let learned = (st?["hosts_learned"] as? Int) ?? 0
        let geph = (st?["geph"] as? String) ?? "off"

        let markName = (state == "off") ? "slip-menubar-mark-off" : "slip-menubar-mark"
        if let url = Bundle.main.url(forResource: markName, withExtension: "svg"),
           let img = NSImage(contentsOf: url) {
            img.isTemplate = true                       // menu bar tints it (light/dark/active)
            img.size = NSSize(width: 30, height: 17)    // 56x32 aspect
            statusItem.button?.image = img
        }
        switch state {
        case "active":
            stateItem.title = "Slipstream — Active"
            var d = "\(conns) connections · \(learned) hosts learned"
            if geph == "up" { d += " · Geph tunnel on" }   // geo-blocked hosts routed
            detailItem.title = d
        case "dormant":
            stateItem.title = "Slipstream — Dormant"
            detailItem.title = "VPN is up; the VPN handles bypass"
        default:
            stateItem.title = "Slipstream — Off"
            detailItem.title = ""
        }
        detailItem.isHidden = detailItem.title.isEmpty
        toggleItem.title = (state == "off") ? "Enable" : "Disable"
    }

    @objc func toggle() {
        let on = lastState != "off"
        let cmd = on
            ? "launchctl bootout system \(PLIST)"
            : "launchctl bootstrap system \(PLIST)"
        runAdmin(cmd)
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { self.refresh() }
    }

    @objc func restartProxy() {
        runAdmin("launchctl kickstart -k system/\(LAUNCHD_LABEL)")
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { self.refresh() }
    }

    @objc func openLog() {
        NSWorkspace.shared.open(URL(fileURLWithPath: LOG_PATH))
    }

    func runAdmin(_ shell: String) {
        let escaped = shell.replacingOccurrences(of: "\"", with: "\\\"")
        let script = "do shell script \"\(escaped)\" with administrator privileges"
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        p.arguments = ["-e", script]
        try? p.run()
    }
}

let app = NSApplication.shared
let controller = Controller()
app.delegate = controller
app.setActivationPolicy(.accessory)   // menu-bar only, no Dock icon
app.run()
