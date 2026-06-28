// Slipstream — tray app (Tauri v2). Unprivileged menu-bar UI over the root
// daemon (tproxy.py). Reads the daemon's status file; controls it via launchctl
// with a one-time admin prompt. Built-in signed auto-updater + a bundled
// geph5-client sidecar (unprivileged SOCKS, started here; the root daemon just
// routes geo-blocked hosts to its local port).
//
// NOTE: authored without a local Rust toolchain — first `cargo build` may need
// small API touch-ups. Build: `npm install && npm run tauri build` (see README).
#![cfg_attr(all(not(debug_assertions), target_os = "windows"), windows_subsystem = "windows")]

use std::fs;
use std::process::Command;
use std::time::Duration;

use serde_json::Value;
use tauri::{
    image::Image,
    menu::{MenuBuilder, MenuItem, MenuItemBuilder, SubmenuBuilder},
    tray::TrayIconBuilder,
    AppHandle, Manager,
};

const STATUS_PATH: &str = "/var/run/slipstream.status";
const LOG_PATH: &str = "/var/log/slipstream.log";
const LAUNCHD_LABEL: &str = "dev.slipstream.tproxy";
const PLIST: &str = "/Library/LaunchDaemons/dev.slipstream.tproxy.plist";

// Menu-item ids (matched in the event handler).
const ID_RESTART: &str = "restart_proxy";
const ID_LOG: &str = "open_log";
const ID_GEPH: &str = "geph_settings";
const ID_UPDATE: &str = "check_updates";
const ID_QUIT: &str = "quit";

/// Daemon status, or None if the file is missing/stale (>15s old → treat as off).
fn read_status() -> Option<Value> {
    let raw = fs::read_to_string(STATUS_PATH).ok()?;
    let v: Value = serde_json::from_str(&raw).ok()?;
    let ts = v.get("ts").and_then(|x| x.as_f64()).unwrap_or(0.0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    if now - ts > 15.0 {
        return None;
    }
    Some(v)
}

/// Run a privileged shell line via one osascript admin prompt (same model as the
/// old Swift app). Used for launchctl control of the root daemon.
fn run_admin(shell: &str) {
    let escaped = shell.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!("do shell script \"{escaped}\" with administrator privileges");
    let _ = Command::new("/usr/bin/osascript").arg("-e").arg(script).spawn();
}

/// Recompute the tray title/detail/icon from the current daemon status.
fn refresh(app: &AppHandle, state_item: &MenuItem<tauri::Wry>, detail_item: &MenuItem<tauri::Wry>) {
    let st = read_status();
    let state = st
        .as_ref()
        .and_then(|v| v.get("state"))
        .and_then(|x| x.as_str())
        .unwrap_or("off");
    let conns = st
        .as_ref()
        .and_then(|v| v.get("conns"))
        .and_then(|x| x.as_i64())
        .unwrap_or(0);
    let learned = st
        .as_ref()
        .and_then(|v| v.get("hosts_learned"))
        .and_then(|x| x.as_i64())
        .unwrap_or(0);
    let geph = st
        .as_ref()
        .and_then(|v| v.get("geph"))
        .and_then(|x| x.as_str())
        .unwrap_or("off");

    let (title, detail) = match state {
        "active" => {
            let mut d = format!("{conns} connections · {learned} hosts learned");
            if geph == "up" {
                d.push_str(" · Geph tunnel on");
            }
            ("Slipstream — Active".to_string(), d)
        }
        "dormant" => (
            "Slipstream — Dormant".to_string(),
            "VPN is up; the VPN handles bypass".to_string(),
        ),
        _ => ("Slipstream — Off".to_string(), String::new()),
    };
    let _ = state_item.set_text(&title);
    let _ = detail_item.set_text(if detail.is_empty() { " " } else { &detail });

    // Swap the menu-bar mark (template image → the bar tints it light/dark/active).
    if let Some(tray) = app.tray_by_id("main") {
        let name = if state == "off" {
            "slip-menubar-mark-off.png"
        } else {
            "slip-menubar-mark.png"
        };
        if let Ok(dir) = app.path().resource_dir() {
            if let Ok(img) = Image::from_path(dir.join("icons").join(name)) {
                let _ = tray.set_icon(Some(img));
                let _ = tray.set_icon_as_template(true);
            }
        }
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            // Tray-only: no Dock icon (macOS).
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            // --- menu ---------------------------------------------------------
            let state_item = MenuItemBuilder::with_id("state", "…").enabled(false).build(app)?;
            let detail_item = MenuItemBuilder::with_id("detail", " ").enabled(false).build(app)?;
            // Geph: settings + login + exit picker (no on/off — it engages only
            // for geo-blocked hosts automatically).
            let geph_submenu = SubmenuBuilder::new(app, "Geph")
                .item(&MenuItemBuilder::with_id(ID_GEPH, "Settings & Login…").build(app)?)
                .build()?;
            let menu = MenuBuilder::new(app)
                .item(&state_item)
                .item(&detail_item)
                .separator()
                .item(&geph_submenu)
                .item(&MenuItemBuilder::with_id(ID_RESTART, "Restart Proxy").build(app)?)
                .item(&MenuItemBuilder::with_id(ID_LOG, "Open Log").build(app)?)
                .separator()
                .item(&MenuItemBuilder::with_id(ID_UPDATE, "Check for Updates…").build(app)?)
                .item(&MenuItemBuilder::with_id("version", "Version 0.1").enabled(false).build(app)?)
                .item(&MenuItemBuilder::with_id(ID_QUIT, "Quit Slipstream").build(app)?)
                .build()?;

            // --- tray ---------------------------------------------------------
            let icon = Image::from_path(
                app.path().resource_dir()?.join("icons").join("slip-menubar-mark.png"),
            )
            .unwrap_or_else(|_| app.default_window_icon().unwrap().clone());
            let _tray = TrayIconBuilder::with_id("main")
                .icon(icon)
                .icon_as_template(true)
                .menu(&menu)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    ID_RESTART => {
                        run_admin(&format!("launchctl kickstart -k system/{LAUNCHD_LABEL}"));
                    }
                    ID_LOG => {
                        let _ = Command::new("/usr/bin/open").arg(LOG_PATH).spawn();
                    }
                    ID_GEPH => open_settings(app),
                    ID_UPDATE => {
                        let app = app.clone();
                        tauri::async_runtime::spawn(async move {
                            check_for_updates(app).await;
                        });
                    }
                    ID_QUIT => app.exit(0),
                    _ => {}
                })
                .build(app)?;

            // --- status poll every 2s ----------------------------------------
            let app_handle = app.handle().clone();
            let s = state_item.clone();
            let d = detail_item.clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    refresh(&app_handle, &s, &d);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            });

            // TODO(geph sidecar): once the CI-built geph5-client lands in
            // binaries/, start it here in SOCKS mode with a config generated from
            // the user's saved login/exit (Keychain). Until then the daemon falls
            // back to detecting an externally-running geph (current behaviour).

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Slipstream tray");
}

/// Open (or focus) the small settings window (geph login + exit picker).
fn open_settings(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("settings") {
        let _ = w.show();
        let _ = w.set_focus();
        return;
    }
    let _ = tauri::WebviewWindowBuilder::new(
        app,
        "settings",
        tauri::WebviewUrl::App("index.html".into()),
    )
    .title("Slipstream — Settings")
    .inner_size(420.0, 360.0)
    .resizable(false)
    .build();
}

/// Built-in signed updater: check the appcast, download + install if newer.
async fn check_for_updates(app: AppHandle) {
    use tauri_plugin_updater::UpdaterExt;
    let updater = match app.updater() {
        Ok(u) => u,
        Err(_) => return,
    };
    if let Ok(Some(update)) = updater.check().await {
        let _ = update.download_and_install(|_, _| {}, || {}).await;
        // restart to apply
        app.restart();
    }
}
