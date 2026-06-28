// Slipstream — tray app (Tauri v2). Unprivileged menu-bar UI over the root
// daemon (tproxy.py). Reads the daemon's status file; controls it via launchctl
// with a one-time admin prompt. Built-in signed auto-updater + a bundled
// geph5-client sidecar (the root daemon routes geo-blocked hosts to its port).
//
// Logic lives here (lib.rs) so the same crate can back a mobile entry point
// later; main.rs is a thin desktop shim.

use std::fs;
use std::process::Command;
use std::time::Duration;

use serde_json::Value;
use tauri::{
    image::Image,
    menu::{MenuBuilder, MenuItem, MenuItemBuilder},
    tray::TrayIconBuilder,
    AppHandle, Manager,
};

const STATUS_PATH: &str = "/var/run/slipstream.status";
const LOG_PATH: &str = "/var/log/slipstream.log";
const LAUNCHD_LABEL: &str = "dev.slipstream.tproxy";

// Menu-item ids (matched in the event handler).
const ID_SETTINGS: &str = "settings";
const ID_RESTART: &str = "restart_proxy";
const ID_LOG: &str = "open_log";
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
    let get_str = |k: &str, d: &'static str| -> String {
        st.as_ref()
            .and_then(|v| v.get(k))
            .and_then(|x| x.as_str())
            .unwrap_or(d)
            .to_string()
    };
    let get_i64 = |k: &str| -> i64 {
        st.as_ref()
            .and_then(|v| v.get(k))
            .and_then(|x| x.as_i64())
            .unwrap_or(0)
    };
    let state = get_str("state", "off");
    let conns = get_i64("conns");
    let learned = get_i64("hosts_learned");
    let geph = get_str("geph", "off");

    let (title, detail) = match state.as_str() {
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

/// Open (or focus) the Settings window. Closing it does NOT quit the app — the
/// ExitRequested guard in run() keeps the tray alive (the bug the screenshot
/// caught). Reopening rebuilds the window; on close it hides instead of being
/// destroyed, preserving form state.
fn open_settings(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("settings") {
        let _ = w.show();
        let _ = w.set_focus();
        return;
    }
    if let Ok(window) = tauri::WebviewWindowBuilder::new(
        app,
        "settings",
        tauri::WebviewUrl::App("index.html".into()),
    )
    .title("Slipstream Settings")
    .inner_size(560.0, 430.0)
    .resizable(false)
    .build()
    {
        // Accessory apps don't auto-activate a freshly-built window -> show+focus
        // explicitly so the FIRST click opens it (it used to need a second click).
        let _ = window.show();
        let _ = window.set_focus();
        let w = window.clone();
        window.on_window_event(move |event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let _ = w.hide();
                api.prevent_close(); // hide, don't destroy -> keeps state + app alive
            }
        });
    }
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
        app.restart();
    }
}

// ---- commands the settings window calls -----------------------------------
/// Live daemon status JSON for the Network panel (None → app shows "Off").
#[tauri::command]
fn daemon_status() -> Option<Value> {
    read_status()
}

/// Save geph login + exit. TODO: store the secret in the Keychain and (re)start
/// the bundled geph5-client with a config for this exit. Stub until the CI binary
/// lands; intentionally does NOT touch the separately-installed Geph.app.
#[tauri::command]
fn save_geph_config(secret: String, exit: String) -> Result<(), String> {
    let _ = (secret, exit);
    Ok(())
}

/// Toggle launch-at-login for the menu-bar app. TODO: wire to the autostart
/// plugin (the root engine already starts at boot independently).
#[tauri::command]
fn set_launch_at_login(enabled: bool) -> Result<(), String> {
    let _ = enabled;
    Ok(())
}

/// Run the updater check from the About panel button.
#[tauri::command]
async fn trigger_update_check(app: AppHandle) {
    check_for_updates(app).await;
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            daemon_status,
            save_geph_config,
            set_launch_at_login,
            trigger_update_check
        ])
        .setup(|app| {
            // Tray-only: no Dock icon (macOS).
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            // --- menu (top-level Settings… with the standard ⌘, accelerator) ---
            let state_item = MenuItemBuilder::with_id("state", "…").enabled(false).build(app)?;
            let detail_item = MenuItemBuilder::with_id("detail", " ").enabled(false).build(app)?;
            let menu = MenuBuilder::new(app)
                .item(&state_item)
                .item(&detail_item)
                .separator()
                .item(
                    &MenuItemBuilder::with_id(ID_SETTINGS, "Settings…")
                        .accelerator("CmdOrCtrl+,")
                        .build(app)?,
                )
                .item(&MenuItemBuilder::with_id(ID_RESTART, "Restart Proxy").build(app)?)
                .item(&MenuItemBuilder::with_id(ID_LOG, "Open Log").build(app)?)
                .separator()
                .item(&MenuItemBuilder::with_id(ID_UPDATE, "Check for Updates…").build(app)?)
                .item(&MenuItemBuilder::with_id("version", "Version 0.1").enabled(false).build(app)?)
                .item(
                    &MenuItemBuilder::with_id(ID_QUIT, "Quit Slipstream")
                        .accelerator("CmdOrCtrl+Q")
                        .build(app)?,
                )
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
                    ID_SETTINGS => open_settings(app),
                    ID_RESTART => {
                        run_admin(&format!("launchctl kickstart -k system/{LAUNCHD_LABEL}"));
                    }
                    ID_LOG => {
                        let _ = Command::new("/usr/bin/open").arg(LOG_PATH).spawn();
                    }
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
            // the saved login/exit. The exit list + load % come from geph itself
            // (a geph5-client query) — do NOT depend on a separately-installed
            // Geph.app; that external-:9909 detection is only an interim bridge.

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building Slipstream tray");

    // Keep the app alive on the tray when windows close (implicit exit, code:None);
    // an explicit Quit (app.exit(0)) carries a code and is allowed through.
    app.run(|_app, event| {
        if let tauri::RunEvent::ExitRequested { code, api, .. } = event {
            if code.is_none() {
                api.prevent_exit();
            }
        }
    });
}
