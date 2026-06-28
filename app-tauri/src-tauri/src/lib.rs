// Slipstream — tray app (Tauri v2). Unprivileged menu-bar UI over the root
// daemon (tproxy.py). The UI is 100% NATIVE: a real NSMenu (tray) + native
// osascript dialogs — no WebView window (a styled WebView always reads as
// "web", which is the look we're avoiding). Tauri still provides the native
// tray, the signed auto-updater, and the geph sidecar.
//
// Logic lives here (lib.rs) so the same crate can back a mobile entry point
// later; main.rs is a thin desktop shim.

use std::fs;
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

use serde_json::Value;
use tauri::{
    image::Image,
    menu::{CheckMenuItem, CheckMenuItemBuilder, MenuBuilder, MenuItem, MenuItemBuilder, SubmenuBuilder},
    tray::TrayIconBuilder,
    AppHandle, Manager,
};
use tauri_plugin_autostart::ManagerExt;
use tauri_plugin_shell::{process::CommandChild, process::CommandEvent, ShellExt};

// Our bundled geph5-client runs an unprivileged SOCKS5 on this port; the root
// daemon routes geo-blocked hosts to it. A dedicated port (not geph's default
// 9909) so it never clashes with a separately-installed Geph.app.
const GEPH_SOCKS_PORT: u16 = 9954;

/// Holds the running geph5-client child so the menu can kill+respawn it on a
/// config change (the supervisor loop then restarts it with the new config).
#[derive(Default)]
struct GephState {
    child: Mutex<Option<CommandChild>>,
}

const STATUS_PATH: &str = "/var/run/slipstream.status";
const LOG_PATH: &str = "/var/log/slipstream.log";
const LAUNCHD_LABEL: &str = "dev.slipstream.tproxy";

const ID_ACCOUNT: &str = "geph_account";
const ID_LAUNCH: &str = "launch_at_login";
const ID_RESTART: &str = "restart_proxy";
const ID_LOG: &str = "open_log";
const ID_UPDATE: &str = "check_updates";
const ID_QUIT: &str = "quit";

// geph exit catalog (value, menu label). Static for now; a geph5-client query
// will replace this with the live list + load % once the bundled binary lands.
const EXITS_CORE: &[(&str, &str)] = &[
    ("ca-montreal", "🇨🇦 CA / Montreal"),
    ("ca-toronto", "🇨🇦 CA / Toronto (beta)"),
    ("ch-zurich", "🇨🇭 CH / Zurich"),
    ("cz-prague", "🇨🇿 CZ / Prague"),
    ("jp-osaka", "🇯🇵 JP / Osaka (beta)"),
    ("jp-tokyo", "🇯🇵 JP / Tokyo"),
    ("pl-warsaw", "🇵🇱 PL / Warsaw"),
    ("se-stockholm", "🇸🇪 SE / Stockholm (beta)"),
    ("sg-singapore", "🇸🇬 SG / Singapore"),
    ("us-ashburn", "🇺🇸 US / Ashburn"),
    ("us-dallas", "🇺🇸 US / Dallas (beta)"),
    ("us-sanjose", "🇺🇸 US / San Jose"),
    ("us-seattle", "🇺🇸 US / Seattle (beta)"),
];
const EXITS_STREAM: &[(&str, &str)] = &[
    ("hk-jordan", "🇭🇰 HK / Jordan"),
    ("tw-taipei", "🇹🇼 TW / Taipei"),
];

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

/// Run a privileged shell line via one osascript admin prompt.
fn run_admin(shell: &str) {
    let escaped = shell.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!("do shell script \"{escaped}\" with administrator privileges");
    let _ = Command::new("/usr/bin/osascript").arg("-e").arg(script).spawn();
}

/// Native secret-entry dialog (the same NSAlert look as TG WS Proxy). Pre-fills
/// the current secret and shows it (a 24-digit secret is unusable to type blind),
/// like geph's own Account screen. Returns the entered text, or None if cancelled.
fn prompt_secret(current: &str) -> Option<String> {
    let cur = current.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!(
        "display dialog \"Geph account secret\" with title \"Slipstream\" \
         default answer \"{cur}\" \
         buttons {{\"Cancel\", \"OK\"}} default button \"OK\""
    );
    let out = Command::new("/usr/bin/osascript").arg("-e").arg(&script).output().ok()?;
    if !out.status.success() {
        return None; // user cancelled
    }
    let s = String::from_utf8_lossy(&out.stdout);
    s.split("text returned:").nth(1).map(|t| t.trim().to_string())
}

/// Persist a geph setting (secret / exit / launch) into the per-user config the
/// bundled geph5-client supervisor will read. Does NOT touch a separately
/// installed Geph.app.
fn geph_config_set(app: &AppHandle, key: &str, val: &str) {
    let Ok(dir) = app.path().app_config_dir() else { return };
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("geph.json");
    let mut cfg: serde_json::Map<String, Value> = fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    cfg.insert(key.to_string(), Value::String(val.to_string()));
    if let Ok(s) = serde_json::to_string_pretty(&Value::Object(cfg)) {
        let _ = fs::write(&path, s);
    }
}

/// Refresh the two status info-items from the daemon status.
fn refresh(state_item: &MenuItem<tauri::Wry>, detail_item: &MenuItem<tauri::Wry>, app: &AppHandle) {
    let st = read_status();
    let get_str = |k: &str, d: &'static str| -> String {
        st.as_ref().and_then(|v| v.get(k)).and_then(|x| x.as_str()).unwrap_or(d).to_string()
    };
    let get_i64 = |k: &str| -> i64 {
        st.as_ref().and_then(|v| v.get(k)).and_then(|x| x.as_i64()).unwrap_or(0)
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

    if let Some(tray) = app.tray_by_id("main") {
        let name = if state == "off" { "slip-menubar-mark-off.png" } else { "slip-menubar-mark.png" };
        if let Ok(dir) = app.path().resource_dir() {
            if let Ok(img) = Image::from_path(dir.join("icons").join(name)) {
                let _ = tray.set_icon(Some(img));
                let _ = tray.set_icon_as_template(true);
            }
        }
    }
}

/// Built-in signed updater: check the appcast, download + install if newer.
async fn check_for_updates(app: AppHandle) {
    use tauri_plugin_updater::UpdaterExt;
    let Ok(updater) = app.updater() else { return };
    if let Ok(Some(update)) = updater.check().await {
        let _ = update.download_and_install(|_, _| {}, || {}).await;
        app.restart();
    }
}

/// Read the saved geph account secret (None → not signed in yet → don't start geph).
fn geph_secret(app: &AppHandle) -> Option<String> {
    let path = app.path().app_config_dir().ok()?.join("geph.json");
    let v: Value = serde_json::from_str(&fs::read_to_string(path).ok()?).ok()?;
    let s = v.get("secret").and_then(|x| x.as_str())?.trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// Build a complete geph5-client YAML config. The broker fronts + Mizaru keys are
/// the public geph-network constants (from geph-official/geph5); only the account
/// secret is user-specific. Exit stays Auto for now (any abroad exit unblocks the
/// geo-locked services; mapping the picked country comes with the live exit list).
fn geph_config_yaml(secret: &str) -> String {
    let esc = secret.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        "socks5_listen: 127.0.0.1:{GEPH_SOCKS_PORT}\n\
         http_proxy_listen: null\n\
         pac_listen: null\n\
         control_listen: null\n\
         exit_constraint: auto\n\
         cache: null\n\
         broker:\n\
         \x20 race:\n\
         \x20   - fronted: {{front: https://www.cdn77.com/, host: 1826209743.rsc.cdn77.org, override_dns: null}}\n\
         \x20   - fronted: {{front: https://vuejs.org/, host: svitania-naidallszei-2.netlify.app, override_dns: null}}\n\
         tunneled_broker: null\n\
         broker_keys:\n\
         \x20 master: 88c1d2d4197bed815b01a22cadfc6c35aa246dddb553682037a118aebfaa3954\n\
         \x20 mizaru_free: 0558216cbab7a9c46f298f4c26e171add9af87d0694988b8a8fe52ee932aa754\n\
         \x20 mizaru_plus: cf6f58868c6d9459b3a63bc2bd86165631b3e916bad7f62b578cd9614e0bcb3b\n\
         \x20 mizaru_bw: \"\"\n\
         task_limit: null\n\
         credentials:\n\
         \x20 secret: \"{esc}\"\n"
    )
}

/// Stop a running geph5-client (e.g. before respawning with a new config).
fn geph_stop(app: &AppHandle) {
    if let Some(child) = app.state::<GephState>().child.lock().unwrap().take() {
        let _ = child.kill();
    }
}

/// Supervisor: whenever a secret is configured, run the bundled geph5-client
/// sidecar and keep it alive (respawn on exit). Killing the child (on a config
/// change) makes this loop pick up the new config on the next iteration.
async fn geph_supervisor(app: AppHandle) {
    loop {
        let Some(secret) = geph_secret(&app) else {
            tokio::time::sleep(Duration::from_secs(3)).await;
            continue;
        };
        // write the active config next to geph.json
        let cfg_path = match app.path().app_config_dir() {
            Ok(dir) => {
                let _ = fs::create_dir_all(&dir);
                dir.join("geph-active.yaml")
            }
            Err(_) => {
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        let _ = fs::write(&cfg_path, geph_config_yaml(&secret));

        let sidecar = match app.shell().sidecar("geph5-client") {
            Ok(c) => c.args(["--config", &cfg_path.to_string_lossy()]),
            Err(e) => {
                eprintln!("geph sidecar missing: {e}");
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
        };
        let (mut rx, child) = match sidecar.spawn() {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("geph spawn failed: {e}");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        *app.state::<GephState>().child.lock().unwrap() = Some(child);
        // drain events until the process exits (crash or killed-for-restart)
        while let Some(ev) = rx.recv().await {
            if let CommandEvent::Terminated(_) = ev {
                break;
            }
        }
        app.state::<GephState>().child.lock().unwrap().take();
        tokio::time::sleep(Duration::from_secs(2)).await; // brief backoff, then respawn
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        // single-instance MUST be the first plugin: a second launch just exits.
        .plugin(tauri_plugin_single_instance::init(|_app, _argv, _cwd| {}))
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            let state_item = MenuItemBuilder::with_id("state", "…").enabled(false).build(app)?;
            let detail_item = MenuItemBuilder::with_id("detail", " ").enabled(false).build(app)?;

            // ---- Geph submenu: Account… + checkable exit list (grouped) ------
            let saved_exit = app
                .path()
                .app_config_dir()
                .ok()
                .map(|d| d.join("geph.json"))
                .and_then(|p| fs::read_to_string(p).ok())
                .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                .and_then(|v| v.get("exit").and_then(|x| x.as_str()).map(String::from))
                .unwrap_or_else(|| "auto".into());

            let mut exit_items: Vec<(String, CheckMenuItem<tauri::Wry>)> = Vec::new();
            let mk = |app: &tauri::App, val: &str, label: &str| {
                CheckMenuItemBuilder::with_id(format!("exit:{val}"), label)
                    .checked(val == saved_exit)
                    .build(app)
            };
            let auto = mk(app, "auto", "Automatic")?;
            exit_items.push(("auto".into(), auto.clone()));

            let mut gb = SubmenuBuilder::new(app, "Geph")
                .item(&MenuItemBuilder::with_id(ID_ACCOUNT, "Account…").accelerator("CmdOrCtrl+,").build(app)?)
                .separator()
                .item(&auto)
                .separator()
                .item(&MenuItemBuilder::with_id("lbl_core", "Core").enabled(false).build(app)?);
            for (val, label) in EXITS_CORE {
                let it = mk(app, val, label)?;
                exit_items.push(((*val).into(), it.clone()));
                gb = gb.item(&it);
            }
            gb = gb
                .separator()
                .item(&MenuItemBuilder::with_id("lbl_stream", "Streaming").enabled(false).build(app)?);
            for (val, label) in EXITS_STREAM {
                let it = mk(app, val, label)?;
                exit_items.push(((*val).into(), it.clone()));
                gb = gb.item(&it);
            }
            let geph_menu = gb.build()?;

            let autostart_on = app.autolaunch().is_enabled().unwrap_or(false);
            let launch = CheckMenuItemBuilder::with_id(ID_LAUNCH, "Launch at Login")
                .checked(autostart_on)
                .build(app)?;

            let menu = MenuBuilder::new(app)
                .item(&state_item)
                .item(&detail_item)
                .separator()
                .item(&geph_menu)
                .item(&launch)
                .item(&MenuItemBuilder::with_id(ID_RESTART, "Restart Proxy").build(app)?)
                .item(&MenuItemBuilder::with_id(ID_LOG, "Open Log").build(app)?)
                .separator()
                .item(&MenuItemBuilder::with_id(ID_UPDATE, "Check for Updates…").build(app)?)
                .item(&MenuItemBuilder::with_id("version", "Version 0.1").enabled(false).build(app)?)
                .item(&MenuItemBuilder::with_id(ID_QUIT, "Quit Slipstream").accelerator("CmdOrCtrl+Q").build(app)?)
                .build()?;

            // ---- tray --------------------------------------------------------
            let icon = Image::from_path(
                app.path().resource_dir()?.join("icons").join("slip-menubar-mark.png"),
            )
            .unwrap_or_else(|_| app.default_window_icon().unwrap().clone());

            let launch_h = launch.clone();
            let _tray = TrayIconBuilder::with_id("main")
                .icon(icon)
                .icon_as_template(true)
                .menu(&menu)
                .on_menu_event(move |app, event| {
                    let id = event.id().as_ref();
                    if let Some(val) = id.strip_prefix("exit:") {
                        for (v, item) in &exit_items {
                            let _ = item.set_checked(v == val);
                        }
                        geph_config_set(app, "exit", val);
                        geph_stop(app); // supervisor respawns geph with the new exit
                        return;
                    }
                    match id {
                        ID_ACCOUNT => {
                            let cur = geph_secret(app).unwrap_or_default();
                            if let Some(secret) = prompt_secret(&cur) {
                                geph_config_set(app, "secret", &secret);
                                geph_stop(app); // supervisor (re)starts geph with the new secret
                            }
                        }
                        ID_LAUNCH => {
                            let mgr = app.autolaunch();
                            let enabled = mgr.is_enabled().unwrap_or(false);
                            let _ = if enabled { mgr.disable() } else { mgr.enable() };
                            let _ = launch_h.set_checked(!enabled); // reflect the real new state
                        }
                        ID_RESTART => run_admin(&format!("launchctl kickstart -k system/{LAUNCHD_LABEL}")),
                        ID_LOG => {
                            let _ = Command::new("/usr/bin/open").arg(LOG_PATH).spawn();
                        }
                        ID_UPDATE => {
                            let app = app.clone();
                            tauri::async_runtime::spawn(async move { check_for_updates(app).await });
                        }
                        ID_QUIT => app.exit(0),
                        _ => {}
                    }
                })
                .build(app)?;

            // ---- status poll every 2s ---------------------------------------
            let app_handle = app.handle().clone();
            let s = state_item.clone();
            let d = detail_item.clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    refresh(&s, &d, &app_handle);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            });

            // geph supervisor: runs the bundled geph5-client whenever a secret is set
            app.manage(GephState::default());
            tauri::async_runtime::spawn(geph_supervisor(app.handle().clone()));
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building Slipstream tray");

    // No windows -> keep the app alive on the tray when an implicit exit fires.
    app.run(|_app, event| {
        if let tauri::RunEvent::ExitRequested { code, api, .. } = event {
            if code.is_none() {
                api.prevent_exit();
            }
        }
    });
}
