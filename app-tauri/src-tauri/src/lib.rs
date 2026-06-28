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
use tauri_plugin_notification::NotificationExt;
use tauri_plugin_shell::{process::CommandChild, process::CommandEvent, ShellExt};

// Our bundled geph5-client runs an unprivileged SOCKS5 on this port; the root
// daemon routes geo-blocked hosts to it. A dedicated port (not geph's default
// 9909) so it never clashes with a separately-installed Geph.app.
const GEPH_SOCKS_PORT: u16 = 9954;
// geph's JSON-RPC control listener — we query it for the LIVE exit list.
const GEPH_CONTROL_PORT: u16 = 9955;

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
const ID_GEPH_ENABLE: &str = "geph_enable";
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
/// Update the menu text from the daemon status; returns the state string so the
/// caller can update the tray icon ONLY when it changes (re-setting the icon every
/// poll made the menu-bar mark visibly blink).
fn refresh(state_item: &MenuItem<tauri::Wry>, detail_item: &MenuItem<tauri::Wry>) -> String {
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
    state
}

/// Set the menu-bar mark for the given state (called only on a state change).
fn set_tray_icon(app: &AppHandle, state: &str) {
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

/// Show a native notification (geph up/down, updates).
fn notify(app: &AppHandle, body: &str) {
    let _ = app.notification().builder().title("Slipstream").body(body).show();
}

/// Built-in signed updater: check the appcast, download + install if newer.
async fn check_for_updates(app: AppHandle) {
    use tauri_plugin_updater::UpdaterExt;
    let Ok(updater) = app.updater() else { return };
    if let Ok(Some(update)) = updater.check().await {
        if update.download_and_install(|_, _| {}, || {}).await.is_ok() {
            notify(&app, "Update installed — restarting");
            app.restart();
        }
    }
}

/// Read a string field from geph.json.
fn geph_field(app: &AppHandle, key: &str) -> Option<String> {
    let path = app.path().app_config_dir().ok()?.join("geph.json");
    let v: Value = serde_json::from_str(&fs::read_to_string(path).ok()?).ok()?;
    v.get(key).and_then(|x| x.as_str()).map(|s| s.to_string())
}

/// Remove a key from geph.json (used to scrub a migrated plaintext secret).
fn geph_config_unset(app: &AppHandle, key: &str) {
    let Ok(dir) = app.path().app_config_dir() else { return };
    let path = dir.join("geph.json");
    let Ok(text) = fs::read_to_string(&path) else { return };
    let Ok(mut cfg) = serde_json::from_str::<serde_json::Map<String, Value>>(&text) else { return };
    if cfg.remove(key).is_some() {
        if let Ok(s) = serde_json::to_string_pretty(&Value::Object(cfg)) {
            let _ = fs::write(&path, s);
        }
    }
}

// The account secret lives in the macOS Keychain, not the plaintext config.
const KC_SERVICE: &str = "dev.slipstream.geph";
const KC_ACCOUNT: &str = "account-secret";

fn keychain_get() -> Option<String> {
    let out = Command::new("/usr/bin/security")
        .args(["find-generic-password", "-s", KC_SERVICE, "-a", KC_ACCOUNT, "-w"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!s.is_empty()).then_some(s)
}

fn keychain_set(secret: &str) {
    let _ = Command::new("/usr/bin/security")
        .args(["add-generic-password", "-U", "-s", KC_SERVICE, "-a", KC_ACCOUNT, "-w", secret])
        .status();
}

/// Read the geph account secret from the Keychain (None → not signed in → don't
/// start geph). One-time migration: a legacy plaintext secret in geph.json is
/// moved into the Keychain and scrubbed from the file.
fn geph_secret(app: &AppHandle) -> Option<String> {
    if let Some(s) = keychain_get() {
        return Some(s);
    }
    let legacy = geph_field(app, "secret")?.trim().to_string();
    if legacy.is_empty() {
        return None;
    }
    keychain_set(&legacy);
    geph_config_unset(app, "secret");
    Some(legacy)
}

/// Whether OUR bundled geph should run. Default true; the user can turn it off
/// (e.g. to use their own VPN — geph allows ONE session per account, so ours must
/// stop or the user's own Geph can't connect).
fn geph_enabled(app: &AppHandle) -> bool {
    geph_field(app, "enabled").map(|s| s != "0").unwrap_or(true)
}

/// geph exit_constraint for a menu exit value ("us-sanjose" -> {country: us}).
/// Country-level (ISO-3166 alpha-2, verified against the binary) is robust and
/// lets the user dodge a blocked exit by region; "auto" lets geph choose.
fn exit_constraint(exit: &str) -> String {
    let e = exit.trim();
    let cc = e.split('-').next().unwrap_or("");
    if e == "auto" || cc.len() != 2 {
        "auto".into()
    } else {
        format!("{{country: {}}}", cc.to_lowercase())
    }
}

/// Build a MINIMAL geph5-client YAML config. We deliberately do NOT hardcode the
/// broker fronts / Mizaru keys — geph5-client has them compiled in as defaults
/// (verified: a config without a `broker` field parses and starts a session), so
/// they auto-update when CI rebuilds the bundled binary instead of going stale.
/// Only the account secret + the user's exit choice are ours; everything else is
/// geph's own default. allow_direct + a persistent cache match the geph GUI (the
/// stability difference: direct exit connections survive a flaky network and the
/// cache makes reconnects warm). control_listen exposes geph's JSON-RPC so we can
/// fetch the LIVE exit list instead of hardcoding it.
fn geph_config_yaml(secret: &str, exit: &str, cache_path: &str) -> String {
    let esc = secret.replace('\\', "\\\\").replace('"', "\\\"");
    let ec = exit_constraint(exit);
    format!(
        "socks5_listen: 127.0.0.1:{GEPH_SOCKS_PORT}\n\
         control_listen: 127.0.0.1:{GEPH_CONTROL_PORT}\n\
         exit_constraint: {ec}\n\
         allow_direct: true\n\
         cache: {cache_path}\n\
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

/// Is geph actually tunnelling? A SOCKS5 CONNECT through it to a reliable host.
/// A geph process that is alive but STUCK (mobile network flapped, account
/// contention) fails this — that's the "needed an app restart" case.
async fn geph_health_ok() -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    let probe = async {
        let mut s = TcpStream::connect(("127.0.0.1", GEPH_SOCKS_PORT)).await.ok()?;
        s.write_all(&[5u8, 1, 0]).await.ok()?; // greeting, no-auth
        let mut g = [0u8; 2];
        s.read_exact(&mut g).await.ok()?;
        if g != [5, 0] {
            return None;
        }
        // CONNECT 1.1.1.1:443 — a host any working exit reaches
        s.write_all(&[5, 1, 0, 1, 1, 1, 1, 1, 0x01, 0xbb]).await.ok()?;
        let mut r = [0u8; 4];
        s.read_exact(&mut r).await.ok()?; // VER REP RSV ATYP
        (r[1] == 0).then_some(()) // REP==0 -> tunnel reached the exit
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(8), probe).await,
        Ok(Some(()))
    )
}

/// Supervisor: whenever a secret is configured, run the bundled geph5-client
/// sidecar and keep it alive — respawn on exit AND on a failed health-check (a
/// stuck-but-alive geph). Killing the child (on a config change) also makes this
/// loop pick up the new config on the next iteration.
async fn geph_supervisor(app: AppHandle) {
    loop {
        // disabled (user prefers their own VPN) -> make sure ours is down
        if !geph_enabled(&app) {
            tokio::time::sleep(Duration::from_secs(3)).await;
            continue;
        }
        let Some(secret) = geph_secret(&app) else {
            tokio::time::sleep(Duration::from_secs(3)).await;
            continue;
        };
        let exit = geph_field(&app, "exit").unwrap_or_else(|| "auto".into());
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
        let cache_path = app
            .path()
            .app_config_dir()
            .map(|d| d.join("geph-cache.db").to_string_lossy().into_owned())
            .unwrap_or_else(|_| "/tmp/geph-cache.db".into());
        let _ = fs::write(&cfg_path, geph_config_yaml(&secret, &exit, &cache_path));

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
        // Drain events; meanwhile health-check every 30s. A geph that's alive but
        // stuck fails the check -> kill it so this loop respawns a fresh one (no
        // manual app restart). Give it 45s to connect before the first check.
        let mut health = tokio::time::interval(Duration::from_secs(30));
        health.tick().await; // immediate tick — skip
        tokio::time::sleep(Duration::from_secs(15)).await; // grace before first real check
        let mut sick = 0;
        loop {
            tokio::select! {
                ev = rx.recv() => {
                    match ev {
                        Some(CommandEvent::Terminated(_)) | None => break,
                        _ => {}
                    }
                }
                _ = health.tick() => {
                    if geph_health_ok().await {
                        sick = 0;
                    } else {
                        sick += 1;
                        if sick >= 2 {            // ~60s stuck -> respawn fresh
                            eprintln!("geph health-check failed -> respawning");
                            geph_stop(&app);
                            break;
                        }
                    }
                }
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
        .plugin(tauri_plugin_notification::init())
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

            let geph_enable = CheckMenuItemBuilder::with_id(ID_GEPH_ENABLE, "Enable Geph")
                .checked(geph_enabled(app.handle()))
                .build(app)?;

            let mut gb = SubmenuBuilder::new(app, "Geph")
                .item(&MenuItemBuilder::with_id(ID_ACCOUNT, "Account…").accelerator("CmdOrCtrl+,").build(app)?)
                .item(&geph_enable)
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
            let enable_h = geph_enable.clone();
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
                                keychain_set(&secret); // Keychain, not plaintext config
                                geph_stop(app); // supervisor (re)starts geph with the new secret
                            }
                        }
                        ID_GEPH_ENABLE => {
                            let new_on = !geph_enabled(app);
                            geph_config_set(app, "enabled", if new_on { "1" } else { "0" });
                            let _ = enable_h.set_checked(new_on);
                            if !new_on {
                                geph_stop(app); // free the account so the user's own VPN/Geph can connect
                            }
                            // enabling -> the supervisor starts geph next loop (secret permitting)
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
                let mut last_geph: Option<bool> = None;
                let mut last_state = String::new();
                loop {
                    let state = refresh(&s, &d);
                    if state != last_state {
                        set_tray_icon(&app_handle, &state); // only on change -> no blink
                        last_state = state;
                    }
                    // notify on Geph tunnel up/down transitions (not on first read)
                    if let Some(up) =
                        read_status().and_then(|v| v.get("geph").and_then(|x| x.as_str()).map(|g| g == "up"))
                    {
                        if last_geph == Some(!up) {
                            notify(&app_handle,
                                if up { "Geph tunnel connected" } else { "Geph tunnel disconnected" });
                        }
                        last_geph = Some(up);
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            });

            // Self-heal: kill any geph orphaned by a previous unclean exit
            // (force-quit / crash / SIGTERM don't run the Exit handler), so a
            // stale geph never keeps holding the account. The pattern matches only
            // OUR bundled geph (path contains Slipstream.app), not the user's
            // separately-installed gephgui.
            let _ = Command::new("/usr/bin/pkill")
                .args(["-f", "Slipstream.app/Contents/MacOS/geph5-client"])
                .status();

            // geph supervisor: runs the bundled geph5-client whenever a secret is set
            app.manage(GephState::default());
            tauri::async_runtime::spawn(geph_supervisor(app.handle().clone()));
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building Slipstream tray");

    // No windows -> keep the app alive on the tray when an implicit exit fires.
    // On a real quit, kill the bundled geph so it never orphans (an orphaned geph
    // holds the account session and blocks the user's own Geph from connecting).
    app.run(|app, event| match event {
        tauri::RunEvent::ExitRequested { code, api, .. } => {
            if code.is_none() {
                api.prevent_exit();
            }
        }
        tauri::RunEvent::Exit => geph_stop(app),
        _ => {}
    });
}
