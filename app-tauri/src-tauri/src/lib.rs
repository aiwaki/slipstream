// Slipstream — tray app (Tauri v2). Unprivileged menu-bar UI over the root
// daemon (tproxy.py). The UI is 100% NATIVE: a real NSMenu (tray) + native
// osascript dialogs — no WebView window (a styled WebView always reads as
// "web", which is the look we're avoiding). Tauri still provides the native
// tray, the signed auto-updater, and the geph sidecar.
//
// Logic lives here (lib.rs) so the same crate can back a mobile entry point
// later; main.rs is a thin desktop shim.

use std::fs;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
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

// Our bundled geph5-client runs an unprivileged SOCKS5 on this port; the root
// daemon routes geo-blocked hosts to it. A dedicated port (not geph's default
// 9909) so it never clashes with a separately-installed Geph.app.
const GEPH_SOCKS_PORT: u16 = 9954;
// geph's JSON-RPC control listener — we query it for the LIVE exit list.
const GEPH_CONTROL_PORT: u16 = 9955;

// geph5-client is spawned DETACHED (its own process group) so it survives a tray
// restart/reinstall — see geph_supervisor. We track/kill it by process match, not
// a held child handle, so no GephState is needed.

const STATUS_PATH: &str = "/var/run/slipstream.status";
const LOG_PATH: &str = "/var/log/slipstream.log";
const LAUNCHD_LABEL: &str = "dev.slipstream.tproxy";
const LAUNCHD_PLIST: &str = "/Library/LaunchDaemons/dev.slipstream.tproxy.plist";

/// Is the system UI language Russian? Cached — the locale doesn't change while we
/// run. Most users are in RU, so the tray speaks Russian when the Mac does.
fn ui_ru() -> bool {
    use std::sync::OnceLock;
    static RU: OnceLock<bool> = OnceLock::new();
    *RU.get_or_init(|| {
        let read = |key: &str| -> String {
            Command::new("defaults")
                .args(["read", "-g", key])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .unwrap_or_default()
        };
        // AppleLanguages[0] is the preferred UI language — more accurate than the
        // region locale. Its `defaults` form is a plist array: ("ru-RU", ...).
        let langs = read("AppleLanguages");
        if let Some(first) = langs.split('"').nth(1) {
            return first.to_lowercase().starts_with("ru");
        }
        read("AppleLocale").trim().to_lowercase().starts_with("ru")
    })
}

/// Localize a tray label. English is the source; Russian strings are returned
/// when the system is Russian. Anything not listed falls back to English.
fn tr(en: &str) -> String {
    if !ui_ru() {
        return en.to_string();
    }
    match en {
        "Account…" => "Аккаунт…",
        "Enable Geph" => "Включить Geph",
        "Automatic" => "Автоматически",
        "Core" => "Основные",
        "Streaming" => "Стриминг",
        "Connect Telegram Proxy" => "Подключить Telegram-прокси",
        "System Proxy (all apps)" => "Системный прокси (все приложения)",
        "Proxy for apps" => "Прокси для приложений",
        "Launch at Login" => "Запускать при входе",
        "Restart Proxy" => "Перезапустить прокси",
        "Open Log" => "Открыть лог",
        "Check for Updates…" => "Проверить обновления…",
        "Quit Slipstream" => "Выйти из Slipstream",
        other => other,
    }
    .to_string()
}

const ID_ACCOUNT: &str = "geph_account";
const ID_GEPH_ENABLE: &str = "geph_enable";
const ID_LAUNCH: &str = "launch_at_login";
const ID_RESTART: &str = "restart_proxy";
const ID_LOG: &str = "open_log";
const ID_UPDATE: &str = "check_updates";
const ID_QUIT: &str = "quit";
const ID_TGWS: &str = "tgws_open";
const ID_SYSPROXY: &str = "system_proxy";
// Daemon publishes the tg://proxy?... link here (world-readable) once the bundled
// tg-ws-proxy is up; the tray opens it so Telegram Desktop adds+enables the proxy
// in one click (no manual host/port/secret entry).
const TGWS_LINK_PATH: &str = "/var/run/slipstream-tgws.link";

// Fallback exit list used ONLY on the first-ever launch, before geph's control
// RPC (net_status) has answered once. After that the LIVE country list is cached
// to geph-exits.json and used instead — no hardcoded catalog. Country-level to
// match the {country: cc} exit_constraint we emit; flags are derived from the CC
// at runtime (cc_flag), so there's no hardcoded flag/label table either.
const EXITS_FALLBACK_CC: &[&str] = &["ca", "us", "ch", "de", "nl", "se", "jp", "sg"];

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

/// Point macOS's system-wide SOCKS proxy at Slipstream's local geph SOCKS
/// (127.0.0.1:GEPH_SOCKS_PORT), or turn it off. Configure once here and every
/// proxy-aware app (Chrome, Claude, VS Code, JetBrains via "use system proxy")
/// follows — no per-app setup. Runs on all enabled network services. Changing
/// network settings needs admin, so it triggers one password prompt.
/// `grep -v '[*]'` drops disabled services (marked with `*`); `tail -n +2` drops
/// the header line — no backslashes so run_admin's escaping stays simple.
/// Returns true only if the admin command actually ran (osascript exits non-zero
/// when the user cancels the password prompt) — so the caller can revert the menu
/// checkmark instead of falsely showing "on".
fn set_system_proxy(on: bool) -> bool {
    let cmd = if on {
        format!(
            "networksetup -listallnetworkservices | tail -n +2 | grep -v '[*]' | \
             while IFS= read -r s; do \
             networksetup -setsocksfirewallproxy \"$s\" 127.0.0.1 {GEPH_SOCKS_PORT}; \
             networksetup -setsocksfirewallproxystate \"$s\" on; done"
        )
    } else {
        "networksetup -listallnetworkservices | tail -n +2 | grep -v '[*]' | \
         while IFS= read -r s; do \
         networksetup -setsocksfirewallproxystate \"$s\" off; done"
            .to_string()
    };
    // Block on the admin prompt (unlike run_admin's fire-and-forget) so we know the
    // real outcome. osascript returns non-zero if the user cancels.
    let escaped = cmd.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!("do shell script \"{escaped}\" with administrator privileges");
    Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(script)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// First launch: if the root daemon isn't installed yet, install it from the
/// bundled self-contained `slipstreamd` (a PyInstaller onedir — scapy, crypto and
/// the Telegram proxy all inside, no system Python needed) with a single admin
/// prompt. That's the only thing the user is ever asked to allow by hand. No-op
/// once the daemon is installed, or in dev builds that don't ship the frozen
/// daemon (there you install it via `sudo python3 spike/tproxy.py --install`).
fn ensure_daemon_installed(app: &AppHandle) {
    if std::path::Path::new(LAUNCHD_PLIST).exists() {
        return; // already installed
    }
    let Ok(res) = app.path().resource_dir() else {
        return;
    };
    let bin = res.join("slipstreamd").join("slipstreamd");
    if !bin.exists() {
        return; // dev build without the bundled daemon
    }
    run_admin(&format!("'{}' --install", bin.to_string_lossy()));
}

/// Native secret-entry dialog (the same NSAlert look as TG WS Proxy). Pre-fills
/// the current secret and shows it (a 24-digit secret is unusable to type blind),
/// like geph's own Account screen. Returns the entered text, or None if cancelled.
fn prompt_secret(current: &str) -> Option<String> {
    let cur = current.replace('\\', "\\\\").replace('"', "\\\"");
    let (msg, cancel) = if ui_ru() {
        ("Ключ аккаунта Geph", "Отмена")
    } else {
        ("Geph account secret", "Cancel")
    };
    let script = format!(
        "display dialog \"{msg}\" with title \"Slipstream\" \
         default answer \"{cur}\" \
         buttons {{\"{cancel}\", \"OK\"}} default button \"OK\" cancel button \"{cancel}\""
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

    let ru = ui_ru();
    let (title, detail) = match state.as_str() {
        "active" => {
            let mut d = if ru {
                format!("{conns} соединений · выучено хостов: {learned}")
            } else {
                format!("{conns} connections · {learned} hosts learned")
            };
            if geph == "up" {
                d.push_str(if ru { " · Geph-туннель включён" } else { " · Geph tunnel on" });
            }
            (
                (if ru { "Slipstream — активен" } else { "Slipstream — Active" }).to_string(),
                d,
            )
        }
        "dormant" => (
            (if ru { "Slipstream — спит" } else { "Slipstream — Dormant" }).to_string(),
            (if ru {
                "VPN включён; обходом занимается он"
            } else {
                "VPN is up; the VPN handles bypass"
            })
            .to_string(),
        ),
        _ => (
            (if ru { "Slipstream — выключен" } else { "Slipstream — Off" }).to_string(),
            String::new(),
        ),
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

/// geph exit_constraint for a menu exit value. Three shapes:
///   "auto"              -> auto                       (geph chooses)
///   "ca|Toronto [BETA]" -> {country_city: [ca, "Toronto [BETA]"]}  (pin a city)
///   "us" / "us-sanjose" -> {country: us}              (country-level / legacy)
/// City pinning (verified against the binary: `{country_city: [cc, City]}`, City
/// case-sensitive & exact from net_status) keeps the user on one exit region so a
/// service that bans on location change never sees them move.
fn exit_constraint(exit: &str) -> String {
    let e = exit.trim();
    if e == "auto" || e.is_empty() {
        return "auto".into();
    }
    if let Some((cc, city)) = e.split_once('|') {
        let cc = cc.trim().to_lowercase();
        let city = city.replace('\\', "\\\\").replace('"', "\\\"");
        if cc.len() == 2 {
            return format!("{{country_city: [{cc}, \"{city}\"]}}");
        }
    }
    let cc = e.split(['-', '|']).next().unwrap_or("");
    if cc.len() == 2 {
        format!("{{country: {}}}", cc.to_lowercase())
    } else {
        "auto".into()
    }
}

/// Flag emoji from a 2-letter ISO country code via regional-indicator codepoints
/// (no hardcoded table). "ca" -> 🇨🇦; "" for anything that isn't 2 ASCII letters.
fn cc_flag(cc: &str) -> String {
    let cc = cc.trim();
    if cc.len() != 2 || !cc.chars().all(|c| c.is_ascii_alphabetic()) {
        return String::new();
    }
    cc.to_ascii_uppercase()
        .chars()
        .filter_map(|c| char::from_u32(0x1F1E6 + (c as u32 - 'A' as u32)))
        .collect()
}

/// Query geph's control RPC (newline-framed JSON-RPC on GEPH_CONTROL_PORT) for the
/// LIVE exit list, one entry per (country, city). Pinning a CITY (not just a
/// country) matters: a service that bans on a location change needs the user to
/// stay on one exit region (the reason to "sit on Toronto"), so the menu offers
/// each city and exit_constraint pins it as {country_city: [cc, "City"]}. Returns
/// sorted (value="cc|City", label="🇨🇦 CA / Toronto") pairs, or None if the control
/// port isn't answering yet.
fn geph_net_status_catalog() -> Option<Vec<(String, String, String)>> {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(("127.0.0.1", GEPH_CONTROL_PORT)).ok()?;
    let to = Duration::from_secs(6);
    let _ = s.set_read_timeout(Some(to));
    let _ = s.set_write_timeout(Some(to));
    s.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"net_status\",\"params\":[]}\n")
        .ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = s.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.contains(&b'\n') || buf.len() > 4_000_000 {
            break;
        }
    }
    let v: Value = serde_json::from_slice(&buf).ok()?;
    let exits = v.get("result")?.get("exits")?.as_object()?;
    // (cc, city) -> category, deduped + sorted by country then city. category
    // ("core"/"streaming", from exit[2]) drives the menu's section headers.
    let mut map: std::collections::BTreeMap<(String, String), String> =
        std::collections::BTreeMap::new();
    for arr in exits.values() {
        let meta = match arr.get(1) {
            Some(m) => m,
            None => continue,
        };
        let category = arr
            .get(2)
            .and_then(|c| c.get("category"))
            .and_then(|x| x.as_str())
            .unwrap_or("core")
            .to_string();
        if let (Some(cc), Some(city)) = (
            meta.get("country").and_then(|x| x.as_str()),
            meta.get("city").and_then(|x| x.as_str()),
        ) {
            let cc = cc.trim().to_lowercase();
            let city = city.trim().to_string();
            if cc.len() == 2 && cc.chars().all(|c| c.is_ascii_alphabetic()) && !city.is_empty() {
                map.entry((cc, city)).or_insert(category);
            }
        }
    }
    if map.is_empty() {
        return None;
    }
    Some(
        map.into_iter()
            .map(|((cc, city), category)| {
                // value carries the EXACT city (case-sensitive) for the constraint;
                // label prettifies "Toronto [BETA]" -> "Toronto (beta)".
                let value = format!("{cc}|{city}");
                let pretty = city.replace(" [BETA]", " (beta)");
                let label = format!("{} {} / {}", cc_flag(&cc), cc.to_uppercase(), pretty);
                (value, label, category)
            })
            .collect(),
    )
}

/// Exit catalog for the tray menu: the LIVE country list if geph's control RPC
/// answers now (also cached to geph-exits.json), else the last cached list, else
/// the static EXITS_FALLBACK_CC. Never hardcodes the live catalog.
fn exit_catalog(cache_path: Option<std::path::PathBuf>) -> Vec<(String, String, String)> {
    if let Some(live) = geph_net_status_catalog() {
        if let Some(p) = &cache_path {
            if let Ok(j) = serde_json::to_string(&live) {
                let _ = fs::write(p, j);
            }
        }
        return live;
    }
    if let Some(p) = &cache_path {
        if let Ok(s) = fs::read_to_string(p) {
            if let Ok(c) = serde_json::from_str::<Vec<(String, String, String)>>(&s) {
                if !c.is_empty() {
                    return c;
                }
            }
        }
    }
    EXITS_FALLBACK_CC
        .iter()
        .map(|cc| {
            (
                cc.to_string(),
                format!("{} {}", cc_flag(cc), cc.to_uppercase()),
                "core".to_string(),
            )
        })
        .collect()
}

/// Background one-shot: once geph's control RPC comes up after launch, write the
/// live country list to geph-exits.json so the NEXT tray build shows the real
/// catalog (the menu is built once at startup, before geph has connected).
fn refresh_exit_cache(cache_path: Option<std::path::PathBuf>) {
    std::thread::spawn(move || {
        for _ in 0..20 {
            std::thread::sleep(Duration::from_secs(2));
            if let Some(live) = geph_net_status_catalog() {
                if let Some(p) = &cache_path {
                    if let Ok(j) = serde_json::to_string(&live) {
                        let _ = fs::write(p, j);
                    }
                }
                return;
            }
        }
    });
}

// geph5-client's broker config — REQUIRED. Verified: WITHOUT a `broker` field,
// every broker-dependent call ("broker information not provided") fails — no
// connect token, no registration. geph5-client does NOT fall back to compiled
// defaults at runtime.
//
// These values are extracted byte-for-byte from the official Geph.app's embedded
// config (gephgui-wry 5.7.x). The earlier cdn77/vuejs `race:` list + empty
// `mizaru_bw` was STALE and the root cause of "cannot get connect token" /
// "mizaru_bw.inner: Encoding error": the fronts no longer serve get_connect_token
// and the empty bw key can't decode. The current broker uses:
//   - `priority_race` (a {priority: source} map, NOT a list), tried high-first;
//   - an aws_lambda "bouncer" as the primary (1500) transport — the fast path;
//   - kubernetes.io domain-fronting (host = netlify) as fallbacks (300/0);
//   - tunneled_broker direct https://broker.geph.io;
//   - the real RSA `mizaru_bw` key (DER hex) so bandwidth-token fetch succeeds.
// The obfs_key below is public (shipped in every Geph.app binary).
const GEPH_BROKER_YAML: &str = "\
broker:\n\
\x20 priority_race:\n\
\x20   1500:\n\
\x20     aws_lambda:\n\
\x20       function_name: geph-lambda-bouncer\n\
\x20       region: us-east-1\n\
\x20       obfs_key: \"855MJGAMB58MCPJBB97NADJ36D64WM2T:C4TN2M1H68VNMRVCCH57GDV2C5VN6V3RB8QMWP235D0P4RT2ACV7GVTRCHX3EC37\"\n\
\x20   300:\n\
\x20     fronted:\n\
\x20       front: https://kubernetes.io/\n\
\x20       host: svitania-naidallszei-2.netlify.app\n\
\x20       override_dns:\n\
\x20         - 75.2.60.5:443\n\
\x20   0:\n\
\x20     fronted:\n\
\x20       front: https://kubernetes.io/\n\
\x20       host: svitania-naidallszei-2.netlify.app\n\
tunneled_broker:\n\
\x20 direct: https://broker.geph.io\n\
broker_keys:\n\
\x20 master: 88c1d2d4197bed815b01a22cadfc6c35aa246dddb553682037a118aebfaa3954\n\
\x20 mizaru_free: 0558216cbab7a9c46f298f4c26e171add9af87d0694988b8a8fe52ee932aa754\n\
\x20 mizaru_plus: cf6f58868c6d9459b3a63bc2bd86165631b3e916bad7f62b578cd9614e0bcb3b\n\
\x20 mizaru_bw: 3082010a0282010100d0ae53a794ea37bf2e100cb3a872177ec6c11e8375fdcbf92960ce0293465674eb1426a1841b7622a58979a5ff3f8aa2301a621545e9b90bb39d1a6bfda19d6ca1aae74a3192ddfd2b9558eb652c3c2c22f42bdde272852fb67d93cae5846213512c474bf799844aee019bf718f6fa64223be06364459fc8dec66796b141d450d730c4fffe1cac7df8f05591560afa44bcf274f6c0e2303b39c21ab09d19b459ee594512b8341f3d407c026e2509f42c6d89f82f6a3a36fd5c05ad423cd99ad39089403eb9122ea60ef6648afff65438e8e26ce41fa55b9b18741965c77a627bae947bd38fc345e9adab42d6c458f6e194e4232cfd3f04924d5a5e932fe769610203010001\n";

/// Build the geph5-client YAML config. The broker block is required (see
/// GEPH_BROKER_YAML); only the account secret + exit choice are ours.
/// `allow_direct: false` matches the official GUI's "My network blocks VPNs"
/// mode (RU/CN/IR): geph hides traffic from the ISP via obfuscated bridges
/// instead of connecting directly. Verified: standalone tunnels (no external
/// VPN) ONLY with `false` on this network — `true` authenticates but the mux
/// data path times out. A persistent cache matches the GUI (faster reconnect);
/// control_listen exposes geph's JSON-RPC (live exit list).
fn geph_config_yaml(secret: &str, exit: &str, cache_path: &str) -> String {
    let esc = secret.replace('\\', "\\\\").replace('"', "\\\"");
    let ec = exit_constraint(exit);
    format!(
        "socks5_listen: 127.0.0.1:{GEPH_SOCKS_PORT}\n\
         control_listen: 127.0.0.1:{GEPH_CONTROL_PORT}\n\
         exit_constraint: {ec}\n\
         allow_direct: false\n\
         cache: {cache_path}\n\
         {GEPH_BROKER_YAML}\
         credentials:\n\
         \x20 secret: \"{esc}\"\n"
    )
}

/// Absolute path to the bundled geph5-client, which sits next to our own
/// executable (Slipstream.app/Contents/MacOS/geph5-client).
fn geph_bin_path() -> Option<std::path::PathBuf> {
    Some(std::env::current_exe().ok()?.parent()?.join("geph5-client"))
}

/// Cheap liveness: is geph's SOCKS5 listener up on GEPH_SOCKS_PORT? A plain TCP
/// connect is enough to ADOPT an already-running geph (its active config already
/// matched). A full SOCKS handshake here can transiently time out under load and
/// cause a needless respawn — which defeats the whole survive-across-restart
/// design — so we deliberately keep this to a connect check.
fn geph_socks_alive() -> bool {
    std::net::TcpStream::connect_timeout(
        &(std::net::Ipv4Addr::LOCALHOST, GEPH_SOCKS_PORT).into(),
        Duration::from_secs(1),
    )
    .is_ok()
}

/// Kill the geph5-client WE launched (matched by our unique config path). Used
/// before a deliberate reconfigure (exit change) or when Geph is disabled.
fn geph_kill_running() {
    let _ = Command::new("/usr/bin/pkill")
        .args(["-f", "geph5-client.*geph-active.yaml"])
        .status();
}

/// Stop a running geph5-client (e.g. before respawning with a new config).
fn geph_stop(_app: &AppHandle) {
    geph_kill_running();
}

/// Supervisor: keep the bundled geph5-client running whenever Geph is enabled and
/// a secret is set. geph is spawned DETACHED (its own process group) so it SURVIVES
/// a tray restart/reinstall — the tunnel the user's apps ride does NOT drop just
/// because the menu-bar app was swapped. On each pass we ADOPT an already-running
/// geph whose active config still matches, and only (re)spawn when geph is actually
/// down or the config (exit/secret) changed. This ends the "reinstall -> restart
/// your app" pain. geph5-client also retries/reconnects internally, so we never
/// kill a live one mid-recovery (that churned broker sessions).
async fn geph_supervisor(app: AppHandle) {
    loop {
        if !geph_enabled(&app) {
            geph_kill_running(); // user disabled Geph -> ensure ours is down
            tokio::time::sleep(Duration::from_secs(3)).await;
            continue;
        }
        let Some(secret) = geph_secret(&app) else {
            tokio::time::sleep(Duration::from_secs(3)).await;
            continue;
        };
        let exit = geph_field(&app, "exit").unwrap_or_else(|| "auto".into());
        let Ok(dir) = app.path().app_config_dir() else {
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        };
        let _ = fs::create_dir_all(&dir);
        let cfg_path = dir.join("geph-active.yaml");
        let cache_path = dir.join("geph-cache.db").to_string_lossy().into_owned();
        let desired = geph_config_yaml(&secret, &exit, &cache_path);

        // ADOPT: if a geph is already tunnelling on :9954 (e.g. it survived this
        // tray's restart/reinstall), do NOT respawn it — respawning drops every
        // connection riding the tunnel (the user's Claude app included). We only
        // (re)spawn when :9954 is actually DOWN. A deliberate config change (exit
        // or account) calls geph_stop(), which frees :9954, so the next pass here
        // sees it down and respawns with the new config. (No config-equality check
        // — it was too brittle and forced a churn on every launch.)
        if geph_socks_alive() {
            tokio::time::sleep(Duration::from_secs(6)).await;
            continue;
        }

        // geph is down -> spawn a fresh, DETACHED geph with the current config.
        geph_kill_running();
        let _ = fs::write(&cfg_path, &desired);
        let Some(bin) = geph_bin_path() else {
            tokio::time::sleep(Duration::from_secs(10)).await;
            continue;
        };
        let spawned = Command::new(&bin)
            .args(["--config", &cfg_path.to_string_lossy()])
            .process_group(0) // detach: not in the tray's group -> survives tray exit
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        if let Err(e) = spawned {
            eprintln!("geph spawn failed: {e}");
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }
        // Let it bind + start tunnelling before the next health check.
        tokio::time::sleep(Duration::from_secs(8)).await;
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

            // First launch: self-install the background service (one password
            // prompt). Everything after this is automatic.
            ensure_daemon_installed(app.handle());

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
            let auto = mk(app, "auto", &tr("Automatic"))?;
            exit_items.push(("auto".into(), auto.clone()));

            let geph_enable = CheckMenuItemBuilder::with_id(ID_GEPH_ENABLE, tr("Enable Geph"))
                .checked(geph_enabled(app.handle()))
                .build(app)?;

            // LIVE country list from geph's control RPC (cached); no hardcoded catalog.
            let exits_cache = app
                .path()
                .app_config_dir()
                .ok()
                .map(|d| d.join("geph-exits.json"));
            let catalog = exit_catalog(exits_cache);

            let mut gb = SubmenuBuilder::new(app, "Geph")
                .item(&MenuItemBuilder::with_id(ID_ACCOUNT, tr("Account…")).accelerator("CmdOrCtrl+,").build(app)?)
                .item(&geph_enable)
                .separator()
                .item(&auto);
            // Group cities by category under disabled section headers — Core first,
            // then Streaming, then anything else — mirroring geph's own grouping.
            // (Core = general exits; Streaming = Plus-only, tuned for Netflix-class
            // services.) The category is live from net_status, never hardcoded.
            let mut cats: Vec<String> = catalog.iter().map(|(_, _, c)| c.clone()).collect();
            cats.sort();
            cats.dedup();
            cats.sort_by_key(|c| match c.as_str() {
                "core" => (0u8, String::new()),
                "streaming" => (1u8, String::new()),
                other => (2u8, other.to_string()),
            });
            for cat in &cats {
                let title = match cat.as_str() {
                    "core" => tr("Core"),
                    "streaming" => tr("Streaming"),
                    other => {
                        let mut ch = other.chars();
                        match ch.next() {
                            Some(f) => f.to_uppercase().collect::<String>() + ch.as_str(),
                            None => other.to_string(),
                        }
                    }
                };
                gb = gb.separator().item(
                    &MenuItemBuilder::with_id(format!("hdr_{cat}"), title)
                        .enabled(false)
                        .build(app)?,
                );
                for (val, label, c) in &catalog {
                    if c == cat {
                        let it = mk(app, val, label)?;
                        exit_items.push((val.clone(), it.clone()));
                        gb = gb.item(&it);
                    }
                }
            }
            let geph_menu = gb.build()?;

            let autostart_on = app.autolaunch().is_enabled().unwrap_or(false);
            let launch = CheckMenuItemBuilder::with_id(ID_LAUNCH, tr("Launch at Login"))
                .checked(autostart_on)
                .build(app)?;
            let version_label = if ui_ru() { "Версия 0.1" } else { "Version 0.1" };
            let sysproxy_on = geph_field(app.handle(), "system_proxy")
                .map(|s| s == "1")
                .unwrap_or(false);
            let sysproxy = CheckMenuItemBuilder::with_id(ID_SYSPROXY, tr("System Proxy (all apps)"))
                .checked(sysproxy_on)
                .build(app)?;
            // Group the app-proxy convenience actions into their own submenu (like
            // Geph) so the top level stays clean.
            let proxy_menu = SubmenuBuilder::new(app, tr("Proxy for apps"))
                .item(&MenuItemBuilder::with_id(ID_TGWS, tr("Connect Telegram Proxy")).build(app)?)
                .item(&sysproxy)
                .build()?;

            let menu = MenuBuilder::new(app)
                .item(&state_item)
                .item(&detail_item)
                .separator()
                .item(&geph_menu)
                .item(&proxy_menu)
                .item(&launch)
                .item(&MenuItemBuilder::with_id(ID_RESTART, tr("Restart Proxy")).build(app)?)
                .item(&MenuItemBuilder::with_id(ID_LOG, tr("Open Log")).build(app)?)
                .separator()
                .item(&MenuItemBuilder::with_id(ID_UPDATE, tr("Check for Updates…")).build(app)?)
                .item(&MenuItemBuilder::with_id("version", version_label).enabled(false).build(app)?)
                .item(&MenuItemBuilder::with_id(ID_QUIT, tr("Quit Slipstream")).accelerator("CmdOrCtrl+Q").build(app)?)
                .build()?;

            // ---- tray --------------------------------------------------------
            let icon = Image::from_path(
                app.path().resource_dir()?.join("icons").join("slip-menubar-mark.png"),
            )
            .unwrap_or_else(|_| app.default_window_icon().unwrap().clone());

            let launch_h = launch.clone();
            let enable_h = geph_enable.clone();
            let sysproxy_h = sysproxy.clone();
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
                        ID_SYSPROXY => {
                            // Toggle the macOS system-wide SOCKS proxy to our geph
                            // SOCKS so every app follows without per-app setup. The
                            // CheckMenuItem already flipped its own checkmark on click;
                            // only KEEP it if the admin command actually ran, else
                            // revert (e.g. the user cancelled the password prompt).
                            let want = !geph_field(app, "system_proxy")
                                .map(|s| s == "1")
                                .unwrap_or(false);
                            if set_system_proxy(want) {
                                geph_config_set(app, "system_proxy", if want { "1" } else { "0" });
                                let _ = sysproxy_h.set_checked(want);
                            } else {
                                let _ = sysproxy_h.set_checked(!want); // revert
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
                        ID_TGWS => {
                            // Open the tg://proxy link the daemon published -> Telegram
                            // Desktop pops "Enable this proxy?" (one click, no manual entry).
                            match std::fs::read_to_string(TGWS_LINK_PATH) {
                                Ok(link) if link.trim().starts_with("tg://") => {
                                    let _ = Command::new("/usr/bin/open").arg(link.trim()).spawn();
                                }
                                _ => {
                                    let msg = if ui_ru() {
                                        "Telegram-прокси ещё запускается — попробуй через пару секунд."
                                    } else {
                                        "Telegram proxy is still starting — try again in a few seconds."
                                    };
                                    let _ = Command::new("/usr/bin/osascript")
                                        .arg("-e")
                                        .arg(format!("display dialog \"{msg}\" with title \"Slipstream\" buttons {{\"OK\"}} default button \"OK\" with icon note"))
                                        .spawn();
                                }
                            }
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
                let mut last_state = String::new();
                // Debounced Geph up/down notification: geph flaps with the network,
                // and notifying on every transition spammed the user. Only fire when
                // a state has HELD for ~3 polls (6s) and differs from what we last
                // notified — a flap that reverts within 6s never surfaces.
                let mut notified_geph: Option<bool> = None;
                let mut pending: Option<bool> = None;
                let mut stable: u8 = 0;
                loop {
                    let state = refresh(&s, &d);
                    if state != last_state {
                        set_tray_icon(&app_handle, &state); // only on change -> no blink
                        last_state = state;
                    }
                    if let Some(up) =
                        read_status().and_then(|v| v.get("geph").and_then(|x| x.as_str()).map(|g| g == "up"))
                    {
                        if pending == Some(up) {
                            stable = stable.saturating_add(1);
                        } else {
                            pending = Some(up);
                            stable = 1;
                        }
                        if stable >= 3 && notified_geph != Some(up) {
                            if notified_geph.is_some() {
                                notify(&app_handle,
                                    if up { "Geph tunnel connected" } else { "Geph tunnel disconnected" });
                            }
                            notified_geph = Some(up); // record even the first stable read silently
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            });

            // NB: we deliberately do NOT kill a leftover geph at startup — a geph
            // that SURVIVED this tray's restart/reinstall (spawned detached) is what
            // lets the supervisor ADOPT it, keeping the tunnel (and the user's apps)
            // up across a reinstall. The account has no device limit, so a lingering
            // geph never blocks the user's own Geph.

            // geph supervisor: runs the bundled geph5-client (detached) whenever a
            // secret is set; survives tray restarts, adopts an already-running one.
            tauri::async_runtime::spawn(geph_supervisor(app.handle().clone()));
            // Populate the live exit catalog cache once geph's control RPC is up,
            // so the next tray build shows real countries instead of the fallback.
            refresh_exit_cache(
                app.path()
                    .app_config_dir()
                    .ok()
                    .map(|d| d.join("geph-exits.json")),
            );

            // First run only: once the bundled tg-ws-proxy has published its
            // tg://proxy link, auto-open it so Telegram Desktop prompts to enable
            // the proxy (Telegram requires that confirmation — we can't set it
            // silently). A marker makes this a one-time thing.
            if geph_field(app.handle(), "tgws_prompted").as_deref() != Some("1") {
                let app_h = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    for _ in 0..40 {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        if let Ok(link) = fs::read_to_string(TGWS_LINK_PATH) {
                            if link.trim().starts_with("tg://") {
                                let _ = Command::new("/usr/bin/open").arg(link.trim()).spawn();
                                geph_config_set(&app_h, "tgws_prompted", "1");
                                break;
                            }
                        }
                    }
                });
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building Slipstream tray");

    // No windows -> keep the app alive on the tray. We do NOT stop geph on exit:
    // it's spawned detached so it SURVIVES the tray quitting/restarting/reinstalling,
    // and the next tray ADOPTS the survivor — that's what keeps the user's apps
    // connected across a reinstall (no "restart your app" dance). The routing daemon
    // is a separate LaunchDaemon that already outlives the tray, so a running tunnel
    // after quit is consistent. To actually stop geph, disable Geph in the menu.
    app.run(|_app, event| {
        if let tauri::RunEvent::ExitRequested { code, api, .. } = event {
            if code.is_none() {
                api.prevent_exit();
            }
        }
    });
}
