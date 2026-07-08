// Slipstream — tray app (Tauri v2). Unprivileged menu-bar UI over the root
// daemon (tproxy.py). The UI is 100% NATIVE: a real NSMenu (tray) + native
// osascript dialogs — no WebView window (a styled WebView always reads as
// "web", which is the look we're avoiding). Tauri still provides the native
// tray, the signed auto-updater, and the geph sidecar.
//
// Logic lives here (lib.rs) so the same crate can back a mobile entry point
// later; main.rs is a thin desktop shim.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tauri::{
    image::Image,
    menu::{
        CheckMenuItem, CheckMenuItemBuilder, MenuBuilder, MenuItem, MenuItemBuilder, SubmenuBuilder,
    },
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
const INSTALLED_DAEMON: &str = "/usr/local/slipstream/slipstreamd";
const TGWS_ACCEPTED_PATH: &str = "/var/tmp/dev.slipstream.tgws.accepted";
const DAEMON_WATCHDOG_MISSES: u8 = 3;
const DAEMON_WATCHDOG_COOLDOWN_SECS: u64 = 5 * 60;
const DIAGNOSTIC_LOG_TAIL_LINES: usize = 80;

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
        "Launch at Login" => "Запускать при входе",
        "Restart Proxy" => "Перезапустить прокси",
        "Open Log" => "Открыть лог",
        "Copy Diagnostics" => "Скопировать диагностику",
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
const ID_DIAGNOSTICS: &str = "copy_diagnostics";
const ID_UPDATE: &str = "check_updates";
const ID_QUIT: &str = "quit";
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
    let _ = Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(script)
        .spawn();
}

fn run_admin_status(shell: &str) -> bool {
    let escaped = shell.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!("do shell script \"{escaped}\" with administrator privileges");
    Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(script)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn shell_quote(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', "'\\''"))
}

fn current_numeric_id(flag: &str) -> Option<String> {
    let out = Command::new("/usr/bin/id").arg(flag).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let id = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if id.chars().all(|c| c.is_ascii_digit()) {
        Some(id)
    } else {
        None
    }
}

fn log_snapshot_shell(log_path: &str, snapshot_path: &Path, uid: &str, gid: &str) -> String {
    let dst = snapshot_path.to_string_lossy();
    format!(
        "/bin/cp {src} {dst} && /usr/sbin/chown {uid}:{gid} {dst} && /bin/chmod 600 {dst}",
        src = shell_quote(log_path),
        dst = shell_quote(dst.as_ref()),
    )
}

fn copy_log_snapshot_direct(log_path: &str, snapshot_path: &Path) -> bool {
    if fs::copy(log_path, snapshot_path).is_err() {
        return false;
    }
    fs::set_permissions(snapshot_path, fs::Permissions::from_mode(0o600)).is_ok()
}

fn open_log_snapshot() -> bool {
    let snapshot = std::env::temp_dir().join("slipstream.log");
    if !copy_log_snapshot_direct(LOG_PATH, &snapshot) {
        let Some(uid) = current_numeric_id("-u") else {
            return false;
        };
        let Some(gid) = current_numeric_id("-g") else {
            return false;
        };
        let shell = log_snapshot_shell(LOG_PATH, &snapshot, &uid, &gid);
        if !run_admin_status(&shell) {
            return false;
        }
    }
    Command::new("/usr/bin/open").arg(snapshot).spawn().is_ok()
}

fn sensitive_json_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    k.contains("secret")
        || k.contains("password")
        || k.contains("token")
        || k.contains("private_key")
}

fn sanitize_json(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let sensitive: Vec<String> = map
                .keys()
                .filter(|key| sensitive_json_key(key))
                .cloned()
                .collect();
            for key in sensitive {
                map.insert(key, Value::String("<redacted>".to_string()));
            }
            for child in map.values_mut() {
                sanitize_json(child);
            }
        }
        Value::Array(items) => {
            for item in items {
                sanitize_json(item);
            }
        }
        Value::String(text) => {
            *text = redact_sensitive_text(text);
        }
        _ => {}
    }
}

fn redact_sensitive_text(input: &str) -> String {
    const KEYS: [&str; 4] = ["secret", "token", "password", "private_key"];
    let lower = input.to_ascii_lowercase();
    let mut out = String::with_capacity(input.len());
    let mut pos = 0;

    while pos < input.len() {
        let next = KEYS
            .iter()
            .filter_map(|key| lower[pos..].find(key).map(|offset| (pos + offset, *key)))
            .min_by_key(|(idx, _)| *idx);
        let Some((key_start, key)) = next else {
            out.push_str(&input[pos..]);
            break;
        };

        let after_key = key_start + key.len();
        let mut sep_end = None;
        for (offset, ch) in input[after_key..].char_indices() {
            if ch == '=' || ch == ':' {
                sep_end = Some(after_key + offset + ch.len_utf8());
                break;
            }
            if !(ch.is_whitespace() || ch == '"' || ch == '\'') {
                break;
            }
        }
        let Some(sep_end) = sep_end else {
            out.push_str(&input[pos..after_key]);
            pos = after_key;
            continue;
        };

        out.push_str(&input[pos..sep_end]);
        out.push_str("<redacted>");
        pos = sep_end;

        while pos < input.len() {
            let Some(ch) = input[pos..].chars().next() else {
                break;
            };
            if ch.is_whitespace() {
                pos += ch.len_utf8();
            } else {
                break;
            }
        }

        let quoted = input[pos..]
            .chars()
            .next()
            .filter(|ch| *ch == '"' || *ch == '\'');
        if let Some(quote) = quoted {
            pos += quote.len_utf8();
            while pos < input.len() {
                let Some(ch) = input[pos..].chars().next() else {
                    break;
                };
                pos += ch.len_utf8();
                if ch == quote {
                    break;
                }
            }
        } else {
            while pos < input.len() {
                let Some(ch) = input[pos..].chars().next() else {
                    break;
                };
                if ch.is_whitespace() || matches!(ch, '&' | ',' | ';' | '}' | ']') {
                    break;
                }
                pos += ch.len_utf8();
            }
        }
    }

    out
}

fn diagnostic_log_tail(log_path: &str, max_lines: usize) -> Value {
    match fs::read_to_string(log_path) {
        Ok(raw) => {
            let all_lines: Vec<&str> = raw.lines().collect();
            let start = all_lines.len().saturating_sub(max_lines);
            let lines: Vec<String> = all_lines[start..]
                .iter()
                .map(|line| redact_sensitive_text(line))
                .collect();
            json!({
                "path": log_path,
                "available": true,
                "truncated": start > 0,
                "lines": lines,
            })
        }
        Err(err) => json!({
            "path": log_path,
            "available": false,
            "error": format!("{:?}", err.kind()),
            "lines": [],
        }),
    }
}

fn launchd_plist_uses_daemon(raw: &str, daemon: &Path) -> bool {
    raw.contains(&format!("<string>{}</string>", daemon.display()))
}

fn install_diagnostic_value(
    bundled_daemon: Option<&Path>,
    installed_daemon: &Path,
    launchd_plist: &Path,
) -> Value {
    let bundled_daemon_path = bundled_daemon.map(|path| path.to_string_lossy().into_owned());
    let bundled_daemon_exists = bundled_daemon.map(|path| path.exists()).unwrap_or(false);
    let installed_daemon_exists = installed_daemon.exists();
    let installed_daemon_matches_bundle = bundled_daemon.and_then(|path| {
        if path.exists() && installed_daemon_exists {
            Some(same_file_bytes(path, installed_daemon))
        } else {
            None
        }
    });
    let launchd_plist_uses_installed_daemon = fs::read_to_string(launchd_plist)
        .ok()
        .map(|raw| launchd_plist_uses_daemon(&raw, installed_daemon));

    json!({
        "daemon_path": installed_daemon.to_string_lossy(),
        "bundled_daemon_path": bundled_daemon_path,
        "installed_daemon_exists": installed_daemon_exists,
        "bundled_daemon_exists": bundled_daemon_exists,
        "installed_daemon_matches_bundle": installed_daemon_matches_bundle,
        "launchd_label": LAUNCHD_LABEL,
        "launchd_plist": launchd_plist.to_string_lossy(),
        "launchd_plist_uses_installed_daemon": launchd_plist_uses_installed_daemon,
        "status_path": STATUS_PATH,
        "log_path": LOG_PATH,
    })
}

fn diagnostic_snapshot_value(
    app_version: &str,
    status: Option<Value>,
    generated_at: f64,
    log_tail: Option<Value>,
    bundled_daemon: Option<&Path>,
) -> Value {
    let mut snapshot = json!({
        "app": {
            "name": "Slipstream",
            "version": app_version,
        },
        "generated_at_unix": generated_at,
        "daemon": status.unwrap_or_else(|| json!({"state": "off"})),
        "install": install_diagnostic_value(
            bundled_daemon,
            Path::new(INSTALLED_DAEMON),
            Path::new(LAUNCHD_PLIST),
        ),
    });
    if let Some(log_tail) = log_tail {
        snapshot["log_tail"] = log_tail;
    }
    sanitize_json(&mut snapshot);
    snapshot
}

fn unix_now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn copy_text_to_clipboard(text: &str) -> bool {
    let Ok(mut child) = Command::new("/usr/bin/pbcopy")
        .stdin(Stdio::piped())
        .spawn()
    else {
        return false;
    };
    let Some(mut stdin) = child.stdin.take() else {
        return false;
    };
    if stdin.write_all(text.as_bytes()).is_err() {
        return false;
    }
    drop(stdin);
    child.wait().map(|status| status.success()).unwrap_or(false)
}

fn copy_diagnostic_snapshot(app: &AppHandle) -> bool {
    let bundled_daemon = bundled_daemon_path(app);
    let snapshot = diagnostic_snapshot_value(
        &app.package_info().version.to_string(),
        read_status(),
        unix_now_secs(),
        Some(diagnostic_log_tail(LOG_PATH, DIAGNOSTIC_LOG_TAIL_LINES)),
        bundled_daemon.as_deref(),
    );
    let Ok(text) = serde_json::to_string_pretty(&snapshot) else {
        return false;
    };
    copy_text_to_clipboard(&text)
}

fn launchd_plist_uses_bundled_daemon(raw: &str) -> bool {
    launchd_plist_uses_daemon(raw, Path::new(INSTALLED_DAEMON))
}

fn same_file_bytes(left: &Path, right: &Path) -> bool {
    match (fs::read(left), fs::read(right)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn daemon_needs_install(bundled: &Path) -> bool {
    let Ok(raw_plist) = fs::read_to_string(LAUNCHD_PLIST) else {
        return true;
    };
    if !launchd_plist_uses_bundled_daemon(&raw_plist) {
        return true;
    }
    !same_file_bytes(bundled, Path::new(INSTALLED_DAEMON))
}

fn bundled_daemon_path(app: &AppHandle) -> Option<PathBuf> {
    Some(
        app.path()
            .resource_dir()
            .ok()?
            .join("slipstreamd")
            .join("slipstreamd"),
    )
}

fn daemon_installed_for_watchdog(app: &AppHandle) -> bool {
    let Some(bin) = bundled_daemon_path(app) else {
        return false;
    };
    bin.exists() && !daemon_needs_install(&bin)
}

fn should_recover_daemon(missing_status_polls: u8, cooldown_ready: bool, installed: bool) -> bool {
    installed && cooldown_ready && missing_status_polls >= DAEMON_WATCHDOG_MISSES
}

fn daemon_recovery_shell() -> String {
    let label = shell_quote(&format!("system/{LAUNCHD_LABEL}"));
    let plist = shell_quote(LAUNCHD_PLIST);
    let daemon = shell_quote(INSTALLED_DAEMON);
    format!(
        "/bin/launchctl kickstart -k {label} >/dev/null 2>&1 \
         || /bin/launchctl bootstrap system {plist} >/dev/null 2>&1 \
         || true; \
         /bin/sleep 3; \
         status=$({daemon} --status 2>/dev/null || echo '{{\"state\":\"off\"}}'); \
         if printf '%s\\n' \"$status\" \
            | /usr/bin/grep -Eq '\"state\"[[:space:]]*:[[:space:]]*\"(active|dormant)\"'; \
         then exit 0; fi; \
         /sbin/pfctl -f /etc/pf.conf >/dev/null 2>&1; \
         /sbin/pfctl -d >/dev/null 2>&1 || true"
    )
}

/// First launch: if the root daemon isn't installed yet, install it from the
/// bundled self-contained `slipstreamd` (a PyInstaller onedir — scapy, crypto and
/// the Telegram proxy all inside, no system Python needed) with a single admin
/// prompt. Also upgrades older script/venv installs and stale bundled daemons.
/// No-op in dev builds that don't ship the frozen daemon (there you install it via
/// `sudo python3 spike/tproxy.py --install`).
fn ensure_daemon_installed(app: &AppHandle) {
    let Some(bin) = bundled_daemon_path(app) else {
        return;
    };
    if !bin.exists() {
        return; // dev build without the bundled daemon
    }
    if daemon_needs_install(&bin) {
        let bin = bin.to_string_lossy();
        run_admin(&format!("{} --install", shell_quote(bin.as_ref())));
    }
}

fn osascript_dialog_args(script: &str) -> Vec<String> {
    vec![
        "-e".into(),
        "activate".into(),
        "-e".into(),
        "delay 0.05".into(),
        "-e".into(),
        script.into(),
    ]
}

fn osascript_dialog(script: &str) -> Command {
    let mut cmd = Command::new("/usr/bin/osascript");
    cmd.args(osascript_dialog_args(script));
    cmd
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
    let out = osascript_dialog(&script).output().ok()?;
    if !out.status.success() {
        return None; // user cancelled
    }
    let s = String::from_utf8_lossy(&out.stdout);
    s.split("text returned:")
        .nth(1)
        .map(|t| t.trim().to_string())
}

/// Persist a geph setting (secret / exit / launch) into the per-user config the
/// bundled geph5-client supervisor will read. Does NOT touch a separately
/// installed Geph.app.
fn geph_config_set(app: &AppHandle, key: &str, val: &str) {
    let Ok(dir) = app.path().app_config_dir() else {
        return;
    };
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

fn telegram_proxy_detail(proxy: &str, suggested: bool, ru: bool) -> Option<&'static str> {
    if suggested {
        return Some(if ru {
            "Telegram-прокси рекомендуется"
        } else {
            "Telegram proxy suggested"
        });
    }

    match proxy {
        "ready" => None,
        "starting" => Some(if ru {
            "Telegram-прокси запускается"
        } else {
            "Telegram proxy starting"
        }),
        "in_use" => None,
        "unavailable" | "error" => Some(if ru {
            "Telegram-прокси недоступен"
        } else {
            "Telegram proxy unavailable"
        }),
        _ => None,
    }
}

fn system_proxy_active_from_scutil(raw: &str) -> bool {
    const ENABLE_KEYS: [&str; 5] = [
        "HTTPEnable",
        "HTTPSEnable",
        "SOCKSEnable",
        "ProxyAutoConfigEnable",
        "ProxyAutoDiscoveryEnable",
    ];

    raw.lines().any(|line| {
        let mut parts = line.splitn(2, ':');
        let key = parts.next().map(str::trim);
        let value = parts.next().map(str::trim);
        matches!((key, value), (Some(k), Some("1")) if ENABLE_KEYS.contains(&k))
    })
}

fn system_proxy_active() -> bool {
    Command::new("/usr/sbin/scutil")
        .arg("--proxy")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .is_some_and(|raw| system_proxy_active_from_scutil(&raw))
}

fn system_proxy_from_status(st: Option<&Value>) -> Option<(bool, String)> {
    let proxy = st?.get("system_proxy")?;
    let state = proxy
        .get("state")
        .and_then(|x| x.as_str())
        .unwrap_or("unknown");
    let kind = proxy
        .get("kind")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    match state {
        "active" => Some((true, kind)),
        "off" => Some((false, kind)),
        _ => None,
    }
}

fn push_detail_part(detail: &mut String, part: &str) {
    if !part.is_empty() {
        detail.push_str(" · ");
        detail.push_str(part);
    }
}

fn health_rank(state: &str) -> u8 {
    match state {
        "blocked" => 3,
        "degraded" => 2,
        "unknown" => 1,
        "ok" => 0,
        _ => 1,
    }
}

fn route_class_health(st: Option<&Value>, route_class: &str) -> Option<String> {
    let routes = st?.get("route_health")?.as_object()?;
    let mut worst: Option<&str> = None;
    for item in routes.values() {
        if item.get("last_route_class").and_then(|x| x.as_str()) != Some(route_class) {
            continue;
        }
        let state = item
            .get("state")
            .and_then(|x| x.as_str())
            .unwrap_or("unknown");
        if match worst {
            Some(current) => health_rank(state) > health_rank(current),
            None => true,
        } {
            worst = Some(state);
        }
    }
    worst.map(str::to_string)
}

fn routing_health_summary(st: Option<&Value>, geph: &str, ru: bool) -> Option<String> {
    let local = route_class_health(st, "local_bypass");
    let geo = if geph == "off" {
        None
    } else {
        route_class_health(st, "geo_exit").or_else(|| Some("unknown".to_string()))
    };

    let local_failed = local
        .as_deref()
        .is_some_and(|s| matches!(s, "blocked" | "degraded"));
    let geph_failed = geo
        .as_deref()
        .is_some_and(|s| matches!(s, "blocked" | "degraded"))
        || geph == "down";

    if local_failed || geph_failed {
        Some(if ru {
            "Требует внимания".to_string()
        } else {
            "Needs attention".to_string()
        })
    } else {
        None
    }
}

/// Refresh the two status info-items from the daemon status.
/// Update the menu text from the daemon status; returns the state string so the
/// caller can update the tray icon ONLY when it changes (re-setting the icon every
/// poll made the menu-bar mark visibly blink).
fn refresh(state_item: &MenuItem<tauri::Wry>, detail_item: &MenuItem<tauri::Wry>) -> String {
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
    let telegram_proxy = get_str("telegram_proxy", "unknown");
    let telegram_proxy_suggested = st
        .as_ref()
        .and_then(|v| v.get("telegram_proxy_suggest"))
        .and_then(|x| x.as_bool())
        .unwrap_or(false);

    let ru = ui_ru();
    let (title, mut detail) = match state.as_str() {
        "active" => {
            let d = if ru {
                format!("{conns} соединений · хостов: {learned}")
            } else {
                format!("{conns} connections · {learned} hosts learned")
            };
            (
                (if ru {
                    "Slipstream — активен"
                } else {
                    "Slipstream — Active"
                })
                .to_string(),
                d,
            )
        }
        "dormant" => (
            (if ru {
                "Slipstream — спит"
            } else {
                "Slipstream — Dormant"
            })
            .to_string(),
            (if ru {
                "VPN включён; обходом занимается он"
            } else {
                "VPN is up; the VPN handles bypass"
            })
            .to_string(),
        ),
        _ => (
            (if ru {
                "Slipstream — выключен"
            } else {
                "Slipstream — Off"
            })
            .to_string(),
            (if ru {
                "Фоновый прокси не запущен"
            } else {
                "Background proxy is not running"
            })
            .to_string(),
        ),
    };
    if matches!(state.as_str(), "active" | "dormant") {
        if let Some(routing) = routing_health_summary(st.as_ref(), &geph, ru) {
            push_detail_part(&mut detail, &routing);
        }
        if let Some(tg) = telegram_proxy_detail(&telegram_proxy, telegram_proxy_suggested, ru) {
            push_detail_part(&mut detail, tg);
        }
        let (proxy_active, proxy_kind) = system_proxy_from_status(st.as_ref())
            .unwrap_or_else(|| (system_proxy_active(), String::new()));
        if proxy_active {
            let proxy_text = if proxy_kind.is_empty() {
                if ru {
                    "Системный прокси включён".to_string()
                } else {
                    "System proxy active".to_string()
                }
            } else if ru {
                format!("Системный прокси: {proxy_kind}")
            } else {
                format!("System proxy: {proxy_kind}")
            };
            push_detail_part(&mut detail, &proxy_text);
        }
    }
    let _ = state_item.set_text(&title);
    let _ = detail_item.set_text(&detail);
    state
}

/// Set the menu-bar mark for the given state (called only on a state change).
fn set_tray_icon(app: &AppHandle, state: &str) {
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

/// Show a native notification (geph up/down, updates).
fn notify(app: &AppHandle, body: &str) {
    let _ = app
        .notification()
        .builder()
        .title("Slipstream")
        .body(body)
        .show();
}

fn open_telegram_proxy_link() -> bool {
    match fs::read_to_string(TGWS_LINK_PATH) {
        Ok(link) if link.trim().starts_with("tg://") => Command::new("/usr/bin/open")
            .arg(link.trim())
            .spawn()
            .is_ok(),
        _ => false,
    }
}

fn mark_telegram_proxy_accepted() {
    let _ = fs::write(TGWS_ACCEPTED_PATH, b"1\n");
}

fn tell_telegram_proxy_starting() {
    let msg = if ui_ru() {
        "Telegram-прокси ещё запускается — попробуй через пару секунд."
    } else {
        "Telegram proxy is still starting — try again in a few seconds."
    };
    let script = format!(
        "display dialog \"{msg}\" with title \"Slipstream\" buttons {{\"OK\"}} \
         default button \"OK\" with icon note"
    );
    let _ = osascript_dialog(&script).spawn();
}

fn prompt_telegram_proxy_offer() -> bool {
    let (msg, connect, later) = if ui_ru() {
        (
            "Похоже, Telegram не подключается напрямую. Подключить встроенный прокси Slipstream?",
            "Подключить",
            "Не сейчас",
        )
    } else {
        (
            "Telegram direct connection looks blocked. Connect the built-in Slipstream proxy?",
            "Connect",
            "Not Now",
        )
    };
    let script = format!(
        "display dialog \"{msg}\" with title \"Slipstream\" buttons {{\"{later}\", \"{connect}\"}} \
         default button \"{connect}\" with icon note"
    );
    let Ok(out) = osascript_dialog(&script).output() else {
        return false;
    };
    if !out.status.success() {
        return false;
    }
    String::from_utf8_lossy(&out.stdout).contains(&format!("button returned:{connect}"))
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
    let Ok(dir) = app.path().app_config_dir() else {
        return;
    };
    let path = dir.join("geph.json");
    let Ok(text) = fs::read_to_string(&path) else {
        return;
    };
    let Ok(mut cfg) = serde_json::from_str::<serde_json::Map<String, Value>>(&text) else {
        return;
    };
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
        .args([
            "find-generic-password",
            "-s",
            KC_SERVICE,
            "-a",
            KC_ACCOUNT,
            "-w",
        ])
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
        .args([
            "add-generic-password",
            "-U",
            "-s",
            KC_SERVICE,
            "-a",
            KC_ACCOUNT,
            "-w",
            secret,
        ])
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

            let state_item = MenuItemBuilder::with_id("state", "…")
                .enabled(false)
                .build(app)?;
            let detail_item = MenuItemBuilder::with_id("detail", " ")
                .enabled(false)
                .build(app)?;

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
                .item(
                    &MenuItemBuilder::with_id(ID_ACCOUNT, tr("Account…"))
                        .accelerator("CmdOrCtrl+,")
                        .build(app)?,
                )
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
            let version_label = format!(
                "{} {}",
                if ui_ru() { "Версия" } else { "Version" },
                app.package_info().version
            );

            let menu = MenuBuilder::new(app)
                .item(&state_item)
                .item(&detail_item)
                .separator()
                .item(&geph_menu)
                .item(&launch)
                .item(&MenuItemBuilder::with_id(ID_RESTART, tr("Restart Proxy")).build(app)?)
                .item(&MenuItemBuilder::with_id(ID_LOG, tr("Open Log")).build(app)?)
                .item(&MenuItemBuilder::with_id(ID_DIAGNOSTICS, tr("Copy Diagnostics")).build(app)?)
                .separator()
                .item(&MenuItemBuilder::with_id(ID_UPDATE, tr("Check for Updates…")).build(app)?)
                .item(
                    &MenuItemBuilder::with_id("version", version_label)
                        .enabled(false)
                        .build(app)?,
                )
                .item(
                    &MenuItemBuilder::with_id(ID_QUIT, tr("Quit Slipstream"))
                        .accelerator("CmdOrCtrl+Q")
                        .build(app)?,
                )
                .build()?;

            let tg_offer_reset = Arc::new(AtomicU64::new(0));

            // ---- tray --------------------------------------------------------
            let icon = Image::from_path(
                app.path()
                    .resource_dir()?
                    .join("icons")
                    .join("slip-menubar-mark.png"),
            )
            .unwrap_or_else(|_| app.default_window_icon().unwrap().clone());

            let launch_h = launch.clone();
            let enable_h = geph_enable.clone();
            let tg_offer_reset_menu = tg_offer_reset.clone();
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
                        ID_RESTART => {
                            tg_offer_reset_menu.fetch_add(1, Ordering::Relaxed);
                            run_admin(&format!("launchctl kickstart -k system/{LAUNCHD_LABEL}"));
                        }
                        ID_LOG => {
                            if !open_log_snapshot() {
                                notify(app, "Unable to open Slipstream log");
                            }
                        }
                        ID_DIAGNOSTICS => {
                            if copy_diagnostic_snapshot(app) {
                                notify(app, "Slipstream diagnostics copied");
                            } else {
                                notify(app, "Unable to copy Slipstream diagnostics");
                            }
                        }
                        ID_UPDATE => {
                            let app = app.clone();
                            tauri::async_runtime::spawn(
                                async move { check_for_updates(app).await },
                            );
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
            let tg_offer_reset_watch = tg_offer_reset.clone();
            tauri::async_runtime::spawn(async move {
                let mut last_state = String::new();
                // Debounced Geph up/down notification: geph flaps with the network,
                // and notifying on every transition spammed the user. Only fire when
                // a state has HELD for ~3 polls (6s) and differs from what we last
                // notified — a flap that reverts within 6s never surfaces.
                let mut notified_geph: Option<bool> = None;
                let mut pending: Option<bool> = None;
                let mut stable: u8 = 0;
                let mut next_tg_offer = Instant::now();
                let mut seen_tg_offer_reset = tg_offer_reset_watch.load(Ordering::Relaxed);
                let mut missing_status_polls: u8 = 0;
                let mut next_daemon_recovery = Instant::now();
                loop {
                    let state = refresh(&s, &d);
                    if state != last_state {
                        set_tray_icon(&app_handle, &state); // only on change -> no blink
                        last_state = state;
                    }
                    let status = read_status();
                    let now = Instant::now();
                    if status.is_some() {
                        missing_status_polls = 0;
                    } else {
                        missing_status_polls = missing_status_polls.saturating_add(1);
                    }
                    let tg_offer_reset_seen_now = tg_offer_reset_watch.load(Ordering::Relaxed);
                    if tg_offer_reset_seen_now != seen_tg_offer_reset {
                        seen_tg_offer_reset = tg_offer_reset_seen_now;
                        next_tg_offer = now;
                    }
                    if should_recover_daemon(
                        missing_status_polls,
                        now >= next_daemon_recovery,
                        daemon_installed_for_watchdog(&app_handle),
                    ) {
                        next_daemon_recovery =
                            now + Duration::from_secs(DAEMON_WATCHDOG_COOLDOWN_SECS);
                        run_admin(&daemon_recovery_shell());
                    }
                    if let Some(up) = status
                        .as_ref()
                        .and_then(|v| v.get("geph"))
                        .and_then(|x| x.as_str())
                        .map(|g| g == "up")
                    {
                        if pending == Some(up) {
                            stable = stable.saturating_add(1);
                        } else {
                            pending = Some(up);
                            stable = 1;
                        }
                        if stable >= 3 && notified_geph != Some(up) {
                            if notified_geph.is_some() {
                                notify(
                                    &app_handle,
                                    if up {
                                        "Geph tunnel connected"
                                    } else {
                                        "Geph tunnel disconnected"
                                    },
                                );
                            }
                            notified_geph = Some(up); // record even the first stable read silently
                        }
                    }
                    let should_offer_tg = status
                        .as_ref()
                        .and_then(|v| v.get("telegram_proxy_suggest"))
                        .and_then(|x| x.as_bool())
                        .unwrap_or(false);
                    if should_offer_tg && Instant::now() >= next_tg_offer {
                        // Telegram requires user confirmation for tg://proxy. We only
                        // ask after the daemon has seen repeated direct DC failures.
                        next_tg_offer = Instant::now() + Duration::from_secs(30 * 60);
                        if prompt_telegram_proxy_offer() {
                            if open_telegram_proxy_link() {
                                mark_telegram_proxy_accepted();
                            } else {
                                tell_telegram_proxy_starting();
                                next_tg_offer = Instant::now() + Duration::from_secs(30);
                            }
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

#[cfg(test)]
mod tests {
    use super::{
        copy_log_snapshot_direct, daemon_recovery_shell, diagnostic_snapshot_value,
        diagnostic_log_tail, install_diagnostic_value, launchd_plist_uses_bundled_daemon,
        log_snapshot_shell, osascript_dialog_args, redact_sensitive_text, route_class_health,
        routing_health_summary, shell_quote, should_recover_daemon, system_proxy_active_from_scutil,
        system_proxy_from_status, telegram_proxy_detail, DAEMON_WATCHDOG_MISSES,
    };
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn shell_quote_wraps_plain_argument() {
        assert_eq!(
            shell_quote("/Applications/Slipstream.app/slipstreamd"),
            "'/Applications/Slipstream.app/slipstreamd'"
        );
    }

    #[test]
    fn shell_quote_escapes_single_quotes() {
        assert_eq!(
            shell_quote("/tmp/Bob's Apps/slipstreamd"),
            "'/tmp/Bob'\\''s Apps/slipstreamd'"
        );
    }

    #[test]
    fn log_snapshot_shell_quotes_paths_and_uses_user_owner() {
        let shell = log_snapshot_shell(
            "/var/log/slipstream.log",
            std::path::Path::new("/tmp/Bob's Logs/slipstream.log"),
            "501",
            "20",
        );

        assert_eq!(
            shell,
            "/bin/cp '/var/log/slipstream.log' '/tmp/Bob'\\''s Logs/slipstream.log' && \
             /usr/sbin/chown 501:20 '/tmp/Bob'\\''s Logs/slipstream.log' && \
             /bin/chmod 600 '/tmp/Bob'\\''s Logs/slipstream.log'"
        );
    }

    #[test]
    fn copy_log_snapshot_direct_copies_and_clamps_permissions() {
        let dir = std::env::temp_dir().join(format!(
            "slipstream-log-copy-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("source.log");
        let dst = dir.join("snapshot.log");
        std::fs::write(&src, "line one\nline two\n").unwrap();
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o640)).unwrap();

        assert!(copy_log_snapshot_direct(src.to_str().unwrap(), &dst));
        assert_eq!(std::fs::read_to_string(&dst).unwrap(), "line one\nline two\n");
        assert_eq!(std::fs::metadata(&dst).unwrap().permissions().mode() & 0o777, 0o600);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn copy_log_snapshot_direct_returns_false_when_unreadable() {
        let dst = std::env::temp_dir().join(format!(
            "slipstream-missing-log-{}.log",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&dst);

        assert!(!copy_log_snapshot_direct("/definitely/missing/slipstream.log", &dst));
    }

    #[test]
    fn diagnostic_snapshot_redacts_sensitive_status_fields() {
        let snapshot = diagnostic_snapshot_value(
            "0.1.5",
            Some(json!({
                "state": "active",
                "route_health": {
                    "openai": {
                        "state": "ok",
                        "last_host": "chatgpt.com"
                    }
                },
                "geph": {
                    "account_secret": "very-secret",
                    "nested": {
                        "api_token": "token-value",
                        "password": "pass-value"
                    }
                }
            })),
            123.0,
            Some(json!({
                "available": true,
                "lines": ["tg://proxy?server=127.0.0.1&secret=old-secret"]
            })),
            None,
        );
        let text = serde_json::to_string(&snapshot).unwrap();

        assert_eq!(snapshot["app"]["version"], "0.1.5");
        assert_eq!(
            snapshot["daemon"]["route_health"]["openai"]["last_host"],
            "chatgpt.com"
        );
        assert!(!text.contains("very-secret"));
        assert!(!text.contains("token-value"));
        assert!(!text.contains("pass-value"));
        assert!(!text.contains("old-secret"));
        assert!(text.contains("<redacted>"));
    }

    #[test]
    fn install_diagnostics_report_bundled_daemon_sync() {
        let dir = std::env::temp_dir().join(format!(
            "slipstream-install-diagnostic-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bundled = dir.join("bundled-slipstreamd");
        let installed = dir.join("installed-slipstreamd");
        let plist = dir.join("dev.slipstream.tproxy.plist");
        std::fs::write(&bundled, "daemon-v1").unwrap();
        std::fs::write(&installed, "daemon-v1").unwrap();
        std::fs::write(
            &plist,
            format!(
                "<array><string>{}</string><string>--status</string></array>",
                installed.display()
            ),
        )
        .unwrap();

        let synced = install_diagnostic_value(Some(&bundled), &installed, &plist);
        assert_eq!(synced["bundled_daemon_exists"], true);
        assert_eq!(synced["installed_daemon_exists"], true);
        assert_eq!(synced["installed_daemon_matches_bundle"], true);
        assert_eq!(synced["launchd_plist_uses_installed_daemon"], true);
        assert_eq!(
            synced["bundled_daemon_path"],
            bundled.to_string_lossy().as_ref()
        );

        std::fs::write(&installed, "daemon-v2").unwrap();
        let stale = install_diagnostic_value(Some(&bundled), &installed, &plist);
        assert_eq!(stale["installed_daemon_matches_bundle"], false);

        let missing_bundle = install_diagnostic_value(None, &installed, &plist);
        assert_eq!(missing_bundle["bundled_daemon_exists"], false);
        assert!(missing_bundle["installed_daemon_matches_bundle"].is_null());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn redact_sensitive_text_handles_urls_yaml_and_json() {
        assert_eq!(
            redact_sensitive_text("tg://proxy?server=127.0.0.1&secret=abc123&port=1443"),
            "tg://proxy?server=127.0.0.1&secret=<redacted>&port=1443"
        );
        assert_eq!(
            redact_sensitive_text("account: { password: \"hunter2\", api_token: token-value }"),
            "account: { password:<redacted>, api_token:<redacted> }"
        );
        assert_eq!(
            redact_sensitive_text("secret-entry dialog stays visible"),
            "secret-entry dialog stays visible"
        );
    }

    #[test]
    fn diagnostic_log_tail_is_bounded_and_redacted() {
        let dir = std::env::temp_dir().join(format!(
            "slipstream-diagnostic-tail-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("slipstream.log");
        std::fs::write(
            &log,
            "one\nsecret=first\nthree\npassword: \"last-secret\"\n",
        )
        .unwrap();

        let tail = diagnostic_log_tail(log.to_str().unwrap(), 3);
        let text = serde_json::to_string(&tail).unwrap();

        assert_eq!(tail["available"], true);
        assert_eq!(tail["truncated"], true);
        assert_eq!(tail["lines"].as_array().unwrap().len(), 3);
        assert!(!text.contains("first"));
        assert!(!text.contains("last-secret"));
        assert!(text.contains("<redacted>"));
        assert!(!text.contains("one"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn diagnostic_log_tail_reports_unavailable_log() {
        let tail = diagnostic_log_tail("/definitely/missing/slipstream.log", 10);

        assert_eq!(tail["available"], false);
        assert_eq!(tail["lines"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn osascript_dialog_args_activate_before_displaying_dialog() {
        assert_eq!(
            osascript_dialog_args("display dialog \"hello\""),
            vec![
                "-e",
                "activate",
                "-e",
                "delay 0.05",
                "-e",
                "display dialog \"hello\"",
            ]
        );
    }

    #[test]
    fn launchd_plist_detects_bundled_daemon() {
        let plist = "<array><string>/usr/local/slipstream/slipstreamd</string><string>--port</string></array>";
        assert!(launchd_plist_uses_bundled_daemon(plist));
    }

    #[test]
    fn launchd_plist_rejects_legacy_script_daemon() {
        let plist = "<array><string>/usr/local/slipstream/venv/bin/python3</string><string>/usr/local/slipstream/tproxy.py</string></array>";
        assert!(!launchd_plist_uses_bundled_daemon(plist));
    }

    #[test]
    fn watchdog_waits_for_threshold_cooldown_and_installed_daemon() {
        assert!(!should_recover_daemon(
            DAEMON_WATCHDOG_MISSES - 1,
            true,
            true
        ));
        assert!(!should_recover_daemon(DAEMON_WATCHDOG_MISSES, false, true));
        assert!(!should_recover_daemon(DAEMON_WATCHDOG_MISSES, true, false));
        assert!(should_recover_daemon(DAEMON_WATCHDOG_MISSES, true, true));
    }

    #[test]
    fn daemon_recovery_shell_kickstarts_before_pf_cleanup() {
        let shell = daemon_recovery_shell();

        assert!(shell.contains("/bin/launchctl kickstart -k 'system/dev.slipstream.tproxy'"));
        assert!(shell.contains("/usr/local/slipstream/slipstreamd' --status"));
        assert!(shell.contains("/sbin/pfctl -f /etc/pf.conf"));
        assert!(shell.find("kickstart").unwrap() < shell.find("pfctl").unwrap());
    }

    #[test]
    fn telegram_proxy_detail_prefers_suggested_state() {
        assert_eq!(
            telegram_proxy_detail("ready", true, true),
            Some("Telegram-прокси рекомендуется")
        );
    }

    #[test]
    fn telegram_proxy_detail_reports_only_actionable_states() {
        assert_eq!(telegram_proxy_detail("ready", false, false), None);
        assert_eq!(telegram_proxy_detail("in_use", false, false), None);
        assert_eq!(
            telegram_proxy_detail("starting", false, false),
            Some("Telegram proxy starting")
        );
        assert_eq!(
            telegram_proxy_detail("error", false, true),
            Some("Telegram-прокси недоступен")
        );
        assert_eq!(telegram_proxy_detail("unknown", false, false), None);
    }

    #[test]
    fn inactive_system_proxy_ignores_stale_servers() {
        let raw = r#"<dictionary> {
  HTTPEnable : 0
  HTTPProxy : 127.0.0.1
  HTTPPort : 9910
  HTTPSEnable : 0
  SOCKSEnable : 0
  ProxyAutoConfigEnable : 0
}"#;

        assert!(!system_proxy_active_from_scutil(raw));
    }

    #[test]
    fn active_system_proxy_detects_manual_and_pac_modes() {
        assert!(system_proxy_active_from_scutil("HTTPSEnable : 1\n"));
        assert!(system_proxy_active_from_scutil("SOCKSEnable : 1\n"));
        assert!(system_proxy_active_from_scutil(
            "ProxyAutoConfigEnable : 1\n"
        ));
        assert!(system_proxy_active_from_scutil(
            "ProxyAutoDiscoveryEnable : 1\n"
        ));
    }

    #[test]
    fn system_proxy_status_prefers_daemon_snapshot_when_available() {
        let status = json!({
            "system_proxy": {
                "state": "active",
                "kind": "https,pac"
            }
        });

        assert_eq!(
            system_proxy_from_status(Some(&status)),
            Some((true, "https,pac".to_string()))
        );
    }

    #[test]
    fn route_health_aggregates_by_route_class() {
        let status = json!({
            "route_health": {
                "discord": {
                    "state": "ok",
                    "last_route_class": "local_bypass"
                },
                "youtube_video": {
                    "state": "degraded",
                    "last_route_class": "local_bypass",
                    "last_host": "www.youtube.com",
                    "last_failure": "strategy probe failed"
                },
                "openai": {
                    "state": "ok",
                    "last_route_class": "geo_exit"
                }
            }
        });

        assert_eq!(
            route_class_health(Some(&status), "local_bypass"),
            Some("degraded".to_string())
        );
        assert_eq!(
            routing_health_summary(Some(&status), "up", false),
            Some("Needs attention".to_string())
        );
    }

    #[test]
    fn routing_health_summary_stays_short_for_geph_failures() {
        let status = json!({
            "route_health": {
                "youtube_video": {
                    "state": "unknown",
                    "last_route_class": "local_bypass"
                },
                "openai": {
                    "state": "degraded",
                    "last_route_class": "geo_exit",
                    "last_host": "billing.openai.com",
                    "last_failure": "SOCKS connect failed"
                }
            }
        });

        assert_eq!(
            routing_health_summary(Some(&status), "up", false),
            Some("Needs attention".to_string())
        );
        assert_eq!(routing_health_summary(Some(&status), "off", false), None);
    }
}
