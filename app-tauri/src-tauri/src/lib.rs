// Slipstream — tray app (Tauri v2). Unprivileged menu-bar UI over the root
// daemon (tproxy.py). The UI is 100% NATIVE: a real NSMenu (tray) + native
// osascript dialogs — no WebView window (a styled WebView always reads as
// "web", which is the look we're avoiding). Tauri still provides the native
// tray, the signed auto-updater, and the geph sidecar.
//
// Logic lives here (lib.rs) so the same crate can back a mobile entry point
// later; main.rs is a thin desktop shim.

mod diagnostics;
mod geph_config;
mod status_client;

pub use slipstream_core::{
    address_attempts, connection_race, route_circuit, route_circuit_registry,
};

use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

#[cfg(test)]
use diagnostics::redact_sensitive_text;
use diagnostics::{
    daemon_recovery_status_value, diagnostic_log_tail, diagnostic_log_tail_from_path,
    diagnostic_snapshot_path, sanitize_json, unix_now_secs, write_diagnostic_snapshot_file,
};
use geph_config::{
    geph_config_set, geph_enabled, geph_field, geph_secret, keychain_delete, keychain_set,
};
use serde_json::{json, Value};
use status_client::{read_status, STATUS_PATH};
use tauri::{
    image::Image,
    menu::{
        CheckMenuItem, CheckMenuItemBuilder, MenuBuilder, MenuItem, MenuItemBuilder, MenuItemKind,
        PredefinedMenuItem, Submenu, SubmenuBuilder,
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
const GEPH_OWNERSHIP_FILE: &str = "geph-owned.json";
const GEPH_LAUNCHD_LABEL: &str = "dev.slipstream.geph";
const GEPH_LAUNCH_AGENT_PLIST: &str = "dev.slipstream.geph.plist";
const GEPH_RUNTIME_DIR: &str = "runtime";
const GEPH_RUNTIME_BIN: &str = "geph5-client";
const GEPH_LAUNCHER_FILE: &str = "geph-launcher";
const GEPH_STDOUT_LOG_FILE: &str = "geph.stdout.log";
const GEPH_STDERR_LOG_FILE: &str = "geph.stderr.log";
const GEPH_LOG_ARCHIVE_SUFFIX: &str = ".previous";
const GEPH_LOG_MAX_BYTES: u64 = 1024 * 1024;
const GEPH_LOG_RETAIN_BYTES: u64 = 256 * 1024;
const GEPH_LOG_GUARD_INTERVAL_SECS: u64 = 5;

// geph5-client is owned by a per-user LaunchAgent. A private launcher writes the
// current PID/executable/config record immediately before exec; a listener alone
// is never sufficient proof that Slipstream may adopt or terminate a process.

const LOG_PATH: &str = "/var/log/slipstream.log";
const LAUNCHD_LABEL: &str = "dev.slipstream.tproxy";
const LAUNCHD_PLIST: &str = "/Library/LaunchDaemons/dev.slipstream.tproxy.plist";
const INSTALLED_DAEMON: &str = "/usr/local/slipstream/slipstreamd";
const PF_ANCHOR: &str = "com.apple/slipstream";
const PF_TOKEN_PATH: &str = "/var/run/slipstream-pf.token";
const TGWS_ACCEPTED_PATH: &str = "/var/tmp/dev.slipstream.tgws.accepted";
const DAEMON_RECOVERY_STATUS_PATH: &str = "/var/tmp/dev.slipstream.daemon-recovery.json";
const DAEMON_WATCHDOG_MISSES: u8 = 3;
const DAEMON_WATCHDOG_COOLDOWN_SECS: u64 = 5 * 60;
const DAEMON_WATCHDOG_STARTUP_GRACE_SECS: u64 = 30;
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
        "Locations unavailable" => "Локации недоступны",
        "Core" => "Основные",
        "Streaming" => "Стриминг",
        "Launch at Login" => "Запускать при входе",
        "Restart Proxy" => "Перезапустить прокси",
        "Open Status" => "Открыть статус",
        "Copy Diagnostics" => "Скопировать диагностику",
        "Unable to save Geph account" => "Не удалось сохранить аккаунт Geph",
        "Check for Updates…" => "Проверить обновления…",
        "Uninstall Slipstream…" => "Удалить Slipstream…",
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
const ID_UNINSTALL: &str = "uninstall_slipstream";
const ID_QUIT: &str = "quit";
// Daemon publishes the tg://proxy?... link here (world-readable) once the bundled
// tg-ws-proxy is up; the tray opens it so Telegram Desktop adds+enables the proxy
// in one click (no manual host/port/secret entry).
const TGWS_LINK_PATH: &str = "/var/run/slipstream-tgws.link";

fn applescript_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn admin_shell_script(shell: &str, prompt: &str) -> String {
    let escaped_shell = applescript_string(shell);
    let escaped_prompt = applescript_string(prompt);
    format!(
        "do shell script \"{escaped_shell}\" with administrator privileges with prompt \"{escaped_prompt}\""
    )
}

/// Run a privileged shell line via one osascript admin prompt.
fn run_admin(shell: &str, prompt: &str) {
    let script = admin_shell_script(shell, prompt);
    let _ = Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(script)
        .spawn();
}

fn run_admin_status(shell: &str, prompt: &str) -> bool {
    let script = admin_shell_script(shell, prompt);
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

fn diagnostic_log_tail_with_admin_fallback(log_path: &str, max_lines: usize) -> Value {
    let direct = diagnostic_log_tail(log_path, max_lines);
    if direct.get("available").and_then(Value::as_bool) == Some(true)
        || !Path::new(log_path).exists()
    {
        return direct;
    }

    let snapshot = std::env::temp_dir().join(format!(
        "slipstream-diagnostic-log-{}.log",
        std::process::id()
    ));
    let _ = fs::remove_file(&snapshot);
    let copied = if copy_log_snapshot_direct(log_path, &snapshot) {
        true
    } else {
        let Some(uid) = current_numeric_id("-u") else {
            return direct;
        };
        let Some(gid) = current_numeric_id("-g") else {
            return direct;
        };
        let shell = log_snapshot_shell(log_path, &snapshot, &uid, &gid);
        run_admin_status(
            &shell,
            "Slipstream needs administrator access to include its daemon log in diagnostics.",
        )
    };
    if !copied {
        return direct;
    }

    let tail = diagnostic_log_tail_from_path(log_path, &snapshot, max_lines);
    let _ = fs::remove_file(snapshot);
    tail
}

fn launchd_plist_uses_daemon(raw: &str, daemon: &Path) -> bool {
    raw.contains(&format!("<string>{}</string>", daemon.display()))
}

fn daemon_binary_format(path: &Path) -> Option<&'static str> {
    let mut magic = [0u8; 4];
    fs::File::open(path).ok()?.read_exact(&mut magic).ok()?;
    match magic {
        [0xfe, 0xed, 0xfa, 0xce]
        | [0xce, 0xfa, 0xed, 0xfe]
        | [0xfe, 0xed, 0xfa, 0xcf]
        | [0xcf, 0xfa, 0xed, 0xfe] => Some("mach-o"),
        [0xca, 0xfe, 0xba, 0xbe]
        | [0xbe, 0xba, 0xfe, 0xca]
        | [0xca, 0xfe, 0xba, 0xbf]
        | [0xbf, 0xba, 0xfe, 0xca] => Some("fat-mach-o"),
        _ => None,
    }
}

fn daemon_binary_executable(path: &Path) -> Option<bool> {
    Some(fs::metadata(path).ok()?.permissions().mode() & 0o111 != 0)
}

fn valid_bundled_daemon(path: &Path) -> bool {
    daemon_binary_format(path).is_some() && daemon_binary_executable(path) == Some(true)
}

fn install_diagnostic_value(
    bundled_daemon: Option<&Path>,
    installed_daemon: &Path,
    launchd_plist: &Path,
) -> Value {
    let bundled_daemon_path = bundled_daemon.map(|path| path.to_string_lossy().into_owned());
    let bundled_daemon_exists = bundled_daemon.map(|path| path.exists()).unwrap_or(false);
    let bundled_daemon_format = bundled_daemon.and_then(daemon_binary_format);
    let bundled_daemon_executable = bundled_daemon.and_then(daemon_binary_executable);
    let bundled_daemon_valid = bundled_daemon.and_then(|path| {
        if path.exists() {
            Some(valid_bundled_daemon(path))
        } else {
            None
        }
    });
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
        "bundled_daemon_format": bundled_daemon_format,
        "bundled_daemon_executable": bundled_daemon_executable,
        "bundled_daemon_valid": bundled_daemon_valid,
        "installed_daemon_matches_bundle": installed_daemon_matches_bundle,
        "launchd_label": LAUNCHD_LABEL,
        "launchd_plist": launchd_plist.to_string_lossy(),
        "launchd_plist_uses_installed_daemon": launchd_plist_uses_installed_daemon,
        "status_path": STATUS_PATH,
        "log_path": LOG_PATH,
    })
}

fn value_string(value: Option<&Value>, key: &str, default: &str) -> String {
    value
        .and_then(|item| item.get(key))
        .and_then(|item| item.as_str())
        .unwrap_or(default)
        .to_string()
}

fn diagnostic_problem_row(source: &str, name: &str, item: &Value) -> Option<Value> {
    let failure = item
        .get("last_failure")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let warning = item
        .get("last_warning")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    if failure.is_empty() && warning.is_empty() {
        return None;
    }
    Some(json!({
        "source": source,
        "name": name,
        "state": value_string(Some(item), "state", "unknown"),
        "route_class": value_string(Some(item), "last_route_class", ""),
        "host": value_string(Some(item), "last_host", ""),
        "backend": value_string(Some(item), "last_backend", ""),
        "failure": failure,
        "warning": warning,
        "warning_host": value_string(Some(item), "last_warning_host", ""),
        "failures_5m": item.get("failures_5m").and_then(|value| value.as_i64()).unwrap_or(0),
    }))
}

fn diagnostic_problem_rows(status: Option<&Value>) -> Value {
    let mut rows = Vec::new();
    if let Some(routes) = status
        .and_then(|status| status.get("route_health"))
        .and_then(|value| value.as_object())
    {
        for (name, item) in routes {
            if let Some(row) = diagnostic_problem_row("route_health", name, item) {
                rows.push(row);
            }
        }
    }
    if let Some(checks) = status
        .and_then(|status| status.get("canaries"))
        .and_then(|value| value.get("checks"))
        .and_then(|value| value.as_object())
    {
        for (name, item) in checks {
            if let Some(row) = diagnostic_problem_row("canary", name, item) {
                rows.push(row);
            }
        }
    }
    Value::Array(rows)
}

fn diagnostic_summary_value(status: Option<&Value>) -> Value {
    let daemon_state = value_string(status, "state", "off");
    let daemon_version = value_string(status, "version", "unknown");
    let geph = value_string(status, "geph", "unknown");
    let telegram_proxy = value_string(status, "telegram_proxy", "unknown");
    let local_bypass = route_class_health(status, "local_bypass").unwrap_or("unknown".to_string());
    let geo_exit = if geph == "off" {
        "off".to_string()
    } else {
        route_class_health(status, "geo_exit").unwrap_or("unknown".to_string())
    };
    let system_proxy = status
        .and_then(|status| status.get("system_proxy"))
        .cloned()
        .unwrap_or_else(|| json!({"state": "unknown", "kind": ""}));
    let system_dns = status
        .and_then(|status| status.get("system_dns"))
        .map(|dns| {
            json!({
                "state": value_string(Some(dns), "state", "unknown"),
                "providers": value_string(Some(dns), "providers", ""),
                "managed_by_slipstream": dns
                    .get("managed_by_slipstream")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false),
                "resolution_state": dns
                    .get("resolution_checks")
                    .and_then(|value| value.get("state"))
                    .and_then(|value| value.as_str())
                    .unwrap_or("unknown"),
            })
        })
        .unwrap_or_else(|| json!({"state": "unknown"}));
    let pf_state = status
        .and_then(|status| status.get("pf_state"))
        .cloned()
        .unwrap_or_else(|| json!({"applied": false, "enabled": false, "rules_loaded": false}));
    let canaries = status
        .and_then(|status| status.get("canaries"))
        .map(|canaries| {
            json!({
                "running": canaries.get("running").and_then(|value| value.as_bool()).unwrap_or(false),
                "last_reason": value_string(Some(canaries), "last_reason", ""),
                "total": canaries.get("total").and_then(|value| value.as_i64()).unwrap_or(0),
                "ok": canaries.get("ok").and_then(|value| value.as_i64()).unwrap_or(0),
                "warnings": canaries.get("warnings").and_then(|value| value.as_i64()).unwrap_or(0),
                "degraded": canaries.get("degraded").and_then(|value| value.as_i64()).unwrap_or(0),
                "unknown": canaries.get("unknown").and_then(|value| value.as_i64()).unwrap_or(0),
            })
        })
        .unwrap_or_else(|| json!({"total": 0, "ok": 0, "warnings": 0, "degraded": 0}));
    let auto_geo_exit = status
        .and_then(|status| status.get("auto_geo_exit"))
        .cloned()
        .unwrap_or_else(|| json!({"enabled": false, "learned": 0, "pending": 0}));
    let routing_policy = status
        .and_then(|status| status.get("routing_policy"))
        .map(|policy| {
            json!({
                "version": policy.get("version").and_then(|value| value.as_i64()).unwrap_or(0),
                "source": value_string(Some(policy), "source", "unknown"),
                "sha256": value_string(Some(policy), "sha256", ""),
                "domains": policy
                    .get("domains")
                    .cloned()
                    .unwrap_or_else(|| json!({})),
                "attempt_limits": policy
                    .get("attempt_limits")
                    .cloned()
                    .unwrap_or_else(|| json!({})),
            })
        })
        .unwrap_or_else(|| json!({"version": 0, "source": "unknown", "sha256": ""}));
    let strategy_scores = status
        .and_then(|status| status.get("strategy_scores"))
        .cloned()
        .unwrap_or_else(|| json!({"hosts": 0, "groups": {}, "strategies": {}}));
    let geph_detail = status
        .and_then(|status| status.get("geph_detail"))
        .map(|detail| {
            json!({
                "port": detail.get("port").and_then(|value| value.as_i64()).unwrap_or(0),
                "failure_reason": value_string(Some(detail), "failure_reason", ""),
                "last_failure_host": value_string(Some(detail), "last_failure_host", ""),
                "last_failure_at": detail
                    .get("last_failure_at")
                    .and_then(|value| value.as_f64())
                    .unwrap_or(0.0),
                "restart_recommended": detail
                    .get("restart_recommended")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false),
                "restart_reason": value_string(Some(detail), "restart_reason", ""),
                "restart_failures_5m": detail
                    .get("restart_failures_5m")
                    .and_then(|value| value.as_i64())
                    .unwrap_or(0),
                "restart_hosts_5m": detail
                    .get("restart_hosts_5m")
                    .and_then(|value| value.as_i64())
                    .unwrap_or(0),
            })
        })
        .unwrap_or_else(|| json!({"port": 0}));

    json!({
        "daemon_state": daemon_state,
        "daemon_version": daemon_version,
        "geph": geph,
        "telegram_proxy": telegram_proxy,
        "routes": {
            "local_bypass": local_bypass,
            "geo_exit": geo_exit,
        },
        "system_proxy": system_proxy,
        "system_dns": system_dns,
        "pf_state": pf_state,
        "canaries": canaries,
        "auto_geo_exit": auto_geo_exit,
        "routing_policy": routing_policy,
        "strategy_scores": strategy_scores,
        "geph_detail": geph_detail,
        "problems": diagnostic_problem_rows(status),
    })
}

fn diagnostic_snapshot_value(
    app_version: &str,
    status: Option<Value>,
    geph_lifecycle: Value,
    generated_at: f64,
    log_tail: Option<Value>,
    daemon_recovery: Option<Value>,
    bundled_daemon: Option<&Path>,
) -> Value {
    let mut summary = diagnostic_summary_value(status.as_ref());
    summary["geph_lifecycle"] = geph_lifecycle;
    let mut snapshot = json!({
        "app": {
            "name": "Slipstream",
            "version": app_version,
        },
        "generated_at_unix": generated_at,
        "summary": summary,
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
    if let Some(daemon_recovery) = daemon_recovery {
        snapshot["daemon_recovery"] = daemon_recovery;
    }
    sanitize_json(&mut snapshot);
    snapshot
}

fn attach_geph_log_tails(app: &AppHandle, snapshot: &mut Value) {
    let Ok(paths) = geph_launch_agent_paths_for_app(app) else {
        return;
    };
    snapshot["geph_logs"] = json!({
        "stdout": {
            "current": diagnostic_log_tail_from_path(
                GEPH_STDOUT_LOG_FILE,
                &paths.stdout_log,
                DIAGNOSTIC_LOG_TAIL_LINES,
            ),
            "previous": diagnostic_log_tail_from_path(
                &format!("{GEPH_STDOUT_LOG_FILE}{GEPH_LOG_ARCHIVE_SUFFIX}"),
                &geph_log_archive_path(&paths.stdout_log),
                DIAGNOSTIC_LOG_TAIL_LINES,
            ),
        },
        "stderr": {
            "current": diagnostic_log_tail_from_path(
                GEPH_STDERR_LOG_FILE,
                &paths.stderr_log,
                DIAGNOSTIC_LOG_TAIL_LINES,
            ),
            "previous": diagnostic_log_tail_from_path(
                &format!("{GEPH_STDERR_LOG_FILE}{GEPH_LOG_ARCHIVE_SUFFIX}"),
                &geph_log_archive_path(&paths.stderr_log),
                DIAGNOSTIC_LOG_TAIL_LINES,
            ),
        },
    });
    sanitize_json(snapshot);
}

fn open_status_snapshot(app: &AppHandle) -> bool {
    let bundled_daemon = bundled_daemon_path(app);
    let status = read_status();
    let daemon_status_present = status.is_some();
    let mut snapshot = diagnostic_snapshot_value(
        &app.package_info().version.to_string(),
        status,
        geph_lifecycle_diagnostic_value(
            Path::new(INSTALLED_DAEMON).exists() && Path::new(LAUNCHD_PLIST).exists(),
            daemon_status_present,
            current_numeric_id("-u").is_some_and(|uid| geph_launch_agent_loaded(&uid)),
        ),
        unix_now_secs(),
        None,
        Some(daemon_recovery_status_value(DAEMON_RECOVERY_STATUS_PATH)),
        bundled_daemon.as_deref(),
    );
    attach_geph_log_tails(app, &mut snapshot);
    let Ok(text) = serde_json::to_string_pretty(&snapshot) else {
        return false;
    };
    let path = std::env::temp_dir().join("slipstream-status.json");
    if !write_diagnostic_snapshot_file(&path, &text) {
        return false;
    }
    Command::new("/usr/bin/open").arg(path).spawn().is_ok()
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

fn reveal_file_in_finder(path: &Path) {
    let _ = Command::new("/usr/bin/open").arg("-R").arg(path).spawn();
}

fn copy_diagnostic_snapshot(app: &AppHandle) -> bool {
    let bundled_daemon = bundled_daemon_path(app);
    let status = read_status();
    let daemon_status_present = status.is_some();
    let mut snapshot = diagnostic_snapshot_value(
        &app.package_info().version.to_string(),
        status,
        geph_lifecycle_diagnostic_value(
            Path::new(INSTALLED_DAEMON).exists() && Path::new(LAUNCHD_PLIST).exists(),
            daemon_status_present,
            current_numeric_id("-u").is_some_and(|uid| geph_launch_agent_loaded(&uid)),
        ),
        unix_now_secs(),
        Some(diagnostic_log_tail_with_admin_fallback(
            LOG_PATH,
            DIAGNOSTIC_LOG_TAIL_LINES,
        )),
        Some(daemon_recovery_status_value(DAEMON_RECOVERY_STATUS_PATH)),
        bundled_daemon.as_deref(),
    );
    attach_geph_log_tails(app, &mut snapshot);
    let Ok(text) = serde_json::to_string_pretty(&snapshot) else {
        return false;
    };
    let copied = copy_text_to_clipboard(&text);
    let path = diagnostic_snapshot_path();
    let saved = write_diagnostic_snapshot_file(&path, &text);
    if saved {
        reveal_file_in_finder(&path);
    }
    copied && saved
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

fn launchd_label_disabled_from_output(raw: &str, label: &str) -> Option<bool> {
    raw.lines().find_map(|line| {
        if !line.contains(&format!("\"{label}\"")) {
            return None;
        }
        let (_, value) = line.split_once("=>")?;
        match value.trim().trim_end_matches(',') {
            "true" | "disabled" => Some(true),
            "false" | "enabled" => Some(false),
            _ => None,
        }
    })
}

fn daemon_label_disabled() -> Option<bool> {
    let output = Command::new("/bin/launchctl")
        .args(["print-disabled", "system"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8(output.stdout).ok()?;
    launchd_label_disabled_from_output(&raw, LAUNCHD_LABEL)
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
    valid_bundled_daemon(&bin)
        && !daemon_needs_install(&bin)
        && matches!(daemon_label_disabled(), Some(false))
}

fn should_recover_daemon(
    missing_status_polls: u8,
    has_seen_status: bool,
    startup_grace_elapsed: bool,
    cooldown_ready: bool,
    installed: bool,
) -> bool {
    installed
        && cooldown_ready
        && missing_status_polls >= DAEMON_WATCHDOG_MISSES
        && (has_seen_status || startup_grace_elapsed)
}

fn daemon_recovery_shell() -> String {
    let label = shell_quote(&format!("system/{LAUNCHD_LABEL}"));
    let plist = shell_quote(LAUNCHD_PLIST);
    let daemon = shell_quote(INSTALLED_DAEMON);
    let recovery = shell_quote(DAEMON_RECOVERY_STATUS_PATH);
    let anchor = shell_quote(PF_ANCHOR);
    let pf_token_path = shell_quote(PF_TOKEN_PATH);
    format!(
        "recovery_status={recovery}; \
         write_recovery() {{ \
           /bin/printf '{{\"result\":\"%s\",\"ts\":%s}}\\n' \"$1\" \"$(/bin/date +%s)\" \
             > \"$recovery_status\"; \
           /bin/chmod 644 \"$recovery_status\"; \
         }}; \
         /bin/launchctl kickstart -k {label} >/dev/null 2>&1 \
         || /bin/launchctl bootstrap system {plist} >/dev/null 2>&1 \
         || true; \
         /bin/sleep 3; \
         status=$({daemon} --status 2>/dev/null || echo '{{\"state\":\"off\"}}'); \
         if printf '%s\\n' \"$status\" \
            | /usr/bin/grep -Eq '\"state\"[[:space:]]*:[[:space:]]*\"(active|dormant)\"'; \
         then write_recovery daemon_recovered; exit 0; fi; \
         /sbin/pfctl -a {anchor} -F rules >/dev/null 2>&1 || true; \
         /sbin/pfctl -a {anchor} -F nat >/dev/null 2>&1 || true; \
         if [ -f {pf_token_path} ]; then \
           pf_token=$(/bin/cat {pf_token_path} 2>/dev/null || true); \
           case \"$pf_token\" in \
             *[!0-9]*|'') ;; \
             *) /sbin/pfctl -X \"$pf_token\" >/dev/null 2>&1 || true ;; \
           esac; \
           /bin/rm -f {pf_token_path}; \
         fi; \
         write_recovery anchor_cleared"
    )
}

/// Install or upgrade the bundled root daemon only when launchd has an explicit
/// enabled state, or after a direct user action such as Restart Proxy. Missing or
/// disabled launchd state is never treated as startup permission.
fn request_daemon_install(app: &AppHandle, allow_disabled: bool) -> bool {
    let Some(bin) = bundled_daemon_path(app) else {
        return false;
    };
    if !bin.exists() {
        return false; // dev build without the bundled daemon
    }
    if !valid_bundled_daemon(&bin) {
        eprintln!(
            "Slipstream bundled daemon is not a valid executable: {}",
            bin.display()
        );
        return false;
    }
    let disabled = daemon_label_disabled();
    if should_request_daemon_install(daemon_needs_install(&bin), disabled, allow_disabled) {
        let bin = bin.to_string_lossy();
        run_admin(
            &format!("{} --install", shell_quote(bin.as_ref())),
            "Slipstream needs administrator access to install its background daemon.",
        );
        return true;
    }
    false
}

fn should_request_daemon_install(
    needs_install: bool,
    disabled: Option<bool>,
    user_initiated: bool,
) -> bool {
    // Missing and disabled state are durable stop intent for automatic paths.
    // A direct user action may restore either state.
    (user_initiated || disabled == Some(false)) && (needs_install || disabled != Some(false))
}

fn ensure_daemon_installed(app: &AppHandle) {
    let _ = request_daemon_install(app, false);
}

fn app_bundle_for_bundled_daemon(bundled: &Path) -> Option<PathBuf> {
    let resources = bundled.parent()?.parent()?;
    if resources.file_name() != Some(OsStr::new("Resources")) {
        return None;
    }
    let contents = resources.parent()?;
    if contents.file_name() != Some(OsStr::new("Contents")) {
        return None;
    }
    let bundle = contents.parent()?;
    (bundle.extension() == Some(OsStr::new("app"))).then(|| bundle.to_path_buf())
}

fn uninstall_shell_for_paths(
    installed: &Path,
    bundled: &Path,
    app_bundle: &Path,
    tray_pid: u32,
) -> String {
    let installed = shell_quote(&installed.to_string_lossy());
    let bundled = shell_quote(&bundled.to_string_lossy());
    let staged_bundle = PathBuf::from(format!(
        "{}.removing-{tray_pid}",
        app_bundle.to_string_lossy()
    ));
    let ready = uninstall_ready_path(tray_pid);
    let app_bundle = shell_quote(&app_bundle.to_string_lossy());
    let staged_bundle = shell_quote(&staged_bundle.to_string_lossy());
    let ready = shell_quote(&ready.to_string_lossy());
    let remove_app = format!(
        "pid={tray_pid}; original={app_bundle}; staged={staged_bundle}; ready={ready}; i=0; \
         while [ ! -f \"$ready\" ] && [ \"$i\" -lt 600 ]; do /bin/sleep 0.1; i=$((i + 1)); done; \
         [ -f \"$ready\" ] || exit 0; /bin/rm -f -- \"$ready\"; \
         bundle_id=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' \
         \"$original/Contents/Info.plist\" 2>/dev/null || true); \
         [ \"$bundle_id\" = 'dev.slipstream.tray' ] || exit 1; \
         [ ! -e \"$staged\" ] && [ ! -L \"$staged\" ] || exit 1; \
         /bin/mv \"$original\" \"$staged\" || exit 1; i=0; \
         process_is_owned() {{ command=$(/bin/ps -p \"$pid\" -o command= 2>/dev/null || true); \
         case \"$command\" in \"$original\"/Contents/MacOS/*|\"$staged\"/Contents/MacOS/*) return 0;; *) return 1;; esac; }}; \
         while process_is_owned && [ \"$i\" -lt 300 ]; do /bin/sleep 0.1; i=$((i + 1)); done; \
         if process_is_owned; then /bin/kill -TERM \"$pid\" 2>/dev/null || true; fi; \
         i=0; while process_is_owned && [ \"$i\" -lt 20 ]; do /bin/sleep 0.1; i=$((i + 1)); done; \
         if process_is_owned; then /bin/kill -KILL \"$pid\" 2>/dev/null || true; fi; \
         /bin/rm -rf -- \"$staged\""
    );
    let remove_app = shell_quote(&remove_app);
    format!(
        "if [ -x {installed} ] && {installed} --uninstall; then cleaned=1; \
         elif [ -x {bundled} ] && {bundled} --uninstall; then cleaned=1; \
         else exit 1; fi; \
         [ \"$cleaned\" = 1 ] || exit 1; \
         bundle_id=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' \
         {app_bundle}/Contents/Info.plist 2>/dev/null || true); \
         [ \"$bundle_id\" = 'dev.slipstream.tray' ] || exit 1; \
         [ ! -e {staged_bundle} ] && [ ! -L {staged_bundle} ] || exit 1; \
         [ ! -e {ready} ] && [ ! -L {ready} ] || exit 1; \
         /usr/bin/nohup /bin/sh -c {remove_app} </dev/null >/dev/null 2>&1 &"
    )
}

fn uninstall_ready_path(tray_pid: u32) -> PathBuf {
    std::env::temp_dir().join(format!("slipstream-uninstall-{tray_pid}.ready"))
}

fn signal_uninstall_ready(tray_pid: u32) -> bool {
    let path = uninstall_ready_path(tray_pid);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let tmp = path.with_extension(format!("ready.tmp-{}-{nonce}", std::process::id()));
    let Ok(mut file) = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)
    else {
        return false;
    };
    let result = (|| -> std::io::Result<()> {
        file.write_all(b"ready\n")?;
        file.sync_all()?;
        set_mode(&tmp, 0o600)?;
        fs::hard_link(&tmp, &path)
    })();
    let _ = fs::remove_file(&tmp);
    if result.is_err() {
        return false;
    }
    true
}

fn uninstall_shell(app: &AppHandle) -> Option<String> {
    let bundled = bundled_daemon_path(app)?;
    if !valid_bundled_daemon(&bundled) {
        return None;
    }
    let app_bundle = app_bundle_for_bundled_daemon(&bundled)?;
    Some(uninstall_shell_for_paths(
        Path::new(INSTALLED_DAEMON),
        &bundled,
        &app_bundle,
        std::process::id(),
    ))
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

fn uninstall_dialog_script_for(ru: bool) -> String {
    let (msg, keep, remove) = if ru {
        (
            "Будут удалены Slipstream, его фоновая служба, встроенный Geph и ключ аккаунта.",
            "Отмена",
            "Удалить",
        )
    } else {
        (
            "This removes Slipstream, its background service, bundled Geph, and account key.",
            "Cancel",
            "Uninstall",
        )
    };
    format!(
        "display dialog \"{msg}\" with title \"Slipstream\" buttons {{\"{keep}\", \"{remove}\"}} default button \"{keep}\" cancel button \"{keep}\" with icon caution"
    )
}

fn prompt_uninstall() -> bool {
    let script = uninstall_dialog_script_for(ui_ru());
    let Ok(out) = osascript_dialog(&script).output() else {
        return false;
    };
    if !out.status.success() {
        return false;
    }
    let expected = if ui_ru() {
        "Удалить"
    } else {
        "Uninstall"
    };
    String::from_utf8_lossy(&out.stdout).contains(&format!("button returned:{expected}"))
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
    for (name, item) in routes {
        if name == "generic" {
            continue;
        }
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

    match (local_failed, geph_failed) {
        (true, true) => Some(if ru {
            "Восстанавливается доступ к сервисам".to_string()
        } else {
            "Restoring service access".to_string()
        }),
        (true, false) => Some(if ru {
            "Восстанавливается локальный доступ".to_string()
        } else {
            "Restoring local access".to_string()
        }),
        (false, true) => Some(if ru {
            "Восстанавливается доступ к внешним сервисам".to_string()
        } else {
            "Restoring access to external services".to_string()
        }),
        (false, false) => None,
    }
}

fn daemon_state_text(state: &str, conns: i64, learned: i64, ru: bool) -> (String, String) {
    match state {
        "active" => {
            let detail = if ru {
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
                detail,
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
        "conflict" => (
            (if ru {
                "Slipstream — приостановлен"
            } else {
                "Slipstream — Paused"
            })
            .to_string(),
            (if ru {
                "Активен другой фильтр трафика"
            } else {
                "Another traffic filter is active"
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
    let (title, mut detail) = daemon_state_text(&state, conns, learned, ru);
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
        let name = if matches!(state, "off" | "conflict") {
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

type ExitCatalog = Vec<(String, String, String)>;

#[derive(Debug, PartialEq, Eq)]
enum ExitCatalogAvailability {
    Available(ExitCatalog),
    Unavailable,
}

struct ExitMenuItems {
    choices: Vec<(String, CheckMenuItem<tauri::Wry>)>,
    dynamic: Vec<MenuItemKind<tauri::Wry>>,
}

#[derive(Default)]
struct ExitMenuRefreshState {
    running: bool,
    pending: bool,
}

fn begin_exit_menu_refresh(state: &Mutex<ExitMenuRefreshState>) -> bool {
    let mut state = state.lock().expect("exit refresh state lock poisoned");
    if state.running {
        state.pending = true;
        return false;
    }
    state.running = true;
    state.pending = false;
    true
}

fn finish_exit_menu_refresh(state: &Mutex<ExitMenuRefreshState>, succeeded: bool) -> bool {
    let mut state = state.lock().expect("exit refresh state lock poisoned");
    if succeeded {
        state.running = false;
        state.pending = false;
        return false;
    }
    if state.pending {
        state.pending = false;
        return true;
    }
    state.running = false;
    false
}

fn cached_exit_catalog(cache_path: Option<&Path>) -> Option<ExitCatalog> {
    let path = cache_path?;
    let raw = fs::read_to_string(path).ok()?;
    let catalog = serde_json::from_str::<ExitCatalog>(&raw).ok()?;
    (!catalog.is_empty()).then_some(catalog)
}

fn cache_exit_catalog(cache_path: Option<&Path>, catalog: &ExitCatalog) {
    let Some(path) = cache_path else {
        return;
    };
    if let Ok(json) = serde_json::to_string(catalog) {
        let _ = write_private_atomic(path, json.as_bytes());
    }
}

fn exit_catalog_availability(catalog: Option<ExitCatalog>) -> ExitCatalogAvailability {
    match catalog.filter(|catalog| !catalog.is_empty()) {
        Some(catalog) => ExitCatalogAvailability::Available(catalog),
        None => ExitCatalogAvailability::Unavailable,
    }
}

/// Exit catalog for the tray menu. A known-good cached city list wins over a
/// potentially slow control RPC, so a tray relaunch stays responsive. Until a
/// live city catalog exists, the menu exposes an explicit unavailable state
/// rather than inventing selectable country-level exits.
fn exit_catalog(cache_path: Option<std::path::PathBuf>) -> ExitCatalogAvailability {
    if let Some(cached) = cached_exit_catalog(cache_path.as_deref()) {
        return exit_catalog_availability(Some(cached));
    }
    let live = geph_net_status_catalog();
    if let Some(catalog) = live.as_ref() {
        cache_exit_catalog(cache_path.as_deref(), catalog);
    }
    exit_catalog_availability(live)
}

fn refresh_exit_menu(
    app: AppHandle<tauri::Wry>,
    cache_path: Option<PathBuf>,
    geph_menu: Submenu<tauri::Wry>,
    exit_items: Arc<Mutex<ExitMenuItems>>,
    refresh_state: Arc<Mutex<ExitMenuRefreshState>>,
) {
    if !begin_exit_menu_refresh(&refresh_state) {
        return;
    }
    std::thread::spawn(move || loop {
        for _ in 0..20 {
            std::thread::sleep(Duration::from_secs(2));
            if let Some(live) = geph_net_status_catalog() {
                cache_exit_catalog(cache_path.as_deref(), &live);
                let selected = geph_field(&app, "exit").unwrap_or_else(|| "auto".into());
                let ui_app = app.clone();
                let catalog = ExitCatalogAvailability::Available(live);
                let _ = app.run_on_main_thread(move || {
                    if let Err(error) = replace_exit_menu_items(
                        &ui_app,
                        &geph_menu,
                        &exit_items,
                        &selected,
                        &catalog,
                    ) {
                        eprintln!("geph exit menu refresh unavailable: {error}");
                    }
                });
                finish_exit_menu_refresh(&refresh_state, true);
                return;
            }
        }
        if !finish_exit_menu_refresh(&refresh_state, false) {
            return;
        }
    });
}

fn replace_exit_menu_items(
    app: &AppHandle<tauri::Wry>,
    geph_menu: &Submenu<tauri::Wry>,
    exit_items: &Arc<Mutex<ExitMenuItems>>,
    selected: &str,
    catalog: &ExitCatalogAvailability,
) -> tauri::Result<()> {
    let mut items = exit_items.lock().expect("exit menu lock poisoned");
    for item in items.dynamic.drain(..) {
        geph_menu.remove(&item)?;
    }
    items.choices.retain(|(value, _)| value == "auto");

    let catalog = match catalog {
        ExitCatalogAvailability::Available(catalog) => catalog,
        ExitCatalogAvailability::Unavailable => {
            let separator = PredefinedMenuItem::separator(app)?;
            geph_menu.append(&separator)?;
            items.dynamic.push(MenuItemKind::Predefined(separator));
            let unavailable =
                MenuItemBuilder::with_id("exit_locations_unavailable", tr("Locations unavailable"))
                    .enabled(false)
                    .build(app)?;
            geph_menu.append(&unavailable)?;
            items.dynamic.push(MenuItemKind::MenuItem(unavailable));
            return Ok(());
        }
    };

    let mut categories: Vec<String> = catalog
        .iter()
        .map(|(_, _, category)| category.clone())
        .collect();
    categories.sort();
    categories.dedup();
    categories.sort_by_key(|category| match category.as_str() {
        "core" => (0u8, String::new()),
        "streaming" => (1u8, String::new()),
        other => (2u8, other.to_string()),
    });

    for category in categories {
        let separator = PredefinedMenuItem::separator(app)?;
        geph_menu.append(&separator)?;
        items.dynamic.push(MenuItemKind::Predefined(separator));

        let title = match category.as_str() {
            "core" => tr("Core"),
            "streaming" => tr("Streaming"),
            other => {
                let mut chars = other.chars();
                match chars.next() {
                    Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                    None => other.to_string(),
                }
            }
        };
        let header = MenuItemBuilder::with_id(format!("hdr_{category}"), title)
            .enabled(false)
            .build(app)?;
        geph_menu.append(&header)?;
        items.dynamic.push(MenuItemKind::MenuItem(header));

        for (value, label, entry_category) in catalog {
            if entry_category != &category {
                continue;
            }
            let item = CheckMenuItemBuilder::with_id(format!("exit:{value}"), label)
                .checked(value == selected)
                .build(app)?;
            geph_menu.append(&item)?;
            items.choices.push((value.clone(), item.clone()));
            items.dynamic.push(MenuItemKind::Check(item));
        }
    }
    Ok(())
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct GephLaunchAgentPaths {
    config_dir: PathBuf,
    runtime_dir: PathBuf,
    executable: PathBuf,
    launcher: PathBuf,
    config: PathBuf,
    cache: PathBuf,
    ownership: PathBuf,
    stdout_log: PathBuf,
    stderr_log: PathBuf,
    plist: PathBuf,
}

fn geph_launch_agent_paths(config_dir: &Path, home: &Path) -> GephLaunchAgentPaths {
    let runtime_dir = config_dir.join(GEPH_RUNTIME_DIR);
    GephLaunchAgentPaths {
        config_dir: config_dir.to_path_buf(),
        executable: runtime_dir.join(GEPH_RUNTIME_BIN),
        launcher: runtime_dir.join(GEPH_LAUNCHER_FILE),
        runtime_dir,
        config: config_dir.join("geph-active.yaml"),
        cache: config_dir.join("geph-cache.db"),
        ownership: config_dir.join(GEPH_OWNERSHIP_FILE),
        stdout_log: config_dir.join(GEPH_STDOUT_LOG_FILE),
        stderr_log: config_dir.join(GEPH_STDERR_LOG_FILE),
        plist: home
            .join("Library")
            .join("LaunchAgents")
            .join(GEPH_LAUNCH_AGENT_PLIST),
    }
}

fn geph_log_archive_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(GEPH_LOG_ARCHIVE_SUFFIX);
    PathBuf::from(name)
}

fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions)
}

fn harden_geph_dir(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    set_mode(dir, 0o700)?;
    let runtime_dir = dir.join(GEPH_RUNTIME_DIR);
    if runtime_dir.exists() {
        set_mode(&runtime_dir, 0o700)?;
    }
    for name in [
        "geph-active.yaml",
        "geph-cache.db",
        "geph-cache.db-shm",
        "geph-cache.db-wal",
        "geph-exits.json",
        "geph.json",
        GEPH_OWNERSHIP_FILE,
        GEPH_STDOUT_LOG_FILE,
        GEPH_STDERR_LOG_FILE,
        "geph.stdout.log.previous",
        "geph.stderr.log.previous",
    ] {
        let path = dir.join(name);
        if path.exists() {
            set_mode(&path, 0o600)?;
        }
    }
    for name in [GEPH_RUNTIME_BIN, GEPH_LAUNCHER_FILE] {
        let path = runtime_dir.join(name);
        if path.exists() {
            set_mode(&path, 0o700)?;
        }
    }
    Ok(())
}

fn ensure_private_append_file(path: &Path) -> std::io::Result<()> {
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    set_mode(path, 0o600)
}

fn write_atomic_mode(path: &Path, content: &[u8], mode: u32) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("atomic file has no parent"))?;
    fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("private"),
        std::process::id()
    ));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(mode)
            .open(&tmp)?;
        file.write_all(content)?;
        file.sync_all()?;
        set_mode(&tmp, mode)?;
        fs::rename(&tmp, path)?;
        set_mode(path, mode)
    })();
    let _ = fs::remove_file(&tmp);
    result
}

fn write_private_atomic(path: &Path, content: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("private file has no parent"))?;
    harden_geph_dir(parent)?;
    write_atomic_mode(path, content, 0o600)
}

fn write_private_if_changed(path: &Path, content: &[u8]) -> std::io::Result<bool> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("private file has no parent"))?;
    harden_geph_dir(parent)?;
    write_atomic_if_changed(path, content, 0o600)
}

fn write_atomic_if_changed(path: &Path, content: &[u8], mode: u32) -> std::io::Result<bool> {
    if fs::read(path).ok().as_deref() == Some(content) {
        set_mode(path, mode)?;
        return Ok(false);
    }
    write_atomic_mode(path, content, mode)?;
    Ok(true)
}

fn files_equal(left: &Path, right: &Path) -> bool {
    let Ok(left_meta) = fs::metadata(left) else {
        return false;
    };
    let Ok(right_meta) = fs::metadata(right) else {
        return false;
    };
    if left_meta.len() != right_meta.len() {
        return false;
    }
    let (Ok(mut left), Ok(mut right)) = (fs::File::open(left), fs::File::open(right)) else {
        return false;
    };
    let mut left_buf = [0u8; 64 * 1024];
    let mut right_buf = [0u8; 64 * 1024];
    loop {
        let Ok(left_read) = left.read(&mut left_buf) else {
            return false;
        };
        let Ok(right_read) = right.read(&mut right_buf) else {
            return false;
        };
        if left_read != right_read || left_buf[..left_read] != right_buf[..right_read] {
            return false;
        }
        if left_read == 0 {
            return true;
        }
    }
}

fn sync_private_executable(source: &Path, target: &Path) -> std::io::Result<bool> {
    let parent = target
        .parent()
        .ok_or_else(|| std::io::Error::other("runtime executable has no parent"))?;
    fs::create_dir_all(parent)?;
    set_mode(parent, 0o700)?;
    if files_equal(source, target) {
        set_mode(target, 0o700)?;
        return Ok(false);
    }
    let tmp = parent.join(format!(".{GEPH_RUNTIME_BIN}.tmp-{}", std::process::id()));
    let result = (|| {
        fs::copy(source, &tmp)?;
        set_mode(&tmp, 0o700)?;
        fs::rename(&tmp, target)?;
        set_mode(target, 0o700)
    })();
    let _ = fs::remove_file(&tmp);
    result.map(|_| true)
}

fn geph_ownership_path(dir: &Path) -> PathBuf {
    dir.join(GEPH_OWNERSHIP_FILE)
}

fn read_geph_ownership(dir: &Path) -> Option<Value> {
    let raw = fs::read(geph_ownership_path(dir)).ok()?;
    serde_json::from_slice(&raw).ok()
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn geph_launcher_script(paths: &GephLaunchAgentPaths) -> String {
    geph_launcher_script_with_log_limits(
        paths,
        GEPH_LOG_MAX_BYTES,
        GEPH_LOG_RETAIN_BYTES,
        GEPH_LOG_GUARD_INTERVAL_SECS,
        GEPH_SOCKS_PORT,
    )
}

fn geph_launcher_script_with_log_limits(
    paths: &GephLaunchAgentPaths,
    log_max_bytes: u64,
    log_retain_bytes: u64,
    log_guard_interval: u64,
    socks_port: u16,
) -> String {
    let executable = paths.executable.to_string_lossy().into_owned();
    let config = paths.config.to_string_lossy().into_owned();
    let ownership = paths.ownership.to_string_lossy().into_owned();
    let stdout_log = paths.stdout_log.to_string_lossy().into_owned();
    let stderr_log = paths.stderr_log.to_string_lossy().into_owned();
    let executable_json = serde_json::to_string(&executable).unwrap_or_else(|_| "\"\"".into());
    let config_json = serde_json::to_string(&config).unwrap_or_else(|_| "\"\"".into());
    let label_json = serde_json::to_string(GEPH_LAUNCHD_LABEL).unwrap_or_else(|_| "\"\"".into());
    format!(
        "#!/bin/sh\n\
         set -eu\n\
         umask 077\n\
         executable={}\n\
         config={}\n\
         ownership={}\n\
         stdout_log={}\n\
         stderr_log={}\n\
         log_max_bytes={log_max_bytes}\n\
         log_retain_bytes={log_retain_bytes}\n\
         log_guard_interval={log_guard_interval}\n\
         compact_log() {{\n\
         \x20 path=\"$1\"\n\
         \x20 [ -f \"$path\" ] || return 0\n\
         \x20 [ ! -L \"$path\" ] || return 0\n\
         \x20 size=$(/usr/bin/stat -f %z \"$path\" 2>/dev/null || /usr/bin/printf 0)\n\
         \x20 case \"$size\" in ''|*[!0-9]*) return 0 ;; esac\n\
         \x20 [ \"$size\" -le \"$log_max_bytes\" ] && return 0\n\
         \x20 archive=\"${{path}}{GEPH_LOG_ARCHIVE_SUFFIX}\"\n\
         \x20 tmp=\"${{archive}}.tmp.$$\"\n\
         \x20 if /usr/bin/tail -c \"$log_retain_bytes\" \"$path\" > \"$tmp\" 2>/dev/null; then\n\
         \x20\x20 /bin/chmod 600 \"$tmp\" 2>/dev/null || true\n\
         \x20\x20 /bin/mv -f \"$tmp\" \"$archive\" 2>/dev/null || true\n\
         \x20\x20 : > \"$path\"\n\
         \x20\x20 /bin/chmod 600 \"$path\" 2>/dev/null || true\n\
         \x20 fi\n\
         \x20 /bin/rm -f \"$tmp\" 2>/dev/null || true\n\
         \x20 return 0\n\
         }}\n\
         uid=$(/usr/bin/id -u)\n\
         /bin/rm -f \"$ownership\"\n\
         while /usr/bin/nc -z -w 1 127.0.0.1 {socks_port} >/dev/null 2>&1; do\n\
         \x20 /bin/sleep 5\n\
         done\n\
         tmp=\"${{ownership}}.tmp.$$\"\n\
         /usr/bin/printf '{{\"pid\":%s,\"uid\":%s,\"executable\":%s,\"config\":%s,\"launchd_label\":%s}}\\n' \"$$\" \"$uid\" {} {} {} > \"$tmp\"\n\
         /bin/chmod 600 \"$tmp\"\n\
         /bin/mv -f \"$tmp\" \"$ownership\"\n\
         compact_log \"$stdout_log\"\n\
         compact_log \"$stderr_log\"\n\
         target_pid=$$\n\
         (\n\
         \x20 while /bin/kill -0 \"$target_pid\" 2>/dev/null; do\n\
         \x20\x20 /bin/sleep \"$log_guard_interval\"\n\
         \x20\x20 /bin/kill -0 \"$target_pid\" 2>/dev/null || exit 0\n\
         \x20\x20 compact_log \"$stdout_log\"\n\
         \x20\x20 compact_log \"$stderr_log\"\n\
         \x20 done\n\
         ) </dev/null >/dev/null 2>&1 &\n\
         exec \"$executable\" --config \"$config\" >> \"$stdout_log\" 2>> \"$stderr_log\"\n",
        shell_quote(&executable),
        shell_quote(&config),
        shell_quote(&ownership),
        shell_quote(&stdout_log),
        shell_quote(&stderr_log),
        shell_quote(&executable_json),
        shell_quote(&config_json),
        shell_quote(&label_json),
    )
}

fn geph_launch_agent_plist(paths: &GephLaunchAgentPaths) -> String {
    let launcher = xml_escape(&paths.launcher.to_string_lossy());
    let workdir = xml_escape(&paths.config_dir.to_string_lossy());
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\"><dict>\n\
         <key>Label</key><string>{GEPH_LAUNCHD_LABEL}</string>\n\
         <key>ProgramArguments</key><array><string>{launcher}</string></array>\n\
         <key>RunAtLoad</key><true/>\n\
         <key>KeepAlive</key><true/>\n\
         <key>ThrottleInterval</key><integer>10</integer>\n\
         <key>ProcessType</key><string>Background</string>\n\
         <key>WorkingDirectory</key><string>{workdir}</string>\n\
         <key>StandardOutPath</key><string>/dev/null</string>\n\
         <key>StandardErrorPath</key><string>/dev/null</string>\n\
         </dict></plist>\n"
    )
}

fn geph_launch_domain(uid: &str) -> String {
    format!("gui/{uid}")
}

fn geph_launch_target(uid: &str) -> String {
    format!("{}/{GEPH_LAUNCHD_LABEL}", geph_launch_domain(uid))
}

fn geph_launch_agent_loaded(uid: &str) -> bool {
    Command::new("/bin/launchctl")
        .args(["print", &geph_launch_target(uid)])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Diagnostics may report the app-owned launch job, but never infer PF state
/// without privileged evidence and never expose PID, config path, or secrets.
fn geph_lifecycle_diagnostic_value(
    daemon_installed: bool,
    daemon_status_present: bool,
    launch_agent_loaded: bool,
) -> Value {
    let root_daemon = if daemon_status_present {
        "running"
    } else if daemon_installed {
        "installed"
    } else {
        "absent"
    };
    let state = if !daemon_installed && !daemon_status_present && launch_agent_loaded {
        "sidecar_only"
    } else if launch_agent_loaded {
        "managed"
    } else {
        "off"
    };
    json!({
        "state": state,
        "root_daemon": root_daemon,
        "owned_launch_agent": if launch_agent_loaded { "loaded" } else { "absent" },
    })
}

fn geph_launch_agent_bootout(uid: &str, plist: &Path) -> bool {
    let _ = Command::new("/bin/launchctl")
        .args(["bootout", &geph_launch_target(uid)])
        .output();
    if geph_launch_agent_loaded(uid) {
        let _ = Command::new("/bin/launchctl")
            .arg("bootout")
            .arg(geph_launch_domain(uid))
            .arg(plist)
            .output();
    }
    for _ in 0..20 {
        if !geph_launch_agent_loaded(uid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn geph_launch_agent_bootstrap(uid: &str, plist: &Path) -> bool {
    Command::new("/bin/launchctl")
        .arg("bootstrap")
        .arg(geph_launch_domain(uid))
        .arg(plist)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn geph_launch_agent_kickstart(uid: &str) -> bool {
    Command::new("/bin/launchctl")
        .args(["kickstart", "-k", &geph_launch_target(uid)])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn geph_process_command(pid: u32) -> Option<String> {
    let output = Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|command| !command.is_empty())
}

fn command_matches_geph(command: &str, executable: &Path, config: &Path) -> bool {
    let executable = executable.to_string_lossy();
    let config = config.to_string_lossy();
    command.trim() == format!("{executable} --config {config}")
}

fn geph_listener_pid() -> Option<u32> {
    let output = Command::new("/usr/sbin/lsof")
        .args([
            "-nP",
            &format!("-iTCP:{GEPH_SOCKS_PORT}"),
            "-sTCP:LISTEN",
            "-t",
        ])
        .output()
        .ok()?;
    output.status.success().then(|| {
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()?
            .trim()
            .parse()
            .ok()
    })?
}

/// Stop only a process whose PID, executable, config, and listener all match the
/// private ownership record. Unknown listeners are external state.
fn geph_kill_owned(dir: &Path) {
    let Some(state) = read_geph_ownership(dir) else {
        let _ = fs::remove_file(geph_ownership_path(dir));
        return;
    };
    let Some(pid) = state
        .get("pid")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
    else {
        let _ = fs::remove_file(geph_ownership_path(dir));
        return;
    };
    let executable = state
        .get("executable")
        .and_then(Value::as_str)
        .map(PathBuf::from);
    let config = state
        .get("config")
        .and_then(Value::as_str)
        .map(PathBuf::from);
    let initially_owned =
        executable
            .as_deref()
            .zip(config.as_deref())
            .is_some_and(|(executable, config)| {
                geph_listener_pid() == Some(pid)
                    && geph_process_command(pid)
                        .is_some_and(|command| command_matches_geph(&command, executable, config))
            });
    if !initially_owned {
        let _ = fs::remove_file(geph_ownership_path(dir));
        return;
    }
    let pid_string = pid.to_string();
    let _ = Command::new("/bin/kill")
        .args(["-TERM", &pid_string])
        .status();
    for _ in 0..20 {
        if Command::new("/bin/kill")
            .args(["-0", &pid_string])
            .status()
            .map(|status| !status.success())
            .unwrap_or(true)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if let (Some(executable), Some(config), Some(command)) = (
        executable.as_deref(),
        config.as_deref(),
        geph_process_command(pid),
    ) {
        // Revalidate immediately before SIGKILL so a rapidly recycled PID can
        // never turn an owned-process shutdown into a broad process kill.
        if geph_listener_pid() == Some(pid) && command_matches_geph(&command, executable, config) {
            let _ = Command::new("/bin/kill")
                .args(["-KILL", &pid_string])
                .status();
        }
    }
    let _ = fs::remove_file(geph_ownership_path(dir));
}

fn geph_launch_agent_paths_for_app(app: &AppHandle) -> Result<GephLaunchAgentPaths, String> {
    let config_dir = app
        .path()
        .app_config_dir()
        .map_err(|error| format!("geph config directory unavailable: {error}"))?;
    let home = app
        .path()
        .home_dir()
        .map_err(|error| format!("home directory unavailable: {error}"))?;
    Ok(geph_launch_agent_paths(&config_dir, &home))
}

fn geph_launch_agent_disable(app: &AppHandle) -> Result<(), String> {
    let paths = geph_launch_agent_paths_for_app(app)?;
    let uid = current_numeric_id("-u").ok_or_else(|| "user id unavailable".to_string())?;
    if !geph_launch_agent_bootout(&uid, &paths.plist) {
        return Err("geph LaunchAgent bootout unavailable".into());
    }
    // One-time migration can leave the old detached process outside launchd.
    // Stop it only through the existing PID/executable/config/listener proof.
    geph_kill_owned(&paths.config_dir);
    let _ = fs::remove_file(&paths.ownership);
    let _ = fs::remove_file(&paths.plist);
    Ok(())
}

fn remove_owned_geph_runtime(config_dir: &Path) -> Result<(), String> {
    if let Err(error) = fs::remove_dir_all(config_dir) {
        if error.kind() != std::io::ErrorKind::NotFound {
            return Err(format!("geph runtime cleanup unavailable: {error}"));
        }
    }
    Ok(())
}

fn geph_launch_agent_uninstall(app: &AppHandle) -> Result<(), String> {
    let paths = geph_launch_agent_paths_for_app(app)?;
    geph_launch_agent_disable(app)?;
    remove_owned_geph_runtime(&paths.config_dir)?;
    keychain_delete();
    Ok(())
}

/// Install or refresh the user LaunchAgent that owns Geph independently of the
/// tray process. Returns false when Geph is intentionally disabled or no account
/// secret has been configured yet.
fn ensure_geph_launch_agent(app: &AppHandle, force_restart: bool) -> Result<bool, String> {
    if !geph_enabled(app) {
        geph_launch_agent_disable(app)?;
        return Ok(false);
    }
    let Some(secret) = geph_secret(app) else {
        // Keep an already-configured job alive if Keychain is temporarily locked.
        return Ok(false);
    };
    let paths = geph_launch_agent_paths_for_app(app)?;
    harden_geph_dir(&paths.config_dir)
        .map_err(|error| format!("geph config permissions unavailable: {error}"))?;
    for log_path in [&paths.stdout_log, &paths.stderr_log] {
        ensure_private_append_file(log_path)
            .map_err(|error| format!("geph log setup unavailable: {error}"))?;
    }
    fs::create_dir_all(&paths.runtime_dir)
        .map_err(|error| format!("geph runtime directory unavailable: {error}"))?;
    set_mode(&paths.runtime_dir, 0o700)
        .map_err(|error| format!("geph runtime permissions unavailable: {error}"))?;

    let source = geph_bin_path().ok_or_else(|| "bundled geph unavailable".to_string())?;
    let binary_changed = sync_private_executable(&source, &paths.executable)
        .map_err(|error| format!("geph runtime sync unavailable: {error}"))?;
    let exit = geph_field(app, "exit").unwrap_or_else(|| "auto".into());
    let desired = geph_config_yaml(&secret, &exit, &paths.cache.to_string_lossy());
    let config_changed = write_private_if_changed(&paths.config, desired.as_bytes())
        .map_err(|error| format!("geph config write unavailable: {error}"))?;
    let launcher = geph_launcher_script(&paths);
    let launcher_changed = write_atomic_if_changed(&paths.launcher, launcher.as_bytes(), 0o700)
        .map_err(|error| format!("geph launcher write unavailable: {error}"))?;
    let plist = geph_launch_agent_plist(&paths);
    let plist_changed = write_atomic_if_changed(&paths.plist, plist.as_bytes(), 0o600)
        .map_err(|error| format!("geph LaunchAgent write unavailable: {error}"))?;

    let uid = current_numeric_id("-u").ok_or_else(|| "user id unavailable".to_string())?;
    let mut loaded = geph_launch_agent_loaded(&uid);
    if loaded && plist_changed {
        if !geph_launch_agent_bootout(&uid, &paths.plist) {
            return Err("geph LaunchAgent reload unavailable".into());
        }
        loaded = false;
    }
    if !loaded {
        // Replace the legacy detached process once, after the stable runtime is
        // ready. Unknown listeners do not match ownership and are never killed;
        // the launcher waits on the occupied port instead.
        geph_kill_owned(&paths.config_dir);
        if !geph_launch_agent_bootstrap(&uid, &paths.plist) && !geph_launch_agent_loaded(&uid) {
            return Err("geph LaunchAgent bootstrap unavailable".into());
        }
    } else if (force_restart || binary_changed || config_changed || launcher_changed)
        && !geph_launch_agent_kickstart(&uid)
    {
        return Err("geph LaunchAgent restart unavailable".into());
    }
    Ok(true)
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
            let saved_exit = geph_field(app.handle(), "exit").unwrap_or_else(|| "auto".into());

            let mk = |app: &tauri::App, val: &str, label: &str| {
                CheckMenuItemBuilder::with_id(format!("exit:{val}"), label)
                    .checked(val == saved_exit)
                    .build(app)
            };
            let auto = mk(app, "auto", &tr("Automatic"))?;
            let exit_items = Arc::new(Mutex::new(ExitMenuItems {
                choices: vec![("auto".into(), auto.clone())],
                dynamic: Vec::new(),
            }));

            let geph_enable = CheckMenuItemBuilder::with_id(ID_GEPH_ENABLE, tr("Enable Geph"))
                .checked(geph_enabled(app.handle()))
                .build(app)?;

            // LIVE country list from geph's control RPC (cached); no hardcoded catalog.
            let exits_cache = app
                .path()
                .app_config_dir()
                .ok()
                .map(|d| d.join("geph-exits.json"));
            let catalog = exit_catalog(exits_cache.clone());
            let exit_refreshing = Arc::new(Mutex::new(ExitMenuRefreshState::default()));

            let geph_menu = SubmenuBuilder::new(app, "Geph")
                .item(
                    &MenuItemBuilder::with_id(ID_ACCOUNT, tr("Account…"))
                        .accelerator("CmdOrCtrl+,")
                        .build(app)?,
                )
                .item(&geph_enable)
                .separator()
                .item(&auto)
                .build()?;
            replace_exit_menu_items(
                app.handle(),
                &geph_menu,
                &exit_items,
                &saved_exit,
                &catalog,
            )?;

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
                .item(&MenuItemBuilder::with_id(ID_LOG, tr("Open Status")).build(app)?)
                .item(&MenuItemBuilder::with_id(ID_DIAGNOSTICS, tr("Copy Diagnostics")).build(app)?)
                .separator()
                .item(&MenuItemBuilder::with_id(ID_UPDATE, tr("Check for Updates…")).build(app)?)
                .item(
                    &MenuItemBuilder::with_id("version", version_label)
                        .enabled(false)
                        .build(app)?,
                )
                .separator()
                .item(
                    &MenuItemBuilder::with_id(ID_UNINSTALL, tr("Uninstall Slipstream…"))
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
            let exit_items_menu = exit_items.clone();
            let exits_cache_menu = exits_cache.clone();
            let geph_menu_events = geph_menu.clone();
            let exit_refreshing_menu = exit_refreshing.clone();
            let _tray = TrayIconBuilder::with_id("main")
                .icon(icon)
                .icon_as_template(true)
                .menu(&menu)
                .on_menu_event(move |app, event| {
                    let id = event.id().as_ref();
                    if let Some(val) = id.strip_prefix("exit:") {
                        {
                            let items = exit_items_menu.lock().expect("exit menu lock poisoned");
                            for (value, item) in &items.choices {
                                let _ = item.set_checked(value == val);
                            }
                        }
                        geph_config_set(app, "exit", val);
                        if let Err(error) = ensure_geph_launch_agent(app, true) {
                            eprintln!("geph exit update unavailable: {error}");
                        }
                        return;
                    }
                    match id {
                        ID_ACCOUNT => {
                            let cur = geph_secret(app).unwrap_or_default();
                            if let Some(secret) = prompt_secret(&cur) {
                                if !keychain_set(&secret) {
                                    eprintln!(
                                        "geph account update unavailable: Keychain write failed"
                                    );
                                    notify(app, &tr("Unable to save Geph account"));
                                    return;
                                }
                                match ensure_geph_launch_agent(app, true) {
                                    Ok(true) => refresh_exit_menu(
                                        app.clone(),
                                        exits_cache_menu.clone(),
                                        geph_menu_events.clone(),
                                        exit_items_menu.clone(),
                                        exit_refreshing_menu.clone(),
                                    ),
                                    Ok(false) => {}
                                    Err(error) => {
                                        eprintln!("geph account update unavailable: {error}");
                                    }
                                }
                            }
                        }
                        ID_GEPH_ENABLE => {
                            let new_on = !geph_enabled(app);
                            geph_config_set(app, "enabled", if new_on { "1" } else { "0" });
                            let _ = enable_h.set_checked(new_on);
                            if new_on {
                                match ensure_geph_launch_agent(app, false) {
                                    Ok(true) => refresh_exit_menu(
                                        app.clone(),
                                        exits_cache_menu.clone(),
                                        geph_menu_events.clone(),
                                        exit_items_menu.clone(),
                                        exit_refreshing_menu.clone(),
                                    ),
                                    Ok(false) => {}
                                    Err(error) => {
                                        eprintln!("geph enable unavailable: {error}");
                                    }
                                }
                            } else {
                                // Boot out only Slipstream's user LaunchAgent and
                                // clean up any verified legacy detached process.
                                if let Err(error) = geph_launch_agent_disable(app) {
                                    eprintln!("geph disable unavailable: {error}");
                                }
                            }
                        }
                        ID_LAUNCH => {
                            let mgr = app.autolaunch();
                            let enabled = mgr.is_enabled().unwrap_or(false);
                            let _ = if enabled { mgr.disable() } else { mgr.enable() };
                            let _ = launch_h.set_checked(!enabled); // reflect the real new state
                        }
                        ID_RESTART => {
                            tg_offer_reset_menu.fetch_add(1, Ordering::Relaxed);
                            if geph_enabled(app) {
                                refresh_exit_menu(
                                    app.clone(),
                                    exits_cache_menu.clone(),
                                    geph_menu_events.clone(),
                                    exit_items_menu.clone(),
                                    exit_refreshing_menu.clone(),
                                );
                            }
                            if !request_daemon_install(app, true) {
                                run_admin(
                                    &format!("launchctl kickstart -k system/{LAUNCHD_LABEL}"),
                                    "Slipstream needs administrator access to restart its background daemon.",
                                );
                            }
                        }
                        ID_LOG => {
                            if !open_status_snapshot(app) {
                                notify(app, "Unable to open Slipstream status");
                            }
                        }
                        ID_DIAGNOSTICS => {
                            if copy_diagnostic_snapshot(app) {
                                notify(app, "Slipstream diagnostics copied and saved");
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
                        ID_UNINSTALL => {
                            if !prompt_uninstall() {
                                return;
                            }
                            let Some(uninstall) = uninstall_shell(app) else {
                                notify(app, "Unable to locate Slipstream uninstaller");
                                return;
                            };
                            if let Err(error) = app.autolaunch().disable() {
                                eprintln!("autostart uninstall cleanup unavailable: {error}");
                                notify(app, "Unable to disable Slipstream launch at login");
                                return;
                            }
                            if !run_admin_status(
                                &uninstall,
                                "Slipstream needs administrator access to remove its background service and application.",
                            ) {
                                notify(
                                    app,
                                    "Unable to remove Slipstream background service",
                                );
                                return;
                            }
                            // The daemon clears PF and drains accepted streams while
                            // its geo-exit backend is still alive. Stopping Geph first
                            // would tear down active ChatGPT/OpenAI connections while
                            // new TCP attempts were still being intercepted.
                            if let Err(error) = geph_launch_agent_uninstall(app) {
                                eprintln!("geph uninstall cleanup unavailable: {error}");
                                notify(app, "Unable to stop bundled Geph; uninstall incomplete");
                                return;
                            }
                            geph_config_set(app, "enabled", "0");
                            if !signal_uninstall_ready(std::process::id()) {
                                notify(app, "Unable to remove Slipstream application");
                                return;
                            }
                            notify(app, "Slipstream uninstalled");
                            app.exit(0);
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
                let mut has_seen_daemon_status = false;
                let watchdog_started = Instant::now();
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
                        has_seen_daemon_status = true;
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
                        has_seen_daemon_status,
                        now.duration_since(watchdog_started)
                            >= Duration::from_secs(DAEMON_WATCHDOG_STARTUP_GRACE_SECS),
                        now >= next_daemon_recovery,
                        daemon_installed_for_watchdog(&app_handle),
                    ) {
                        next_daemon_recovery =
                            now + Duration::from_secs(DAEMON_WATCHDOG_COOLDOWN_SECS);
                        run_admin(
                            &daemon_recovery_shell(),
                            "Slipstream needs administrator access to repair its background daemon.",
                        );
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

            // Geph belongs to a user LaunchAgent, not this tray process. The first
            // call migrates the old detached sidecar to a stable private runtime;
            // later calls only sync changed app/config artifacts.
            if let Err(error) = ensure_geph_launch_agent(app.handle(), false) {
                eprintln!("geph LaunchAgent setup unavailable: {error}");
            }
            // A fresh install may not have Geph's city catalog yet. Once its control
            // RPC is ready, replace the explicit unavailable state in this live menu.
            refresh_exit_menu(
                app.handle().clone(),
                exits_cache,
                geph_menu.clone(),
                exit_items.clone(),
                exit_refreshing,
            );

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building Slipstream tray");

    // No windows -> keep the app alive on the tray. We do not stop Geph on exit:
    // its user LaunchAgent remains responsible for the tunnel and crash recovery.
    // The routing daemon also outlives the tray, so a running tunnel after quit is
    // consistent. To actually stop Geph, disable it in the menu.
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
        admin_shell_script, app_bundle_for_bundled_daemon, begin_exit_menu_refresh,
        command_matches_geph, copy_log_snapshot_direct, daemon_binary_format,
        daemon_recovery_shell, daemon_recovery_status_value, daemon_state_text,
        diagnostic_log_tail, diagnostic_log_tail_from_path, diagnostic_snapshot_value,
        diagnostic_summary_value, exit_catalog, exit_catalog_availability,
        finish_exit_menu_refresh, geph_launch_agent_paths, geph_launch_agent_plist,
        geph_launch_domain, geph_launch_target, geph_launcher_script,
        geph_launcher_script_with_log_limits, geph_lifecycle_diagnostic_value, harden_geph_dir,
        install_diagnostic_value, launchd_label_disabled_from_output,
        launchd_plist_uses_bundled_daemon, log_snapshot_shell, osascript_dialog_args,
        redact_sensitive_text, remove_owned_geph_runtime, route_class_health,
        routing_health_summary, shell_quote, should_recover_daemon, should_request_daemon_install,
        signal_uninstall_ready, sync_private_executable, system_proxy_active_from_scutil,
        system_proxy_from_status, telegram_proxy_detail, uninstall_dialog_script_for,
        uninstall_ready_path, uninstall_shell_for_paths, valid_bundled_daemon,
        write_atomic_if_changed, write_diagnostic_snapshot_file, write_private_atomic,
        ExitCatalogAvailability, ExitMenuRefreshState, DAEMON_RECOVERY_STATUS_PATH,
        DAEMON_WATCHDOG_MISSES, GEPH_LAUNCHD_LABEL, GEPH_STDERR_LOG_FILE, PF_TOKEN_PATH,
    };
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::Mutex;

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
    fn launchd_disabled_parser_requires_an_explicit_label_state() {
        let label = "dev.slipstream.tproxy";

        assert_eq!(
            launchd_label_disabled_from_output(
                "{\n  \"dev.slipstream.tproxy\" => disabled\n}",
                label,
            ),
            Some(true)
        );
        assert_eq!(
            launchd_label_disabled_from_output("{\n  \"dev.slipstream.tproxy\" => false\n}", label,),
            Some(false)
        );
        assert_eq!(
            launchd_label_disabled_from_output("{\n  \"other.service\" => false\n}", label),
            None
        );
    }

    #[test]
    fn automatic_install_requires_explicit_enabled_state() {
        assert!(!should_request_daemon_install(true, None, false));
        assert!(!should_request_daemon_install(true, Some(true), false));
        assert!(should_request_daemon_install(true, Some(false), false));
        assert!(!should_request_daemon_install(false, Some(false), false));

        assert!(should_request_daemon_install(true, None, true));
        assert!(should_request_daemon_install(false, Some(true), true));
    }

    #[test]
    fn uninstall_shell_falls_back_to_the_bundled_owned_uninstaller() {
        let shell = uninstall_shell_for_paths(
            Path::new("/usr/local/slipstream/slipstreamd"),
            Path::new("/Applications/Slipstream.app/Contents/Resources/slipstreamd/slipstreamd"),
            Path::new("/Applications/Slipstream.app"),
            4242,
        );

        assert!(shell.contains("'/usr/local/slipstream/slipstreamd' --uninstall"));
        assert!(shell.contains(
            "'/Applications/Slipstream.app/Contents/Resources/slipstreamd/slipstreamd' --uninstall"
        ));
        assert!(shell.contains("/usr/bin/nohup /bin/sh -c"));
        assert!(shell.contains("/bin/ps -p \"$pid\" -o command="));
        assert!(shell.contains("pid=4242"));
        assert!(shell.contains("Slipstream.app.removing-4242"));
        assert!(shell.contains("slipstream-uninstall-4242.ready"));
        assert!(shell.contains("[ ! -e"));
        assert!(shell.contains("[ ! -L"));
        assert!(shell.contains("/bin/mv"));
        assert!(shell.contains("[ \"$i\" -lt 300 ]"));
        assert!(shell.contains("/bin/kill -TERM"));
        assert!(shell.contains("/bin/kill -KILL"));
        assert!(shell.contains("/usr/libexec/PlistBuddy"));
        assert!(shell.contains("dev.slipstream.tray"));
        assert!(shell.contains("/bin/rm -rf --"));
        assert!(!shell.contains("pfctl"));
        assert!(!shell.contains("pkill"));
        assert!(!shell.contains("launchctl disable"));
        assert!(std::process::Command::new("/bin/sh")
            .args(["-n", "-c", &shell])
            .status()
            .unwrap()
            .success());
    }

    #[test]
    fn app_bundle_is_derived_only_from_the_expected_tauri_resource_layout() {
        assert_eq!(
            app_bundle_for_bundled_daemon(Path::new(
                "/Applications/Slipstream.app/Contents/Resources/slipstreamd/slipstreamd"
            )),
            Some(Path::new("/Applications/Slipstream.app").to_path_buf())
        );
        assert_eq!(
            app_bundle_for_bundled_daemon(Path::new(
                "/tmp/Slipstream.app/Resources/slipstreamd/slipstreamd"
            )),
            None
        );
        assert_eq!(
            app_bundle_for_bundled_daemon(Path::new(
                "/tmp/Slipstream/Contents/Resources/slipstreamd/slipstreamd"
            )),
            None
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn uninstall_shell_removes_the_validated_app_after_bundled_cleanup() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "slipstream uninstall test-{}-{unique}",
            std::process::id()
        ));
        let app = root.join("Slipstream.app");
        let contents = app.join("Contents");
        let bundled = contents.join("Resources/slipstreamd/slipstreamd");
        std::fs::create_dir_all(bundled.parent().unwrap()).unwrap();
        std::fs::create_dir_all(contents.join("MacOS")).unwrap();
        std::fs::write(
            contents.join("Info.plist"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>dev.slipstream.tray</string>
</dict></plist>
"#,
        )
        .unwrap();
        std::fs::write(&bundled, b"#!/bin/sh\n[ \"$1\" = \"--uninstall\" ]\n").unwrap();
        let mut permissions = std::fs::metadata(&bundled).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&bundled, permissions).unwrap();

        let shell = uninstall_shell_for_paths(
            &root.join("missing-installed-daemon"),
            &bundled,
            &app,
            u32::MAX,
        );
        let staged =
            std::path::PathBuf::from(format!("{}.removing-{}", app.to_string_lossy(), u32::MAX));
        let ready = uninstall_ready_path(u32::MAX);
        let _ = std::fs::remove_file(&ready);
        assert!(std::process::Command::new("/bin/sh")
            .args(["-c", &shell])
            .status()
            .unwrap()
            .success());
        assert!(signal_uninstall_ready(u32::MAX));
        for _ in 0..40 {
            if !app.exists() && !staged.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        assert!(!app.exists());
        assert!(!staged.exists());
        assert!(!ready.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn uninstall_dialog_defaults_to_cancel_in_each_supported_language() {
        let english = uninstall_dialog_script_for(false);
        let russian = uninstall_dialog_script_for(true);

        assert!(english.contains("default button \"Cancel\" cancel button \"Cancel\""));
        assert!(english.contains("\"Uninstall\""));
        assert!(!english.contains("remains in Applications"));
        assert!(russian.contains("default button \"Отмена\" cancel button \"Отмена\""));
        assert!(russian.contains("\"Удалить\""));
        assert!(!russian.contains("останется в Applications"));
    }

    #[test]
    fn uninstall_ready_signal_never_replaces_an_existing_path() {
        let pid = u32::MAX - 1;
        let ready = uninstall_ready_path(pid);
        let _ = std::fs::remove_file(&ready);
        std::fs::write(&ready, b"foreign\n").unwrap();

        assert!(!signal_uninstall_ready(pid));
        assert_eq!(std::fs::read(&ready).unwrap(), b"foreign\n");

        let _ = std::fs::remove_file(ready);
    }

    #[test]
    fn owned_geph_runtime_cleanup_stays_inside_the_app_config_directory() {
        let root = std::env::temp_dir().join(format!(
            "slipstream-geph-uninstall-test-{}",
            std::process::id()
        ));
        let config_dir = root.join("config");
        let untouched = root.join("outside.txt");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(config_dir.join("runtime")).unwrap();
        std::fs::write(config_dir.join("runtime/geph5-client"), b"binary").unwrap();
        std::fs::write(config_dir.join("geph-active.yaml"), b"secret").unwrap();
        std::fs::write(&untouched, b"keep").unwrap();

        remove_owned_geph_runtime(&config_dir).unwrap();

        assert!(!config_dir.exists());
        assert!(untouched.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn exit_catalog_prefers_cached_city_entries_without_waiting_for_control_rpc() {
        let path = std::env::temp_dir().join(format!(
            "slipstream-exit-catalog-test-{}.json",
            std::process::id()
        ));
        let expected = vec![
            (
                "ca|Montreal".to_string(),
                "CA / Montreal".to_string(),
                "core".to_string(),
            ),
            (
                "jp|Tokyo".to_string(),
                "JP / Tokyo".to_string(),
                "core".to_string(),
            ),
        ];
        std::fs::write(&path, serde_json::to_string(&expected).unwrap()).unwrap();

        assert_eq!(
            exit_catalog(Some(path.clone())),
            ExitCatalogAvailability::Available(expected)
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn exit_catalog_refresh_queues_a_retrigger_without_parallel_workers() {
        let state = Mutex::new(ExitMenuRefreshState::default());

        assert!(begin_exit_menu_refresh(&state));
        assert!(!begin_exit_menu_refresh(&state));
        assert!(finish_exit_menu_refresh(&state, false));
        assert!(!finish_exit_menu_refresh(&state, false));

        assert!(begin_exit_menu_refresh(&state));
        assert!(!finish_exit_menu_refresh(&state, true));
        assert!(begin_exit_menu_refresh(&state));
    }

    #[test]
    fn unavailable_exit_catalog_never_invents_country_choices() {
        assert_eq!(
            exit_catalog_availability(None),
            ExitCatalogAvailability::Unavailable
        );
    }

    #[test]
    fn admin_shell_script_names_prompt_and_escapes_applescript_strings() {
        let script = admin_shell_script(
            "/bin/echo \"hi\" \\ done",
            "Slipstream \"daemon\" \\ prompt",
        );

        assert!(script.contains("with administrator privileges with prompt"));
        assert!(script.contains("/bin/echo \\\"hi\\\" \\\\ done"));
        assert!(script.contains("Slipstream \\\"daemon\\\" \\\\ prompt"));
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
        let dir =
            std::env::temp_dir().join(format!("slipstream-log-copy-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("source.log");
        let dst = dir.join("snapshot.log");
        std::fs::write(&src, "line one\nline two\n").unwrap();
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o640)).unwrap();

        assert!(copy_log_snapshot_direct(src.to_str().unwrap(), &dst));
        assert_eq!(
            std::fs::read_to_string(&dst).unwrap(),
            "line one\nline two\n"
        );
        assert_eq!(
            std::fs::metadata(&dst).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn copy_log_snapshot_direct_returns_false_when_unreadable() {
        let dst =
            std::env::temp_dir().join(format!("slipstream-missing-log-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&dst);

        assert!(!copy_log_snapshot_direct(
            "/definitely/missing/slipstream.log",
            &dst
        ));
    }

    #[test]
    fn write_diagnostic_snapshot_file_clamps_permissions() {
        let dir = std::env::temp_dir().join(format!(
            "slipstream-diagnostic-export-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("slipstream-diagnostics.json");

        assert!(write_diagnostic_snapshot_file(&path, "{\"ok\":true}\n"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"ok\":true}\n");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn diagnostic_snapshot_redacts_sensitive_status_fields() {
        let snapshot = diagnostic_snapshot_value(
            "0.1.5",
            Some(json!({
                "state": "active",
                "version": "0.1.5",
                "geph": "up",
                "telegram_proxy": "ready",
                "route_health": {
                    "openai": {
                        "state": "ok",
                        "last_host": "chatgpt.com",
                        "last_route_class": "geo_exit"
                    },
                    "youtube_video": {
                        "state": "ok",
                        "last_host": "redirector.googlevideo.com",
                        "last_route_class": "local_bypass",
                        "last_warning": "strategy probe failed",
                        "last_warning_host": "www.youtube.com"
                    }
                },
                "canaries": {
                    "total": 2,
                    "ok": 1,
                    "warnings": 1,
                    "degraded": 0,
                    "checks": {
                        "youtube_web": {
                            "state": "unknown",
                            "last_route_class": "local_bypass",
                            "last_warning": "strategy probe failed",
                            "last_warning_host": "www.youtube.com"
                        }
                    }
                },
                "system_proxy": {"state": "off", "kind": ""},
                "system_dns": {
                    "state": "xbox_dns",
                    "providers": "xbox_dns",
                    "managed_by_slipstream": false,
                    "resolution_checks": {"state": "ok"}
                },
                "pf_state": {"applied": true, "enabled": true, "rules_loaded": true},
                "auto_geo_exit": {
                    "enabled": true,
                    "learned": 1,
                    "pending": 0,
                    "last_host": "payments.example.com"
                },
                "routing_policy": {
                    "version": 1,
                    "source": "bundled",
                    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "domains": {
                        "direct_passthrough": 5,
                        "local_bypass": 30,
                        "geo_exit": 15
                    },
                    "attempt_limits": {
                        "default": 2,
                        "local_bypass": 4
                    },
                    "groups": {
                        "discord": {
                            "route_class": "local_bypass",
                            "strategy_set": "fake_only",
                            "domains": 23
                        }
                    }
                },
                "strategy_scores": {
                    "hosts": 2,
                    "groups": {
                        "discord": {
                            "hosts": 1,
                            "strategies": {
                                "split64+fake": {
                                    "hosts": 1,
                                    "ok": 3,
                                    "fail": 0,
                                    "last_seen": 100.0
                                }
                            }
                        },
                        "youtube_video": {
                            "hosts": 1,
                            "strategies": {
                                "fake5": {
                                    "hosts": 1,
                                    "ok": 1,
                                    "fail": 1,
                                    "last_seen": 110.0
                                }
                            }
                        }
                    }
                },
                "secrets": {
                    "account_secret": "very-secret",
                    "nested": {
                        "api_token": "token-value",
                        "password": "pass-value"
                    }
                }
            })),
            geph_lifecycle_diagnostic_value(false, true, true),
            123.0,
            Some(json!({
                "available": true,
                "lines": ["tg://proxy?server=127.0.0.1&secret=old-secret"]
            })),
            Some(json!({
                "available": true,
                "last": {
                    "result": "daemon_recovered",
                    "ts": 12345
                }
            })),
            None,
        );
        let text = serde_json::to_string(&snapshot).unwrap();

        assert_eq!(snapshot["app"]["version"], "0.1.5");
        assert_eq!(snapshot["summary"]["daemon_state"], "active");
        assert_eq!(snapshot["summary"]["geph_lifecycle"]["state"], "managed");
        assert_eq!(snapshot["summary"]["daemon_version"], "0.1.5");
        assert_eq!(snapshot["summary"]["routes"]["local_bypass"], "ok");
        assert_eq!(snapshot["summary"]["routes"]["geo_exit"], "ok");
        assert_eq!(snapshot["summary"]["system_dns"]["resolution_state"], "ok");
        assert_eq!(snapshot["summary"]["auto_geo_exit"]["learned"], 1);
        assert_eq!(snapshot["summary"]["routing_policy"]["version"], 1);
        assert_eq!(snapshot["summary"]["routing_policy"]["source"], "bundled");
        assert_eq!(
            snapshot["summary"]["routing_policy"]["sha256"],
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(
            snapshot["summary"]["routing_policy"]["domains"]["local_bypass"],
            30
        );
        assert_eq!(
            snapshot["summary"]["routing_policy"]["attempt_limits"]["local_bypass"],
            4
        );
        assert_eq!(snapshot["summary"]["strategy_scores"]["hosts"], 2);
        assert_eq!(
            snapshot["summary"]["strategy_scores"]["groups"]["discord"]["strategies"]
                ["split64+fake"]["ok"],
            3
        );
        let strategy_summary =
            serde_json::to_string(&snapshot["summary"]["strategy_scores"]).unwrap();
        assert_eq!(snapshot["summary"]["problems"].as_array().unwrap().len(), 2);
        assert_eq!(
            snapshot["daemon_recovery"]["last"]["result"],
            "daemon_recovered"
        );
        assert_eq!(
            snapshot["daemon"]["route_health"]["openai"]["last_host"],
            "chatgpt.com"
        );
        assert!(!text.contains("very-secret"));
        assert!(!strategy_summary.contains("discord.com"));
        assert!(!strategy_summary.contains("googlevideo.com"));
        assert!(!text.contains("token-value"));
        assert!(!text.contains("pass-value"));
        assert!(!text.contains("old-secret"));
        assert!(text.contains("<redacted>"));
    }

    #[test]
    fn diagnostic_summary_reports_off_state_without_daemon_status() {
        let summary = diagnostic_summary_value(None);

        assert_eq!(summary["daemon_state"], "off");
        assert_eq!(summary["daemon_version"], "unknown");
        assert_eq!(summary["routes"]["local_bypass"], "unknown");
        assert_eq!(summary["routes"]["geo_exit"], "unknown");
        assert_eq!(summary["auto_geo_exit"]["enabled"], false);
        assert_eq!(summary["routing_policy"]["version"], 0);
        assert_eq!(summary["routing_policy"]["source"], "unknown");
        assert_eq!(summary["routing_policy"]["sha256"], "");
        assert_eq!(summary["problems"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn geph_lifecycle_reports_owned_sidecar_without_claiming_pf_state() {
        let lifecycle = geph_lifecycle_diagnostic_value(false, false, true);
        let text = serde_json::to_string(&lifecycle).unwrap();

        assert_eq!(lifecycle["state"], "sidecar_only");
        assert_eq!(lifecycle["root_daemon"], "absent");
        assert_eq!(lifecycle["owned_launch_agent"], "loaded");
        assert!(!text.contains("pid"));
        assert!(!text.contains("config"));
        assert!(!text.contains("pf"));
    }

    #[test]
    fn geph_lifecycle_marks_no_owned_sidecar_as_off() {
        let lifecycle = geph_lifecycle_diagnostic_value(false, false, false);

        assert_eq!(lifecycle["state"], "off");
        assert_eq!(lifecycle["root_daemon"], "absent");
        assert_eq!(lifecycle["owned_launch_agent"], "absent");
    }

    #[test]
    fn daemon_recovery_status_reports_last_watchdog_result() {
        let dir = std::env::temp_dir().join(format!(
            "slipstream-daemon-recovery-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("daemon-recovery.json");
        std::fs::write(&path, r#"{"result":"pf_reset","ts":12345}"#).unwrap();

        let status = daemon_recovery_status_value(path.to_str().unwrap());

        assert_eq!(status["available"], true);
        assert_eq!(status["last"]["result"], "pf_reset");
        assert_eq!(status["last"]["ts"], 12345);

        std::fs::write(&path, "not json secret=hidden").unwrap();
        let broken = daemon_recovery_status_value(path.to_str().unwrap());
        assert_eq!(broken["available"], true);
        assert_eq!(broken["last"]["parse_error"], true);

        let missing = daemon_recovery_status_value("/definitely/missing/recovery.json");
        assert_eq!(missing["available"], false);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bundled_daemon_validation_accepts_executable_macho_only() {
        let dir = std::env::temp_dir().join(format!(
            "slipstream-daemon-format-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let macho = dir.join("slipstreamd");
        let text = dir.join("slipstreamd.txt");
        let noexec = dir.join("slipstreamd-noexec");

        std::fs::write(&macho, [0xfe, 0xed, 0xfa, 0xcf, 0, 0, 0, 0]).unwrap();
        std::fs::set_permissions(&macho, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(&text, b"not a daemon").unwrap();
        std::fs::set_permissions(&text, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(&noexec, [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0]).unwrap();
        std::fs::set_permissions(&noexec, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert_eq!(daemon_binary_format(&macho), Some("mach-o"));
        assert!(valid_bundled_daemon(&macho));
        assert_eq!(daemon_binary_format(&text), None);
        assert!(!valid_bundled_daemon(&text));
        assert_eq!(daemon_binary_format(&noexec), Some("fat-mach-o"));
        assert!(!valid_bundled_daemon(&noexec));

        let _ = std::fs::remove_dir_all(&dir);
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
        let daemon_v1 = [0xfe, 0xed, 0xfa, 0xcf, 0, 0, 0, 1];
        let daemon_v2 = [0xfe, 0xed, 0xfa, 0xcf, 0, 0, 0, 2];
        std::fs::write(&bundled, daemon_v1).unwrap();
        std::fs::set_permissions(&bundled, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(&installed, daemon_v1).unwrap();
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
        assert_eq!(synced["bundled_daemon_format"], "mach-o");
        assert_eq!(synced["bundled_daemon_executable"], true);
        assert_eq!(synced["bundled_daemon_valid"], true);
        assert_eq!(synced["installed_daemon_matches_bundle"], true);
        assert_eq!(synced["launchd_plist_uses_installed_daemon"], true);
        assert_eq!(
            synced["bundled_daemon_path"],
            bundled.to_string_lossy().as_ref()
        );

        std::fs::write(&installed, daemon_v2).unwrap();
        let stale = install_diagnostic_value(Some(&bundled), &installed, &plist);
        assert_eq!(stale["installed_daemon_matches_bundle"], false);

        let missing_bundle = install_diagnostic_value(None, &installed, &plist);
        assert_eq!(missing_bundle["bundled_daemon_exists"], false);
        assert!(missing_bundle["bundled_daemon_format"].is_null());
        assert!(missing_bundle["bundled_daemon_valid"].is_null());
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
    fn diagnostic_log_tail_reads_only_a_bounded_byte_window() {
        let dir = std::env::temp_dir().join(format!(
            "slipstream-diagnostic-byte-tail-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("geph.log");
        let mut content = String::from("secret=outside-window\n");
        content.push_str(&"x".repeat(192 * 1024));
        content.push_str("\ntail-one\ntail-two\n");
        std::fs::write(&log, content).unwrap();

        let tail = diagnostic_log_tail(log.to_str().unwrap(), 2);
        let text = serde_json::to_string(&tail).unwrap();

        assert_eq!(tail["available"], true);
        assert_eq!(tail["truncated"], true);
        assert_eq!(tail["lines"], json!(["tail-one", "tail-two"]));
        assert!(!text.contains("outside-window"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn diagnostic_log_tail_from_snapshot_preserves_raw_log_display_path() {
        let dir = std::env::temp_dir().join(format!(
            "slipstream-diagnostic-log-tail-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let snapshot = dir.join("snapshot.log");
        std::fs::write(&snapshot, "safe line\n").unwrap();

        let tail = diagnostic_log_tail_from_path("/var/log/slipstream.log", &snapshot, 10);

        assert_eq!(tail["path"], "/var/log/slipstream.log");
        assert_eq!(tail["available"], true);
        assert_eq!(tail["lines"], json!(["safe line"]));
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
    fn watchdog_waits_for_initial_status_or_startup_grace() {
        assert!(!should_recover_daemon(
            DAEMON_WATCHDOG_MISSES - 1,
            true,
            false,
            true,
            true
        ));
        assert!(!should_recover_daemon(
            DAEMON_WATCHDOG_MISSES,
            false,
            false,
            true,
            true
        ));
        assert!(!should_recover_daemon(
            DAEMON_WATCHDOG_MISSES,
            true,
            false,
            false,
            true
        ));
        assert!(!should_recover_daemon(
            DAEMON_WATCHDOG_MISSES,
            true,
            false,
            true,
            false
        ));
        assert!(should_recover_daemon(
            DAEMON_WATCHDOG_MISSES,
            true,
            false,
            true,
            true
        ));
        assert!(should_recover_daemon(
            DAEMON_WATCHDOG_MISSES,
            false,
            true,
            true,
            true
        ));
    }

    #[test]
    fn daemon_recovery_shell_kickstarts_before_pf_cleanup() {
        let shell = daemon_recovery_shell();

        assert!(shell.contains("/bin/launchctl kickstart -k 'system/dev.slipstream.tproxy'"));
        assert!(shell.contains("/usr/local/slipstream/slipstreamd' --status"));
        assert!(shell.contains(DAEMON_RECOVERY_STATUS_PATH));
        assert!(shell.contains("daemon_recovered"));
        assert!(shell.contains("anchor_cleared"));
        assert!(shell.contains("/sbin/pfctl -a 'com.apple/slipstream' -F rules"));
        assert!(shell.contains("/sbin/pfctl -a 'com.apple/slipstream' -F nat"));
        assert!(!shell.contains("-F all"));
        assert!(!shell.contains("-F states"));
        assert!(shell.contains(PF_TOKEN_PATH));
        assert!(!shell.contains("/sbin/pfctl -f /etc/pf.conf"));
        assert!(!shell.contains("/sbin/pfctl -d"));
        assert!(shell.find("kickstart").unwrap() < shell.find("pfctl").unwrap());
        assert!(shell.find("--status").unwrap() < shell.find("pfctl").unwrap());
    }

    #[test]
    fn geph_private_files_and_directory_use_owner_only_permissions() {
        let dir = std::env::temp_dir().join(format!(
            "slipstream-geph-permissions-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("geph-active.yaml");
        let runtime_dir = dir.join("runtime");
        let runtime_bin = runtime_dir.join("geph5-client");
        let stderr_log = dir.join(GEPH_STDERR_LOG_FILE);
        std::fs::write(&config, "credentials:\n secret: test\n").unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&stderr_log, "startup failed\n").unwrap();
        std::fs::set_permissions(&stderr_log, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::create_dir_all(&runtime_dir).unwrap();
        std::fs::write(&runtime_bin, b"binary").unwrap();
        std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&runtime_bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        harden_geph_dir(&dir).unwrap();
        write_private_atomic(&config, b"credentials:\n secret: replaced\n").unwrap();

        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&config).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&stderr_log).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&runtime_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&runtime_bin)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn geph_launch_agent_uses_stable_private_runtime_and_keepalive() {
        let config_dir =
            std::path::Path::new("/Users/test/Library/Application Support/dev.slipstream.tray");
        let home = std::path::Path::new("/Users/test");
        let paths = geph_launch_agent_paths(config_dir, home);
        let plist = geph_launch_agent_plist(&paths);

        assert_eq!(
            paths.executable,
            config_dir.join("runtime").join("geph5-client")
        );
        assert_eq!(
            paths.plist,
            home.join("Library")
                .join("LaunchAgents")
                .join("dev.slipstream.geph.plist")
        );
        assert!(plist.contains(&format!("<string>{GEPH_LAUNCHD_LABEL}</string>")));
        assert!(plist.contains("<key>KeepAlive</key><true/>"));
        assert!(plist.contains("<key>RunAtLoad</key><true/>"));
        assert!(plist.contains(&format!("<string>{}</string>", paths.launcher.display())));
        assert_eq!(plist.matches("<string>/dev/null</string>").count(), 2);
        assert!(!plist.contains(&format!("<string>{}</string>", paths.stdout_log.display())));
        assert!(!plist.contains(&format!("<string>{}</string>", paths.stderr_log.display())));
        assert!(!plist.contains("geph-active.yaml"));
        assert!(!plist.contains("secret"));
    }

    #[test]
    fn geph_launcher_waits_for_unknown_listener_and_records_exec_identity() {
        let config_dir =
            std::path::Path::new("/Users/O'Neil/Library/Application Support/dev.slipstream.tray");
        let paths = geph_launch_agent_paths(config_dir, std::path::Path::new("/Users/O'Neil"));
        let script = geph_launcher_script(&paths);

        assert!(script.contains("/usr/bin/nc -z -w 1 127.0.0.1 9954"));
        assert!(script.contains("\"pid\":%s"));
        assert!(script.contains("\"uid\":%s"));
        assert!(script.contains("\"launchd_label\":%s"));
        assert!(script.contains("uid=$(/usr/bin/id -u)"));
        let ownership_write = script
            .lines()
            .find(|line| line.contains("/usr/bin/printf") && line.contains("{\"pid\":"))
            .expect("launcher writes an ownership record");
        assert!(ownership_write.contains("\"$$\""));
        assert!(ownership_write.contains("\"$uid\""));
        assert!(ownership_write.contains("> \"$tmp\""));
        assert!(!script.contains("\n+"));
        assert!(script.contains("log_max_bytes=1048576"));
        assert!(script.contains("log_retain_bytes=262144"));
        assert!(script.contains("log_guard_interval=5"));
        assert!(script.contains("/usr/bin/tail -c \"$log_retain_bytes\""));
        assert!(script.contains("archive=\"${path}.previous\""));
        assert!(script.contains("/bin/kill -0 \"$target_pid\""));
        assert!(script.contains(
            "exec \"$executable\" --config \"$config\" >> \"$stdout_log\" 2>> \"$stderr_log\""
        ));
        assert!(script.contains("'\\''"));
        assert!(!script.contains("pkill"));
        assert!(!script.contains("killall"));
        assert!(!script
            .lines()
            .any(|line| line.contains("/bin/kill ") && !line.contains("/bin/kill -0")));
    }

    #[test]
    fn geph_launcher_rotates_live_logs_without_replacing_the_geph_pid() {
        let dir = std::env::temp_dir().join(format!(
            "slipstream-geph-log-rotation-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let config_dir = dir.join("Application Support").join("dev.slipstream.tray");
        let home = dir.join("home");
        let paths = geph_launch_agent_paths(&config_dir, &home);
        std::fs::create_dir_all(&paths.runtime_dir).unwrap();
        std::fs::write(&paths.config, "test: true\n").unwrap();
        std::fs::write(
            &paths.executable,
            "#!/bin/sh\n\
             i=0\n\
             while [ \"$i\" -lt 300 ]; do\n\
             \x20 /usr/bin/printf 'stdout-line-that-forces-rotation-%04d\\n' \"$i\"\n\
             \x20 /usr/bin/printf 'stderr-line-that-forces-rotation-%04d\\n' \"$i\" >&2\n\
             \x20 i=$((i + 1))\n\
             done\n\
             /bin/sleep 2\n",
        )
        .unwrap();
        std::fs::set_permissions(&paths.executable, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let unused_port = listener.local_addr().unwrap().port();
        drop(listener);
        std::fs::write(
            &paths.launcher,
            geph_launcher_script_with_log_limits(&paths, 4096, 512, 1, unused_port),
        )
        .unwrap();
        std::fs::set_permissions(&paths.launcher, std::fs::Permissions::from_mode(0o700)).unwrap();

        let status = std::process::Command::new(&paths.launcher)
            .status()
            .unwrap();
        assert!(status.success());
        std::thread::sleep(std::time::Duration::from_millis(1100));

        for path in [&paths.stdout_log, &paths.stderr_log] {
            let archive = super::geph_log_archive_path(path);
            assert!(std::fs::metadata(path).unwrap().len() <= 4096);
            assert!(std::fs::metadata(&archive).unwrap().len() <= 512);
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(archive).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn geph_runtime_sync_is_atomic_idempotent_and_owner_only() {
        let dir = std::env::temp_dir().join(format!(
            "slipstream-geph-runtime-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("source");
        let target = dir.join("runtime").join("geph5-client");
        std::fs::write(&source, b"version-one").unwrap();

        assert!(sync_private_executable(&source, &target).unwrap());
        assert!(!sync_private_executable(&source, &target).unwrap());
        assert_eq!(std::fs::read(&target).unwrap(), b"version-one");
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o700
        );

        std::fs::write(&source, b"version-two").unwrap();
        assert!(sync_private_executable(&source, &target).unwrap());
        assert_eq!(std::fs::read(&target).unwrap(), b"version-two");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn geph_launch_agent_plist_write_does_not_change_parent_permissions() {
        let dir = std::env::temp_dir().join(format!(
            "slipstream-geph-launchagent-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let plist = dir.join("dev.slipstream.geph.plist");

        assert!(write_atomic_if_changed(&plist, b"plist-v1", 0o600).unwrap());
        assert!(!write_atomic_if_changed(&plist, b"plist-v1", 0o600).unwrap());
        assert_eq!(
            std::fs::metadata(&plist).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o755
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn generated_geph_launch_artifacts_parse_on_macos() {
        let dir = std::env::temp_dir().join(format!(
            "slipstream-geph-launch-artifacts-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let config_dir = dir.join("Application Support").join("dev.slipstream.tray");
        let home = dir.join("home");
        let paths = geph_launch_agent_paths(&config_dir, &home);
        std::fs::create_dir_all(paths.launcher.parent().unwrap()).unwrap();
        std::fs::create_dir_all(paths.plist.parent().unwrap()).unwrap();
        std::fs::write(&paths.launcher, geph_launcher_script(&paths)).unwrap();
        std::fs::write(&paths.plist, geph_launch_agent_plist(&paths)).unwrap();

        assert!(std::process::Command::new("/bin/sh")
            .args(["-n", paths.launcher.to_str().unwrap()])
            .status()
            .unwrap()
            .success());
        assert!(std::process::Command::new("/usr/bin/plutil")
            .args(["-lint", paths.plist.to_str().unwrap()])
            .status()
            .unwrap()
            .success());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn geph_launchctl_scope_is_exactly_the_user_job() {
        assert_eq!(geph_launch_domain("502"), "gui/502");
        assert_eq!(geph_launch_target("502"), "gui/502/dev.slipstream.geph");
    }

    #[test]
    fn geph_command_match_requires_exact_executable_and_config() {
        let executable =
            std::path::Path::new("/Applications/Slipstream.app/Contents/MacOS/geph5-client");
        let config = std::path::Path::new(
            "/Users/test/Library/Application Support/dev.slipstream.tray/geph-active.yaml",
        );
        let command = format!("{} --config {}", executable.display(), config.display());

        assert!(command_matches_geph(&command, executable, config));
        assert!(!command_matches_geph(
            "/tmp/geph5-client --config /tmp/geph-active.yaml",
            executable,
            config
        ));
        assert!(!command_matches_geph(
            executable.to_str().unwrap(),
            executable,
            config
        ));
        assert!(!command_matches_geph(
            &(command + ".untrusted"),
            executable,
            config
        ));
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
            Some("Restoring local access".to_string())
        );
    }

    #[test]
    fn routing_health_summary_names_combined_recovery() {
        let status = json!({
            "route_health": {
                "discord": {
                    "state": "degraded",
                    "last_route_class": "local_bypass"
                },
                "openai": {
                    "state": "blocked",
                    "last_route_class": "geo_exit"
                }
            }
        });

        assert_eq!(
            routing_health_summary(Some(&status), "up", false),
            Some("Restoring service access".to_string())
        );
        assert_eq!(
            routing_health_summary(Some(&status), "up", true),
            Some("Восстанавливается доступ к сервисам".to_string())
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
            Some("Restoring access to external services".to_string())
        );
        assert_eq!(routing_health_summary(Some(&status), "off", false), None);
    }

    #[test]
    fn competing_pf_interceptor_has_clear_compact_state_text() {
        assert_eq!(
            daemon_state_text("conflict", 0, 0, false),
            (
                "Slipstream — Paused".to_string(),
                "Another traffic filter is active".to_string(),
            )
        );
    }

    #[test]
    fn routing_health_summary_ignores_warning_only_checks() {
        let status = json!({
            "route_health": {
                "youtube_video": {
                    "state": "ok",
                    "last_route_class": "local_bypass",
                    "last_warning": "strategy probe failed",
                    "last_warning_host": "www.youtube.com"
                },
                "openai": {
                    "state": "ok",
                    "last_route_class": "geo_exit",
                    "last_warning": "SOCKS connect failed",
                    "last_warning_host": "billing.openai.com"
                }
            },
            "canaries": {
                "warnings": 2,
                "degraded": 0
            }
        });

        assert_eq!(routing_health_summary(Some(&status), "up", false), None);
    }

    #[test]
    fn routing_health_summary_ignores_generic_geo_exit_noise() {
        let status = json!({
            "route_health": {
                "openai": {
                    "state": "ok",
                    "last_route_class": "geo_exit"
                },
                "generic": {
                    "state": "degraded",
                    "last_route_class": "geo_exit",
                    "last_host": "gue1-spclient.spotify.com",
                    "last_failure": "remote closed without response"
                }
            }
        });

        assert_eq!(routing_health_summary(Some(&status), "up", false), None);
    }
}
