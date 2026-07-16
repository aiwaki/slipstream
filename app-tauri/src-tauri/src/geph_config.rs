use std::{fs, path::PathBuf, process::Command};

use serde_json::{Map, Value};
use tauri::{AppHandle, Manager};

use super::write_private_atomic;

const CONFIG_FILE: &str = "geph.json";

// The account secret lives in the macOS Keychain, not the plaintext config.
const KC_SERVICE: &str = "dev.slipstream.geph";
const KC_ACCOUNT: &str = "account-secret";

fn config_path(app: &AppHandle) -> Option<PathBuf> {
    Some(app.path().app_config_dir().ok()?.join(CONFIG_FILE))
}

fn config_map(text: &str) -> Option<Map<String, Value>> {
    serde_json::from_str(text).ok()
}

fn config_with_field(existing: Option<&str>, key: &str, value: &str) -> Map<String, Value> {
    let mut config = existing.and_then(config_map).unwrap_or_default();
    config.insert(key.to_string(), Value::String(value.to_string()));
    config
}

fn config_without_field(existing: &str, key: &str) -> Option<Map<String, Value>> {
    let mut config = config_map(existing)?;
    config.remove(key)?;
    Some(config)
}

/// Persist a setting for Slipstream's bundled Geph client. This never touches
/// the configuration of a separately installed Geph application.
pub(super) fn geph_config_set(app: &AppHandle, key: &str, value: &str) {
    let Some(path) = config_path(app) else {
        return;
    };
    let existing = fs::read_to_string(&path).ok();
    let config = config_with_field(existing.as_deref(), key, value);
    if let Ok(serialized) = serde_json::to_string_pretty(&Value::Object(config)) {
        let _ = write_private_atomic(&path, serialized.as_bytes());
    }
}

/// Read a string field from Slipstream's Geph configuration.
pub(super) fn geph_field(app: &AppHandle, key: &str) -> Option<String> {
    let config = config_map(&fs::read_to_string(config_path(app)?).ok()?)?;
    config.get(key).and_then(Value::as_str).map(str::to_string)
}

/// Remove a field from the private configuration. Used to scrub a migrated
/// legacy plaintext secret after it has been copied into the Keychain.
fn geph_config_unset(app: &AppHandle, key: &str) {
    let Some(path) = config_path(app) else {
        return;
    };
    let Ok(existing) = fs::read_to_string(&path) else {
        return;
    };
    let Some(config) = config_without_field(&existing, key) else {
        return;
    };
    if let Ok(serialized) = serde_json::to_string_pretty(&Value::Object(config)) {
        let _ = write_private_atomic(&path, serialized.as_bytes());
    }
}

fn keychain_get() -> Option<String> {
    let output = Command::new("/usr/bin/security")
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
    if !output.status.success() {
        return None;
    }
    let secret = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!secret.is_empty()).then_some(secret)
}

pub(super) fn keychain_set(secret: &str) {
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

fn keychain_delete_args() -> [&'static str; 5] {
    [
        "delete-generic-password",
        "-s",
        KC_SERVICE,
        "-a",
        KC_ACCOUNT,
    ]
}

pub(super) fn keychain_delete() {
    let _ = Command::new("/usr/bin/security")
        .args(keychain_delete_args())
        .status();
}

/// Read the account secret from the Keychain. A legacy plaintext secret is
/// migrated once and then removed from geph.json.
pub(super) fn geph_secret(app: &AppHandle) -> Option<String> {
    if let Some(secret) = keychain_get() {
        return Some(secret);
    }
    let legacy = geph_field(app, "secret")?.trim().to_string();
    if legacy.is_empty() {
        return None;
    }
    keychain_set(&legacy);
    geph_config_unset(app, "secret");
    Some(legacy)
}

fn resolve_geph_enabled_state(
    explicit: Option<&str>,
    legacy_config_present: bool,
    secret_present: bool,
) -> (bool, bool) {
    if let Some(value) = explicit {
        return (value != "0", false);
    }
    let migrate_legacy_opt_in = legacy_config_present && secret_present;
    (migrate_legacy_opt_in, migrate_legacy_opt_in)
}

/// Whether Slipstream's bundled Geph should run. A valid legacy config plus
/// credentials is migrated once; an orphaned Keychain secret cannot recreate
/// deleted state.
pub(super) fn geph_enabled(app: &AppHandle) -> bool {
    let explicit = geph_field(app, "enabled");
    let legacy_config_present = config_path(app)
        .and_then(|path| fs::read_to_string(path).ok())
        .and_then(|text| config_map(&text))
        .is_some();
    let secret_present = explicit.is_none() && legacy_config_present && geph_secret(app).is_some();
    let (enabled, migrate) =
        resolve_geph_enabled_state(explicit.as_deref(), legacy_config_present, secret_present);
    if migrate {
        geph_config_set(app, "enabled", "1");
    }
    enabled
}

#[cfg(test)]
mod tests {
    use super::{
        config_map, config_with_field, config_without_field, keychain_delete_args,
        resolve_geph_enabled_state,
    };

    #[test]
    fn config_updates_preserve_unrelated_fields_and_scrub_only_the_target() {
        let existing = r#"{"enabled":"1","exit":"ca","secret":"legacy"}"#;
        let updated = config_with_field(Some(existing), "exit", "us");
        assert_eq!(updated.get("enabled").and_then(|v| v.as_str()), Some("1"));
        assert_eq!(updated.get("exit").and_then(|v| v.as_str()), Some("us"));
        assert_eq!(
            updated.get("secret").and_then(|v| v.as_str()),
            Some("legacy")
        );

        let scrubbed = config_without_field(existing, "secret").unwrap();
        assert_eq!(scrubbed.get("enabled").and_then(|v| v.as_str()), Some("1"));
        assert_eq!(scrubbed.get("exit").and_then(|v| v.as_str()), Some("ca"));
        assert!(!scrubbed.contains_key("secret"));
        assert!(config_without_field(existing, "missing").is_none());
        assert!(config_map("not-json").is_none());
    }

    #[test]
    fn legacy_opt_in_migrates_without_reviving_orphaned_secrets() {
        assert_eq!(
            resolve_geph_enabled_state(Some("0"), true, true),
            (false, false)
        );
        assert_eq!(
            resolve_geph_enabled_state(Some("1"), true, true),
            (true, false)
        );
        assert_eq!(resolve_geph_enabled_state(None, true, true), (true, true));
        assert_eq!(
            resolve_geph_enabled_state(None, false, true),
            (false, false)
        );
        assert_eq!(
            resolve_geph_enabled_state(None, true, false),
            (false, false)
        );
    }

    #[test]
    fn keychain_cleanup_targets_only_slipstream_geph_account() {
        assert_eq!(
            keychain_delete_args(),
            [
                "delete-generic-password",
                "-s",
                "dev.slipstream.geph",
                "-a",
                "account-secret",
            ]
        );
    }
}
