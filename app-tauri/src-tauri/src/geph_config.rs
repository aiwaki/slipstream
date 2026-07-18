use std::{fs, path::PathBuf, process::Command};

use serde_json::{Map, Value};
use tauri::{AppHandle, Manager};

use super::write_private_atomic;

const CONFIG_FILE: &str = "geph.json";

// The account secret lives in the macOS Keychain, not the plaintext config.
const KC_SERVICE: &str = "dev.slipstream.geph";
const KC_ACCOUNT: &str = "account-secret";
const KEYCHAIN_ITEM_NOT_FOUND_EXIT: i32 = 44;

enum KeychainSecretState {
    Present(String),
    Missing,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum GephSecretAvailability {
    Present,
    Missing,
    Unavailable,
}

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

fn classify_keychain_read(exit_code: Option<i32>, stdout: &[u8]) -> KeychainSecretState {
    match exit_code {
        Some(0) => {
            let secret = String::from_utf8_lossy(stdout).trim().to_string();
            if secret.is_empty() {
                KeychainSecretState::Unavailable
            } else {
                KeychainSecretState::Present(secret)
            }
        }
        Some(KEYCHAIN_ITEM_NOT_FOUND_EXIT) => KeychainSecretState::Missing,
        _ => KeychainSecretState::Unavailable,
    }
}

fn keychain_get() -> KeychainSecretState {
    let Ok(output) = Command::new("/usr/bin/security")
        .args([
            "find-generic-password",
            "-s",
            KC_SERVICE,
            "-a",
            KC_ACCOUNT,
            "-w",
        ])
        .output()
    else {
        return KeychainSecretState::Unavailable;
    };
    classify_keychain_read(output.status.code(), &output.stdout)
}

pub(super) fn keychain_set(secret: &str) -> bool {
    Command::new("/usr/bin/security")
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
        .status()
        .is_ok_and(|status| status.success())
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

fn migrate_legacy_secret(
    legacy: &str,
    store: impl FnOnce(&str) -> bool,
    scrub: impl FnOnce(),
) -> (Option<String>, bool) {
    let secret = legacy.trim().to_string();
    if secret.is_empty() {
        return (None, false);
    }
    let stored = store(&secret);
    if stored {
        scrub();
    }
    (Some(secret), stored)
}

fn geph_secret_state(app: &AppHandle) -> KeychainSecretState {
    let unavailable = match keychain_get() {
        KeychainSecretState::Present(secret) => {
            // Retry cleanup if a previous atomic config write could not remove
            // the migrated plaintext copy after Keychain storage succeeded.
            geph_config_unset(app, "secret");
            return KeychainSecretState::Present(secret);
        }
        state => state,
    };
    let Some(legacy) = geph_field(app, "secret") else {
        return unavailable;
    };
    let (secret, stored) =
        migrate_legacy_secret(&legacy, keychain_set, || geph_config_unset(app, "secret"));
    if secret.is_some() && !stored {
        eprintln!("geph secret migration deferred: Keychain write unavailable");
    }
    match secret {
        Some(secret) => KeychainSecretState::Present(secret),
        None => unavailable,
    }
}

/// Read the account secret from the Keychain. A legacy plaintext secret is
/// migrated once and then removed from geph.json.
pub(super) fn geph_secret(app: &AppHandle) -> Option<String> {
    match geph_secret_state(app) {
        KeychainSecretState::Present(secret) => Some(secret),
        KeychainSecretState::Missing | KeychainSecretState::Unavailable => None,
    }
}

pub(super) fn geph_secret_availability(app: &AppHandle) -> GephSecretAvailability {
    match geph_secret_state(app) {
        KeychainSecretState::Present(_) => GephSecretAvailability::Present,
        KeychainSecretState::Missing => GephSecretAvailability::Missing,
        KeychainSecretState::Unavailable => GephSecretAvailability::Unavailable,
    }
}

fn resolve_geph_enabled_state(
    explicit: Option<&str>,
    legacy_config_present: bool,
    secret: GephSecretAvailability,
) -> (bool, bool) {
    if let Some(value) = explicit {
        return (
            value != "0" && secret != GephSecretAvailability::Missing,
            false,
        );
    }
    let migrate_legacy_opt_in = legacy_config_present && secret == GephSecretAvailability::Present;
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
    let secret = geph_secret_availability(app);
    let (enabled, migrate) =
        resolve_geph_enabled_state(explicit.as_deref(), legacy_config_present, secret);
    if migrate {
        geph_config_set(app, "enabled", "1");
    }
    enabled
}

#[cfg(test)]
mod tests {
    use super::{
        classify_keychain_read, config_map, config_with_field, config_without_field,
        keychain_delete_args, migrate_legacy_secret, resolve_geph_enabled_state,
        GephSecretAvailability, KeychainSecretState,
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
            resolve_geph_enabled_state(Some("0"), true, GephSecretAvailability::Present),
            (false, false)
        );
        assert_eq!(
            resolve_geph_enabled_state(Some("1"), true, GephSecretAvailability::Present),
            (true, false)
        );
        assert_eq!(
            resolve_geph_enabled_state(Some("1"), true, GephSecretAvailability::Missing),
            (false, false)
        );
        assert_eq!(
            resolve_geph_enabled_state(Some("1"), true, GephSecretAvailability::Unavailable),
            (true, false)
        );
        assert_eq!(
            resolve_geph_enabled_state(None, true, GephSecretAvailability::Present),
            (true, true)
        );
        assert_eq!(
            resolve_geph_enabled_state(None, false, GephSecretAvailability::Present),
            (false, false)
        );
        assert_eq!(
            resolve_geph_enabled_state(None, true, GephSecretAvailability::Missing),
            (false, false)
        );
        assert_eq!(
            resolve_geph_enabled_state(None, true, GephSecretAvailability::Unavailable),
            (false, false)
        );
    }

    #[test]
    fn keychain_read_distinguishes_missing_from_transient_unavailability() {
        match classify_keychain_read(Some(0), b"  account-secret\n") {
            KeychainSecretState::Present(secret) => assert_eq!(secret, "account-secret"),
            KeychainSecretState::Missing | KeychainSecretState::Unavailable => {
                panic!("successful Keychain output must be available")
            }
        }
        assert!(matches!(
            classify_keychain_read(Some(44), b""),
            KeychainSecretState::Missing
        ));
        assert!(matches!(
            classify_keychain_read(Some(1), b""),
            KeychainSecretState::Unavailable
        ));
        assert!(matches!(
            classify_keychain_read(None, b""),
            KeychainSecretState::Unavailable
        ));
        assert!(matches!(
            classify_keychain_read(Some(0), b"  \n"),
            KeychainSecretState::Unavailable
        ));
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

    #[test]
    fn legacy_secret_is_scrubbed_only_after_keychain_storage_succeeds() {
        let mut scrubbed = false;
        let (secret, stored) = migrate_legacy_secret(
            "  legacy-secret  ",
            |value| {
                assert_eq!(value, "legacy-secret");
                false
            },
            || scrubbed = true,
        );
        assert_eq!(secret.as_deref(), Some("legacy-secret"));
        assert!(!stored);
        assert!(!scrubbed);

        let (secret, stored) = migrate_legacy_secret("legacy-secret", |_| true, || scrubbed = true);
        assert_eq!(secret.as_deref(), Some("legacy-secret"));
        assert!(stored);
        assert!(scrubbed);

        let (secret, stored) = migrate_legacy_secret("  ", |_| true, || {});
        assert!(secret.is_none());
        assert!(!stored);
    }
}
