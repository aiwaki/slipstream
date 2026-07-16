//! Privacy-bounded diagnostics data and export primitives.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

fn sensitive_json_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("secret")
        || key.contains("password")
        || key.contains("token")
        || key.contains("private_key")
}

pub(crate) fn sanitize_json(value: &mut Value) {
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

pub(crate) fn redact_sensitive_text(input: &str) -> String {
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

pub(crate) fn diagnostic_log_tail_from_path(
    display_path: &str,
    read_path: &Path,
    max_lines: usize,
) -> Value {
    match fs::read_to_string(read_path) {
        Ok(raw) => {
            let all_lines: Vec<&str> = raw.lines().collect();
            let start = all_lines.len().saturating_sub(max_lines);
            let lines: Vec<String> = all_lines[start..]
                .iter()
                .map(|line| redact_sensitive_text(line))
                .collect();
            json!({
                "path": display_path,
                "available": true,
                "truncated": start > 0,
                "lines": lines,
            })
        }
        Err(err) => json!({
            "path": display_path,
            "available": false,
            "error": format!("{:?}", err.kind()),
            "lines": [],
        }),
    }
}

pub(crate) fn diagnostic_log_tail(log_path: &str, max_lines: usize) -> Value {
    diagnostic_log_tail_from_path(log_path, Path::new(log_path), max_lines)
}

pub(crate) fn daemon_recovery_status_value(path: &str) -> Value {
    match fs::read_to_string(path) {
        Ok(raw) => {
            let parsed = serde_json::from_str::<Value>(&raw).unwrap_or_else(|_| {
                json!({
                    "parse_error": true,
                    "raw": raw,
                })
            });
            json!({
                "path": path,
                "available": true,
                "last": parsed,
            })
        }
        Err(err) => json!({
            "path": path,
            "available": false,
            "error": format!("{:?}", err.kind()),
        }),
    }
}

pub(crate) fn unix_now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}

pub(crate) fn diagnostic_snapshot_path() -> PathBuf {
    std::env::temp_dir().join("slipstream-diagnostics.json")
}

pub(crate) fn write_diagnostic_snapshot_file(path: &Path, text: &str) -> bool {
    if fs::write(path, text).is_err() {
        return false;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).is_ok()
}
