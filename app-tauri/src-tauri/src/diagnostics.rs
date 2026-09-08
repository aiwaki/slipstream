//! Privacy-bounded diagnostics data and export primitives.

use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

pub(crate) const DIAGNOSTIC_LOG_TAIL_MAX_BYTES: u64 = 128 * 1024;

fn sensitive_json_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("secret")
        || key.contains("password")
        || key.contains("token")
        || key.contains("private_key")
        || opaque_sensitive_key(&key)
}

fn opaque_sensitive_key(key: &str) -> bool {
    matches!(key, "cookie" | "cookies" | "set-cookie" | "route_subtree")
        || key.ends_with("_cookie")
        || key.ends_with("_cookies")
}

fn opaque_sensitive_value_offsets(lower: &str) -> Vec<usize> {
    let is_identifier = |ch: char| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-');
    let mut characters = lower.char_indices().peekable();
    let mut offsets = Vec::new();
    while let Some((start, first)) = characters.next() {
        if !is_identifier(first) {
            continue;
        }
        let mut end = start + first.len_utf8();
        while let Some(&(position, ch)) = characters.peek() {
            if !is_identifier(ch) {
                break;
            }
            end = position + ch.len_utf8();
            characters.next();
        }
        if opaque_sensitive_key(&lower[start..end]) {
            let after_key = lower[end..].trim_start_matches(|ch: char| {
                ch.is_whitespace() || matches!(ch, '"' | '\'' | '\\')
            });
            if after_key.starts_with([':', '=']) {
                offsets.push(lower.len() - after_key.len() + 1);
            }
        }
    }
    offsets
}

fn contains_opaque_sensitive_field(lower: &str) -> bool {
    !opaque_sensitive_value_offsets(lower).is_empty()
}

fn opaque_sensitive_record_may_continue(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let mut verified_until = 0;
    for offset in opaque_sensitive_value_offsets(&lower) {
        if offset < verified_until {
            continue;
        }
        let mut values = serde_json::Deserializer::from_str(&line[offset..]).into_iter::<Value>();
        if !matches!(values.next(), Some(Ok(_))) {
            return true;
        }
        // A complete containing value also covers any nested sensitive fields;
        // do not repeatedly parse progressively smaller copies of that value.
        verified_until = offset + values.byte_offset();
    }
    false
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
    // Geph route payloads can contain nested/escaped JSON, arrays, or a
    // truncated value. Scalar scanning cannot safely retain part of such a
    // record. Omit the complete record without decoding or copying its value.
    if contains_opaque_sensitive_field(&lower) {
        return "<sensitive diagnostic record omitted>".to_string();
    }
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
            let mut escaped = false;
            while pos < input.len() {
                let Some(ch) = input[pos..].chars().next() else {
                    break;
                };
                pos += ch.len_utf8();
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
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
    diagnostic_log_tail_with_policy(display_path, read_path, max_lines, false)
}

pub(crate) fn diagnostic_geph_log_tail_from_path(
    display_path: &str,
    read_path: &Path,
    max_lines: usize,
) -> Value {
    diagnostic_log_tail_with_policy(display_path, read_path, max_lines, true)
}

fn diagnostic_log_tail_with_policy(
    display_path: &str,
    read_path: &Path,
    max_lines: usize,
    omit_byte_truncated: bool,
) -> Value {
    let read_tail = (|| {
        let mut file = fs::File::open(read_path)?;
        let length = file.metadata()?.len();
        let start = length.saturating_sub(DIAGNOSTIC_LOG_TAIL_MAX_BYTES);
        file.seek(SeekFrom::Start(start))?;
        let mut bytes = Vec::with_capacity((length - start) as usize);
        file.take(DIAGNOSTIC_LOG_TAIL_MAX_BYTES)
            .read_to_end(&mut bytes)?;

        // A bounded read can begin in the middle of a UTF-8 line. Drop that
        // partial line so diagnostics never show a malformed fragment.
        if start > 0 {
            if let Some(newline) = bytes.iter().position(|byte| *byte == b'\n') {
                bytes.drain(..=newline);
            } else {
                bytes.clear();
            }
        }
        Ok::<_, std::io::Error>((String::from_utf8_lossy(&bytes).into_owned(), start > 0))
    })();

    match read_tail {
        Ok((raw, byte_truncated)) => {
            let all_lines: Vec<&str> = raw.lines().collect();
            let start = all_lines.len().saturating_sub(max_lines);
            // Check the full bounded read BEFORE line slicing. A key-bearing
            // opener may otherwise be outside max_lines while its multiline
            // array/object continuation is exported as apparently plain text.
            // If the value cannot be proven complete on its own physical line,
            // omit this tail rather than guessing where the sensitive span ends.
            // Geph may emit opaque route credentials. After byte truncation,
            // their opener can lie outside this window; its continuation has
            // no reliable label. Keep metadata/structured backend state, not
            // raw Geph lines whose record boundaries cannot be established.
            let omit_sensitive_tail = (omit_byte_truncated && byte_truncated)
                || all_lines
                    .iter()
                    .any(|line| opaque_sensitive_record_may_continue(line));
            let lines: Vec<String> = if omit_sensitive_tail && max_lines > 0 {
                vec!["<sensitive diagnostic tail omitted>".to_string()]
            } else {
                all_lines[start..]
                    .iter()
                    .map(|line| redact_sensitive_text(line))
                    .collect()
            };
            json!({
                "path": display_path,
                "available": true,
                "truncated": byte_truncated || start > 0 || omit_sensitive_tail,
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

#[cfg(test)]
mod privacy_tests {
    use super::*;

    #[test]
    fn diagnostics_omit_opaque_cookie_and_route_records_in_all_value_shapes() {
        for record in [
            r#"event route_subtree={"cookie":"synthetic-value","nodes":[1,2]} state=ok"#,
            r#"event {"cookie":["synthetic-first","synthetic-tail"]}"#,
            r#"event {\"cookie\":\"synthetic-value\"}"#,
            r#"event {\\\"cookie\\\":\\\"synthetic-value\\\"}"#,
            r#"event route_subtree={"nodes":["synthetic-first","synthetic-tail"#,
            r#"COOKIE = "synthetic-value" state=ok"#,
            r#"session_cookie={"nested":"synthetic-value"}"#,
            r#"Set-Cookie: synthetic-session; Path=/"#,
            "event cookie=[\"synthetic-first\",\n\"synthetic-tail\"]",
        ] {
            let redacted = redact_sensitive_text(record);
            assert_eq!(redacted, "<sensitive diagnostic record omitted>");
            assert_eq!(redact_sensitive_text(&redacted), redacted);
        }
    }

    #[test]
    fn diagnostics_redact_structural_cookie_values_and_keep_safe_metadata() {
        let mut snapshot = json!({
            "cookie": ["synthetic-first", {"value": "synthetic-tail"}],
            "nested": [{"session_cookie": "synthetic-session"}],
            "route_subtree": {"unknown_container": ["synthetic-node"]},
            "cookie_count": 3,
            "route_subtree_cache_hit": true,
            "state": "connected",
        });
        sanitize_json(&mut snapshot);
        assert_eq!(snapshot["cookie"], "<redacted>");
        assert_eq!(snapshot["nested"][0]["session_cookie"], "<redacted>");
        assert_eq!(snapshot["route_subtree"], "<redacted>");
        assert_eq!(snapshot["cookie_count"], 3);
        assert_eq!(snapshot["route_subtree_cache_hit"], true);
        assert_eq!(snapshot["state"], "connected");
        assert!(!snapshot.to_string().contains("synthetic-"));
    }

    #[test]
    fn diagnostics_keep_non_sensitive_cookie_prose_and_metadata() {
        for record in [
            "cookie check passed; state=connected",
            "route_subtree is unavailable; state=retrying",
            "cookie_count=3 route_subtree_cache_hit=true state=connected",
            r#"{"cookie_count":3,"route_subtree_cache_hit":true}"#,
            "state=connected sessions=2",
        ] {
            assert_eq!(redact_sensitive_text(record), record);
        }
    }

    #[test]
    fn diagnostics_log_tail_and_snapshot_omit_sensitive_records_preserving_neighbors() {
        let path = std::env::temp_dir().join(format!(
            "slipstream-cookie-export-test-{}-{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        fs::write(
            &path,
            concat!(
                "state=starting\n",
                "event route_subtree={\"cookie\":[\"synthetic-first\",\"synthetic-tail\"]}\n",
                "state=connected sessions=2\n",
            ),
        )
        .unwrap();
        let tail = diagnostic_log_tail_from_path("synthetic-geph.stderr", &path, 8);
        fs::remove_file(&path).unwrap();
        let mut snapshot = json!({"logs": {"geph_stderr": tail}});
        sanitize_json(&mut snapshot);
        assert_eq!(
            snapshot["logs"]["geph_stderr"]["lines"],
            json!([
                "state=starting",
                "<sensitive diagnostic record omitted>",
                "state=connected sessions=2",
            ])
        );
        assert!(!snapshot.to_string().contains("synthetic-first"));
        assert!(!snapshot.to_string().contains("synthetic-tail"));
    }

    #[test]
    fn diagnostics_log_tail_omits_multiline_sensitive_payload_before_line_slicing() {
        let path = std::env::temp_dir().join(format!(
            "slipstream-multiline-cookie-test-{}-{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        fs::write(
            &path,
            "event cookie=[\"synthetic-first\",\n\"synthetic-tail\"]\nstate=connected\n",
        )
        .unwrap();
        let tails: Vec<Value> = [8, 2]
            .into_iter()
            .map(|max_lines| {
                diagnostic_log_tail_from_path("synthetic-geph.stderr", &path, max_lines)
            })
            .collect();
        fs::remove_file(path).unwrap();
        for mut tail in tails {
            sanitize_json(&mut tail);
            assert!(!tail.to_string().contains("synthetic-first"));
            assert!(!tail.to_string().contains("synthetic-tail"));
            assert_eq!(
                tail["lines"],
                json!(["<sensitive diagnostic tail omitted>"])
            );
        }
    }

    #[test]
    fn diagnostics_long_cookie_identifier_is_plain_text() {
        let record = format!("{}=not-sensitive", "cookie".repeat(24_000));
        assert!(!contains_opaque_sensitive_field(&record));
        assert_eq!(redact_sensitive_text(&record), record);
    }

    #[test]
    fn diagnostics_geph_byte_truncation_omits_keyless_sensitive_continuations_only() {
        let path = std::env::temp_dir().join(format!(
            "slipstream-truncated-cookie-test-{}-{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let safe_decision = "auto_geo_decision state=local_pending reason=tls_timeout";
        let content = format!(
            "event route_subtree={{\"cookie\":[\n{}\n\"synthetic-keyless-tail\"]}}\n{safe_decision}\n",
            " ".repeat(DIAGNOSTIC_LOG_TAIL_MAX_BYTES as usize + 64),
        );
        fs::write(&path, content).unwrap();
        let mut geph = diagnostic_geph_log_tail_from_path("synthetic-geph.stderr", &path, 8);
        // Generic/root logs retain their existing bounded decision visibility.
        let root = diagnostic_log_tail_from_path("synthetic-root.log", &path, 1);
        fs::remove_file(path).unwrap();
        sanitize_json(&mut geph);
        assert_eq!(
            geph["lines"],
            json!(["<sensitive diagnostic tail omitted>"])
        );
        assert_eq!(geph["available"], true);
        assert_eq!(geph["truncated"], true);
        assert!(!geph.to_string().contains("synthetic-keyless-tail"));
        assert_eq!(root["lines"], json!([safe_decision]));
    }
}
