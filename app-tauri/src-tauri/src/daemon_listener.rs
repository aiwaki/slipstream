//! Current daemon listener evidence, not a replacement for process/install checks.
//!
//! The root daemon samples its own live listening sockets for every heartbeat.
//! Only this fixed, trusted publication may fill a missing unprivileged kernel
//! observation. Callers must still reject an observed different listener owner.

use serde_json::Value;
use std::fs::{self, Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const STATUS_PATH: &str = "/private/var/run/slipstream.status";
const MAX_STATUS_BYTES: u64 = 64 * 1024;
const MAX_AGE_SECONDS: f64 = 6.0;

pub(crate) fn witnessed_listener_pid(expected_pid: u32, port: u16) -> Option<u32> {
    for parent in ["/private", "/private/var", "/private/var/run"] {
        let metadata = fs::symlink_metadata(parent).ok()?;
        if !trusted_parent(
            parent,
            metadata.file_type().is_dir(),
            metadata.uid(),
            metadata.gid(),
            metadata.mode(),
        ) {
            return None;
        }
    }
    let (status, modified) = read_snapshot_at(Path::new(STATUS_PATH), 0)?;
    // Sample the clock after the bounded read: a publication that arrived
    // during open/read must not look artificially future-dated.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs_f64();
    if !fresh(modified, now) {
        return None;
    }
    witness_from_value(&status, expected_pid, port, now)
}

fn trusted_parent(path: &str, is_directory: bool, uid: u32, gid: u32, mode: u32) -> bool {
    if !matches!(path, "/private" | "/private/var" | "/private/var/run")
        || !is_directory
        || uid != 0
    {
        return false;
    }
    let permissions = mode & 0o7777;
    if permissions & 0o022 == 0 {
        return true;
    }
    // Stock macOS permits root:daemon to write this exact runtime directory.
    // That group may deny access or replay a root-authored inode within the
    // existing six-second lease, but cannot mint UID 0 file contents or alter
    // their mtime. The final nofollow, non-writable, single-link root descriptor
    // remains mandatory; no other writable ancestor receives this exception.
    path == "/private/var/run" && gid == 1 && permissions == 0o775
}

fn safe_metadata(metadata: &Metadata, expected_uid: u32) -> bool {
    metadata.file_type().is_file()
        && metadata.uid() == expected_uid
        && metadata.nlink() == 1
        && metadata.mode() & 0o022 == 0
        && metadata.len() <= MAX_STATUS_BYTES
}

fn same_snapshot(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
        && before.uid() == after.uid()
        && before.mode() == after.mode()
        && before.nlink() == after.nlink()
}

fn fresh(timestamp: f64, now: f64) -> bool {
    timestamp.is_finite()
        && now.is_finite()
        && timestamp > 0.0
        && (0.0..=MAX_AGE_SECONDS).contains(&(now - timestamp))
}

// The producer emits UTC with exactly millisecond precision. Reject other
// formats instead of adding a permissive date parser to an ownership boundary.
fn heartbeat_epoch(raw: &str) -> Option<f64> {
    let bytes = raw.as_bytes();
    if bytes.len() != 24
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'.'
        || bytes[23] != b'Z'
    {
        return None;
    }
    let number = |start: usize, end: usize| -> Option<i32> {
        bytes[start..end].iter().try_fold(0, |value, byte| {
            byte.is_ascii_digit()
                .then(|| value * 10 + i32::from(byte - b'0'))
        })
    };
    let fields = (
        number(0, 4)? - 1900,
        number(5, 7)? - 1,
        number(8, 10)?,
        number(11, 13)?,
        number(14, 16)?,
        number(17, 19)?,
    );
    // SAFETY: libc::tm contains integer/pointer fields for which zero is valid;
    // timegm receives one initialized, exclusively borrowed local structure.
    let mut date: libc::tm = unsafe { std::mem::zeroed() };
    (
        date.tm_year,
        date.tm_mon,
        date.tm_mday,
        date.tm_hour,
        date.tm_min,
        date.tm_sec,
    ) = fields;
    let seconds = unsafe { libc::timegm(&mut date) };
    // timegm normalizes out-of-range dates; normalized input is not evidence.
    if seconds < 0
        || (
            date.tm_year,
            date.tm_mon,
            date.tm_mday,
            date.tm_hour,
            date.tm_min,
            date.tm_sec,
        ) != fields
    {
        return None;
    }
    Some(seconds as f64 + f64::from(number(20, 23)?) / 1000.0)
}

fn witness_from_value(status: &Value, expected_pid: u32, port: u16, now: f64) -> Option<u32> {
    if expected_pid <= 1 || port == 0 || status.get("schema_version")?.as_u64()? != 2 {
        return None;
    }
    let daemon = status.get("daemon")?;
    if daemon.get("pid")?.as_u64()? != u64::from(expected_pid)
        || daemon.get("state")?.as_str()? != "active"
        || daemon.get("phase")?.as_str()? != "active"
        || daemon.get("heartbeat_seq")?.as_u64()? == 0
    {
        return None;
    }
    let pf = status.get("environment")?.get("pf")?;
    if pf.get("state")?.as_str()? != "ready"
        || !pf.get("applied")?.as_bool()?
        || !pf.get("enabled")?.as_bool()?
        || !pf.get("rules_loaded")?.as_bool()?
    {
        return None;
    }
    let witness = daemon.get("listener_ownership")?.as_object()?;
    if witness.len() != 4
        || witness.get("schema_version")?.as_u64()? != 1
        || witness.get("pid")?.as_u64()? != u64::from(expected_pid)
    {
        return None;
    }
    let sampled_at = witness.get("sampled_at")?.as_f64()?;
    let heartbeat_at = heartbeat_epoch(daemon.get("heartbeat_at")?.as_str()?)?;
    let updated_at = daemon.get("updated_at")?.as_f64()?;
    if !fresh(sampled_at, now)
        || !fresh(heartbeat_at, now)
        || !fresh(updated_at, now)
        || (updated_at - sampled_at).abs() > 0.002
        || (sampled_at - heartbeat_at).abs() > 0.002
    {
        return None;
    }
    let listeners = witness.get("listeners")?.as_array()?;
    if listeners.is_empty() || listeners.len() > 2 {
        return None;
    }
    let mut ipv4 = false;
    let mut ipv6 = false;
    for listener in listeners {
        let listener = listener.as_object()?;
        if listener.len() != 2 || listener.get("port")?.as_u64()? != u64::from(port) {
            return None;
        }
        match listener.get("address")?.as_str()? {
            "127.0.0.1" if !ipv4 => ipv4 = true,
            "::1" if !ipv6 => ipv6 = true,
            _ => return None,
        }
    }
    ipv4.then_some(expected_pid)
}

// Private injection supports unprivileged temporary fixtures; the public entry
// point above always uses the fixed protected path and UID 0.
fn read_snapshot_at(path: &Path, expected_uid: u32) -> Option<(Value, f64)> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .ok()?;
    let before = file.metadata().ok()?;
    if !safe_metadata(&before, expected_uid) {
        return None;
    }
    let modified = before
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs_f64();
    let mut raw = Vec::with_capacity(before.len() as usize);
    file.by_ref()
        .take(MAX_STATUS_BYTES + 1)
        .read_to_end(&mut raw)
        .ok()?;
    let after = file.metadata().ok()?;
    if raw.len() as u64 > MAX_STATUS_BYTES
        || !safe_metadata(&after, expected_uid)
        || !same_snapshot(&before, &after)
    {
        return None;
    }
    Some((serde_json::from_slice(&raw).ok()?, modified))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::time::Duration;

    const NOW: f64 = 1_700_000_005.0;
    const PID: u32 = 4321;

    fn read_witness_at(
        path: &Path,
        expected_pid: u32,
        port: u16,
        now: f64,
        expected_uid: u32,
    ) -> Option<u32> {
        let (status, modified) = read_snapshot_at(path, expected_uid)?;
        if !fresh(modified, now) {
            return None;
        }
        witness_from_value(&status, expected_pid, port, now)
    }

    fn status() -> Value {
        json!({"schema_version":2,"environment":{"pf":{
            "state":"ready","applied":true,"enabled":true,"rules_loaded":true
        }},"daemon":{
            "pid":PID,"state":"active","phase":"active","heartbeat_seq":7,
            "updated_at":1_700_000_004.0,"heartbeat_at":"2023-11-14T22:13:24.000Z",
            "listener_ownership":{"schema_version":1,"pid":PID,"sampled_at":1_700_000_004.0,
                "listeners":[{"address":"127.0.0.1","port":1080},{"address":"::1","port":1080}]}
        }})
    }

    fn fixture(raw: &[u8]) -> (tempfile::TempDir, std::path::PathBuf, u32) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status");
        fs::write(&path, raw).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let file = fs::File::open(&path).unwrap();
        file.set_times(
            fs::FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(1_700_000_004)),
        )
        .unwrap();
        let owner = file.metadata().unwrap().uid();
        (directory, path, owner)
    }

    #[test]
    fn parent_policy_allows_only_exact_macos_runtime_directory_exception() {
        for path in ["/private", "/private/var", "/private/var/run"] {
            assert!(trusted_parent(path, true, 0, 0, 0o40755));
        }
        assert!(trusted_parent("/private/var/run", true, 0, 1, 0o40775));
        for (path, directory, uid, gid, mode) in [
            ("/private/var/run", true, 501, 1, 0o775),
            ("/private/var/run", true, 0, 0, 0o775),
            ("/private/var/run", true, 0, 80, 0o775),
            ("/private/var/run", true, 0, 1, 0o777),
            ("/private/var/run", true, 0, 1, 0o2775),
            ("/private/var/run", false, 0, 1, 0o775),
            ("/private/var", true, 0, 1, 0o775),
            ("/private", true, 0, 1, 0o775),
            ("/var/run", true, 0, 1, 0o775),
            ("/tmp", true, 0, 0, 0o755),
        ] {
            assert!(
                !trusted_parent(path, directory, uid, gid, mode),
                "{path} {uid}:{gid} {mode:o}"
            );
        }
    }

    #[test]
    fn current_root_publication_with_loopback_listeners_is_accepted() {
        let (_directory, path, uid) = fixture(&serde_json::to_vec(&status()).unwrap());
        assert_eq!(read_witness_at(&path, PID, 1080, NOW, uid), Some(PID));
        let mut fractional = status();
        fractional["daemon"]["updated_at"] = json!(1_700_000_004.123456);
        fractional["daemon"]["heartbeat_at"] = json!("2023-11-14T22:13:24.123Z");
        fractional["daemon"]["listener_ownership"]["sampled_at"] = json!(1_700_000_004.123);
        assert_eq!(witness_from_value(&fractional, PID, 1080, NOW), Some(PID));
        let mut ipv4_only = status();
        ipv4_only["daemon"]["listener_ownership"]["listeners"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert_eq!(witness_from_value(&ipv4_only, PID, 1080, NOW), Some(PID));
    }

    #[test]
    fn publication_requires_both_current_expected_process_ids() {
        assert_eq!(witness_from_value(&status(), PID + 1, 1080, NOW), None);
        for field in ["pid", "listener_ownership/pid"] {
            let mut value = status();
            *value.pointer_mut(&format!("/daemon/{field}")).unwrap() = json!(PID + 1);
            assert_eq!(witness_from_value(&value, PID, 1080, NOW), None);
        }
        assert_eq!(witness_from_value(&status(), 1, 1080, NOW), None);
    }

    #[test]
    fn unavailable_inactive_or_malformed_listener_evidence_is_rejected() {
        let changes = [
            ("/schema_version", json!(1)),
            ("/environment/pf/state", json!("unknown")),
            ("/environment/pf/applied", json!(false)),
            ("/environment/pf/enabled", json!(false)),
            ("/environment/pf/rules_loaded", json!(false)),
            ("/daemon/state", json!("dormant")),
            ("/daemon/phase", json!("stopping")),
            ("/daemon/heartbeat_seq", json!(0)),
            ("/daemon/listener_ownership", Value::Null),
            ("/daemon/listener_ownership/schema_version", json!(2)),
            ("/daemon/listener_ownership/listeners", json!([])),
            (
                "/daemon/listener_ownership/listeners",
                json!([{"address":"::1","port":1080}]),
            ),
            (
                "/daemon/listener_ownership/listeners/0/address",
                json!("0.0.0.0"),
            ),
            (
                "/daemon/listener_ownership/listeners/1/address",
                json!("127.0.0.1"),
            ),
            ("/daemon/listener_ownership/listeners/0/port", json!(9954)),
            ("/daemon/listener_ownership/listeners/0/port", json!("1080")),
        ];
        for (path, replacement) in changes {
            let mut value = status();
            *value.pointer_mut(path).unwrap() = replacement;
            assert_eq!(witness_from_value(&value, PID, 1080, NOW), None, "{path}");
        }
    }

    #[test]
    fn heartbeat_and_listener_sample_must_be_fresh_and_same_generation() {
        assert_eq!(witness_from_value(&status(), PID, 1080, NOW + 6.0), None);
        assert_eq!(witness_from_value(&status(), PID, 1080, NOW - 2.0), None);
        for (path, replacement) in [
            ("/daemon/updated_at", json!(1_700_000_003.0)),
            ("/daemon/heartbeat_at", json!("2023-11-14T22:13:23.000Z")),
            ("/daemon/heartbeat_at", json!("2023-11-14T22:13:26.000Z")),
            (
                "/daemon/listener_ownership/sampled_at",
                json!(1_700_000_000.0),
            ),
            ("/daemon/listener_ownership/sampled_at", json!("NaN")),
        ] {
            let mut value = status();
            *value.pointer_mut(path).unwrap() = replacement;
            assert_eq!(witness_from_value(&value, PID, 1080, NOW), None, "{path}");
        }
        assert!(!fresh(f64::NAN, NOW));
        assert!(!fresh(f64::INFINITY, NOW));
        assert!(!fresh(NOW, f64::INFINITY));
    }

    #[test]
    fn heartbeat_parser_rejects_invalid_calendar_or_noncanonical_utc() {
        assert_eq!(
            heartbeat_epoch("2023-11-14T22:13:20.123Z"),
            Some(1_700_000_000.123)
        );
        for raw in [
            "",
            "2023-11-14T22:13:20Z",
            "2023-11-14T22:13:20.123+00:00",
            "2023-02-30T22:13:20.000Z",
            "2023-11-14T25:13:20.000Z",
            "2023-11-14T22:13:60.000Z",
            "2023-11-14T22:13:20.nanZ",
        ] {
            assert_eq!(heartbeat_epoch(raw), None, "{raw}");
        }
    }

    #[test]
    fn status_file_owner_writable_mode_and_hardlinks_are_rejected() {
        let (directory, path, uid) = fixture(&serde_json::to_vec(&status()).unwrap());
        assert_eq!(
            read_witness_at(&path, PID, 1080, NOW, uid.wrapping_add(1)),
            None
        );
        for mode in [0o664, 0o646, 0o666] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(read_witness_at(&path, PID, 1080, NOW, uid), None);
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::hard_link(&path, directory.path().join("second-link")).unwrap();
        assert_eq!(read_witness_at(&path, PID, 1080, NOW, uid), None);
    }

    #[test]
    fn symlink_fifo_and_directory_cannot_supply_listener_evidence() {
        let (directory, path, uid) = fixture(&serde_json::to_vec(&status()).unwrap());
        let link = directory.path().join("symlink");
        symlink(&path, &link).unwrap();
        assert_eq!(read_witness_at(&link, PID, 1080, NOW, uid), None);
        assert_eq!(read_witness_at(directory.path(), PID, 1080, NOW, uid), None);
        let fifo = directory.path().join("fifo");
        let fifo_c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid terminated temporary path, with no other FIFO user.
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        assert_eq!(read_witness_at(&fifo, PID, 1080, NOW, uid), None);
    }

    #[test]
    fn oversized_or_invalid_status_is_rejected() {
        for raw in [
            vec![b' '; MAX_STATUS_BYTES as usize + 1],
            b"not json".to_vec(),
        ] {
            let (_directory, path, uid) = fixture(&raw);
            assert_eq!(read_witness_at(&path, PID, 1080, NOW, uid), None);
        }
    }

    #[test]
    fn publication_mtime_cannot_be_stale_or_in_the_future() {
        let (_directory, path, uid) = fixture(&serde_json::to_vec(&status()).unwrap());
        let file = fs::File::open(&path).unwrap();
        for modified in [1_699_999_998, 1_700_000_006] {
            file.set_times(
                fs::FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(modified)),
            )
            .unwrap();
            assert_eq!(read_witness_at(&path, PID, 1080, NOW, uid), None);
        }
    }

    #[test]
    fn metadata_change_during_read_is_not_a_stable_publication() {
        let (_directory, path, _uid) = fixture(&serde_json::to_vec(&status()).unwrap());
        let file = fs::File::open(&path).unwrap();
        let before = file.metadata().unwrap();
        assert!(same_snapshot(&before, &file.metadata().unwrap()));
        file.set_times(
            fs::FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(1_700_000_003)),
        )
        .unwrap();
        assert!(!same_snapshot(&before, &file.metadata().unwrap()));
    }
}
