//! Observation and guarded cleanup boundaries for Slipstream's owned Geph.

use std::fs;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LaunchAgentState {
    Loaded,
    Absent,
    Unknown,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ProcessObservation {
    Present(String),
    Absent,
    Unknown,
}

pub(crate) fn classify_process(
    exit_code: Option<i32>,
    stdout: &str,
    stderr: &str,
) -> ProcessObservation {
    match (exit_code, stdout.trim(), stderr.trim()) {
        (Some(0), command, "") if !command.is_empty() => {
            ProcessObservation::Present(command.to_string())
        }
        (Some(1), "", "") => ProcessObservation::Absent,
        _ => ProcessObservation::Unknown,
    }
}

pub(crate) fn classify_launch_agent(
    exit_code: Option<i32>,
    stdout: &str,
    stderr: &str,
    uid: &str,
    label: &str,
) -> LaunchAgentState {
    if uid.is_empty() || !uid.bytes().all(|byte| byte.is_ascii_digit()) {
        return LaunchAgentState::Unknown;
    }
    let header = format!("gui/{uid}/{label} = {{");
    if exit_code == Some(0) {
        return if stdout.lines().next().map(str::trim) == Some(header.as_str()) {
            LaunchAgentState::Loaded
        } else {
            LaunchAgentState::Unknown
        };
    }
    let missing = format!("Could not find service \"{label}\" in domain for user gui: {uid}");
    if exit_code.is_some_and(|code| code != 0)
        && stderr.lines().any(|line| line.trim() == missing)
        && !stdout.lines().any(|line| line.trim() == header)
    {
        return LaunchAgentState::Absent;
    }
    LaunchAgentState::Unknown
}

/// An accepted/failed bootout request is not proof of terminal state. Observe
/// the exact job after each attempt; unknown observations must retain intent.
pub(crate) fn stop_launch_agent(
    mut observe: impl FnMut() -> LaunchAgentState,
    mut bootout: impl FnMut(),
    mut pause: impl FnMut(),
) -> Result<(), &'static str> {
    match observe() {
        LaunchAgentState::Absent => return Ok(()),
        LaunchAgentState::Unknown => return Err("geph LaunchAgent status unavailable"),
        LaunchAgentState::Loaded => bootout(),
    }
    match observe() {
        LaunchAgentState::Absent => return Ok(()),
        LaunchAgentState::Unknown => return Err("geph LaunchAgent stop unconfirmed"),
        LaunchAgentState::Loaded => bootout(),
    }
    for attempt in 0..20 {
        match observe() {
            LaunchAgentState::Absent => return Ok(()),
            LaunchAgentState::Unknown => return Err("geph LaunchAgent stop unconfirmed"),
            LaunchAgentState::Loaded if attempt < 19 => pause(),
            LaunchAgentState::Loaded => {}
        }
    }
    Err("geph LaunchAgent remains loaded")
}

/// Observe legacy cleanup after each bounded wait, preserving unknown results.
pub(crate) fn wait_for_process_stop(
    mut still_owned: impl FnMut() -> Result<bool, String>,
    mut pause: impl FnMut(),
) -> Result<bool, String> {
    for attempt in 0..=20 {
        if !still_owned()? {
            return Ok(true);
        }
        if attempt < 20 {
            pause();
        }
    }
    Ok(false)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessCensus {
    Clear,
    Candidate,
    Unknown,
}

fn command_contains_path(command: &str, path: &str, directory: bool) -> bool {
    command.match_indices(path).any(|(start, _)| {
        let before = command[..start].chars().next_back();
        let after = command[start + path.len()..].chars().next();
        let boundary = |value: Option<char>| {
            value.is_none_or(|ch| ch.is_whitespace() || matches!(ch, '\'' | '"' | '='))
        };
        boundary(before) && (boundary(after) || (directory && after == Some('/')))
    })
}

/// A negative census is useful only when the complete, wide ps query succeeded.
/// Match private paths conservatively: a shell preparing to exec is also a
/// candidate, and legacy clients can still execute from an old app bundle.
pub(crate) fn classify_process_census(
    exit_code: Option<i32>,
    stdout: &str,
    stderr: &str,
    uid: u32,
    current_pid: u32,
    config: &Path,
    runtime: &Path,
) -> ProcessCensus {
    if exit_code != Some(0) || !stderr.trim().is_empty() || stdout.trim().is_empty() {
        return ProcessCensus::Unknown;
    }
    let config = config.to_string_lossy();
    let runtime = runtime.to_string_lossy();
    let mut saw_current_process = false;
    for line in stdout.lines() {
        let Some((row_uid, rest)) = line.trim_start().split_once(char::is_whitespace) else {
            return ProcessCensus::Unknown;
        };
        // Darwin ps can render system uid_t values as signed 32-bit numbers
        // (for example nobody). Normalize that representation, not the row.
        let Ok(row_uid) = row_uid
            .parse::<u32>()
            .or_else(|_| row_uid.parse::<i32>().map(|value| value as u32))
        else {
            return ProcessCensus::Unknown;
        };
        // Preserve the command remainder: private paths can contain spaces.
        let Some((pid, rest)) = rest.trim_start().split_once(char::is_whitespace) else {
            return ProcessCensus::Unknown;
        };
        let Ok(pid) = pid.parse::<u32>() else {
            return ProcessCensus::Unknown;
        };
        let Some((state, command)) = rest.trim_start().split_once(char::is_whitespace) else {
            return ProcessCensus::Unknown;
        };
        let command = command.trim();
        if state.is_empty() || command.is_empty() {
            return ProcessCensus::Unknown;
        }
        if row_uid != uid || state.starts_with('Z') {
            continue;
        }
        saw_current_process |= pid == current_pid;
        if command_contains_path(command, config.as_ref(), false)
            || command_contains_path(command, runtime.as_ref(), true)
        {
            return ProcessCensus::Candidate;
        }
        if command == "geph5-client" || command == "(geph5-client)" {
            return ProcessCensus::Unknown;
        }
    }
    if saw_current_process {
        ProcessCensus::Clear
    } else {
        ProcessCensus::Unknown
    }
}

pub(crate) fn guarded_ownership_quarantine(
    mut observe_job: impl FnMut() -> LaunchAgentState,
    census: impl FnOnce() -> ProcessCensus,
    quarantine: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    if observe_job() != LaunchAgentState::Absent
        || census() != ProcessCensus::Clear
        || observe_job() != LaunchAgentState::Absent
    {
        return Err("geph malformed ownership cleanup unconfirmed".into());
    }
    quarantine()
}

#[derive(Debug)]
pub(crate) struct OwnershipSnapshot {
    pub(crate) bytes: Vec<u8>,
    metadata: fs::Metadata,
}

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.mode() == right.mode()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

/// Read only an unchanged regular file owned by the current user. Failures are
/// not malformed JSON and never authorize retiring an ownership record.
pub(crate) fn read_ownership_snapshot(
    path: &Path,
    uid: u32,
) -> Result<Option<OwnershipSnapshot>, String> {
    let parent = path.parent().ok_or("geph ownership parent unavailable")?;
    let parent_metadata = match fs::symlink_metadata(parent) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("geph ownership parent unavailable".into()),
    };
    if !parent_metadata.is_dir() || parent_metadata.uid() != uid {
        return Err("geph ownership parent untrusted".into());
    }
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("geph ownership metadata unavailable".into()),
    };
    if !before.is_file() || before.uid() != uid || before.len() > 16 * 1024 {
        return Err("geph ownership file untrusted".into());
    }
    let file = fs::File::open(path).map_err(|_| "geph ownership read unavailable")?;
    let opened = file
        .metadata()
        .map_err(|_| "geph ownership metadata unavailable")?;
    if !same_file(&before, &opened) {
        return Err("geph ownership changed during read".into());
    }
    let mut bytes = Vec::new();
    file.take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "geph ownership read unavailable")?;
    let after = fs::symlink_metadata(path).map_err(|_| "geph ownership metadata unavailable")?;
    if !same_file(&before, &after) || bytes.len() as u64 != before.len() {
        return Err("geph ownership changed during read".into());
    }
    Ok(Some(OwnershipSnapshot {
        bytes,
        metadata: before,
    }))
}

/// Preserve the malformed record without overwriting an earlier quarantine.
/// A concurrently replaced source is never accepted as successful cleanup.
pub(crate) fn quarantine_ownership_file(
    path: &Path,
    expected: &OwnershipSnapshot,
    uid: u32,
) -> Result<PathBuf, String> {
    let unchanged = read_ownership_snapshot(path, uid)?.is_some_and(|current| {
        same_file(&current.metadata, &expected.metadata) && current.bytes == expected.bytes
    });
    if !unchanged {
        return Err("geph ownership changed before quarantine".into());
    }
    static NEXT_QUARANTINE: AtomicU64 = AtomicU64::new(0);
    let parent = path.parent().ok_or("geph ownership parent unavailable")?;
    let quarantine = loop {
        let candidate = parent.join(format!(
            "geph-ownership-quarantine-{}-{}",
            std::process::id(),
            NEXT_QUARANTINE.fetch_add(1, Ordering::Relaxed)
        ));
        match fs::DirBuilder::new().mode(0o700).create(&candidate) {
            Ok(()) => break candidate,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err("geph ownership quarantine unavailable".into()),
        }
    };
    let destination = quarantine.join("geph-owned.json");
    fs::rename(path, &destination).map_err(|_| "geph ownership quarantine unavailable")?;
    let moved = read_ownership_snapshot(&destination, uid);
    // Rename changes ctime, so validate the stable identity and exact bytes.
    let matches = moved.ok().flatten().is_some_and(|current| {
        current.metadata.dev() == expected.metadata.dev()
            && current.metadata.ino() == expected.metadata.ino()
            && current.metadata.mode() == expected.metadata.mode()
            && current.metadata.mtime() == expected.metadata.mtime()
            && current.metadata.mtime_nsec() == expected.metadata.mtime_nsec()
            && current.bytes == expected.bytes
    });
    if !matches {
        // Restore only if the original name is still free; keep the quarantined
        // evidence even when another writer has already recreated that name.
        let _ = fs::hard_link(&destination, path);
        return Err("geph ownership changed during quarantine".into());
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(destination),
        _ => Err("geph ownership recreated during quarantine".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    const LABEL: &str = "dev.slipstream.geph";

    fn census(code: Option<i32>, body: &str, error: &str) -> ProcessCensus {
        classify_process_census(
            code,
            body,
            error,
            502,
            10,
            Path::new(
                "/Users/test/Library/Application Support/dev.slipstream.tray/geph-active.yaml",
            ),
            Path::new("/Users/test/Library/Application Support/dev.slipstream.tray/runtime"),
        )
    }

    const SELF: &str = "502 10 S /Applications/Slipstream.app/Contents/MacOS/slipstream\n";

    #[test]
    fn census_rejects_live_private_clients_in_both_layouts_and_shell_startup() {
        for command in [
            "/Applications/Old Slipstream.app/Contents/MacOS/geph5-client --config /Users/test/Library/Application Support/dev.slipstream.tray/geph-active.yaml",
            "/Users/test/Library/Application Support/dev.slipstream.tray/runtime/geph5-client --config /elsewhere/config",
            "/bin/sh /Users/test/Library/Application Support/dev.slipstream.tray/runtime/geph-launcher",
        ] {
            assert_eq!(census(Some(0), &format!("{SELF}502 20 S {command}\n"), ""), ProcessCensus::Candidate);
        }
    }

    #[test]
    fn census_preserves_external_geph_and_sibling_paths() {
        for command in [
            "/Applications/Geph.app/Contents/MacOS/geph5-client --config /Library/Application Support/geph/config.yaml",
            "/Users/test/Library/Application Support/dev.slipstream.tray/runtime-external/geph5-client --config /external/config",
            "/Applications/Other.app/geph5-client --config /Users/test/Library/Application Support/dev.slipstream.tray/geph-active.yaml.backup",
        ] {
            assert_eq!(census(Some(0), &format!("{SELF}502 20 S {command}\n"), ""), ProcessCensus::Clear);
        }
    }

    #[test]
    fn census_error_or_incomplete_output_never_proves_absence() {
        for (code, body, error) in [
            (None, SELF, ""),
            (Some(1), SELF, ""),
            (Some(0), SELF, "denied"),
            (Some(0), "", ""),
            (Some(0), "502 20 S /other\n", ""),
            (Some(0), "502 broken S /other\n", ""),
            (Some(0), "502 10 S\n", ""),
        ] {
            assert_eq!(census(code, body, error), ProcessCensus::Unknown);
        }
    }

    #[test]
    fn census_accepts_darwin_signed_system_uid_without_skipping_identity_checks() {
        assert_eq!(
            census(
                Some(0),
                &format!("{SELF}-2 20 S /usr/libexec/system-service\n"),
                ""
            ),
            ProcessCensus::Clear,
        );
        assert_eq!(
            census(
                Some(0),
                &format!("{SELF}-2 broken S /usr/libexec/system-service\n"),
                ""
            ),
            ProcessCensus::Unknown,
        );
        assert_eq!(
            classify_process_census(
                Some(0),
                "-2 10 S /private/runtime/geph5-client\n",
                "",
                (-2i32) as u32,
                10,
                Path::new("/private/geph-active.yaml"),
                Path::new("/private/runtime")
            ),
            ProcessCensus::Candidate,
        );
        assert_eq!(
            census(Some(0), "-2 10 S /usr/libexec/system-service\n", ""),
            ProcessCensus::Unknown,
        );
    }

    #[test]
    fn census_uid_normalization_is_bounded_to_32_bits() {
        for (printed, uid) in [("-2147483648", 2147483648u32), ("-1", u32::MAX)] {
            assert_eq!(
                classify_process_census(
                    Some(0),
                    &format!("{printed} 10 S /private/runtime/geph5-client\n"),
                    "",
                    uid,
                    10,
                    Path::new("/private/geph-active.yaml"),
                    Path::new("/private/runtime"),
                ),
                ProcessCensus::Candidate,
            );
        }
        for printed in ["-2147483649", "+4294967296", "-4294966794"] {
            assert_eq!(
                census(
                    Some(0),
                    &format!("{SELF}{printed} 20 S /usr/libexec/system-service\n"),
                    ""
                ),
                ProcessCensus::Unknown,
            );
        }
    }

    #[test]
    fn quarantine_guard_rejects_unknown_present_and_reappeared_job() {
        use LaunchAgentState::{Absent, Loaded, Unknown};
        for (before, processes, after) in [
            (Unknown, ProcessCensus::Clear, Absent),
            (Loaded, ProcessCensus::Clear, Absent),
            (Absent, ProcessCensus::Candidate, Absent),
            (Absent, ProcessCensus::Unknown, Absent),
            (Absent, ProcessCensus::Clear, Loaded),
            (Absent, ProcessCensus::Clear, Unknown),
        ] {
            let mut jobs = [before, after].into_iter();
            assert!(guarded_ownership_quarantine(
                || jobs.next().unwrap(),
                || processes,
                || panic!("unconfirmed absence must not quarantine"),
            )
            .is_err());
        }
        let mut retired = false;
        assert_eq!(
            guarded_ownership_quarantine(
                || Absent,
                || ProcessCensus::Clear,
                || {
                    retired = true;
                    Ok(())
                },
            ),
            Ok(())
        );
        assert!(retired);
    }

    struct TestDirectory(PathBuf);
    impl TestDirectory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "slipstream-geph-quarantine-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
        fn uid(&self) -> u32 {
            fs::metadata(&self.0).unwrap().uid()
        }
        fn record(&self) -> PathBuf {
            let path = self.0.join("geph-owned.json");
            fs::write(&path, b"{broken legacy ownership\n").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            path
        }
    }
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn quarantine_preserves_exact_bytes_in_private_unique_directory() {
        let directory = TestDirectory::new();
        let path = directory.record();
        let snapshot = read_ownership_snapshot(&path, directory.uid())
            .unwrap()
            .unwrap();
        let backup = quarantine_ownership_file(&path, &snapshot, directory.uid()).unwrap();
        assert!(!path.exists());
        assert_eq!(fs::read(&backup).unwrap(), snapshot.bytes);
        assert_eq!(
            fs::metadata(backup.parent().unwrap()).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(fs::metadata(backup).unwrap().mode() & 0o777, 0o600);
    }

    #[test]
    fn changed_record_cannot_be_retired_and_keeps_new_bytes() {
        let directory = TestDirectory::new();
        let path = directory.record();
        let snapshot = read_ownership_snapshot(&path, directory.uid())
            .unwrap()
            .unwrap();
        fs::write(&path, b"replacement ownership").unwrap();
        assert!(quarantine_ownership_file(&path, &snapshot, directory.uid()).is_err());
        assert_eq!(fs::read(path).unwrap(), b"replacement ownership");
    }

    #[test]
    fn symlink_foreign_owner_and_oversized_records_are_untrusted() {
        let directory = TestDirectory::new();
        let path = directory.record();
        let link = directory.0.join("linked-record");
        symlink(&path, &link).unwrap();
        assert!(read_ownership_snapshot(&link, directory.uid()).is_err());
        assert!(read_ownership_snapshot(&path, directory.uid().wrapping_add(1)).is_err());
        let parent_link = directory.0.join("linked-parent");
        symlink(&directory.0, &parent_link).unwrap();
        assert!(
            read_ownership_snapshot(&parent_link.join("geph-owned.json"), directory.uid()).is_err()
        );
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(16 * 1024 + 1)
            .unwrap();
        assert!(read_ownership_snapshot(&path, directory.uid()).is_err());
    }

    #[test]
    fn absent_record_in_absent_parent_is_already_clean() {
        let directory = TestDirectory::new();
        assert!(read_ownership_snapshot(
            &directory.0.join("absent/geph-owned.json"),
            directory.uid()
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn process_exit_during_final_wait_is_observed() {
        let mut observations = 0;
        let mut waits = 0;
        let stopped = wait_for_process_stop(
            || {
                observations += 1;
                Ok(observations <= 20)
            },
            || waits += 1,
        );
        assert_eq!(stopped, Ok(true));
        assert_eq!(waits, 20);
        assert_eq!(observations, 21);
    }

    #[test]
    fn final_process_observation_error_does_not_confirm_cleanup() {
        let mut observations = 0;
        let stopped = wait_for_process_stop(
            || {
                observations += 1;
                if observations <= 20 {
                    Ok(true)
                } else {
                    Err("process query unavailable".into())
                }
            },
            || {},
        );
        assert!(stopped.is_err());
    }

    #[test]
    fn process_query_error_cannot_prove_legacy_cleanup() {
        for (code, stdout, stderr) in [
            (None, "", ""),
            (Some(1), "", "Operation not permitted"),
            (Some(2), "", ""),
            (Some(0), "", ""),
        ] {
            assert_eq!(
                classify_process(code, stdout, stderr),
                ProcessObservation::Unknown
            );
        }
        assert_eq!(
            classify_process(Some(1), "", ""),
            ProcessObservation::Absent
        );
        assert_eq!(
            classify_process(Some(0), "/owned/geph --config /owned/config\n", ""),
            ProcessObservation::Present("/owned/geph --config /owned/config".into())
        );
    }

    #[test]
    fn query_failure_does_not_prove_absence() {
        assert_eq!(
            classify_launch_agent(Some(1), "", "Operation not permitted", "502", LABEL),
            LaunchAgentState::Unknown
        );
    }

    #[test]
    fn interrupted_query_does_not_prove_absence() {
        assert_eq!(
            classify_launch_agent(None, "", "", "502", LABEL),
            LaunchAgentState::Unknown
        );
    }

    #[test]
    fn absence_requires_the_exact_job_and_user() {
        let missing = format!(
            "Bad request.\nCould not find service \"{LABEL}\" in domain for user gui: 502\n"
        );
        assert_eq!(
            classify_launch_agent(Some(113), "", &missing, "502", LABEL),
            LaunchAgentState::Absent
        );
        for (uid, label) in [("503", LABEL), ("502", "dev.other.geph"), ("", LABEL)] {
            assert_eq!(
                classify_launch_agent(Some(113), "", &missing, uid, label),
                LaunchAgentState::Unknown
            );
        }
        assert_eq!(
            classify_launch_agent(None, "", &missing, "502", LABEL),
            LaunchAgentState::Unknown
        );
    }

    #[test]
    fn loaded_requires_success_and_exact_job_header() {
        let header = format!("gui/502/{LABEL} = {{\n  active count = 1\n}}\n");
        assert_eq!(
            classify_launch_agent(Some(0), &header, "", "502", LABEL),
            LaunchAgentState::Loaded
        );
        for (code, stdout, uid) in [
            (Some(0), "", "502"),
            (Some(0), header.as_str(), "503"),
            (Some(1), header.as_str(), "502"),
        ] {
            assert_eq!(
                classify_launch_agent(code, stdout, "", uid, LABEL),
                LaunchAgentState::Unknown
            );
        }
    }

    #[test]
    fn unknown_query_never_reports_stopped_or_mutates_a_job() {
        let result = stop_launch_agent(
            || LaunchAgentState::Unknown,
            || panic!("unknown state cannot authorize bootout"),
            || panic!("unknown state cannot be retried as loaded"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn bootout_followed_by_unknown_query_does_not_report_stopped() {
        let mut observed = [LaunchAgentState::Loaded, LaunchAgentState::Unknown].into_iter();
        let mut attempts = 0;
        let result = stop_launch_agent(
            || observed.next().unwrap(),
            || attempts += 1,
            || panic!("unknown observation must stop polling"),
        );
        assert!(result.is_err());
        assert_eq!(attempts, 1);
    }

    #[test]
    fn rejected_bootouts_with_surviving_job_do_not_report_stopped() {
        let mut attempts = 0;
        let mut waits = 0;
        let result =
            stop_launch_agent(|| LaunchAgentState::Loaded, || attempts += 1, || waits += 1);
        assert!(result.is_err());
        assert_eq!(attempts, 2);
        assert_eq!(waits, 19);
    }

    #[test]
    fn confirmed_absence_finishes_stop_without_fallback() {
        let mut observed = [LaunchAgentState::Loaded, LaunchAgentState::Absent].into_iter();
        let mut attempts = 0;
        let result = stop_launch_agent(
            || observed.next().unwrap(),
            || attempts += 1,
            || panic!("already absent"),
        );
        assert_eq!(result, Ok(()));
        assert_eq!(attempts, 1);
    }

    #[test]
    fn delayed_absence_after_retry_is_accepted() {
        use LaunchAgentState::{Absent, Loaded};
        let mut observed = [Loaded, Loaded, Loaded, Absent].into_iter();
        let mut attempts = 0;
        let mut waits = 0;
        let result =
            stop_launch_agent(|| observed.next().unwrap(), || attempts += 1, || waits += 1);
        assert_eq!(result, Ok(()));
        assert_eq!(attempts, 2);
        assert_eq!(waits, 1);
    }

    #[test]
    fn already_absent_requires_no_bootout() {
        assert_eq!(
            stop_launch_agent(
                || LaunchAgentState::Absent,
                || panic!("already absent"),
                || panic!("already absent")
            ),
            Ok(())
        );
    }
}
