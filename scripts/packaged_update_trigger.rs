//! Disposable-CI entry point for OLD production preparation, not an app CLI.
//! The installed OLD watchdog and the real successor own all later decisions.

use crate::app_update;
use crate::updater_transaction::{self, daemon_update, AuthorizationOutcome};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PREPARATION_LEASE_LIMIT: Duration = Duration::from_secs(300);
const AUTHORIZATION_CLEANUP_LIMIT: Duration = Duration::from_secs(5);

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    version: String,
    source_commit: String,
    archive_sha256: String,
    app_executable_sha256: String,
    daemon_sha256: String,
    bundle_tree_sha256: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Pair<T> {
    old: T,
    new: T,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PinnedFile {
    path: PathBuf,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema_version: u8,
    uid: u32,
    runner_temp: PathBuf,
    output_dir: PathBuf,
    pair: PinnedFile,
    manifests: Pair<PinnedFile>,
    archive_path: PathBuf,
    signature: PinnedFile,
    expected: Pair<Artifact>,
}

#[derive(Serialize)]
struct Receipt {
    schema_version: u8,
    // Preparation/root acceptance is not an ACK or a committed transaction.
    prepared: bool,
    journal_path: Option<PathBuf>,
    initiator_pid: u32,
    identity: Option<daemon_update::PrepareIdentity>,
    expected: Pair<Artifact>,
    error: Option<String>,
}

fn require(ok: bool, message: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

fn bounded_file(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| format!("cannot open pinned file: {e}"))?;
    let info = file.metadata().map_err(|e| e.to_string())?;
    require(
        info.is_file() && info.len() <= limit as u64,
        "pinned input is not a bounded regular file",
    )?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    require(bytes.len() <= limit, "pinned input grew beyond its bound")?;
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn verify_file(pin: &PinnedFile, limit: usize) -> Result<Vec<u8>, String> {
    let bytes = bounded_file(&pin.path, limit)?;
    require(sha256(&bytes) == pin.sha256, "pinned input digest changed")?;
    Ok(bytes)
}

fn verify_signature(archive: &[u8], signature: &str, key: &str) -> Result<(), String> {
    let key = app_update::decode_public_key(key)?;
    let signature = app_update::decode_signature(signature.trim())?;
    let mut verifier = key
        .verify_stream(&signature)
        .map_err(|_| "signature does not match OLD updater key".to_owned())?;
    verifier.update(archive);
    verifier
        .finalize()
        .map_err(|_| "archive signature verification failed".to_owned())
}

fn validate_identity(
    identity: &daemon_update::PrepareIdentity,
    expected: &Pair<Artifact>,
    uid: u32,
) -> Result<(), String> {
    require(
        identity.schema_version == 1
            && identity.uid == uid
            && identity.old_version == expected.old.version
            && identity.new_version == expected.new.version
            && identity.archive_sha256 == expected.new.archive_sha256
            && identity.old_app_executable_sha256 == expected.old.app_executable_sha256
            && identity.new_app_executable_sha256 == expected.new.app_executable_sha256
            && identity.old_daemon_sha256 == expected.old.daemon_sha256
            && identity.new_daemon_sha256 == expected.new.daemon_sha256
            && identity.old_bundle_tree_sha256 == expected.old.bundle_tree_sha256
            && identity.new_bundle_tree_sha256 == expected.new.bundle_tree_sha256,
        "production preparation differs from authenticated pair",
    )
}

fn authorization_exit(code: Option<i32>) -> AuthorizationOutcome {
    match code {
        Some(0) => AuthorizationOutcome::Completed,
        // Only the fixed production --update-prepare command can return this
        // reserved no-operation result. sudo's ordinary failure is uncertain.
        Some(77) => AuthorizationOutcome::NotExecuted("root preparer proved no operation".into()),
        _ => AuthorizationOutcome::Uncertain(format!("root preparation exit: {code:?}")),
    }
}

fn unix_seconds() -> u64 {
    // A clock before the epoch cannot establish a live authorization lease.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .unwrap_or(u64::MAX)
}

fn authorization_remaining(
    deadline_unix: u64,
    started_unix: u64,
    elapsed: Duration,
    now_unix: u64,
) -> Duration {
    Duration::from_secs(deadline_unix.saturating_sub(started_unix))
        .min(PREPARATION_LEASE_LIMIT)
        .saturating_sub(elapsed)
        .min(Duration::from_secs(deadline_unix.saturating_sub(now_unix)))
}

fn wait_for_authorization(
    mut remaining: impl FnMut() -> Duration,
    mut poll: impl FnMut() -> std::io::Result<Option<ExitStatus>>,
    mut sleep: impl FnMut(Duration),
) -> Result<ExitStatus, String> {
    loop {
        let budget = remaining();
        if budget.is_zero() {
            return Err("root preparation lease expired".into());
        }
        match poll().map_err(|error| format!("root preparation wait failed: {error}"))? {
            Some(status) => {
                // A completed child first observed after expiry is not ready.
                if remaining().is_zero() {
                    return Err("root preparation lease expired".into());
                }
                return Ok(status);
            }
            None => sleep(budget.min(Duration::from_millis(100))),
        }
    }
}

fn authorize(identity: &daemon_update::PrepareIdentity) -> AuthorizationOutcome {
    let argument = match serde_json::to_string(identity) {
        Ok(value) => value,
        Err(error) => return AuthorizationOutcome::NotExecuted(error.to_string()),
    };
    // Include spawn time in the immutable preparation budget, and never grant
    // another full lease when the clock moves backwards.
    let started = Instant::now();
    let started_unix = unix_seconds();
    let remaining = || {
        authorization_remaining(
            identity.prepare_deadline_unix,
            started_unix,
            started.elapsed(),
            unix_seconds(),
        )
    };
    if remaining().is_zero() {
        return AuthorizationOutcome::NotExecuted("preparation lease expired before spawn".into());
    }
    let mut child = match Command::new("/usr/bin/sudo")
        .args([
            "-n",
            "/usr/local/slipstream/slipstreamd",
            "--update-prepare",
            &argument,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => return AuthorizationOutcome::Uncertain(error.to_string()),
    };
    match wait_for_authorization(remaining, || child.try_wait(), thread::sleep) {
        Ok(status) => authorization_exit(status.code()),
        Err(error) => {
            // This grace is only for terminating/reaping our child. It cannot
            // make an expired preparation successful or renew its root lease.
            // Killing sudo does not prove privileged descendants have stopped.
            let cleanup_started = Instant::now();
            let _ = child.kill();
            let _ = wait_for_authorization(
                || AUTHORIZATION_CLEANUP_LIMIT.saturating_sub(cleanup_started.elapsed()),
                || child.try_wait(),
                thread::sleep,
            );
            AuthorizationOutcome::Uncertain(error)
        }
    }
}

fn guard_values(is_macos: bool, ci: bool, uid: u32, euid: u32, console: u32) -> Result<(), String> {
    require(
        is_macos && ci && uid > 0 && euid == uid && console == uid,
        "requires an unprivileged console user on disposable hosted macOS",
    )
}

fn runtime_guard(plan: &Plan) -> Result<(), String> {
    let ci = [
        ("CI", "true"),
        ("GITHUB_ACTIONS", "true"),
        ("SLIPSTREAM_DISPOSABLE_CI", "1"),
        ("RUNNER_OS", "macOS"),
    ]
    .iter()
    .all(|(key, value)| std::env::var(key).as_deref() == Ok(*value));
    let console = fs::metadata("/dev/console")
        .map_err(|e| e.to_string())?
        .uid();
    let uid = unsafe { libc::getuid() };
    guard_values(
        cfg!(target_os = "macos"),
        ci,
        uid,
        unsafe { libc::geteuid() },
        console,
    )?;
    require(
        plan.schema_version == 1 && plan.uid == uid,
        "compiled plan UID mismatch",
    )?;
    let runner = PathBuf::from(std::env::var_os("RUNNER_TEMP").ok_or("RUNNER_TEMP missing")?)
        .canonicalize()
        .map_err(|e| e.to_string())?;
    require(runner == plan.runner_temp, "compiled runner path changed")?;
    let info = fs::symlink_metadata(&plan.output_dir).map_err(|e| e.to_string())?;
    require(
        info.is_dir()
            && !info.file_type().is_symlink()
            && info.uid() == uid
            && info.mode() & 0o777 == 0o700
            && plan.output_dir.parent() == Some(runner.as_path()),
        "unsafe trigger output directory",
    )
}

fn preflight(plan: &Plan) -> Result<Vec<u8>, String> {
    verify_file(&plan.pair, 1024 * 1024)?;
    verify_file(&plan.manifests.old, 1024 * 1024)?;
    verify_file(&plan.manifests.new, 1024 * 1024)?;
    let archive = bounded_file(&plan.archive_path, app_update::MAX_UPDATE_ARCHIVE_BYTES)?;
    require(
        sha256(&archive) == plan.expected.new.archive_sha256,
        "candidate archive changed",
    )?;
    let signature = verify_file(&plan.signature, 16 * 1024)?;
    verify_signature(
        &archive,
        std::str::from_utf8(&signature).map_err(|e| e.to_string())?,
        crate::OLD_PUBLIC_KEY,
    )?;
    let old_version =
        semver::Version::parse(&plan.expected.old.version).map_err(|e| e.to_string())?;
    let new_version =
        semver::Version::parse(&plan.expected.new.version).map_err(|e| e.to_string())?;
    require(
        new_version > old_version,
        "candidate does not advance the OLD version",
    )?;
    app_update::validate_macos_archive(&archive, &new_version)?;
    let target = Path::new(daemon_update::TARGET);
    require(
        daemon_update::bundle_tree_sha256(target)? == plan.expected.old.bundle_tree_sha256,
        "installed OLD app differs from authenticated candidate",
    )?;
    // No invented old-tray identity. This trigger qualifies preparation and
    // watchdog/ACK, while the ordinary tray Quit gate remains separate.
    let status = Command::new("/usr/bin/pgrep")
        .args(["-x", "slipstream"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| e.to_string())?;
    require(
        status.code() == Some(1),
        "OLD tray must not be running during this gate",
    )?;
    Ok(archive)
}

fn prepare(plan: &Plan, receipt: &mut Receipt) -> Result<(), String> {
    let archive = preflight(plan)?;
    let home = PathBuf::from(std::env::var_os("HOME").ok_or("HOME missing")?);
    let state = home.join("Library/Application Support/dev.slipstream.tray");
    let transaction = updater_transaction::prepare_transaction(
        &Path::new(daemon_update::TARGET).join("Contents/MacOS/slipstream"),
        &state,
        &home.join("Library/LaunchAgents"),
        &archive,
        &plan.expected.old.version,
        &plan.expected.new.version,
        |identity| {
            receipt.identity = Some(identity.clone());
            match validate_identity(identity, &plan.expected, plan.uid) {
                Ok(()) => authorize(identity),
                Err(error) => AuthorizationOutcome::NotExecuted(error),
            }
        },
    )?;
    receipt.prepared = true;
    receipt.journal_path = Some(transaction.journal_path);
    Ok(())
}

fn run() -> Result<(), String> {
    require(
        std::env::args().skip(1).collect::<Vec<_>>() == ["--prepare"],
        "only --prepare is supported",
    )?;
    let plan: Plan = serde_json::from_str(crate::PINNED_PLAN).map_err(|e| e.to_string())?;
    runtime_guard(&plan)?;
    let mut output: File = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(plan.output_dir.join("prepare-result.json"))
        .map_err(|e| format!("cannot reserve preparation receipt: {e}"))?;
    let mut receipt = Receipt {
        schema_version: 1,
        prepared: false,
        journal_path: None,
        initiator_pid: std::process::id(),
        identity: None,
        expected: plan.expected.clone(),
        error: None,
    };
    let result = prepare(&plan, &mut receipt);
    if let Err(error) = &result {
        receipt.error = Some(error.clone());
    }
    let bytes = serde_json::to_vec_pretty(&receipt).map_err(|e| e.to_string())?;
    output.write_all(&bytes).map_err(|e| e.to_string())?;
    output.sync_all().map_err(|e| e.to_string())?;
    // Do not wait for, retry, kickstart, or synthesize the packaged watchdog.
    // Its first ordinary launch, including any failure, is the observation.
    result
}

pub fn main() {
    if let Err(error) = run() {
        eprintln!("packaged update preparation failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use std::cell::Cell;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn only_disposable_console_user_can_prepare() {
        assert!(guard_values(true, true, 501, 501, 501).is_ok());
        for args in [
            (false, true, 501, 501, 501),
            (true, false, 501, 501, 501),
            (true, true, 0, 0, 0),
            (true, true, 501, 0, 501),
            (true, true, 501, 501, 502),
        ] {
            assert!(guard_values(args.0, args.1, args.2, args.3, args.4).is_err());
        }
    }

    #[test]
    fn root_exit_classification_never_calls_ordinary_sudo_failure_a_cancel() {
        assert!(matches!(
            authorization_exit(Some(0)),
            AuthorizationOutcome::Completed
        ));
        assert!(matches!(
            authorization_exit(Some(77)),
            AuthorizationOutcome::NotExecuted(_)
        ));
        for code in [None, Some(1), Some(126), Some(127)] {
            assert!(matches!(
                authorization_exit(code),
                AuthorizationOutcome::Uncertain(_)
            ));
        }
    }

    #[test]
    fn preparation_completed_after_ninety_seconds_still_uses_original_lease() {
        let elapsed = Cell::new(Duration::ZERO);
        let status = wait_for_authorization(
            || authorization_remaining(1300, 1000, elapsed.get(), 1000 + elapsed.get().as_secs()),
            || Ok((elapsed.get() >= Duration::from_secs(150)).then(|| ExitStatus::from_raw(0))),
            |duration| elapsed.set(elapsed.get() + duration),
        )
        .unwrap();
        assert_eq!(elapsed.get(), Duration::from_secs(150));
        assert!(matches!(
            authorization_exit(status.code()),
            AuthorizationOutcome::Completed
        ));
    }

    #[test]
    fn preparation_wait_preserves_remaining_lease_across_clock_changes() {
        for (wall_shift, expected_seconds) in [(0i64, 7), (-600, 7), (600, 2)] {
            let elapsed = Cell::new(Duration::ZERO);
            let result = wait_for_authorization(
                || {
                    let seconds = elapsed.get().as_secs();
                    let shift = if seconds >= 2 { wall_shift } else { 0 };
                    authorization_remaining(
                        1007,
                        1000,
                        elapsed.get(),
                        (1000 + seconds as i64 + shift) as u64,
                    )
                },
                || Ok(None),
                |duration| elapsed.set(elapsed.get() + duration),
            );
            assert_eq!(result.unwrap_err(), "root preparation lease expired");
            assert_eq!(elapsed.get(), Duration::from_secs(expected_seconds));
        }
    }

    #[test]
    fn expired_preparation_never_polls_and_future_clock_cannot_grant_extra_lease() {
        assert_eq!(
            authorization_remaining(u64::MAX, 1000, Duration::ZERO, 1000),
            PREPARATION_LEASE_LIMIT
        );
        let result = wait_for_authorization(
            || authorization_remaining(1000, 1000, Duration::ZERO, 1000),
            || panic!("expired preparation must not poll a child"),
            |_| panic!("expired preparation must not wait"),
        );
        assert_eq!(result.unwrap_err(), "root preparation lease expired");
    }

    #[test]
    fn child_success_first_observed_after_expiry_stays_uncertain() {
        let elapsed = Cell::new(Duration::ZERO);
        let result = wait_for_authorization(
            || authorization_remaining(1007, 1000, elapsed.get(), 1000),
            || {
                elapsed.set(Duration::from_secs(7));
                Ok(Some(ExitStatus::from_raw(0)))
            },
            |_| panic!("completed child should not sleep"),
        );
        assert_eq!(result.unwrap_err(), "root preparation lease expired");
    }

    #[test]
    fn child_poll_failure_does_not_consume_a_new_preparation_budget() {
        let result = wait_for_authorization(
            || Duration::from_secs(300),
            || Err(std::io::Error::other("fixture wait failure")),
            |_| panic!("poll failure should not sleep"),
        );
        assert!(result.unwrap_err().contains("fixture wait failure"));
    }

    #[test]
    fn child_cleanup_has_its_own_short_bound_even_if_child_never_exits() {
        let elapsed = Cell::new(Duration::ZERO);
        assert!(wait_for_authorization(
            || AUTHORIZATION_CLEANUP_LIMIT.saturating_sub(elapsed.get()),
            || Ok(None),
            |duration| elapsed.set(elapsed.get() + duration),
        )
        .is_err());
        assert_eq!(elapsed.get(), Duration::from_secs(5));
    }

    #[test]
    fn pinned_identity_covers_both_trees_daemons_apps_and_archive() {
        let artifact = |version: &str, hash: &str| Artifact {
            version: version.into(),
            source_commit: "a".repeat(40),
            archive_sha256: hash.repeat(64),
            app_executable_sha256: hash.repeat(64),
            daemon_sha256: hash.repeat(64),
            bundle_tree_sha256: hash.repeat(64),
        };
        let expected = Pair {
            old: artifact("0.1.9-preview.24", "b"),
            new: artifact("0.1.9-preview.25", "c"),
        };
        let identity = daemon_update::PrepareIdentity {
            schema_version: 1,
            uid: 501,
            nonce: "d".repeat(32),
            prepare_deadline_unix: 300,
            old_version: expected.old.version.clone(),
            new_version: expected.new.version.clone(),
            old_app_executable_sha256: expected.old.app_executable_sha256.clone(),
            new_app_executable_sha256: expected.new.app_executable_sha256.clone(),
            old_daemon_sha256: expected.old.daemon_sha256.clone(),
            new_daemon_sha256: expected.new.daemon_sha256.clone(),
            old_bundle_tree_sha256: expected.old.bundle_tree_sha256.clone(),
            new_bundle_tree_sha256: expected.new.bundle_tree_sha256.clone(),
            archive_sha256: expected.new.archive_sha256.clone(),
        };
        assert!(validate_identity(&identity, &expected, 501).is_ok());
        for field in [
            "old_version",
            "new_version",
            "archive_sha256",
            "old_app_executable_sha256",
            "new_app_executable_sha256",
            "old_daemon_sha256",
            "new_daemon_sha256",
            "old_bundle_tree_sha256",
            "new_bundle_tree_sha256",
        ] {
            let mut value = serde_json::to_value(&identity).unwrap();
            value[field] = "changed".into();
            let changed = serde_json::from_value(value).unwrap();
            assert!(
                validate_identity(&changed, &expected, 501).is_err(),
                "{field}"
            );
        }
        assert!(validate_identity(&identity, &expected, 502).is_err());
    }

    #[test]
    fn old_signature_verifier_accepts_fixture_and_rejects_changed_bytes() {
        // Public test vector from pinned minisign-verify 0.2.5; no private key.
        let key = base64::engine::general_purpose::STANDARD.encode("untrusted comment: fixture\nRWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3\n");
        let signature = base64::engine::general_purpose::STANDARD.encode("untrusted comment: signature from minisign secret key\nRUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\ntrusted comment: timestamp:1556193335\tfile:test\ny/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1FkZZSNCisQbuQY+bHwhEBg==");
        assert!(verify_signature(b"test", &signature, &key).is_ok());
        assert!(verify_signature(b"changed", &signature, &key).is_err());
        assert!(verify_signature(b"test", "bad", &key).is_err());
    }

    #[test]
    fn bounded_input_rejects_symlink_fifo_and_overflow() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("input");
        fs::write(&path, b"abcd").unwrap();
        assert_eq!(bounded_file(&path, 4).unwrap(), b"abcd");
        assert!(bounded_file(&path, 3).is_err());
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(bounded_file(&link, 4).is_err());
        let fifo = temp.path().join("fifo");
        let cpath = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        assert!(bounded_file(&fifo, 4).is_err());
    }
}
