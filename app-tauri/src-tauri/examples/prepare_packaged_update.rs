//! Disposable-CI driver for the production transaction, never shipped in the app.
#[path = "../src/updater_transaction.rs"]
mod updater_transaction;

use std::path::PathBuf;

fn run() -> Result<(), String> {
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || std::env::var("SLIPSTREAM_DISPOSABLE_CI").as_deref() != Ok("1")
        || unsafe { libc::getuid() } == 0
    {
        return Err("requires an unprivileged disposable GitHub Actions runner".into());
    }
    let mut raw: Vec<_> = std::env::args_os().skip(1).collect();
    let migration = raw.first().is_some_and(|arg| arg == "--legacy-migration");
    if migration {
        raw.remove(0);
    }
    let running_pid = if raw.first().is_some_and(|arg| arg == "--running-legacy-pid") {
        if !migration || raw.len() < 2 {
            return Err("running PID requires migration mode".into());
        }
        raw.remove(0);
        Some(
            raw.remove(0)
                .to_str()
                .ok_or("invalid PID")?
                .parse::<u32>()
                .map_err(|_| "invalid PID")?,
        )
    } else {
        None
    };
    let args: Vec<PathBuf> = raw.into_iter().map(PathBuf::from).collect();
    if args.len() != 3 {
        return Err("usage: prepare_packaged_update CURRENT_EXE ARCHIVE STATE_DIR".into());
    }
    let root = PathBuf::from(std::env::var_os("RUNNER_TEMP").ok_or("missing RUNNER_TEMP")?)
        .canonicalize()
        .map_err(|e| e.to_string())?;
    for path in &args {
        let path = path.canonicalize().map_err(|e| e.to_string())?;
        if !path.starts_with(&root) || path == root {
            return Err("all transaction inputs must be inside RUNNER_TEMP".into());
        }
    }
    let launch_agents =
        PathBuf::from(std::env::var_os("HOME").ok_or("missing HOME")?).join("Library/LaunchAgents");
    if launch_agents
        .join("dev.slipstream.update-watchdog.plist")
        .symlink_metadata()
        .is_ok()
    {
        return Err("existing update LaunchAgent must not be replaced by qualification".into());
    }
    let loaded = std::process::Command::new("/bin/launchctl")
        .args([
            "print",
            &format!("gui/{}/dev.slipstream.update-watchdog", unsafe {
                libc::getuid()
            }),
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if loaded.status.success() {
        return Err("existing update watchdog must not be replaced by qualification".into());
    }
    let version = env!("CARGO_PKG_VERSION");
    let info = args[0]
        .parent()
        .and_then(|p| p.parent())
        .ok_or("invalid bundle path")?
        .join("Info.plist");
    let plist = plist::Value::from_file(info).map_err(|e| e.to_string())?;
    let current_version = plist
        .as_dictionary()
        .and_then(|v| v.get("CFBundleShortVersionString"))
        .and_then(plist::Value::as_string)
        .ok_or("missing current version")?;
    // Input archives are canonical local candidates. Signature/feed discovery
    // remains a separate release qualification; this driver never ships.
    // BEGIN_RUNNING_MIGRATION
    if let Some(pid) = running_pid {
        let transaction = updater_transaction::prepare_running_legacy_migration(
            &args[0],
            pid,
            &args[2],
            &launch_agents,
            &std::fs::read(&args[1]).map_err(|e| e.to_string())?,
            version,
        )?;
        println!("{}", transaction.journal_path.display());
        return Ok(());
    }
    // END_RUNNING_MIGRATION
    let prepare = if migration {
        updater_transaction::prepare_legacy_migration_transaction
    } else {
        updater_transaction::prepare_transaction
    };
    let transaction = prepare(
        &args[0],
        &args[2],
        &launch_agents,
        &std::fs::read(&args[1]).map_err(|e| e.to_string())?,
        current_version,
        version,
    )?;
    println!("{}", transaction.journal_path.display());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
