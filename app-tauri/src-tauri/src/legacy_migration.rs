//! One-shot external .23 migration, before Tauri or single-instance forwarding.
use std::ffi::OsString;
use std::io::Read;
use std::path::PathBuf;

struct Request {
    version: String,
    signature_file: PathBuf,
    executable: PathBuf,
    pid: u32,
}

fn parse(args: &[OsString]) -> Result<Request, String> {
    if args.len() != 5 || args[0] != "--migrate-legacy" {
        return Err("usage: --migrate-legacy VERSION SIGNATURE_FILE TARGET_EXE PID".into());
    }
    let version = args[1]
        .to_str()
        .ok_or("invalid migration version")?
        .to_string();
    let pid: u32 = args[4]
        .to_str()
        .ok_or("invalid tray PID")?
        .parse()
        .map_err(|_| "invalid tray PID")?;
    if !(2..=i32::MAX as u32).contains(&pid) {
        return Err("invalid tray PID".into());
    }
    if !PathBuf::from(&args[2]).is_absolute() || !PathBuf::from(&args[3]).is_absolute() {
        return Err("migration input paths must be absolute".into());
    }
    Ok(Request {
        version,
        signature_file: (&args[2]).into(),
        executable: (&args[3]).into(),
        pid,
    })
}

#[cfg(target_os = "macos")]
fn run(request: Request) -> Result<PathBuf, String> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    // This entry runs before the runtime starts worker threads. Copy the passwd
    // result immediately; HOME cannot redirect the canonical transaction state.
    let uid = unsafe { libc::getuid() };
    if uid == 0 {
        return Err("legacy migration must not run as root".into());
    }
    let home = unsafe {
        let entry = libc::getpwuid(uid);
        if entry.is_null() || (*entry).pw_dir.is_null() {
            return Err("cannot resolve the current user's home directory".into());
        }
        PathBuf::from(std::ffi::OsStr::from_bytes(
            std::ffi::CStr::from_ptr((*entry).pw_dir).to_bytes(),
        ))
    };
    if !home.is_absolute() {
        return Err("user home directory is not absolute".into());
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&request.signature_file)
        .map_err(|_| "cannot open migration signature file")?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect migration signature file")?;
    if !metadata.is_file() || metadata.len() > 16384 {
        return Err("migration signature file must be a bounded regular file".into());
    }
    let mut signature = String::new();
    (&mut file)
        .take(16385)
        .read_to_string(&mut signature)
        .map_err(|_| "cannot read migration signature")?;
    if signature.len() > 16384 {
        return Err("migration signature is too large".into());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "cannot start migration downloader")?;
    let admitted = runtime.block_on(crate::app_update::VerifiedLegacyMigration::download(
        &request.version,
        signature.trim(),
    ))?;
    // No tray termination or local mutation takes place before admission.
    let prepared = admitted.prepare_running_tray(
        &request.executable,
        request.pid,
        &home.join("Library/Application Support/dev.slipstream.tray"),
        &home.join("Library/LaunchAgents"),
    )?;
    Ok(prepared.journal_path)
}

/// None means normal startup. Recognized invalid migration requests never fall
/// through to AppKit, automatic daemon setup or another ordinary tray instance.
pub fn requested() -> Option<Result<PathBuf, String>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.first().is_none_or(|arg| arg != "--migrate-legacy") {
        return None;
    }
    Some(parse(&args).and_then(|request| {
        #[cfg(target_os = "macos")]
        {
            run(request)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = request;
            Err("legacy migration requires macOS".into())
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }
    #[test]
    fn migration_command_is_exact_and_paths_are_explicit() {
        let valid = [
            "--migrate-legacy",
            "0.1.9-preview.24",
            "/tmp/archive.sig",
            "/Applications/Slipstream.app/Contents/MacOS/slipstream",
            "234",
        ];
        let request = parse(&args(&valid)).unwrap();
        assert_eq!(request.pid, 234);
        for count in 0..5 {
            assert!(parse(&args(&valid[..count])).is_err());
        }
        let mut extra = args(&valid);
        extra.push("ignored".into());
        assert!(parse(&extra).is_err());
        for (index, value) in [
            (0, "--quit"),
            (2, "relative.sig"),
            (3, "relative.app"),
            (4, "0"),
            (4, "1"),
            (4, "-1"),
            (4, "2147483648"),
        ] {
            let mut invalid = args(&valid);
            invalid[index] = value.into();
            assert!(parse(&invalid).is_err());
        }
    }
}
