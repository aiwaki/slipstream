#[cfg(windows)]
use sha2::{Digest, Sha256};
#[cfg(windows)]
use slipstream_windows_adapter::service_controller::WindowsServiceController;
#[cfg(windows)]
use slipstream_windows_adapter::service_lifecycle::{
    WindowsServiceCommand, WindowsServiceIdentity, WINDOWS_SERVICE_NAME,
};
#[cfg(windows)]
use std::fs::File;
#[cfg(windows)]
use std::io::{Read, Write};
#[cfg(windows)]
use std::path::{Path, PathBuf};

#[cfg(windows)]
fn main() {
    if let Err(error) = run() {
        let _ = writeln!(std::io::stderr(), "{error}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn run() -> Result<(), String> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let source_path = PathBuf::from(
        arguments
            .next()
            .ok_or_else(|| "missing service source path".to_owned())?,
    );
    let generation: u64 = arguments
        .next()
        .ok_or_else(|| "missing service generation".to_owned())?
        .to_string_lossy()
        .parse()
        .map_err(|_| "service generation must be a positive integer".to_owned())?;
    let command_name = arguments
        .next()
        .ok_or_else(|| "missing controller command".to_owned())?
        .to_string_lossy()
        .into_owned();
    if arguments.next().is_some() {
        return Err("unexpected controller fixture argument".to_owned());
    }

    let identity = WindowsServiceIdentity {
        service_name: WINDOWS_SERVICE_NAME.to_owned(),
        executable_sha256: sha256_file(&source_path)?,
        generation,
    };
    let command = match command_name.as_str() {
        "install" => WindowsServiceCommand::Install { identity },
        "start" => WindowsServiceCommand::Start,
        "stop" => WindowsServiceCommand::Stop,
        "crash" => WindowsServiceCommand::CrashObserved,
        "uninstall" => WindowsServiceCommand::Uninstall,
        _ => return Err(format!("unknown controller command {command_name:?}")),
    };

    let result = WindowsServiceController::new(source_path)
        .execute(&command)
        .map_err(|error| error.to_string())?;
    serde_json::to_writer(std::io::stdout(), &result).map_err(|error| error.to_string())?;
    Ok(())
}

#[cfg(windows)]
fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(not(windows))]
fn main() {
    eprintln!("the disposable Windows controller fixture requires Windows");
}
