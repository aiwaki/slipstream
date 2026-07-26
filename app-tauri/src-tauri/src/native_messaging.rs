use serde_json::{json, Value};
use slipstream_core::semantic_route_signal::parse_semantic_route_signal_v1;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const NATIVE_HOST_NAME: &str = "dev.slipstream.semantic";
pub const CHROMIUM_EXTENSION_ID: &str = "cecdingohhpfggapnlbghppcegbaciam";
pub const CHROMIUM_EXTENSION_ORIGIN: &str = "chrome-extension://cecdingohhpfggapnlbghppcegbaciam/";
pub const SEMANTIC_SIGNAL_SOCKET_PATH: &str = "/var/run/slipstream-semantic.sock";

const FRAME_HEADER_BYTES: usize = 4;
const MAX_SIGNAL_BYTES: usize = 1024;
const MAX_DAEMON_RESPONSE_BYTES: usize = 1024;
const IPC_TIMEOUT: Duration = Duration::from_secs(2);
const CHROME_NATIVE_HOST_RELATIVE_PATH: &str =
    "Library/Application Support/Google/Chrome/NativeMessagingHosts/dev.slipstream.semantic.json";

fn native_host_manifest_path(home: &Path) -> PathBuf {
    home.join(CHROME_NATIVE_HOST_RELATIVE_PATH)
}

fn is_bundled_macos_executable(executable: &Path) -> bool {
    let Some(macos_dir) = executable.parent() else {
        return false;
    };
    let Some(contents_dir) = macos_dir.parent() else {
        return false;
    };
    let Some(app_bundle) = contents_dir.parent() else {
        return false;
    };
    executable.is_absolute()
        && executable.is_file()
        && macos_dir.file_name() == Some(OsStr::new("MacOS"))
        && contents_dir.file_name() == Some(OsStr::new("Contents"))
        && app_bundle.extension() == Some(OsStr::new("app"))
}

fn native_host_manifest(executable: &Path) -> io::Result<Vec<u8>> {
    if !is_bundled_macos_executable(executable) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native host executable is not inside a macOS app bundle",
        ));
    }
    if CHROMIUM_EXTENSION_ORIGIN != format!("chrome-extension://{CHROMIUM_EXTENSION_ID}/") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native host extension identity is inconsistent",
        ));
    }
    let mut manifest = serde_json::to_vec_pretty(&json!({
        "name": NATIVE_HOST_NAME,
        "description": "Slipstream Browser Companion",
        "path": executable,
        "type": "stdio",
        "allowed_origins": [CHROMIUM_EXTENSION_ORIGIN],
    }))
    .map_err(io::Error::other)?;
    manifest.push(b'\n');
    Ok(manifest)
}

fn write_atomic_private(path: &Path, payload: &[u8]) -> io::Result<()> {
    let Some(parent) = path.parent() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native host manifest has no parent",
        ));
    };
    fs::create_dir_all(parent)?;
    if fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native host manifest path is a symlink",
        ));
    }

    let file_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid manifest filename"))?;
    let mut temporary = None;
    for suffix in 0..16_u8 {
        let candidate = parent.join(format!(".{file_name}.tmp-{}-{suffix}", std::process::id()));
        match fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&candidate)
        {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    let Some((temporary_path, mut file)) = temporary else {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "native host temporary files are occupied",
        ));
    };
    let result = (|| -> io::Result<()> {
        file.write_all(payload)?;
        file.sync_all()?;
        fs::set_permissions(&temporary_path, fs::Permissions::from_mode(0o600))?;
        fs::rename(&temporary_path, path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

fn register_native_host_for(executable: &Path, home: &Path) -> io::Result<Option<PathBuf>> {
    if !is_bundled_macos_executable(executable) {
        return Ok(None);
    }
    let path = native_host_manifest_path(home);
    let payload = native_host_manifest(executable)?;
    match fs::read(&path) {
        Ok(existing) if existing == payload => {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(existing) if manifest_is_owned(&existing) => {
            write_atomic_private(&path, &payload)?;
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "native host manifest is not owned by Slipstream",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            write_atomic_private(&path, &payload)?;
        }
        Err(error) => return Err(error),
    }
    Ok(Some(path))
}

fn manifest_is_owned(payload: &[u8]) -> bool {
    let Ok(Value::Object(manifest)) = serde_json::from_slice(payload) else {
        return false;
    };
    manifest.get("name").and_then(Value::as_str) == Some(NATIVE_HOST_NAME)
        && manifest.get("type").and_then(Value::as_str) == Some("stdio")
        && manifest
            .get("allowed_origins")
            .and_then(Value::as_array)
            .is_some_and(|origins| {
                origins.len() == 1 && origins[0].as_str() == Some(CHROMIUM_EXTENSION_ORIGIN)
            })
}

fn unregister_native_host_for(home: &Path) -> io::Result<()> {
    let path = native_host_manifest_path(home);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native host manifest path is a symlink",
        ));
    }
    let payload = fs::read(&path)?;
    if !manifest_is_owned(&payload) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "native host manifest is not owned by Slipstream",
        ));
    }
    fs::remove_file(path)
}

pub fn register_chromium_native_host() -> io::Result<Option<PathBuf>> {
    let executable = std::env::current_exe()?;
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Ok(None);
    };
    register_native_host_for(&executable, &home)
}

pub fn unregister_chromium_native_host() -> io::Result<()> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Ok(());
    };
    unregister_native_host_for(&home)
}

fn fixed_response(accepted: bool, action: &str, reason: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema_version": 1,
        "accepted": accepted,
        "action": action,
        "reason": reason,
    }))
    .expect("fixed native messaging response must serialize")
}

fn response_is_private_and_bounded(payload: &[u8]) -> bool {
    if payload.is_empty() || payload.len() > MAX_DAEMON_RESPONSE_BYTES {
        return false;
    }
    let Ok(Value::Object(object)) = serde_json::from_slice(payload) else {
        return false;
    };
    let expected = ["accepted", "action", "reason", "schema_version"];
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return false;
    }
    let Some(version) = object["schema_version"].as_u64() else {
        return false;
    };
    let Some(action) = object["action"].as_str() else {
        return false;
    };
    let Some(reason) = object["reason"].as_str() else {
        return false;
    };
    version == 1
        && object["accepted"].is_boolean()
        && !action.is_empty()
        && action.len() <= 64
        && action
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        && !reason.is_empty()
        && reason.len() <= 96
        && reason
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
}

fn read_frame<R: Read>(reader: &mut R, max_bytes: usize) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    let first = reader.read(&mut header[..1])?;
    if first == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut header[1..])?;
    let length = u32::from_ne_bytes(header) as usize;
    if length == 0 || length > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native messaging frame is outside bounds",
        ));
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload)?;
    Ok(Some(payload))
}

fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    let length = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response is too large"))?;
    writer.write_all(&length.to_ne_bytes())?;
    writer.write_all(payload)?;
    writer.flush()
}

fn forward_to_daemon(payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut stream = UnixStream::connect(SEMANTIC_SIGNAL_SOCKET_PATH)?;
    stream.set_read_timeout(Some(IPC_TIMEOUT))?;
    stream.set_write_timeout(Some(IPC_TIMEOUT))?;
    let length = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "signal is too large"))?;
    stream.write_all(&length.to_le_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;

    let mut header = [0_u8; FRAME_HEADER_BYTES];
    stream.read_exact(&mut header)?;
    let response_length = u32::from_le_bytes(header) as usize;
    if response_length == 0 || response_length > MAX_DAEMON_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "daemon response is outside bounds",
        ));
    }
    let mut response = vec![0_u8; response_length];
    stream.read_exact(&mut response)?;
    Ok(response)
}

fn process_message<F>(origin: &str, payload: &[u8], forward: F) -> Vec<u8>
where
    F: FnOnce(&[u8]) -> io::Result<Vec<u8>>,
{
    if origin != CHROMIUM_EXTENSION_ORIGIN {
        return fixed_response(false, "none", "origin_forbidden");
    }
    if payload.len() > MAX_SIGNAL_BYTES || parse_semantic_route_signal_v1(payload).is_err() {
        return fixed_response(false, "none", "invalid_signal");
    }
    let Ok(response) = forward(payload) else {
        return fixed_response(false, "none", "daemon_unavailable");
    };
    if !response_is_private_and_bounded(&response) {
        return fixed_response(false, "none", "invalid_daemon_response");
    }
    response
}

fn native_messaging_origin(args: &[String]) -> Option<&str> {
    args.get(1)
        .map(String::as_str)
        .filter(|argument| argument.starts_with("chrome-extension://"))
}

fn run_stdio_host<R: Read, W: Write, F>(
    origin: &str,
    reader: &mut R,
    writer: &mut W,
    forward: F,
) -> io::Result<()>
where
    F: FnOnce(&[u8]) -> io::Result<Vec<u8>>,
{
    let response = match read_frame(reader, MAX_SIGNAL_BYTES) {
        Ok(Some(payload)) => process_message(origin, &payload, forward),
        Ok(None) => return Ok(()),
        Err(_) => fixed_response(false, "none", "invalid_frame"),
    };
    write_frame(writer, &response)
}

pub fn run_native_messaging_if_requested() -> bool {
    let args: Vec<String> = std::env::args().collect();
    let Some(origin) = native_messaging_origin(&args) else {
        return false;
    };
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    let _ = run_stdio_host(origin, &mut reader, &mut writer, forward_to_daemon);
    true
}

#[cfg(test)]
mod tests {
    use super::{
        fixed_response, manifest_is_owned, native_host_manifest, native_host_manifest_path,
        native_messaging_origin, process_message, read_frame, register_native_host_for,
        response_is_private_and_bounded, run_stdio_host, unregister_native_host_for,
        CHROMIUM_EXTENSION_ID, CHROMIUM_EXTENSION_ORIGIN, NATIVE_HOST_NAME,
    };
    use serde_json::{json, Value};
    use std::cell::Cell;
    use std::fs;
    use std::io::{self, Cursor};
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn signal() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "schema_version": 1,
            "signal_id": "0123456789abcdef0123456789abcdef",
            "source": "browser_extension",
            "host": "weather.com",
            "category": "regional_access_denied",
            "confidence_bps": 9500,
            "observed_at_unix_ms": 1_000_000,
            "top_level": true,
        }))
        .unwrap()
    }

    fn daemon_response() -> Vec<u8> {
        fixed_response(true, "confirm_exact_host_geo_exit", "accepted")
    }

    #[test]
    fn dispatches_only_extension_origin_invocations() {
        let normal = vec!["slipstream".to_string()];
        let deep_link = vec!["slipstream".to_string(), "slipstream://open".to_string()];
        let native = vec![
            "slipstream".to_string(),
            CHROMIUM_EXTENSION_ORIGIN.to_string(),
        ];

        assert_eq!(native_messaging_origin(&normal), None);
        assert_eq!(native_messaging_origin(&deep_link), None);
        assert_eq!(
            native_messaging_origin(&native),
            Some(CHROMIUM_EXTENSION_ORIGIN)
        );
    }

    #[test]
    fn valid_signal_is_forwarded_byte_for_byte() {
        let payload = signal();
        let observed = Cell::new(false);
        let response = process_message(CHROMIUM_EXTENSION_ORIGIN, &payload, |forwarded| {
            assert_eq!(forwarded, payload);
            observed.set(true);
            Ok(daemon_response())
        });

        assert!(observed.get());
        assert_eq!(response, daemon_response());
    }

    #[test]
    fn privacy_expanding_signal_is_rejected_before_forwarding() {
        let mut value: Value = serde_json::from_slice(&signal()).unwrap();
        value["url"] = Value::String("https://weather.com/private".to_string());
        let payload = serde_json::to_vec(&value).unwrap();
        let forwarded = Cell::new(false);

        let response = process_message(CHROMIUM_EXTENSION_ORIGIN, &payload, |_| {
            forwarded.set(true);
            Ok(daemon_response())
        });

        assert!(!forwarded.get());
        assert_eq!(
            serde_json::from_slice::<Value>(&response).unwrap()["reason"],
            "invalid_signal"
        );
    }

    #[test]
    fn wrong_origin_is_rejected_before_forwarding() {
        let forwarded = Cell::new(false);
        let response = process_message(
            "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
            &signal(),
            |_| {
                forwarded.set(true);
                Ok(daemon_response())
            },
        );

        assert!(!forwarded.get());
        assert_eq!(
            serde_json::from_slice::<Value>(&response).unwrap()["reason"],
            "origin_forbidden"
        );
    }

    #[test]
    fn daemon_response_cannot_expand_browser_visible_data() {
        assert!(response_is_private_and_bounded(&daemon_response()));
        assert!(!response_is_private_and_bounded(
            br#"{"schema_version":1,"accepted":true,"action":"none","reason":"ok","host":"weather.com"}"#
        ));
    }

    #[test]
    fn stdio_protocol_is_one_bounded_native_endian_frame() {
        let payload = signal();
        let mut request = Vec::new();
        request.extend_from_slice(&(payload.len() as u32).to_ne_bytes());
        request.extend_from_slice(&payload);
        let mut output = Vec::new();

        run_stdio_host(
            CHROMIUM_EXTENSION_ORIGIN,
            &mut Cursor::new(request),
            &mut output,
            |_| Ok(daemon_response()),
        )
        .unwrap();

        let decoded = read_frame(&mut Cursor::new(output), 1024).unwrap().unwrap();
        assert_eq!(decoded, daemon_response());
    }

    #[test]
    fn daemon_failure_returns_bounded_private_response() {
        let response = process_message(CHROMIUM_EXTENSION_ORIGIN, &signal(), |_| {
            Err(io::Error::new(io::ErrorKind::ConnectionRefused, "offline"))
        });

        assert_eq!(
            serde_json::from_slice::<Value>(&response).unwrap()["reason"],
            "daemon_unavailable"
        );
        assert!(response_is_private_and_bounded(&response));
    }

    #[test]
    fn native_host_manifest_is_exact_and_private() {
        let unique = format!("slipstream-native-host-test-{}", std::process::id());
        let root = std::env::temp_dir().join(unique);
        let home = root.join("home");
        let executable = root.join("Slipstream.app/Contents/MacOS/slipstream");
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::write(&executable, b"test").unwrap();

        let registered = register_native_host_for(&executable, &home)
            .unwrap()
            .unwrap();
        assert_eq!(registered, native_host_manifest_path(&home));
        assert_eq!(
            fs::read(&registered).unwrap(),
            native_host_manifest(&executable).unwrap()
        );
        assert_eq!(
            fs::metadata(&registered).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let value: Value = serde_json::from_slice(&fs::read(&registered).unwrap()).unwrap();
        assert_eq!(value["name"], NATIVE_HOST_NAME);
        assert_eq!(value["path"], executable.to_string_lossy().as_ref());
        assert_eq!(value["allowed_origins"], json!([CHROMIUM_EXTENSION_ORIGIN]));
        assert_eq!(
            CHROMIUM_EXTENSION_ORIGIN,
            format!("chrome-extension://{CHROMIUM_EXTENSION_ID}/")
        );
        assert!(manifest_is_owned(&fs::read(&registered).unwrap()));

        unregister_native_host_for(&home).unwrap();
        assert!(!registered.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn development_binary_is_not_registered() {
        let root = std::env::temp_dir().join(format!(
            "slipstream-native-host-dev-test-{}",
            std::process::id()
        ));
        let executable = root.join("target/debug/slipstream");
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::write(&executable, b"test").unwrap();

        assert_eq!(
            register_native_host_for(&executable, &root.join("home")).unwrap(),
            None
        );
        assert!(!native_host_manifest_path(&root.join("home")).exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn uninstall_refuses_foreign_or_symlinked_manifest() {
        let root = std::env::temp_dir().join(format!(
            "slipstream-native-host-foreign-test-{}",
            std::process::id()
        ));
        let home = root.join("home");
        let manifest = native_host_manifest_path(&home);
        fs::create_dir_all(manifest.parent().unwrap()).unwrap();
        fs::write(&manifest, br#"{"name":"someone.else"}"#).unwrap();
        let executable = root.join("Slipstream.app/Contents/MacOS/slipstream");
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::write(&executable, b"test").unwrap();
        assert_eq!(
            register_native_host_for(&executable, &home)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(fs::read(&manifest).unwrap(), br#"{"name":"someone.else"}"#);
        assert_eq!(
            unregister_native_host_for(&home).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(manifest.exists());

        fs::remove_file(&manifest).unwrap();
        std::os::unix::fs::symlink(Path::new("/tmp/foreign"), &manifest).unwrap();
        assert_eq!(
            unregister_native_host_for(&home).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(fs::symlink_metadata(&manifest)
            .unwrap()
            .file_type()
            .is_symlink());
        let _ = fs::remove_dir_all(root);
    }
}
