use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const BROWSER_PROBE_ARGUMENT: &str = "--pending-navigation-browser-probe";

const SCHEMA_VERSION: u8 = 1;
const PRODUCTION_SOCKET_PATH: &str = "/var/run/slipstream-browser-probe.sock";
const MAX_IPC_BYTES: usize = 2_048;
const IPC_TIMEOUT: Duration = Duration::from_secs(2);
const CAPABILITY_HEX_CHARS: usize = 32;
const CAPABILITY_TTL_MS: u64 = 30_000;
const MAX_CLAIM_AGE_MS: u64 = 5_000;
const MIN_PENDING_OBSERVATION: Duration = Duration::from_secs(8);
const MIN_START_BUDGET_MS: u64 = 16_000;
const CHROME_LAUNCH_TIMEOUT: Duration = Duration::from_secs(10);
const CDP_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const CHROME_STOP_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_DEVTOOLS_FILE_BYTES: u64 = 4_096;
const MAX_HTTP_BYTES: u64 = 256 * 1024;
const MAX_WEBSOCKET_BYTES: usize = 1024 * 1024;
const WEBSOCKET_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const WEBSOCKET_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
const OUTCOME_PENDING: &str = "navigation_pending";
const OUTCOME_TERMINAL: &str = "navigation_terminal";

#[derive(Debug, Clone, Copy)]
struct ProbeError(&'static str);

impl std::fmt::Display for ProbeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for ProbeError {}

type ProbeResult<T> = Result<T, ProbeError>;

fn error(kind: &'static str) -> ProbeError {
    ProbeError(kind)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProbeJob {
    schema_version: u8,
    capability: String,
    host: String,
    request_started_at_unix_ms: u64,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IpcResponse {
    schema_version: u8,
    accepted: bool,
    operation: String,
    reason: String,
    job: Option<ProbeJob>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ProbeResultPayload<'a> {
    schema_version: u8,
    capability: &'a str,
    host: &'a str,
    request_started_at_unix_ms: u64,
    observed_at_unix_ms: u64,
    outcome: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DevToolsTarget {
    #[serde(rename = "type")]
    target_type: String,
    url: String,
    web_socket_debugger_url: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OwnedProcess {
    pid: u32,
    process_group: u32,
    command: String,
}

#[derive(Debug)]
struct ChromeConfig {
    executable: PathBuf,
    application_bundle: PathBuf,
    target_url: String,
    host_resolver_rules: Option<String>,
    ignore_certificate_errors: bool,
}

struct ChromeSession {
    uid: u32,
    config: ChromeConfig,
    profile: PathBuf,
    launcher: Option<Child>,
    rooted_process_groups: BTreeSet<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NavigationObservation {
    Pending,
    Terminal,
}

pub fn run_browser_probe_if_requested() -> Option<i32> {
    let arguments: Vec<OsString> = std::env::args_os().collect();
    if !is_browser_probe_invocation(&arguments) {
        return None;
    }
    Some(match run_one_probe() {
        Ok(()) => 0,
        Err(failure) => {
            eprintln!("slipstream browser probe failed: {failure}");
            1
        }
    })
}

fn is_browser_probe_invocation(arguments: &[OsString]) -> bool {
    arguments.len() == 2 && arguments[1] == OsStr::new(BROWSER_PROBE_ARGUMENT)
}

fn run_one_probe() -> ProbeResult<()> {
    let uid = current_uid()?;
    let socket_path = configured_socket_path();
    let job = match claim_job(&socket_path, uid)? {
        Some(job) => job,
        None => return Ok(()),
    };
    let now = unix_now_ms()?;
    if job.expires_at_unix_ms.saturating_sub(now) < MIN_START_BUDGET_MS {
        return Err(error("job_budget_exhausted"));
    }

    let config = ChromeConfig::discover(&job, uid)?;
    let mut chrome = ChromeSession::launch(uid, config)?;
    let observation = match chrome.observe_navigation() {
        Ok(observation) => observation,
        Err(failure) => {
            let _ = chrome.cleanup();
            return Err(failure);
        }
    };
    chrome.cleanup()?;
    let observed_at_unix_ms = unix_now_ms()?;

    let outcome = match observation {
        NavigationObservation::Pending => OUTCOME_PENDING,
        NavigationObservation::Terminal => OUTCOME_TERMINAL,
    };
    let response = submit_result(
        &socket_path,
        uid,
        &ProbeResultPayload {
            schema_version: SCHEMA_VERSION,
            capability: &job.capability,
            host: &job.host,
            request_started_at_unix_ms: job.request_started_at_unix_ms,
            observed_at_unix_ms,
            outcome,
        },
    )?;
    match observation {
        NavigationObservation::Pending if response.accepted && response.reason == "accepted" => {
            Ok(())
        }
        NavigationObservation::Terminal
            if !response.accepted && response.reason == "result_rejected" =>
        {
            Ok(())
        }
        _ => Err(error("submit_rejected")),
    }
}

fn disposable_ci() -> bool {
    std::env::var_os("CI").as_deref() == Some(OsStr::new("true"))
        && std::env::var_os("GITHUB_ACTIONS").as_deref() == Some(OsStr::new("true"))
        && std::env::var_os("SLIPSTREAM_DISPOSABLE_CI").as_deref() == Some(OsStr::new("1"))
}

fn configured_socket_path() -> PathBuf {
    if disposable_ci() {
        if let Some(path) = std::env::var_os("SLIPSTREAM_BROWSER_PROBE_SOCKET") {
            return PathBuf::from(path);
        }
    }
    PathBuf::from(PRODUCTION_SOCKET_PATH)
}

fn current_uid() -> ProbeResult<u32> {
    let output = Command::new("/usr/bin/id")
        .arg("-u")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| error("uid_unavailable"))?;
    if !output.status.success() {
        return Err(error("uid_unavailable"));
    }
    std::str::from_utf8(&output.stdout)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .ok_or_else(|| error("uid_invalid"))
}

fn unix_now_ms() -> ProbeResult<u64> {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| error("clock_invalid"))?
        .as_millis();
    u64::try_from(milliseconds).map_err(|_| error("clock_invalid"))
}

fn canonical_host(host: &str) -> bool {
    if host.is_empty()
        || host.len() > 253
        || !host.is_ascii()
        || host.bytes().any(|byte| byte.is_ascii_uppercase())
        || host.starts_with('.')
        || host.ends_with('.')
        || host.parse::<std::net::IpAddr>().is_ok()
    {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && label.as_bytes()[0] != b'-'
                && label.as_bytes()[label.len() - 1] != b'-'
        })
}

fn validate_job(job: &ProbeJob) -> ProbeResult<()> {
    let now = unix_now_ms()?;
    if job.schema_version != SCHEMA_VERSION
        || job.capability.len() != CAPABILITY_HEX_CHARS
        || !job
            .capability
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !canonical_host(&job.host)
        || job.request_started_at_unix_ms == 0
        || job.request_started_at_unix_ms > job.issued_at_unix_ms
        || job.issued_at_unix_ms == 0
        || job.expires_at_unix_ms.saturating_sub(job.issued_at_unix_ms) != CAPABILITY_TTL_MS
        || now < job.issued_at_unix_ms
        || now.saturating_sub(job.issued_at_unix_ms) > MAX_CLAIM_AGE_MS
        || job.expires_at_unix_ms <= now
    {
        return Err(error("claimed_job_invalid"));
    }
    Ok(())
}

fn socket_metadata(path: &Path, uid: u32) -> ProbeResult<fs::Metadata> {
    let metadata = fs::symlink_metadata(path).map_err(|_| error("socket_unavailable"))?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(error("socket_unowned"));
    }
    Ok(metadata)
}

fn ipc_request(
    path: &Path,
    uid: u32,
    operation: &str,
    request: &Value,
) -> ProbeResult<IpcResponse> {
    let payload = serde_json::to_vec(request).map_err(|_| error("ipc_encode_failed"))?;
    if payload.is_empty() || payload.len() > MAX_IPC_BYTES {
        return Err(error("ipc_request_invalid"));
    }
    let before = socket_metadata(path, uid)?;
    let mut connection = UnixStream::connect(path).map_err(|_| error("ipc_unavailable"))?;
    let after = socket_metadata(path, uid)?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(error("socket_replaced"));
    }
    connection
        .set_read_timeout(Some(IPC_TIMEOUT))
        .map_err(|_| error("ipc_unavailable"))?;
    connection
        .set_write_timeout(Some(IPC_TIMEOUT))
        .map_err(|_| error("ipc_unavailable"))?;
    let length = u32::try_from(payload.len()).map_err(|_| error("ipc_request_invalid"))?;
    connection
        .write_all(&length.to_le_bytes())
        .and_then(|_| connection.write_all(&payload))
        .map_err(|_| error("ipc_unavailable"))?;
    let mut header = [0_u8; 4];
    connection
        .read_exact(&mut header)
        .map_err(|_| error("ipc_response_invalid"))?;
    let response_length = u32::from_le_bytes(header) as usize;
    if response_length == 0 || response_length > MAX_IPC_BYTES {
        return Err(error("ipc_response_invalid"));
    }
    let mut response_payload = vec![0_u8; response_length];
    connection
        .read_exact(&mut response_payload)
        .map_err(|_| error("ipc_response_invalid"))?;
    let response: IpcResponse =
        serde_json::from_slice(&response_payload).map_err(|_| error("ipc_response_invalid"))?;
    if response.schema_version != SCHEMA_VERSION || response.operation != operation {
        return Err(error("ipc_response_invalid"));
    }
    Ok(response)
}

fn claim_job(path: &Path, uid: u32) -> ProbeResult<Option<ProbeJob>> {
    let response = ipc_request(
        path,
        uid,
        "claim",
        &json!({"schema_version": SCHEMA_VERSION, "operation": "claim"}),
    )?;
    if !response.accepted {
        return Err(error("claim_rejected"));
    }
    match (response.reason.as_str(), response.job) {
        ("no_job", None) => Ok(None),
        ("job_ready", Some(job)) => {
            validate_job(&job)?;
            Ok(Some(job))
        }
        _ => Err(error("claim_response_invalid")),
    }
}

fn submit_result(
    path: &Path,
    uid: u32,
    result: &ProbeResultPayload<'_>,
) -> ProbeResult<IpcResponse> {
    ipc_request(
        path,
        uid,
        "submit",
        &json!({
            "schema_version": SCHEMA_VERSION,
            "operation": "submit",
            "result": result,
        }),
    )
}

impl ChromeConfig {
    fn discover(job: &ProbeJob, uid: u32) -> ProbeResult<Self> {
        let ci_override = disposable_ci()
            .then(|| std::env::var_os("SLIPSTREAM_BROWSER_PROBE_CHROME"))
            .flatten()
            .map(PathBuf::from);
        let require_google_identity = ci_override.is_none();
        let executable = ci_override
            .or_else(discover_production_chrome)
            .ok_or_else(|| error("chrome_unavailable"))?
            .canonicalize()
            .map_err(|_| error("chrome_unavailable"))?;
        let metadata = fs::metadata(&executable).map_err(|_| error("chrome_unavailable"))?;
        if !metadata.is_file()
            || metadata.uid() != 0 && metadata.uid() != uid
            || metadata.mode() & 0o111 == 0
            || metadata.mode() & 0o002 != 0
        {
            return Err(error("chrome_untrusted"));
        }
        let application_bundle = chrome_application_bundle(&executable)?;
        let bundle_metadata =
            fs::metadata(&application_bundle).map_err(|_| error("chrome_untrusted"))?;
        if bundle_metadata.uid() != 0 && bundle_metadata.uid() != uid
            || bundle_metadata.mode() & 0o002 != 0
        {
            return Err(error("chrome_untrusted"));
        }
        if require_google_identity {
            verify_google_chrome_identity(&application_bundle)?;
        }

        let mut target_url = format!("https://{}/", job.host);
        let mut host_resolver_rules = None;
        let mut ignore_certificate_errors = false;
        if disposable_ci() {
            if let Ok(origin) = std::env::var("SLIPSTREAM_BROWSER_PROBE_ORIGIN") {
                validate_ci_origin(&origin, &job.host)?;
                target_url = origin;
            }
            host_resolver_rules = std::env::var("SLIPSTREAM_BROWSER_PROBE_HOST_RESOLVER_RULES")
                .ok()
                .filter(|rules| !rules.is_empty() && rules.len() <= 512);
            ignore_certificate_errors =
                std::env::var_os("SLIPSTREAM_BROWSER_PROBE_IGNORE_CERTIFICATE_ERRORS").as_deref()
                    == Some(OsStr::new("1"));
        }
        Ok(Self {
            executable,
            application_bundle,
            target_url,
            host_resolver_rules,
            ignore_certificate_errors,
        })
    }

    fn chrome_arguments(&self, profile: &Path) -> Vec<OsString> {
        let mut arguments = vec![
            OsString::from("--headless"),
            OsString::from("--disable-background-networking"),
            OsString::from("--disable-component-update"),
            OsString::from("--disable-default-apps"),
            OsString::from("--disable-extensions"),
            OsString::from("--disable-features=MediaRouter,OptimizationHints,Translate"),
            OsString::from("--disable-quic"),
            OsString::from("--disable-sync"),
            OsString::from("--metrics-recording-only"),
            OsString::from("--no-default-browser-check"),
            OsString::from("--no-first-run"),
            OsString::from("--no-proxy-server"),
            OsString::from("--password-store=basic"),
            OsString::from("--remote-debugging-address=127.0.0.1"),
            OsString::from("--remote-debugging-port=0"),
            OsString::from(format!("--user-data-dir={}", profile.display())),
        ];
        if let Some(rules) = &self.host_resolver_rules {
            arguments.push(OsString::from(format!("--host-resolver-rules={rules}")));
        }
        if self.ignore_certificate_errors {
            arguments.push(OsString::from("--ignore-certificate-errors"));
        }
        arguments.push(OsString::from("about:blank"));
        arguments
    }
}

fn verify_google_chrome_identity(application_bundle: &Path) -> ProbeResult<()> {
    let verification = Command::new("/usr/bin/codesign")
        .arg("--verify")
        .arg(application_bundle)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| error("chrome_signature_invalid"))?;
    if !verification.success() {
        return Err(error("chrome_signature_invalid"));
    }
    let identity = Command::new("/usr/bin/codesign")
        .args(["-dv", "--verbose=4"])
        .arg(application_bundle)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .output()
        .map_err(|_| error("chrome_signature_invalid"))?;
    if !identity.status.success() {
        return Err(error("chrome_signature_invalid"));
    }
    let details =
        String::from_utf8(identity.stderr).map_err(|_| error("chrome_signature_invalid"))?;
    if !google_chrome_identity(&details) {
        return Err(error("chrome_signature_invalid"));
    }
    Ok(())
}

fn google_chrome_identity(details: &str) -> bool {
    let lines: BTreeSet<&str> = details.lines().collect();
    lines.contains("Identifier=com.google.Chrome") && lines.contains("TeamIdentifier=EQHXZ8M8AV")
}

fn discover_production_chrome() -> Option<PathBuf> {
    let system = PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    if system.is_file() {
        return Some(system);
    }
    let home = std::env::var_os("HOME")?;
    let user =
        PathBuf::from(home).join("Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    user.is_file().then_some(user)
}

fn chrome_application_bundle(executable: &Path) -> ProbeResult<PathBuf> {
    let macos = executable
        .parent()
        .ok_or_else(|| error("chrome_untrusted"))?;
    let contents = macos.parent().ok_or_else(|| error("chrome_untrusted"))?;
    let bundle = contents.parent().ok_or_else(|| error("chrome_untrusted"))?;
    if macos.file_name() != Some(OsStr::new("MacOS"))
        || contents.file_name() != Some(OsStr::new("Contents"))
        || bundle.extension() != Some(OsStr::new("app"))
        || !contents.join("Info.plist").is_file()
    {
        return Err(error("chrome_untrusted"));
    }
    Ok(bundle.to_path_buf())
}

fn validate_ci_origin(origin: &str, host: &str) -> ProbeResult<()> {
    let authority = origin
        .strip_prefix("https://")
        .and_then(|value| value.strip_suffix('/'))
        .ok_or_else(|| error("ci_origin_invalid"))?;
    if authority.contains('/')
        || authority.contains('@')
        || authority.contains('?')
        || authority.contains('#')
    {
        return Err(error("ci_origin_invalid"));
    }
    let (origin_host, port) = authority
        .split_once(':')
        .ok_or_else(|| error("ci_origin_invalid"))?;
    if origin_host != host
        || port
            .parse::<u16>()
            .ok()
            .filter(|value| *value > 0)
            .is_none()
    {
        return Err(error("ci_origin_invalid"));
    }
    Ok(())
}

impl ChromeSession {
    fn launch(uid: u32, config: ChromeConfig) -> ProbeResult<Self> {
        let profile = create_private_profile()?;
        let mut session = Self {
            uid,
            config,
            profile,
            launcher: None,
            rooted_process_groups: BTreeSet::new(),
        };
        if let Err(failure) = session.start() {
            let _ = session.cleanup();
            return Err(failure);
        }
        Ok(session)
    }

    fn start(&mut self) -> ProbeResult<()> {
        let stdout_path = self.profile.join("chrome.stdout.log");
        let stderr_path = self.profile.join("chrome.stderr.log");
        create_private_file(&stdout_path)?;
        create_private_file(&stderr_path)?;
        let mut command = Command::new("/usr/bin/open");
        command
            .args(["-n", "-W", "-j", "--stdout"])
            .arg(&stdout_path)
            .arg("--stderr")
            .arg(&stderr_path)
            .arg("-a")
            .arg(&self.config.application_bundle)
            .arg("--args")
            .args(self.config.chrome_arguments(&self.profile))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        self.launcher = Some(command.spawn().map_err(|_| error("chrome_launch_failed"))?);

        let deadline = Instant::now() + CHROME_LAUNCH_TIMEOUT;
        while Instant::now() < deadline {
            if let Some(status) = self
                .launcher
                .as_mut()
                .and_then(|launcher| launcher.try_wait().ok())
            {
                if status.is_some() {
                    return Err(error("chrome_launch_failed"));
                }
            }
            let processes = owned_chrome_processes(
                self.uid,
                &self.config.executable,
                &self.config.application_bundle,
                &self.profile,
                &mut self.rooted_process_groups,
            )?;
            if processes
                .iter()
                .filter(|process| {
                    process
                        .command
                        .starts_with(&self.config.executable.to_string_lossy().to_string())
                })
                .count()
                > 1
            {
                return Err(error("chrome_ownership_ambiguous"));
            }
            if !processes.is_empty()
                && matches!(read_devtools_port(&self.profile, self.uid), Ok(Some(_)))
            {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(error("chrome_launch_timeout"))
    }

    fn observe_navigation(&mut self) -> ProbeResult<NavigationObservation> {
        let port = read_devtools_port(&self.profile, self.uid)?
            .ok_or_else(|| error("devtools_unavailable"))?;
        let target = wait_for_page_target(port)?;
        let (websocket_host, websocket_path) =
            parse_websocket_location(&target.web_socket_debugger_url, port)?;
        let mut websocket = websocket_connect(port, websocket_host, &websocket_path)?;
        websocket_send_json(
            &mut websocket,
            &json!({"id": 1, "method": "Network.enable"}),
        )?;
        websocket_send_json(&mut websocket, &json!({"id": 2, "method": "Page.enable"}))?;
        websocket_send_json(
            &mut websocket,
            &json!({
                "id": 3,
                "method": "Page.navigate",
                "params": {"url": self.config.target_url},
            }),
        )?;

        let overall_deadline = Instant::now() + MIN_PENDING_OBSERVATION + Duration::from_secs(4);
        let mut request_id = None;
        let mut request_started = None;
        while Instant::now() < overall_deadline {
            let event = match websocket_read_json(&mut websocket, overall_deadline)? {
                Some(event) => event,
                None => {
                    if request_started.is_some_and(|started: Instant| {
                        Instant::now().duration_since(started) >= MIN_PENDING_OBSERVATION
                    }) {
                        let _ = websocket_send_json(
                            &mut websocket,
                            &json!({"id": 99, "method": "Browser.close"}),
                        );
                        return Ok(NavigationObservation::Pending);
                    }
                    continue;
                }
            };
            if event.get("id").and_then(Value::as_u64) == Some(3)
                && (event.get("error").is_some()
                    || event
                        .pointer("/result/errorText")
                        .and_then(Value::as_str)
                        .is_some_and(|message| !message.is_empty()))
            {
                let _ = websocket_send_json(
                    &mut websocket,
                    &json!({"id": 99, "method": "Browser.close"}),
                );
                return Ok(NavigationObservation::Terminal);
            }
            let Some(method) = event.get("method").and_then(Value::as_str) else {
                if request_started.is_some_and(|started: Instant| {
                    Instant::now().duration_since(started) >= MIN_PENDING_OBSERVATION
                }) {
                    let _ = websocket_send_json(
                        &mut websocket,
                        &json!({"id": 99, "method": "Browser.close"}),
                    );
                    return Ok(NavigationObservation::Pending);
                }
                continue;
            };
            if method == "Network.requestWillBeSent"
                && event.pointer("/params/type").and_then(Value::as_str) == Some("Document")
                && event.pointer("/params/request/url").and_then(Value::as_str)
                    == Some(self.config.target_url.as_str())
            {
                if event.pointer("/params/redirectResponse").is_some() {
                    let _ = websocket_send_json(
                        &mut websocket,
                        &json!({"id": 99, "method": "Browser.close"}),
                    );
                    return Ok(NavigationObservation::Terminal);
                }
                if let Some(observed_id) =
                    event.pointer("/params/requestId").and_then(Value::as_str)
                {
                    request_id = Some(observed_id.to_string());
                    request_started.get_or_insert_with(Instant::now);
                }
            }
            if let Some(expected) = request_id.as_deref() {
                let event_request_id = event.pointer("/params/requestId").and_then(Value::as_str);
                if matches!(
                    method,
                    "Network.responseReceived"
                        | "Network.loadingFailed"
                        | "Network.loadingFinished"
                ) && event_request_id == Some(expected)
                {
                    let _ = websocket_send_json(
                        &mut websocket,
                        &json!({"id": 99, "method": "Browser.close"}),
                    );
                    return Ok(NavigationObservation::Terminal);
                }
            }
            if request_started.is_some_and(|started| {
                Instant::now().duration_since(started) >= MIN_PENDING_OBSERVATION
            }) {
                let _ = websocket_send_json(
                    &mut websocket,
                    &json!({"id": 99, "method": "Browser.close"}),
                );
                return Ok(NavigationObservation::Pending);
            }
        }
        Err(error("navigation_observation_timeout"))
    }

    fn cleanup(&mut self) -> ProbeResult<()> {
        let mut cleanup_failed = false;
        let first_deadline = Instant::now() + CHROME_STOP_TIMEOUT;
        loop {
            let processes = match owned_chrome_processes(
                self.uid,
                &self.config.executable,
                &self.config.application_bundle,
                &self.profile,
                &mut self.rooted_process_groups,
            ) {
                Ok(processes) => processes,
                Err(_) => {
                    cleanup_failed = true;
                    break;
                }
            };
            if processes.is_empty() {
                break;
            }
            if Instant::now() >= first_deadline {
                for process in processes.iter().rev() {
                    signal_owned_process(process, self.uid, "KILL");
                }
                break;
            }
            for process in processes.iter().rev() {
                signal_owned_process(process, self.uid, "TERM");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let final_deadline = Instant::now() + CHROME_STOP_TIMEOUT;
        loop {
            let processes = match owned_chrome_processes(
                self.uid,
                &self.config.executable,
                &self.config.application_bundle,
                &self.profile,
                &mut self.rooted_process_groups,
            ) {
                Ok(processes) => processes,
                Err(_) => {
                    cleanup_failed = true;
                    break;
                }
            };
            if processes.is_empty() {
                break;
            }
            if Instant::now() >= final_deadline {
                cleanup_failed = true;
                break;
            }
            for process in processes.iter().rev() {
                signal_owned_process(process, self.uid, "KILL");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if let Some(mut launcher) = self.launcher.take() {
            if launcher.try_wait().ok().flatten().is_none() {
                let _ = launcher.kill();
            }
            let _ = launcher.wait();
        }
        let settle_deadline = Instant::now() + CHROME_STOP_TIMEOUT;
        let mut absent_since = None;
        let mut settled = false;
        while Instant::now() < settle_deadline {
            let processes = match owned_chrome_processes(
                self.uid,
                &self.config.executable,
                &self.config.application_bundle,
                &self.profile,
                &mut self.rooted_process_groups,
            ) {
                Ok(processes) => processes,
                Err(_) => {
                    cleanup_failed = true;
                    break;
                }
            };
            if processes.is_empty() {
                let now = Instant::now();
                let first_absent = absent_since.get_or_insert(now);
                if now.duration_since(*first_absent) >= Duration::from_millis(500) {
                    settled = true;
                    break;
                }
            } else {
                absent_since = None;
                for process in processes.iter().rev() {
                    signal_owned_process(process, self.uid, "KILL");
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let final_absence = owned_chrome_processes(
            self.uid,
            &self.config.executable,
            &self.config.application_bundle,
            &self.profile,
            &mut self.rooted_process_groups,
        )
        .map(|processes| processes.is_empty())
        .unwrap_or(false);
        if !settled || !final_absence {
            cleanup_failed = true;
        }
        if cleanup_failed {
            return Err(error("chrome_cleanup_failed"));
        }
        let metadata =
            fs::symlink_metadata(&self.profile).map_err(|_| error("profile_cleanup_failed"))?;
        if !metadata.is_dir() || metadata.uid() != self.uid || metadata.mode() & 0o777 != 0o700 {
            return Err(error("profile_cleanup_failed"));
        }
        fs::remove_dir_all(&self.profile).map_err(|_| error("profile_cleanup_failed"))?;
        Ok(())
    }
}

fn create_private_profile() -> ProbeResult<PathBuf> {
    let root = std::env::temp_dir();
    for _ in 0..16 {
        let nonce = random_hex(16)?;
        let path = root.join(format!("slipstream-browser-probe-{nonce}"));
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&path) {
            Ok(()) => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .map_err(|_| error("profile_create_failed"))?;
                return Ok(path);
            }
            Err(failure) if failure.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(error("profile_create_failed")),
        }
    }
    Err(error("profile_create_failed"))
}

fn create_private_file(path: &Path) -> ProbeResult<()> {
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map(|_| ())
        .map_err(|_| error("profile_create_failed"))
}

fn random_hex(bytes: usize) -> ProbeResult<String> {
    let mut payload = vec![0_u8; bytes];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut payload))
        .map_err(|_| error("random_unavailable"))?;
    let mut encoded = String::with_capacity(bytes * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in payload {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(encoded)
}

fn read_devtools_port(profile: &Path, uid: u32) -> ProbeResult<Option<u16>> {
    let path = profile.join("DevToolsActivePort");
    let path_metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(failure) if failure.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(error("devtools_file_invalid")),
    };
    if !path_metadata.is_file() || path_metadata.file_type().is_symlink() {
        return Err(error("devtools_file_invalid"));
    }
    let file = File::open(&path).map_err(|_| error("devtools_file_invalid"))?;
    let metadata = file
        .metadata()
        .map_err(|_| error("devtools_file_invalid"))?;
    if metadata.dev() != path_metadata.dev()
        || metadata.ino() != path_metadata.ino()
        || metadata.uid() != uid
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > MAX_DEVTOOLS_FILE_BYTES
    {
        return Err(error("devtools_file_invalid"));
    }
    let mut payload = String::new();
    file.take(MAX_DEVTOOLS_FILE_BYTES + 1)
        .read_to_string(&mut payload)
        .map_err(|_| error("devtools_file_invalid"))?;
    if payload.len() as u64 != metadata.len() {
        return Err(error("devtools_file_invalid"));
    }
    let mut lines = payload.lines();
    let port = lines
        .next()
        .and_then(|line| line.parse::<u16>().ok())
        .filter(|port| *port > 0)
        .ok_or_else(|| error("devtools_file_invalid"))?;
    let browser_path = lines.next().ok_or_else(|| error("devtools_file_invalid"))?;
    if !browser_path.starts_with("/devtools/browser/")
        || browser_path.len() > 256
        || lines.next().is_some()
    {
        return Err(error("devtools_file_invalid"));
    }
    Ok(Some(port))
}

fn take_process_field(input: &str) -> Option<(&str, &str)> {
    let input = input.trim_start();
    let split = input.find(char::is_whitespace).unwrap_or(input.len());
    let field = &input[..split];
    (!field.is_empty()).then_some((field, &input[split..]))
}

fn owned_chrome_processes(
    uid: u32,
    executable: &Path,
    application_bundle: &Path,
    profile: &Path,
    rooted_process_groups: &mut BTreeSet<u32>,
) -> ProbeResult<Vec<OwnedProcess>> {
    let output = Command::new("/bin/ps")
        .args(["-ww", "-axo", "pid=,uid=,pgid=,command="])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| error("process_enumeration_failed"))?;
    if !output.status.success() {
        return Err(error("process_enumeration_failed"));
    }
    let listing =
        String::from_utf8(output.stdout).map_err(|_| error("process_enumeration_failed"))?;
    let executable_prefix = executable.to_string_lossy();
    let helper_prefix = application_bundle
        .join("Contents/Frameworks")
        .to_string_lossy()
        .to_string();
    let profile_argument = format!("--user-data-dir={}", profile.display());
    let mut candidates = Vec::new();
    for line in listing.lines() {
        let Some((pid, rest)) = take_process_field(line) else {
            continue;
        };
        let Some((observed_uid, rest)) = take_process_field(rest) else {
            continue;
        };
        let Some((process_group, command)) = take_process_field(rest) else {
            continue;
        };
        let (Ok(pid), Ok(observed_uid), Ok(process_group)) = (
            pid.parse::<u32>(),
            observed_uid.parse::<u32>(),
            process_group.parse::<u32>(),
        ) else {
            continue;
        };
        let command = command.trim_start();
        let is_main =
            command == executable_prefix || command.starts_with(&format!("{executable_prefix} "));
        let is_helper = command.starts_with(&helper_prefix);
        if observed_uid != uid || process_group == 0 || (!is_main && !is_helper) {
            continue;
        }
        let has_profile = command
            .split_whitespace()
            .any(|argument| argument == profile_argument);
        if is_main && has_profile {
            rooted_process_groups.insert(process_group);
        }
        candidates.push((
            OwnedProcess {
                pid,
                process_group,
                command: command.to_string(),
            },
            is_main,
            has_profile,
        ));
    }
    let mut owned: Vec<OwnedProcess> = candidates
        .into_iter()
        .filter_map(|(process, is_main, has_profile)| {
            ((is_main && has_profile)
                || (!is_main && rooted_process_groups.contains(&process.process_group)))
            .then_some(process)
        })
        .collect();
    owned.sort_by_key(|process| process.pid);
    Ok(owned)
}

fn signal_owned_process(process: &OwnedProcess, uid: u32, signal: &str) {
    let identity = Command::new("/bin/ps")
        .args(["-p", &process.pid.to_string(), "-o", "uid=,pgid=,command="])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    let Some(listing) = identity
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
    else {
        return;
    };
    let Some((observed_uid, rest)) = take_process_field(&listing) else {
        return;
    };
    let Some((observed_group, observed_command)) = take_process_field(rest) else {
        return;
    };
    if observed_uid.parse::<u32>().ok() != Some(uid)
        || observed_group.parse::<u32>().ok() != Some(process.process_group)
        || observed_command.trim() != process.command
    {
        return;
    }
    let _ = Command::new("/bin/kill")
        .arg(format!("-{signal}"))
        .arg(process.pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn loopback_stream(port: u16, timeout: Duration) -> ProbeResult<TcpStream> {
    let address = ("127.0.0.1", port)
        .to_socket_addrs()
        .map_err(|_| error("devtools_unavailable"))?
        .next()
        .ok_or_else(|| error("devtools_unavailable"))?;
    let stream =
        TcpStream::connect_timeout(&address, timeout).map_err(|_| error("devtools_unavailable"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|_| error("devtools_unavailable"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|_| error("devtools_unavailable"))?;
    Ok(stream)
}

fn http_get(port: u16, path: &str) -> ProbeResult<Vec<u8>> {
    if !path.starts_with('/') || path.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(error("devtools_http_invalid"));
    }
    let mut stream = loopback_stream(port, CDP_CONNECT_TIMEOUT)?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    )
    .map_err(|_| error("devtools_http_invalid"))?;
    let mut response = Vec::new();
    stream
        .take(MAX_HTTP_BYTES + 1)
        .read_to_end(&mut response)
        .map_err(|_| error("devtools_http_invalid"))?;
    if response.len() as u64 > MAX_HTTP_BYTES {
        return Err(error("devtools_http_invalid"));
    }
    let body_offset = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|offset| offset + 4)
        .ok_or_else(|| error("devtools_http_invalid"))?;
    let header = std::str::from_utf8(&response[..body_offset])
        .map_err(|_| error("devtools_http_invalid"))?;
    if !header.starts_with("HTTP/1.1 200 ") && !header.starts_with("HTTP/1.0 200 ") {
        return Err(error("devtools_http_invalid"));
    }
    Ok(response[body_offset..].to_vec())
}

fn wait_for_page_target(port: u16) -> ProbeResult<DevToolsTarget> {
    let deadline = Instant::now() + CDP_CONNECT_TIMEOUT;
    while Instant::now() < deadline {
        if let Ok(payload) = http_get(port, "/json/list") {
            if let Ok(targets) = serde_json::from_slice::<Vec<DevToolsTarget>>(&payload) {
                let mut matching = targets
                    .into_iter()
                    .filter(|target| target.target_type == "page" && target.url == "about:blank");
                if let Some(target) = matching.next() {
                    if matching.next().is_none() {
                        return Ok(target);
                    }
                    return Err(error("devtools_target_ambiguous"));
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(error("devtools_target_unavailable"))
}

fn parse_websocket_location(location: &str, expected_port: u16) -> ProbeResult<(&str, String)> {
    let rest = location
        .strip_prefix("ws://")
        .ok_or_else(|| error("devtools_websocket_invalid"))?;
    let (authority, path) = rest
        .split_once('/')
        .ok_or_else(|| error("devtools_websocket_invalid"))?;
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| error("devtools_websocket_invalid"))?;
    if !matches!(host, "127.0.0.1" | "localhost")
        || port.parse::<u16>().ok() != Some(expected_port)
        || !path.starts_with("devtools/page/")
        || path.len() > 512
        || path.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(error("devtools_websocket_invalid"));
    }
    Ok((host, format!("/{path}")))
}

fn websocket_connect(port: u16, host: &str, path: &str) -> ProbeResult<TcpStream> {
    let mut stream = loopback_stream(port, CDP_CONNECT_TIMEOUT)?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {WEBSOCKET_KEY}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    .map_err(|_| error("devtools_websocket_invalid"))?;
    let mut response = Vec::new();
    let mut byte = [0_u8; 1];
    while response.len() <= 16 * 1024 {
        stream
            .read_exact(&mut byte)
            .map_err(|_| error("devtools_websocket_invalid"))?;
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let header = std::str::from_utf8(&response).map_err(|_| error("devtools_websocket_invalid"))?;
    let lower = header.to_ascii_lowercase();
    if !header.starts_with("HTTP/1.1 101 ")
        || !lower.contains("\r\nupgrade: websocket\r\n")
        || !lower.contains("\r\nconnection: upgrade\r\n")
        || !header.contains(&format!("\r\nSec-WebSocket-Accept: {WEBSOCKET_ACCEPT}\r\n"))
    {
        return Err(error("devtools_websocket_invalid"));
    }
    stream
        .set_read_timeout(Some(Duration::from_millis(250)))
        .map_err(|_| error("devtools_websocket_invalid"))?;
    Ok(stream)
}

fn websocket_send_json(stream: &mut TcpStream, value: &Value) -> ProbeResult<()> {
    let payload = serde_json::to_vec(value).map_err(|_| error("devtools_message_invalid"))?;
    websocket_send_frame(stream, 0x1, &payload)
}

fn websocket_send_frame(stream: &mut TcpStream, opcode: u8, payload: &[u8]) -> ProbeResult<()> {
    if payload.len() > MAX_WEBSOCKET_BYTES {
        return Err(error("devtools_message_invalid"));
    }
    let mut header = vec![0x80 | (opcode & 0x0f)];
    match payload.len() {
        length @ 0..=125 => header.push(0x80 | length as u8),
        length @ 126..=65_535 => {
            header.push(0x80 | 126);
            header.extend_from_slice(&(length as u16).to_be_bytes());
        }
        length => {
            header.push(0x80 | 127);
            header.extend_from_slice(&(length as u64).to_be_bytes());
        }
    }
    let mut mask = [0_u8; 4];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut mask))
        .map_err(|_| error("random_unavailable"))?;
    header.extend_from_slice(&mask);
    stream
        .write_all(&header)
        .map_err(|_| error("devtools_unavailable"))?;
    let masked: Vec<u8> = payload
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ mask[index % 4])
        .collect();
    stream
        .write_all(&masked)
        .map_err(|_| error("devtools_unavailable"))
}

fn websocket_read_json(stream: &mut TcpStream, deadline: Instant) -> ProbeResult<Option<Value>> {
    let mut fragmented = Vec::new();
    loop {
        if Instant::now() >= deadline {
            return Ok(None);
        }
        let mut first = [0_u8; 2];
        match stream.read_exact(&mut first) {
            Ok(()) => {}
            Err(failure)
                if matches!(
                    failure.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(None)
            }
            Err(_) => return Err(error("devtools_unavailable")),
        }
        let fin = first[0] & 0x80 != 0;
        let opcode = first[0] & 0x0f;
        if first[1] & 0x80 != 0 {
            return Err(error("devtools_message_invalid"));
        }
        let mut length = u64::from(first[1] & 0x7f);
        if length == 126 {
            let mut encoded = [0_u8; 2];
            stream
                .read_exact(&mut encoded)
                .map_err(|_| error("devtools_unavailable"))?;
            length = u64::from(u16::from_be_bytes(encoded));
        } else if length == 127 {
            let mut encoded = [0_u8; 8];
            stream
                .read_exact(&mut encoded)
                .map_err(|_| error("devtools_unavailable"))?;
            length = u64::from_be_bytes(encoded);
        }
        let length = usize::try_from(length).map_err(|_| error("devtools_message_invalid"))?;
        if length > MAX_WEBSOCKET_BYTES
            || fragmented.len().saturating_add(length) > MAX_WEBSOCKET_BYTES
        {
            return Err(error("devtools_message_invalid"));
        }
        let mut payload = vec![0_u8; length];
        stream
            .read_exact(&mut payload)
            .map_err(|_| error("devtools_unavailable"))?;
        match opcode {
            0x0 | 0x1 => {
                fragmented.extend_from_slice(&payload);
                if fin {
                    return serde_json::from_slice(&fragmented)
                        .map(Some)
                        .map_err(|_| error("devtools_message_invalid"));
                }
            }
            0x8 => return Err(error("devtools_unavailable")),
            0x9 => websocket_send_frame(stream, 0xA, &payload)?,
            0xA => {}
            _ => return Err(error("devtools_message_invalid")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(now: u64) -> ProbeJob {
        ProbeJob {
            schema_version: 1,
            capability: "0123456789abcdef0123456789abcdef".to_string(),
            host: "unknown.example".to_string(),
            request_started_at_unix_ms: now - 10_000,
            issued_at_unix_ms: now,
            expires_at_unix_ms: now + CAPABILITY_TTL_MS,
        }
    }

    #[test]
    fn hidden_mode_requires_the_exact_sole_argument() {
        assert!(is_browser_probe_invocation(&[
            OsString::from("slipstream"),
            OsString::from(BROWSER_PROBE_ARGUMENT),
        ]));
        assert!(!is_browser_probe_invocation(&[OsString::from(
            "slipstream"
        )]));
        assert!(!is_browser_probe_invocation(&[
            OsString::from("slipstream"),
            OsString::from(BROWSER_PROBE_ARGUMENT),
            OsString::from("unknown.example"),
        ]));
    }

    #[test]
    fn host_and_ci_origin_are_narrow() {
        assert!(canonical_host("unknown.example"));
        for invalid in [
            "UNKNOWN.example",
            "unknown.example.",
            "localhost",
            "127.0.0.1",
            "-unknown.example",
            "unknown-.example",
        ] {
            assert!(!canonical_host(invalid), "accepted {invalid}");
        }
        assert!(validate_ci_origin("https://unknown.example:8443/", "unknown.example").is_ok());
        assert!(validate_ci_origin("https://other.example:8443/", "unknown.example").is_err());
        assert!(validate_ci_origin("https://unknown.example/path", "unknown.example").is_err());
    }

    #[test]
    fn websocket_endpoint_is_exact_loopback_page() {
        assert_eq!(
            parse_websocket_location("ws://127.0.0.1:9222/devtools/page/abc", 9222,).unwrap(),
            ("127.0.0.1", "/devtools/page/abc".to_string())
        );
        assert!(parse_websocket_location("ws://example.com:9222/devtools/page/abc", 9222).is_err());
        assert!(parse_websocket_location("ws://127.0.0.1:9223/devtools/page/abc", 9222).is_err());
        assert!(
            parse_websocket_location("ws://127.0.0.1:9222/devtools/browser/abc", 9222).is_err()
        );
    }

    #[test]
    fn production_arguments_keep_the_sandbox_and_private_profile() {
        let config = ChromeConfig {
            executable: PathBuf::from(
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            ),
            application_bundle: PathBuf::from("/Applications/Google Chrome.app"),
            target_url: "https://unknown.example/".to_string(),
            host_resolver_rules: None,
            ignore_certificate_errors: false,
        };
        let arguments = config.chrome_arguments(Path::new("/private/tmp/probe"));
        let arguments: Vec<String> = arguments
            .iter()
            .map(|argument| argument.to_string_lossy().to_string())
            .collect();
        assert!(arguments.contains(&"--headless".to_string()));
        assert!(arguments.contains(&"--disable-extensions".to_string()));
        assert!(arguments.contains(&"--disable-quic".to_string()));
        assert!(arguments.contains(&"--user-data-dir=/private/tmp/probe".to_string()));
        assert!(!arguments.iter().any(|argument| argument == "--no-sandbox"));
        assert!(!arguments
            .iter()
            .any(|argument| argument == "--ignore-certificate-errors"));
    }

    #[test]
    fn production_chrome_identity_requires_google_bundle_and_team() {
        assert!(google_chrome_identity(
            "Identifier=com.google.Chrome\nTeamIdentifier=EQHXZ8M8AV\n"
        ));
        assert!(!google_chrome_identity(
            "Identifier=com.google.Chrome\nTeamIdentifier=OTHER\n"
        ));
        assert!(!google_chrome_identity(
            "Identifier=com.google.Chrome.canary\nTeamIdentifier=EQHXZ8M8AV\n"
        ));
    }

    #[test]
    fn job_shape_rejects_rebinding_and_expiry_changes() {
        let now = unix_now_ms().unwrap();
        let valid = job(now);
        assert!(validate_job(&valid).is_ok());
        let mut invalid = valid.clone();
        invalid.capability = "A123456789abcdef0123456789abcdef".to_string();
        assert!(validate_job(&invalid).is_err());
        let mut invalid = valid.clone();
        invalid.host = "UNKNOWN.example".to_string();
        assert!(validate_job(&invalid).is_err());
        let mut invalid = valid;
        invalid.expires_at_unix_ms += 1;
        assert!(validate_job(&invalid).is_err());
    }
}
