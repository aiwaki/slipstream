use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, OnceLock,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const BROWSER_PROBE_ARGUMENT: &str = "--pending-navigation-browser-probe";

const SCHEMA_VERSION: u8 = 1;
const PRODUCTION_SOCKET_PATH: &str = "/var/run/slipstream-browser-probe.sock";
const MAX_IPC_BYTES: usize = 2_048;
const IPC_TIMEOUT: Duration = Duration::from_secs(2);
const CAPABILITY_HEX_CHARS: usize = 32;
const WORKER_LAUNCH_ID_HEX_CHARS: usize = 16;
const WORKER_LAUNCH_ID_ENV: &str = "SLIPSTREAM_BROWSER_PROBE_LAUNCH_ID";
const CAPABILITY_TTL_MS: u64 = 30_000;
const MAX_CLAIM_AGE_MS: u64 = 2_000;
const MIN_START_BUDGET_MS: u64 = 6_000;
const WORKER_START_ATTESTATION_GRACE: Duration = Duration::from_millis(200);
const WORKER_EMPTY_QUEUE_GRACE: Duration = Duration::from_millis(500);
const CLASSIFICATION_BUDGET: Duration = Duration::from_secs(8);
const EMPTY_QUEUE_POLL_INTERVAL: Duration = Duration::from_millis(250);
const CDP_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const CHROME_STOP_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_DEVTOOLS_FILE_BYTES: u64 = 4_096;
const MAX_LAUNCH_DIAGNOSTIC_BYTES: u64 = 64 * 1_024;
const MAX_HTTP_BYTES: u64 = 256 * 1024;
const MAX_WEBSOCKET_BYTES: usize = 1024 * 1024;
const WEBSOCKET_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const WEBSOCKET_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
const OUTCOME_PENDING: &str = "navigation_pending";
const OUTCOME_REGIONAL_DENIAL: &str = "regional_access_denied";
const OUTCOME_EDGE_DENIAL: &str = "edge_access_denied";
const OUTCOME_CHALLENGE_OR_AUTH: &str = "challenge_or_auth";
const OUTCOME_USABLE: &str = "usable";
const OUTCOME_TERMINAL_ERROR: &str = "terminal_error";
const ROUTE_PREFLIGHT_MAX_DEADLINE_MS: u64 = 8_000;
const ROUTE_PREFLIGHT_MIN_START_BUDGET_MS: u64 = 2_000;
const OWNED_GEPH_ROUTE: &str = "owned_geph";
const OWNED_GEPH_PORT_ENV: &str = "SLIPSTREAM_BROWSER_PROBE_OWNED_GEPH_PORT";
const DOM_CLASSIFICATION_COMMAND_ID: u64 = 4;
const PINNED_HEADLESS_RUNTIME_VERSION: &str = "151.0.7922.77";
const PINNED_HEADLESS_RUNTIME_ARCHIVE_SHA256: &str =
    "44a2ab4206fc5d5d33974adbc3fd2a80966e7a88167914794f524fa29a3d8e8e";
const PINNED_HEADLESS_RUNTIME_MANIFEST: &str = "manifest.json";
const DOM_CLASSIFIER: &str = concat!(
    include_str!("../../../browser-companion/chromium/detector.js"),
    r#"
(() => {
  const MAX_BODY = 16000;
  const MAX_DIALOG = 8192;
  const MAX_NODES = 512;
  function boundedVisibleText(root, limit) {
    let text = "";
    let visited = 0;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      visited += 1;
      if (visited > MAX_NODES) return { text, truncated: true };
      const node = walker.currentNode;
      const parent = node.parentElement;
      if (!parent || parent.closest('script,style,noscript,template,[hidden],[aria-hidden="true"]')) continue;
      const value = node.textContent || "";
      if (!value.trim()) continue;
      const remaining = limit - text.length;
      if (remaining <= 0) return { text, truncated: true };
      text += ` ${value.slice(0, remaining)}`;
      if (value.length > remaining) return { text, truncated: true };
    }
    return { text, truncated: false };
  }
  function dialogText() {
    let text = "";
    for (const dialog of document.querySelectorAll('[role="dialog"],[aria-modal="true"]')) {
      const style = getComputedStyle(dialog);
      if (style.display === "none" || style.visibility === "hidden" || Number(style.opacity) === 0) continue;
      const remaining = MAX_DIALOG - text.length;
      if (remaining <= 0) break;
      const collected = boundedVisibleText(dialog, remaining);
      text += collected.text;
      if (collected.truncated) break;
    }
    return text;
  }
  const linkCount = document.links ? document.links.length : 0;
  const formCount = document.forms ? document.forms.length : 0;
  const bodyText = document.body && linkCount <= 40 && formCount <= 4
    ? boundedVisibleText(document.body, MAX_BODY)
    : { text: "", truncated: true };
  const result = globalThis.SlipstreamRegionalDenialDetector.detectSemanticDenial({
    title: document.title || "",
    dialogText: dialogText(),
    bodyText: bodyText.text,
    bodyTextTruncated: bodyText.truncated,
    linkCount,
    formCount
  });
  return result ? result.category : "usable";
})()
"#,
);

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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RoutePreflightProbeJob {
    schema_version: u8,
    capability: String,
    host: String,
    candidate_routes: Vec<String>,
    issued_at_unix_ms: u64,
    deadline_unix_ms: u64,
}

#[derive(Clone, Debug)]
enum ClaimedProbeJob {
    PendingNavigation(ProbeJob),
    RoutePreflight(RoutePreflightProbeJob),
}

impl ClaimedProbeJob {
    fn host(&self) -> &str {
        match self {
            Self::PendingNavigation(job) => &job.host,
            Self::RoutePreflight(job) => &job.host,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IpcResponse {
    schema_version: u8,
    accepted: bool,
    operation: String,
    reason: String,
    job: Option<Value>,
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

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct RoutePreflightResultPayload<'a> {
    schema_version: u8,
    capability: &'a str,
    host: &'a str,
    candidate_route: &'a str,
    outcome: &'a str,
    observed_at_unix_ms: u64,
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
    is_root: bool,
}

#[derive(Debug)]
struct ChromeConfig {
    executable: PathBuf,
    target_url: String,
    host_resolver_rules: Option<String>,
    ignore_certificate_errors: bool,
    proxy_server: Option<String>,
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
    RegionalAccessDenied,
    EdgeAccessDenied,
    ChallengeOrAuth,
    Usable,
    TerminalError,
}

fn failed_navigation_observation(request_elapsed: Option<Duration>) -> NavigationObservation {
    let _ = request_elapsed;
    NavigationObservation::TerminalError
}

fn document_event_observation(
    method: &str,
    event_request_id: Option<&str>,
    expected_request_id: &str,
    request_elapsed: Duration,
) -> Option<NavigationObservation> {
    if event_request_id != Some(expected_request_id) {
        return None;
    }
    match method {
        // Headers alone do not prove that the document body completed. A
        // blocked route can deliver them and then leave the body unfinished.
        "Network.loadingFinished" => Some(NavigationObservation::Usable),
        "Network.loadingFailed" => Some(failed_navigation_observation(Some(request_elapsed))),
        _ => None,
    }
}

fn is_correlated_document_redirect(event: &Value, expected_request_id: Option<&str>) -> bool {
    let Some(expected_request_id) = expected_request_id else {
        return false;
    };
    event.get("method").and_then(Value::as_str) == Some("Network.requestWillBeSent")
        && event.pointer("/params/type").and_then(Value::as_str) == Some("Document")
        && event.pointer("/params/requestId").and_then(Value::as_str) == Some(expected_request_id)
        && event.pointer("/params/redirectResponse").is_some()
}

fn full_navigation_completed(
    document_finished: bool,
    stopped_frame_id: Option<&str>,
    main_frame_id: Option<&str>,
) -> bool {
    document_finished && main_frame_id.is_some() && stopped_frame_id == main_frame_id
}

fn observation_outcome(observation: NavigationObservation) -> &'static str {
    match observation {
        NavigationObservation::Pending => OUTCOME_PENDING,
        NavigationObservation::RegionalAccessDenied => OUTCOME_REGIONAL_DENIAL,
        NavigationObservation::EdgeAccessDenied => OUTCOME_EDGE_DENIAL,
        NavigationObservation::ChallengeOrAuth => OUTCOME_CHALLENGE_OR_AUTH,
        NavigationObservation::Usable => OUTCOME_USABLE,
        NavigationObservation::TerminalError => OUTCOME_TERMINAL_ERROR,
    }
}

fn classified_dom_observation(event: &Value) -> ProbeResult<NavigationObservation> {
    if event.get("id").and_then(Value::as_u64) != Some(DOM_CLASSIFICATION_COMMAND_ID)
        || event.get("error").is_some()
    {
        return Err(error("dom_classification_invalid"));
    }
    match event
        .pointer("/result/result/value")
        .and_then(Value::as_str)
    {
        Some(OUTCOME_REGIONAL_DENIAL) => Ok(NavigationObservation::RegionalAccessDenied),
        Some(OUTCOME_EDGE_DENIAL) => Ok(NavigationObservation::EdgeAccessDenied),
        Some(OUTCOME_CHALLENGE_OR_AUTH) => Ok(NavigationObservation::ChallengeOrAuth),
        Some(OUTCOME_USABLE) => Ok(NavigationObservation::Usable),
        _ => Err(error("dom_classification_invalid")),
    }
}

fn classify_loaded_document(
    websocket: &mut TcpStream,
    deadline: Instant,
) -> ProbeResult<NavigationObservation> {
    websocket_send_json(
        websocket,
        &json!({
            "id": DOM_CLASSIFICATION_COMMAND_ID,
            "method": "Runtime.evaluate",
            "params": {
                "expression": DOM_CLASSIFIER,
                "returnByValue": true,
                "awaitPromise": false,
            },
        }),
    )?;
    while Instant::now() < deadline {
        let Some(event) = websocket_read_json(websocket, deadline)? else {
            continue;
        };
        if event.get("id").and_then(Value::as_u64) == Some(DOM_CLASSIFICATION_COMMAND_ID) {
            return classified_dom_observation(&event);
        }
    }
    Err(error("dom_classification_timeout"))
}

pub fn run_browser_probe_if_requested() -> Option<i32> {
    let arguments: Vec<OsString> = std::env::args_os().collect();
    if !is_browser_probe_invocation(&arguments) {
        return None;
    }
    Some(match run_probe_worker() {
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

fn run_probe_worker() -> ProbeResult<()> {
    let classification_deadline = Instant::now() + CLASSIFICATION_BUDGET;
    let termination_requested = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(
        signal_hook::consts::SIGTERM,
        Arc::clone(&termination_requested),
    )
    .map_err(|_| error("termination_handler_failed"))?;
    let uid = current_uid()?;
    let socket_path = configured_socket_path();
    let launch_id = configured_launch_id()?;
    // Keep the exact worker process observable long enough for the root
    // launcher to attest its final Aqua UID and command even when the first
    // queued capability has already become too old to start safely.
    if disposable_ci() {
        std::thread::sleep(WORKER_START_ATTESTATION_GRACE);
    }
    let empty_deadline = Instant::now() + WORKER_EMPTY_QUEUE_GRACE;
    loop {
        require_not_terminated(&termination_requested)?;
        if Instant::now() >= classification_deadline {
            return Ok(());
        }
        let Some(job) = claim_job(&socket_path, uid, &launch_id)? else {
            if Instant::now() >= empty_deadline {
                return Ok(());
            }
            std::thread::sleep(EMPTY_QUEUE_POLL_INTERVAL);
            continue;
        };
        let _ = run_claimed_probe(
            &socket_path,
            uid,
            &launch_id,
            job,
            &termination_requested,
            classification_deadline,
        )?;
        return Ok(());
    }
}

fn run_claimed_probe(
    socket_path: &Path,
    uid: u32,
    launch_id: &str,
    job: ClaimedProbeJob,
    termination_requested: &AtomicBool,
    classification_deadline: Instant,
) -> ProbeResult<bool> {
    let now = unix_now_ms()?;
    if !claimed_job_has_start_budget(&job, now) {
        // The broker lease keeps this stale job from being reclaimed while the
        // same process drains fresher work. It expires naturally and is not a
        // worker-launch failure.
        return Ok(false);
    }

    let claimed_deadline_unix_ms = match &job {
        ClaimedProbeJob::PendingNavigation(job) => job.expires_at_unix_ms,
        ClaimedProbeJob::RoutePreflight(job) => job.deadline_unix_ms,
    };
    let remaining_ms = claimed_deadline_unix_ms.saturating_sub(now);
    let claimed_deadline = Instant::now() + Duration::from_millis(remaining_ms);
    let classification_deadline = classification_deadline.min(claimed_deadline);

    let config = ChromeConfig::discover(&job, uid, classification_deadline)?;
    let mut chrome = ChromeSession::launch(uid, config, classification_deadline)?;
    let observation =
        match chrome.observe_navigation(termination_requested, classification_deadline) {
            Ok(observation) => observation,
            Err(failure) => {
                chrome.cleanup()?;
                return Err(failure);
            }
        };
    let outcome = observation_outcome(observation);
    let response = submit_before_cleanup(
        || {
            let observed_at_unix_ms = unix_now_ms()?;
            let payload = match &job {
                ClaimedProbeJob::PendingNavigation(job) => {
                    serde_json::to_value(ProbeResultPayload {
                        schema_version: SCHEMA_VERSION,
                        capability: &job.capability,
                        host: &job.host,
                        request_started_at_unix_ms: job.request_started_at_unix_ms,
                        observed_at_unix_ms,
                        outcome,
                    })
                }
                ClaimedProbeJob::RoutePreflight(job) => {
                    serde_json::to_value(RoutePreflightResultPayload {
                        schema_version: SCHEMA_VERSION,
                        capability: &job.capability,
                        host: &job.host,
                        candidate_route: OWNED_GEPH_ROUTE,
                        outcome,
                        observed_at_unix_ms,
                    })
                }
            }
            .map_err(|_| error("ipc_encode_failed"))?;
            submit_result(socket_path, uid, launch_id, &payload)
        },
        || chrome.cleanup(),
    )?;
    submission_ends_launch(observation, &response)
}

fn claimed_job_has_start_budget(job: &ClaimedProbeJob, now_unix_ms: u64) -> bool {
    match job {
        ClaimedProbeJob::PendingNavigation(job) => job_has_start_budget(job, now_unix_ms),
        ClaimedProbeJob::RoutePreflight(job) => {
            job.deadline_unix_ms.saturating_sub(now_unix_ms) >= ROUTE_PREFLIGHT_MIN_START_BUDGET_MS
        }
    }
}

fn job_has_start_budget(job: &ProbeJob, now_unix_ms: u64) -> bool {
    job.expires_at_unix_ms.saturating_sub(now_unix_ms) >= MIN_START_BUDGET_MS
}

fn submission_ends_launch(
    observation: NavigationObservation,
    response: &IpcResponse,
) -> ProbeResult<bool> {
    if response.accepted && response.reason == "accepted" {
        let _ = observation;
        Ok(true)
    } else {
        Err(error("submit_rejected"))
    }
}

fn submit_before_cleanup<T, Submit, Cleanup>(submit: Submit, cleanup: Cleanup) -> ProbeResult<T>
where
    Submit: FnOnce() -> ProbeResult<T>,
    Cleanup: FnOnce() -> ProbeResult<()>,
{
    let submission = submit();
    cleanup()?;
    submission
}

fn require_not_terminated(termination_requested: &AtomicBool) -> ProbeResult<()> {
    if termination_requested.load(Ordering::Relaxed) {
        Err(error("worker_terminated"))
    } else {
        Ok(())
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

fn configured_launch_id() -> ProbeResult<String> {
    let launch_id = std::env::var(WORKER_LAUNCH_ID_ENV).map_err(|_| error("launch_id_invalid"))?;
    if launch_id.len() != WORKER_LAUNCH_ID_HEX_CHARS
        || !launch_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(error("launch_id_invalid"));
    }
    Ok(launch_id)
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

fn validate_route_preflight_job(job: &RoutePreflightProbeJob) -> ProbeResult<()> {
    let now = unix_now_ms()?;
    let mut routes = job.candidate_routes.clone();
    routes.sort();
    routes.dedup();
    if job.schema_version != SCHEMA_VERSION
        || job.capability.len() != CAPABILITY_HEX_CHARS
        || !job
            .capability
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !canonical_host(&job.host)
        || job.candidate_routes.is_empty()
        || job.candidate_routes.len() > 4
        || routes.len() != job.candidate_routes.len()
        || !job.candidate_routes.iter().all(|route| {
            matches!(
                route.as_str(),
                "system" | "app_doh" | "local_strategy" | OWNED_GEPH_ROUTE
            )
        })
        || !job
            .candidate_routes
            .iter()
            .any(|route| route == OWNED_GEPH_ROUTE)
        || job.issued_at_unix_ms == 0
        || job.deadline_unix_ms <= job.issued_at_unix_ms
        || job.deadline_unix_ms - job.issued_at_unix_ms > ROUTE_PREFLIGHT_MAX_DEADLINE_MS
        || now < job.issued_at_unix_ms
        || now.saturating_sub(job.issued_at_unix_ms) > MAX_CLAIM_AGE_MS
        || job.deadline_unix_ms <= now
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

fn claim_job(path: &Path, uid: u32, launch_id: &str) -> ProbeResult<Option<ClaimedProbeJob>> {
    let response = ipc_request(
        path,
        uid,
        "claim",
        &json!({
            "schema_version": SCHEMA_VERSION,
            "operation": "claim",
            "launch_id": launch_id,
        }),
    )?;
    if !response.accepted {
        return Err(error("claim_rejected"));
    }
    match (response.reason.as_str(), response.job) {
        ("no_job", None) => Ok(None),
        ("job_ready", Some(job)) => {
            if let Ok(job) = serde_json::from_value::<ProbeJob>(job.clone()) {
                validate_job(&job)?;
                return Ok(Some(ClaimedProbeJob::PendingNavigation(job)));
            }
            let job = serde_json::from_value::<RoutePreflightProbeJob>(job)
                .map_err(|_| error("claimed_job_invalid"))?;
            validate_route_preflight_job(&job)?;
            Ok(Some(ClaimedProbeJob::RoutePreflight(job)))
        }
        _ => Err(error("claim_response_invalid")),
    }
}

fn submit_result(
    path: &Path,
    uid: u32,
    launch_id: &str,
    result: &Value,
) -> ProbeResult<IpcResponse> {
    ipc_request(
        path,
        uid,
        "submit",
        &json!({
            "schema_version": SCHEMA_VERSION,
            "operation": "submit",
            "launch_id": launch_id,
            "result": result,
        }),
    )
}

impl ChromeConfig {
    fn discover(
        job: &ClaimedProbeJob,
        uid: u32,
        classification_deadline: Instant,
    ) -> ProbeResult<Self> {
        let ci_override = disposable_ci()
            .then(|| std::env::var_os("SLIPSTREAM_BROWSER_PROBE_CHROME"))
            .flatten()
            .map(PathBuf::from);
        let production_runtime = ci_override.is_none();
        let executable = ci_override
            .or_else(discover_pinned_headless_runtime)
            .ok_or_else(|| error("headless_runtime_unavailable"))?
            .canonicalize()
            .map_err(|_| error("headless_runtime_unavailable"))?;
        let metadata =
            fs::metadata(&executable).map_err(|_| error("headless_runtime_unavailable"))?;
        if !metadata.is_file()
            || metadata.uid() != 0 && metadata.uid() != uid
            || metadata.mode() & 0o111 == 0
            || metadata.mode() & 0o002 != 0
        {
            return Err(error("headless_runtime_untrusted"));
        }
        if production_runtime {
            verify_pinned_headless_runtime(&executable, classification_deadline)?;
        }
        let mut target_url = format!("https://{}/", job.host());
        let mut host_resolver_rules = None;
        let mut ignore_certificate_errors = false;
        if disposable_ci() {
            if let Ok(origin) = std::env::var("SLIPSTREAM_BROWSER_PROBE_ORIGIN") {
                validate_ci_origin(&origin, job.host())?;
                target_url = origin;
            }
            host_resolver_rules = std::env::var("SLIPSTREAM_BROWSER_PROBE_HOST_RESOLVER_RULES")
                .ok()
                .filter(|rules| !rules.is_empty() && rules.len() <= 512);
            ignore_certificate_errors =
                std::env::var_os("SLIPSTREAM_BROWSER_PROBE_IGNORE_CERTIFICATE_ERRORS").as_deref()
                    == Some(OsStr::new("1"));
        }
        let proxy_server = match job {
            ClaimedProbeJob::PendingNavigation(_) => None,
            ClaimedProbeJob::RoutePreflight(_) => {
                let port = std::env::var(OWNED_GEPH_PORT_ENV)
                    .ok()
                    .and_then(|value| value.parse::<u16>().ok())
                    .filter(|port| *port > 0)
                    .ok_or_else(|| error("owned_geph_proxy_invalid"))?;
                Some(format!("socks5://127.0.0.1:{port}"))
            }
        };
        Ok(Self {
            executable,
            target_url,
            host_resolver_rules,
            ignore_certificate_errors,
            proxy_server,
        })
    }

    fn chrome_arguments(&self, profile: &Path) -> Vec<OsString> {
        let mut arguments = vec![
            OsString::from("--headless=new"),
            OsString::from("--hide-scrollbars"),
            OsString::from("--mute-audio"),
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
            OsString::from("--password-store=basic"),
            OsString::from("--remote-debugging-address=127.0.0.1"),
            OsString::from("--remote-debugging-port=0"),
            OsString::from(format!("--user-data-dir={}", profile.display())),
        ];
        if let Some(proxy) = &self.proxy_server {
            arguments.push(OsString::from(format!("--proxy-server={proxy}")));
        } else {
            arguments.push(OsString::from("--no-proxy-server"));
        }
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

fn verify_pinned_headless_runtime(executable: &Path, deadline: Instant) -> ProbeResult<()> {
    static VERIFICATION: OnceLock<ProbeResult<()>> = OnceLock::new();
    *VERIFICATION.get_or_init(|| verify_pinned_headless_runtime_once(executable, deadline))
}

fn verify_pinned_headless_runtime_once(executable: &Path, deadline: Instant) -> ProbeResult<()> {
    let executable_metadata =
        fs::symlink_metadata(executable).map_err(|_| error("headless_runtime_untrusted"))?;
    if !executable_metadata.is_file()
        || executable_metadata.file_type().is_symlink()
        || executable_metadata.mode() & 0o111 == 0
        || executable_metadata.mode() & 0o022 != 0
    {
        return Err(error("headless_runtime_untrusted"));
    }
    let runtime_dir = executable
        .parent()
        .ok_or_else(|| error("headless_runtime_untrusted"))?;
    let manifest_path = runtime_dir.join(PINNED_HEADLESS_RUNTIME_MANIFEST);
    let manifest_metadata = fs::symlink_metadata(&manifest_path)
        .map_err(|_| error("headless_runtime_manifest_invalid"))?;
    if !manifest_metadata.is_file()
        || manifest_metadata.file_type().is_symlink()
        || manifest_metadata.mode() & 0o022 != 0
        || manifest_metadata.len() == 0
        || manifest_metadata.len() > 4096
    {
        return Err(error("headless_runtime_manifest_invalid"));
    }
    let manifest: Value = serde_json::from_slice(
        &fs::read(&manifest_path).map_err(|_| error("headless_runtime_manifest_invalid"))?,
    )
    .map_err(|_| error("headless_runtime_manifest_invalid"))?;
    let executable_sha = manifest
        .get("executable_sha256")
        .and_then(Value::as_str)
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| error("headless_runtime_manifest_invalid"))?;
    if manifest.get("version").and_then(Value::as_str) != Some(PINNED_HEADLESS_RUNTIME_VERSION)
        || manifest.get("schema_version").and_then(Value::as_u64) != Some(1)
        || manifest.get("platform").and_then(Value::as_str) != Some("mac-arm64")
        || manifest.get("archive_sha256").and_then(Value::as_str)
            != Some(PINNED_HEADLESS_RUNTIME_ARCHIVE_SHA256)
        || executable_sha.len() != 64
    {
        return Err(error("headless_runtime_digest_invalid"));
    }
    let application_bundle = runtime_dir
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .filter(|bundle| bundle.extension() == Some(OsStr::new("app")))
        .ok_or_else(|| error("headless_runtime_untrusted"))?;
    let mut bundle_verification = Command::new("/usr/bin/codesign");
    bundle_verification
        .args(["--verify", "--deep", "--strict"])
        .arg(application_bundle)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if !command_succeeds_before(&mut bundle_verification, deadline)? {
        return Err(error("headless_runtime_signature_invalid"));
    }
    let mut verification = Command::new("/usr/bin/codesign");
    verification
        .args(["--verify", "--strict"])
        .arg(executable)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if !command_succeeds_before(&mut verification, deadline)? {
        return Err(error("headless_runtime_signature_invalid"));
    }
    Ok(())
}

fn command_succeeds_before(command: &mut Command, deadline: Instant) -> ProbeResult<bool> {
    let mut child = command
        .spawn()
        .map_err(|_| error("headless_runtime_signature_invalid"))?;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| error("headless_runtime_signature_invalid"))?
        {
            return Ok(status.success());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error("classification_deadline_exceeded"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn discover_pinned_headless_runtime() -> Option<PathBuf> {
    let current = std::env::current_exe().ok()?.canonicalize().ok()?;
    let macos = current.parent()?;
    let contents = macos.parent()?;
    if macos.file_name() != Some(OsStr::new("MacOS"))
        || contents.file_name() != Some(OsStr::new("Contents"))
    {
        return None;
    }
    let runtime = contents.join("Resources/chromium-headless-shell/chrome-headless-shell");
    runtime.is_file().then_some(runtime)
}

#[cfg(test)]
fn chrome_source_bundle(executable: &Path) -> ProbeResult<PathBuf> {
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
    fn launch(
        uid: u32,
        config: ChromeConfig,
        classification_deadline: Instant,
    ) -> ProbeResult<Self> {
        if Instant::now() >= classification_deadline {
            return Err(error("classification_deadline_exceeded"));
        }
        let profile = create_private_profile()?;
        let mut session = Self {
            uid,
            config,
            profile,
            launcher: None,
            rooted_process_groups: BTreeSet::new(),
        };
        if let Err(failure) = session.start(classification_deadline) {
            return match session.cleanup() {
                Ok(()) => Err(failure),
                Err(cleanup_failure) => Err(cleanup_failure),
            };
        }
        Ok(session)
    }

    fn start(&mut self, classification_deadline: Instant) -> ProbeResult<()> {
        let stdout_path = self.profile.join("chrome.stdout.log");
        let stderr_path = self.profile.join("chrome.stderr.log");
        create_private_file(&stdout_path)?;
        create_private_file(&stderr_path)?;
        let stdout = OpenOptions::new()
            .write(true)
            .open(&stdout_path)
            .map_err(|_| error("profile_create_failed"))?;
        let stderr = OpenOptions::new()
            .write(true)
            .open(&stderr_path)
            .map_err(|_| error("profile_create_failed"))?;
        let mut command = Command::new(&self.config.executable);
        command
            .args(self.config.chrome_arguments(&self.profile))
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        // A fresh process group makes cleanup exact without LaunchServices,
        // AppKit activation, or an Aqua application lifecycle.
        command.process_group(0);
        self.launcher = Some(
            command
                .spawn()
                .map_err(|_| error("headless_runtime_launch_failed"))?,
        );

        let deadline = classification_deadline;
        let mut observed_owned_main = false;
        let mut owned_main_alive = false;
        let mut devtools_file_failure = None;
        while Instant::now() < deadline {
            let processes = owned_chrome_processes(
                self.uid,
                &self.config.executable,
                &self.profile,
                &mut self.rooted_process_groups,
            )?;
            let owned_main_count = processes.iter().filter(|process| process.is_root).count();
            if owned_main_count > 1 {
                return Err(error("chrome_ownership_ambiguous"));
            }
            owned_main_alive = owned_main_count == 1;
            observed_owned_main |= owned_main_alive;
            match read_devtools_port(&self.profile, self.uid) {
                Ok(Some(_)) if owned_main_alive => return Ok(()),
                Ok(_) => devtools_file_failure = None,
                Err(failure) => devtools_file_failure = Some(failure),
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if let Some(failure) = devtools_file_failure {
            Err(failure)
        } else if observed_owned_main && !owned_main_alive {
            Err(error("chrome_main_exited_before_devtools"))
        } else {
            Err(error(chrome_start_failure_class(
                &stderr_path,
                self.uid,
                "chrome_devtools_start_timeout",
            )))
        }
    }

    fn observe_navigation(
        &mut self,
        termination_requested: &AtomicBool,
        classification_deadline: Instant,
    ) -> ProbeResult<NavigationObservation> {
        let port = read_devtools_port(&self.profile, self.uid)?
            .ok_or_else(|| error("devtools_unavailable"))?;
        let target = wait_for_page_target(port, classification_deadline)?;
        let (websocket_host, websocket_path) =
            parse_websocket_location(&target.web_socket_debugger_url, port)?;
        let mut websocket = websocket_connect(
            port,
            websocket_host,
            &websocket_path,
            classification_deadline,
        )?;
        websocket_send_json(
            &mut websocket,
            &json!({"id": 1, "method": "Network.enable"}),
        )?;
        websocket_send_json(&mut websocket, &json!({"id": 2, "method": "Page.enable"}))?;
        let navigation_started = Instant::now();
        websocket_send_json(
            &mut websocket,
            &json!({
                "id": 3,
                "method": "Page.navigate",
                "params": {"url": self.config.target_url},
            }),
        )?;

        let overall_deadline = classification_deadline;
        let mut request_id = None;
        let mut request_started = None;
        let mut main_frame_id = None;
        let mut document_finished = false;
        let mut stopped_frame_id = None;
        while Instant::now() < overall_deadline {
            require_not_terminated(termination_requested)?;
            let event = match websocket_read_json(&mut websocket, overall_deadline)? {
                Some(event) => event,
                None => {
                    require_not_terminated(termination_requested)?;
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
                return Ok(failed_navigation_observation(Some(
                    Instant::now().duration_since(request_started.unwrap_or(navigation_started)),
                )));
            }
            if event.get("id").and_then(Value::as_u64) == Some(3) {
                main_frame_id = event
                    .pointer("/result/frameId")
                    .and_then(Value::as_str)
                    .map(str::to_string);
            }
            let Some(method) = event.get("method").and_then(Value::as_str) else {
                continue;
            };
            if is_correlated_document_redirect(&event, request_id.as_deref()) {
                let _ = websocket_send_json(
                    &mut websocket,
                    &json!({"id": 99, "method": "Browser.close"}),
                );
                return Ok(NavigationObservation::TerminalError);
            }
            if method == "Network.requestWillBeSent"
                && event.pointer("/params/type").and_then(Value::as_str) == Some("Document")
                && event.pointer("/params/request/url").and_then(Value::as_str)
                    == Some(self.config.target_url.as_str())
            {
                if let Some(observed_id) =
                    event.pointer("/params/requestId").and_then(Value::as_str)
                {
                    request_id = Some(observed_id.to_string());
                    request_started.get_or_insert_with(Instant::now);
                }
            }
            if method == "Page.frameStoppedLoading" {
                stopped_frame_id = event
                    .pointer("/params/frameId")
                    .and_then(Value::as_str)
                    .map(str::to_string);
            }
            if let Some(expected) = request_id.as_deref() {
                let event_request_id = event.pointer("/params/requestId").and_then(Value::as_str);
                if let Some(observation) = document_event_observation(
                    method,
                    event_request_id,
                    expected,
                    request_started
                        .map(|started| Instant::now().duration_since(started))
                        .unwrap_or_default(),
                ) {
                    if observation == NavigationObservation::Usable {
                        document_finished = true;
                    } else {
                        let _ = websocket_send_json(
                            &mut websocket,
                            &json!({"id": 99, "method": "Browser.close"}),
                        );
                        return Ok(observation);
                    }
                }
            }
            if full_navigation_completed(
                document_finished,
                stopped_frame_id.as_deref(),
                main_frame_id.as_deref(),
            ) {
                let observation = classify_loaded_document(&mut websocket, overall_deadline)
                    .unwrap_or(NavigationObservation::TerminalError);
                let _ = websocket_send_json(
                    &mut websocket,
                    &json!({"id": 99, "method": "Browser.close"}),
                );
                return Ok(observation);
            }
        }
        let _ = websocket_send_json(
            &mut websocket,
            &json!({"id": 99, "method": "Browser.close"}),
        );
        Ok(if request_started.is_some() {
            NavigationObservation::Pending
        } else {
            NavigationObservation::TerminalError
        })
    }

    fn cleanup(&mut self) -> ProbeResult<()> {
        let mut cleanup_failed = false;
        let first_deadline = Instant::now() + CHROME_STOP_TIMEOUT;
        loop {
            let processes = match owned_chrome_processes(
                self.uid,
                &self.config.executable,
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
            if !terminate_child_bounded(&mut launcher, CHROME_STOP_TIMEOUT) {
                cleanup_failed = true;
            }
        }
        let settle_deadline = Instant::now() + CHROME_STOP_TIMEOUT;
        let mut absent_since = None;
        let mut settled = false;
        while Instant::now() < settle_deadline {
            let processes = match owned_chrome_processes(
                self.uid,
                &self.config.executable,
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

fn terminate_child_bounded(child: &mut Child, timeout: Duration) -> bool {
    match child.try_wait() {
        Ok(Some(_)) => return true,
        Ok(None) => {
            let _ = child.kill();
        }
        Err(_) => return false,
    }
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) | Err(_) => return false,
        }
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
                if fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).is_err() {
                    // The directory exists already, so returning immediately
                    // would strand an otherwise unreferenced browser profile.
                    // It is still empty and owned by this worker at this point.
                    let _ = fs::remove_dir(&path);
                    return Err(error("profile_create_failed"));
                }
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

#[cfg(test)]
fn classify_launch_diagnostic(diagnostic: &str) -> &'static str {
    if diagnostic.contains("Code=-10827") || diagnostic.contains("error -10827") {
        "chrome_launch_executable_missing"
    } else if diagnostic.contains("Code=-10814") || diagnostic.contains("error -10814") {
        "chrome_launch_application_missing"
    } else if diagnostic.contains("Code=-10825") || diagnostic.contains("error -10825") {
        "chrome_launch_system_incompatible"
    } else if diagnostic.contains("Code=-10826") || diagnostic.contains("error -10826") {
        "chrome_launch_architecture_invalid"
    } else if diagnostic.contains("Code=-10810")
        || diagnostic.contains("error -10810")
        || diagnostic.contains("Code=-10673")
        || diagnostic.contains("error -10673")
    {
        "chrome_launchservices_failed"
    } else if diagnostic.is_empty() {
        "chrome_launch_failed"
    } else {
        "chrome_launchservices_rejected"
    }
}

fn read_private_diagnostic(path: &Path, uid: u32) -> Option<Vec<u8>> {
    let Ok(path_metadata) = fs::symlink_metadata(path) else {
        return None;
    };
    if !path_metadata.is_file()
        || path_metadata.file_type().is_symlink()
        || path_metadata.uid() != uid
        || path_metadata.mode() & 0o777 != 0o600
        || path_metadata.len() > MAX_LAUNCH_DIAGNOSTIC_BYTES
    {
        return None;
    }
    let Ok(mut source) = File::open(path) else {
        return None;
    };
    let Ok(open_metadata) = source.metadata() else {
        return None;
    };
    if open_metadata.dev() != path_metadata.dev()
        || open_metadata.ino() != path_metadata.ino()
        || open_metadata.uid() != uid
        || open_metadata.mode() & 0o777 != 0o600
        || open_metadata.len() != path_metadata.len()
    {
        return None;
    }
    let mut payload = Vec::with_capacity(path_metadata.len() as usize);
    if source.read_to_end(&mut payload).is_err()
        || payload.len() as u64 != path_metadata.len()
        || payload.len() as u64 > MAX_LAUNCH_DIAGNOSTIC_BYTES
    {
        return None;
    }
    Some(payload)
}

fn classify_chrome_start_diagnostic(diagnostic: &str) -> &'static str {
    if (diagnostic.contains("bootstrap_look_up") || diagnostic.contains("MachPortRendezvous"))
        && diagnostic.contains("Permission denied")
    {
        "chrome_bootstrap_denied"
    } else if diagnostic.contains("ProcessSingleton") {
        "chrome_process_singleton_failed"
    } else if diagnostic.contains("DevToolsActivePort") {
        "chrome_devtools_start_failed"
    } else if diagnostic.contains("sandbox") || diagnostic.contains("Sandbox") {
        "chrome_sandbox_start_failed"
    } else if diagnostic.is_empty() {
        "chrome_launch_timeout"
    } else {
        "chrome_start_failed"
    }
}

fn chrome_start_failure_class(path: &Path, uid: u32, fallback: &'static str) -> &'static str {
    read_private_diagnostic(path, uid)
        .and_then(|payload| {
            std::str::from_utf8(&payload)
                .ok()
                .map(classify_chrome_start_diagnostic)
        })
        .unwrap_or(fallback)
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

fn chromium_process_role(command: &str, executable: &Path, profile: &Path) -> Option<(bool, bool)> {
    let executable = executable.to_string_lossy();
    if command != executable && !command.starts_with(&format!("{executable} ")) {
        return None;
    }
    let profile_argument = format!("--user-data-dir={}", profile.display());
    let mut is_root = true;
    let mut has_profile = false;
    for argument in command.split_whitespace().skip(1) {
        is_root &= !argument.starts_with("--type=");
        has_profile |= argument == profile_argument;
    }
    Some((is_root, has_profile))
}

fn owned_chrome_processes(
    uid: u32,
    executable: &Path,
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
    Ok(owned_chrome_processes_from_listing(
        &listing,
        uid,
        executable,
        profile,
        rooted_process_groups,
    ))
}

fn owned_chrome_processes_from_listing(
    listing: &str,
    uid: u32,
    executable: &Path,
    profile: &Path,
    rooted_process_groups: &mut BTreeSet<u32>,
) -> Vec<OwnedProcess> {
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
        if observed_uid != uid || process_group == 0 {
            continue;
        }
        let is_root = chromium_process_role(command, executable, profile)
            .is_some_and(|(is_root, has_profile)| is_root && has_profile);
        if is_root {
            rooted_process_groups.insert(process_group);
        }
        candidates.push(OwnedProcess {
            pid,
            process_group,
            command: command.to_string(),
            is_root,
        });
    }
    let mut owned: Vec<OwnedProcess> = candidates
        .into_iter()
        .filter_map(|process| {
            rooted_process_groups
                .contains(&process.process_group)
                .then_some(process)
        })
        .collect();
    owned.sort_by_key(|process| process.pid);
    owned
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

fn remaining_timeout(deadline: Instant, cap: Duration) -> ProbeResult<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|remaining| remaining.min(cap))
        .ok_or_else(|| error("classification_deadline_exceeded"))
}

fn http_response_extent(response: &[u8]) -> ProbeResult<Option<(usize, usize)>> {
    let Some(body_offset) = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|offset| offset + 4)
    else {
        return Ok(None);
    };
    let header = std::str::from_utf8(&response[..body_offset])
        .map_err(|_| error("devtools_http_invalid"))?;
    if !header.starts_with("HTTP/1.1 200 ") && !header.starts_with("HTTP/1.0 200 ") {
        return Err(error("devtools_http_invalid"));
    }
    let mut content_length = None;
    for line in header.lines().skip(1) {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(error("devtools_http_invalid"));
        };
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(error("devtools_http_invalid"));
            }
            content_length = value.trim().parse::<usize>().ok();
            if content_length.is_none() {
                return Err(error("devtools_http_invalid"));
            }
        }
    }
    let content_length = content_length.ok_or_else(|| error("devtools_http_invalid"))?;
    let response_length = body_offset
        .checked_add(content_length)
        .filter(|length| *length as u64 <= MAX_HTTP_BYTES)
        .ok_or_else(|| error("devtools_http_invalid"))?;
    Ok(Some((body_offset, response_length)))
}

fn http_get(port: u16, path: &str, deadline: Instant) -> ProbeResult<Vec<u8>> {
    if !path.starts_with('/') || path.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(error("devtools_http_invalid"));
    }
    let mut stream = loopback_stream(port, remaining_timeout(deadline, CDP_CONNECT_TIMEOUT)?)?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    )
    .map_err(|_| error("devtools_http_invalid"))?;
    let mut response = Vec::new();
    let mut chunk = [0_u8; 4_096];
    let (body_offset, response_length) = loop {
        let received = stream
            .read(&mut chunk)
            .map_err(|_| error("devtools_http_invalid"))?;
        if received == 0 {
            return Err(error("devtools_http_invalid"));
        }
        response.extend_from_slice(&chunk[..received]);
        if response.len() as u64 > MAX_HTTP_BYTES {
            return Err(error("devtools_http_invalid"));
        }
        if let Some(extent) = http_response_extent(&response)? {
            if response.len() > extent.1 {
                return Err(error("devtools_http_invalid"));
            }
            if response.len() == extent.1 {
                break extent;
            }
        }
    };
    if response.len() != response_length {
        return Err(error("devtools_http_invalid"));
    }
    Ok(response[body_offset..].to_vec())
}

fn wait_for_page_target(port: u16, deadline: Instant) -> ProbeResult<DevToolsTarget> {
    while Instant::now() < deadline {
        if let Ok(payload) = http_get(port, "/json/list", deadline) {
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

fn websocket_connect(
    port: u16,
    host: &str,
    path: &str,
    deadline: Instant,
) -> ProbeResult<TcpStream> {
    let mut stream = loopback_stream(port, remaining_timeout(deadline, CDP_CONNECT_TIMEOUT)?)?;
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
    use std::cell::RefCell;

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

    fn route_preflight_job(now: u64) -> RoutePreflightProbeJob {
        RoutePreflightProbeJob {
            schema_version: 1,
            capability: "abcdef0123456789abcdef0123456789".to_string(),
            host: "unknown.example".to_string(),
            candidate_routes: vec!["system".to_string(), OWNED_GEPH_ROUTE.to_string()],
            issued_at_unix_ms: now,
            deadline_unix_ms: now + ROUTE_PREFLIGHT_MAX_DEADLINE_MS,
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
    fn termination_request_is_a_bounded_worker_error() {
        let requested = AtomicBool::new(false);
        assert!(require_not_terminated(&requested).is_ok());
        requested.store(true, Ordering::Relaxed);
        assert_eq!(
            require_not_terminated(&requested).unwrap_err().0,
            "worker_terminated"
        );
    }

    #[test]
    fn one_headless_worker_has_one_hard_classification_budget() {
        assert_eq!(WORKER_EMPTY_QUEUE_GRACE, Duration::from_millis(500));
        assert_eq!(CLASSIFICATION_BUDGET, Duration::from_secs(8));
        assert_eq!(EMPTY_QUEUE_POLL_INTERVAL, Duration::from_millis(250));
        assert_eq!(MAX_CLAIM_AGE_MS, 2_000);
        assert_eq!(MIN_START_BUDGET_MS, 6_000);
        assert_eq!(WORKER_START_ATTESTATION_GRACE, Duration::from_millis(200));
        assert!(WORKER_EMPTY_QUEUE_GRACE < CLASSIFICATION_BUDGET);
    }

    #[test]
    fn route_preflight_claim_is_exact_owned_geph_and_eight_seconds() {
        let now = unix_now_ms().expect("clock");
        let valid = route_preflight_job(now);
        assert!(validate_route_preflight_job(&valid).is_ok());
        assert!(claimed_job_has_start_budget(
            &ClaimedProbeJob::RoutePreflight(valid.clone()),
            now,
        ));

        let mut rebound = valid.clone();
        rebound.candidate_routes = vec!["system".to_string()];
        assert!(validate_route_preflight_job(&rebound).is_err());

        let mut over_budget = valid;
        over_budget.deadline_unix_ms += 1;
        assert!(validate_route_preflight_job(&over_budget).is_err());
    }

    #[test]
    fn usable_requires_document_and_main_frame_completion() {
        assert!(!full_navigation_completed(
            false,
            Some("main"),
            Some("main")
        ));
        assert!(!full_navigation_completed(true, None, Some("main")));
        assert!(!full_navigation_completed(
            true,
            Some("subframe"),
            Some("main"),
        ));
        assert!(full_navigation_completed(true, Some("main"), Some("main"),));
    }

    #[test]
    fn root_process_is_distinct_from_same_binary_children() {
        let executable = Path::new("/private/runtime/chrome-headless-shell");
        let profile = Path::new("/private/tmp/probe");
        assert_eq!(
            chromium_process_role(
                "/private/runtime/chrome-headless-shell --headless=new --user-data-dir=/private/tmp/probe about:blank",
                executable,
                profile,
            ),
            Some((true, true))
        );
        assert_eq!(
            chromium_process_role(
                "/private/runtime/chrome-headless-shell --type=renderer --user-data-dir=/private/tmp/probe",
                executable,
                profile,
            ),
            Some((false, true))
        );
        assert_eq!(
            chromium_process_role(
                "/private/runtime/chrome-headless-shell --type=gpu-process",
                executable,
                profile,
            ),
            Some((false, false))
        );
        assert_eq!(
            chromium_process_role(
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --type=renderer",
                executable,
                profile,
            ),
            None
        );
    }

    #[test]
    fn owned_process_fixture_has_one_root_and_all_process_group_children() {
        let executable = Path::new("/private/runtime/chrome-headless-shell");
        let profile = Path::new("/private/tmp/probe");
        let listing = "\
101 501 101 /private/runtime/chrome-headless-shell --headless=new --user-data-dir=/private/tmp/probe about:blank\n\
102 501 101 /private/runtime/chrome-headless-shell --type=renderer\n\
103 501 101 /private/runtime/Headless Helper --type=gpu-process\n\
104 501 104 /private/runtime/chrome-headless-shell --type=renderer\n\
105 502 101 /private/runtime/unrelated\n";
        let mut groups = BTreeSet::new();
        let owned =
            owned_chrome_processes_from_listing(listing, 501, executable, profile, &mut groups);

        assert_eq!(groups, BTreeSet::from([101]));
        assert_eq!(
            owned.iter().map(|process| process.pid).collect::<Vec<_>>(),
            [101, 102, 103]
        );
        assert_eq!(owned.iter().filter(|process| process.is_root).count(), 1);
    }

    #[test]
    fn stale_claim_is_skipped_without_starting_chrome() {
        let now = 1_000_000;
        let mut claimed = job(now);
        claimed.expires_at_unix_ms = now + MIN_START_BUDGET_MS - 1;
        assert!(!job_has_start_budget(&claimed, now));
        claimed.expires_at_unix_ms = now + MIN_START_BUDGET_MS;
        assert!(job_has_start_budget(&claimed, now));
    }

    #[test]
    fn every_accepted_result_ends_launch_after_cleanup() {
        let accepted = IpcResponse {
            schema_version: SCHEMA_VERSION,
            accepted: true,
            operation: "submit".to_string(),
            reason: "accepted".to_string(),
            job: None,
        };
        assert!(submission_ends_launch(NavigationObservation::Pending, &accepted).unwrap());
        assert!(submission_ends_launch(NavigationObservation::Usable, &accepted).unwrap());
        assert!(submission_ends_launch(NavigationObservation::TerminalError, &accepted).unwrap());
    }

    #[test]
    fn document_failure_is_terminal_instead_of_route_authority() {
        assert_eq!(
            failed_navigation_observation(Some(Duration::from_secs(7))),
            NavigationObservation::TerminalError
        );
        assert_eq!(
            document_event_observation(
                "Network.loadingFailed",
                Some("document-1"),
                "document-1",
                Duration::from_secs(7),
            ),
            Some(NavigationObservation::TerminalError)
        );
    }

    #[test]
    fn response_headers_are_not_completion_but_finish_and_fast_failure_are_terminal() {
        assert_eq!(
            failed_navigation_observation(Some(Duration::from_secs(3))),
            NavigationObservation::TerminalError
        );
        assert_eq!(
            failed_navigation_observation(None),
            NavigationObservation::TerminalError
        );
        assert_eq!(
            document_event_observation(
                "Network.responseReceived",
                Some("document-1"),
                "document-1",
                Duration::from_secs(7),
            ),
            None
        );
        assert_eq!(
            document_event_observation(
                "Network.loadingFinished",
                Some("document-1"),
                "document-1",
                Duration::from_secs(7),
            ),
            Some(NavigationObservation::Usable)
        );
        assert_eq!(
            document_event_observation(
                "Network.loadingFailed",
                Some("other-document"),
                "document-1",
                Duration::from_secs(7),
            ),
            None
        );
    }

    #[test]
    fn dom_classifier_emits_only_route_preflight_outcomes() {
        for (category, expected) in [
            (
                OUTCOME_REGIONAL_DENIAL,
                NavigationObservation::RegionalAccessDenied,
            ),
            (OUTCOME_EDGE_DENIAL, NavigationObservation::EdgeAccessDenied),
            (
                OUTCOME_CHALLENGE_OR_AUTH,
                NavigationObservation::ChallengeOrAuth,
            ),
            (OUTCOME_USABLE, NavigationObservation::Usable),
        ] {
            let event = json!({
                "id": DOM_CLASSIFICATION_COMMAND_ID,
                "result": {"result": {"value": category}}
            });
            assert_eq!(classified_dom_observation(&event).unwrap(), expected);
        }
        assert!(classified_dom_observation(&json!({
            "id": DOM_CLASSIFICATION_COMMAND_ID,
            "result": {"result": {"value": "navigation_complete"}}
        }))
        .is_err());
        assert!(!DOM_CLASSIFIER.contains("chrome.runtime.sendMessage"));
        assert!(!DOM_CLASSIFIER.contains("location.href"));
        assert!(!DOM_CLASSIFIER.contains("document.cookie"));
    }

    #[test]
    fn correlated_document_redirect_is_detected_before_destination_url_filtering() {
        let redirect = json!({
            "method": "Network.requestWillBeSent",
            "params": {
                "requestId": "document-1",
                "type": "Document",
                "request": {"url": "https://redirected.example/"},
                "redirectResponse": {"status": 302}
            }
        });
        assert!(is_correlated_document_redirect(
            &redirect,
            Some("document-1")
        ));
        assert!(!is_correlated_document_redirect(
            &redirect,
            Some("other-document")
        ));
        assert!(!is_correlated_document_redirect(&redirect, None));
    }

    #[test]
    fn result_is_submitted_before_cleanup_and_cleanup_always_runs() {
        let events = RefCell::new(Vec::new());
        let result = submit_before_cleanup(
            || {
                events.borrow_mut().push("submit");
                Err::<(), _>(error("submit_failed"))
            },
            || {
                events.borrow_mut().push("cleanup");
                Ok(())
            },
        );

        assert_eq!(result.unwrap_err().0, "submit_failed");
        assert_eq!(*events.borrow(), ["submit", "cleanup"]);
    }

    #[test]
    fn cleanup_failure_overrides_a_successful_submission() {
        let result = submit_before_cleanup(|| Ok("accepted"), || Err(error("cleanup_failed")));
        assert_eq!(result.unwrap_err().0, "cleanup_failed");
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
    fn devtools_http_extent_uses_one_bounded_content_length() {
        assert_eq!(
            http_response_extent(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]").unwrap(),
            Some((38, 40))
        );
        assert_eq!(
            http_response_extent(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n").unwrap(),
            None
        );
        assert!(http_response_extent(b"HTTP/1.1 200 OK\r\n\r\n[]").is_err());
        assert!(http_response_extent(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n[]"
        )
        .is_err());
        let oversized = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_HTTP_BYTES
        );
        assert!(http_response_extent(oversized.as_bytes()).is_err());
    }

    #[test]
    fn launchservices_diagnostics_are_reduced_to_static_classes() {
        assert_eq!(
            classify_launch_diagnostic("NSOSStatusErrorDomain Code=-10827 executable missing"),
            "chrome_launch_executable_missing"
        );
        assert_eq!(
            classify_launch_diagnostic("LSOpenURLsWithRole() failed with error -10810"),
            "chrome_launchservices_failed"
        );
        assert_eq!(
            classify_launch_diagnostic("unexpected private path and payload"),
            "chrome_launchservices_rejected"
        );
        assert_eq!(classify_launch_diagnostic(""), "chrome_launch_failed");
        assert_eq!(
            classify_chrome_start_diagnostic(
                "bootstrap_look_up com.google.chrome MachPortRendezvous Permission denied"
            ),
            "chrome_bootstrap_denied"
        );
        assert_eq!(
            classify_chrome_start_diagnostic("Failed to create a ProcessSingleton"),
            "chrome_process_singleton_failed"
        );
        assert_eq!(
            classify_chrome_start_diagnostic(""),
            "chrome_launch_timeout"
        );
    }

    #[test]
    fn production_arguments_keep_the_sandbox_and_private_profile() {
        let config = ChromeConfig {
            executable: PathBuf::from(
                "/Applications/Slipstream.app/Contents/Resources/chromium-headless-shell/chrome-headless-shell",
            ),
            target_url: "https://unknown.example/".to_string(),
            host_resolver_rules: None,
            ignore_certificate_errors: false,
            proxy_server: None,
        };
        let arguments = config.chrome_arguments(Path::new("/private/tmp/probe"));
        let arguments: Vec<String> = arguments
            .iter()
            .map(|argument| argument.to_string_lossy().to_string())
            .collect();
        assert!(arguments.contains(&"--headless=new".to_string()));
        assert!(arguments.contains(&"--hide-scrollbars".to_string()));
        assert!(arguments.contains(&"--mute-audio".to_string()));
        assert!(arguments.contains(&"--disable-extensions".to_string()));
        assert!(arguments.contains(&"--disable-quic".to_string()));
        assert!(arguments.contains(&"--user-data-dir=/private/tmp/probe".to_string()));
        assert!(!arguments.iter().any(|argument| argument == "--no-sandbox"));
        assert!(!arguments
            .iter()
            .any(|argument| argument == "--ignore-certificate-errors"));
    }

    #[test]
    fn launcher_cleanup_reaps_a_live_child_inside_one_bounded_wait() {
        let mut child = Command::new("/bin/sleep").arg("5").spawn().unwrap();
        let started = Instant::now();

        assert!(terminate_child_bounded(&mut child, Duration::from_secs(1)));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(child.try_wait().unwrap().is_some());
    }

    #[test]
    fn owned_geph_candidate_uses_only_the_loopback_socks_proxy() {
        let config = ChromeConfig {
            executable: PathBuf::from(
                "/Applications/Slipstream.app/Contents/Resources/chromium-headless-shell/chrome-headless-shell",
            ),
            target_url: "https://unknown.example/".to_string(),
            host_resolver_rules: None,
            ignore_certificate_errors: false,
            proxy_server: Some("socks5://127.0.0.1:9954".to_string()),
        };
        let arguments: Vec<String> = config
            .chrome_arguments(Path::new("/private/tmp/probe"))
            .iter()
            .map(|argument| argument.to_string_lossy().to_string())
            .collect();
        assert!(arguments.contains(&"--proxy-server=socks5://127.0.0.1:9954".to_string()));
        assert!(!arguments.contains(&"--no-proxy-server".to_string()));
        assert!(!arguments.iter().any(|argument| argument == "--no-sandbox"));
    }

    #[test]
    fn production_runtime_is_bundle_pinned_and_does_not_search_installed_browsers() {
        let runtime = Path::new("/Applications/Slipstream.app/Contents/Resources/chromium-headless-shell/chrome-headless-shell");
        assert_eq!(
            runtime.file_name(),
            Some(OsStr::new("chrome-headless-shell"))
        );
        assert_eq!(
            runtime.parent().unwrap().file_name(),
            Some(OsStr::new("chromium-headless-shell"))
        );
        assert_eq!(PINNED_HEADLESS_RUNTIME_VERSION, "151.0.7922.77");
    }

    #[test]
    fn extensionless_chrome_bundle_is_disposable_ci_only() {
        let root = std::env::temp_dir().join(format!(
            "slipstream-extensionless-chrome-test-{}",
            std::process::id()
        ));
        let executable = root.join("Probe.app/Contents/MacOS/Google Chrome for Testing");
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::write(root.join("Probe.app/Contents/Info.plist"), b"plist").unwrap();
        fs::write(&executable, b"chrome").unwrap();
        assert_eq!(
            chrome_source_bundle(&executable).unwrap(),
            root.join("Probe.app")
        );
        fs::remove_dir_all(&root).unwrap();
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
