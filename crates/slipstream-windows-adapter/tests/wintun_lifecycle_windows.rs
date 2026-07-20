#![cfg(all(windows, feature = "disposable-windows-packet-fixture"))]

use slipstream_windows_adapter::packet_adapter::{
    collect_windows_packet_adapter_artifact, WindowsCollectedPacketAdapterAdmission,
    WindowsPacketAdapterArchitecture,
};
use std::ffi::c_void;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::ptr;
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    FreeLibrary, GetLastError, ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND, HMODULE,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

const DISPOSABLE_CI_ENV: &str = "SLIPSTREAM_WINDOWS_DISPOSABLE_CI";
const WINTUN_LIFECYCLE_CI_ENV: &str = "SLIPSTREAM_WINDOWS_WINTUN_LIFECYCLE_CI";
const WINTUN_CRASH_CI_ENV: &str = "SLIPSTREAM_WINDOWS_WINTUN_CRASH_CI";
const WINTUN_CRASH_CHILD_ENV: &str = "SLIPSTREAM_WINDOWS_WINTUN_CRASH_CHILD";
const WINTUN_CRASH_ADAPTER_ENV: &str = "SLIPSTREAM_WINDOWS_WINTUN_CRASH_ADAPTER";
const WINTUN_CRASH_READY_ENV: &str = "SLIPSTREAM_WINDOWS_WINTUN_CRASH_READY";
const WINTUN_MIN_RING_CAPACITY: u32 = 0x2_0000;
const CHILD_READY_TIMEOUT: Duration = Duration::from_secs(45);
const CHILD_FAILSAFE_LIFETIME: Duration = Duration::from_secs(90);
const ADAPTER_REMOVAL_TIMEOUT: Duration = Duration::from_secs(30);
const PROBE_INTERVAL: Duration = Duration::from_millis(100);

type WintunAdapterHandle = *mut c_void;
type WintunSessionHandle = *mut c_void;
type WintunCreateAdapter = unsafe extern "system" fn(
    name: *const u16,
    tunnel_type: *const u16,
    requested_guid: *const GUID,
) -> WintunAdapterHandle;
type WintunOpenAdapter = unsafe extern "system" fn(name: *const u16) -> WintunAdapterHandle;
type WintunCloseAdapter = unsafe extern "system" fn(adapter: WintunAdapterHandle);
type WintunGetRunningDriverVersion = unsafe extern "system" fn() -> u32;
type WintunStartSession =
    unsafe extern "system" fn(adapter: WintunAdapterHandle, capacity: u32) -> WintunSessionHandle;
type WintunEndSession = unsafe extern "system" fn(session: WintunSessionHandle);

#[test]
fn native_wintun_adapter_and_session_lifecycle_is_owned_and_disposable() {
    if std::env::var(DISPOSABLE_CI_ENV).as_deref() != Ok("1")
        || std::env::var(WINTUN_LIFECYCLE_CI_ENV).as_deref() != Ok("1")
    {
        return;
    }

    let (admission, api) = load_admitted_wintun()
        .unwrap_or_else(|error| panic!("prepare admitted Wintun DLL: {error}"));
    let adapter_name = wide(&unique_adapter_name("Lifecycle"));
    let tunnel_type = wide("Slipstream CI");

    api.require_adapter_absent(&adapter_name, "before creation")
        .unwrap_or_else(|error| panic!("Wintun preflight: {error}"));

    let lifecycle_result = (|| {
        let mut lifecycle = OwnedWintunLifecycle::create(&api, &adapter_name, &tunnel_type)?;
        lifecycle.start_session()?;
        lifecycle.end_session();
        lifecycle.close_adapter();
        Ok::<(), String>(())
    })();

    let cleanup_result = api.require_adapter_absent(&adapter_name, "after cleanup");
    if let Err(cleanup_error) = cleanup_result {
        panic!(
            "Wintun cleanup proof failed: {cleanup_error}; lifecycle result: {lifecycle_result:?}"
        );
    }
    if let Err(lifecycle_error) = lifecycle_result {
        panic!("disposable Wintun lifecycle failed after clean rollback: {lifecycle_error}");
    }

    // Keep the read-only artifact admission alive until after the DLL is unloaded.
    drop(api);
    assert_eq!(
        admission
            .retained_dll_length()
            .expect("revalidate retained admitted Wintun DLL"),
        admission.evidence().dll_length
    );
}

#[test]
fn native_wintun_child_termination_removes_owned_adapter_and_session() {
    if std::env::var(DISPOSABLE_CI_ENV).as_deref() != Ok("1")
        || std::env::var(WINTUN_CRASH_CI_ENV).as_deref() != Ok("1")
    {
        return;
    }

    let (admission, api) = load_admitted_wintun()
        .unwrap_or_else(|error| panic!("prepare admitted Wintun DLL: {error}"));
    let adapter_name_string = unique_adapter_name("Crash");
    let adapter_name = wide(&adapter_name_string);
    api.require_adapter_absent(&adapter_name, "before crash fixture")
        .unwrap_or_else(|error| panic!("Wintun crash preflight: {error}"));

    let fixture_dir = OwnedFixtureDirectory::create()
        .unwrap_or_else(|error| panic!("create exact crash fixture directory: {error}"));
    let current_exe = std::env::current_exe()
        .unwrap_or_else(|error| panic!("resolve exact integration-test executable: {error}"));
    let child = Command::new(current_exe)
        .args([
            "--exact",
            "native_wintun_crash_child_holds_owned_adapter_and_session",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(WINTUN_CRASH_CHILD_ENV, "1")
        .env(WINTUN_CRASH_ADAPTER_ENV, &adapter_name_string)
        .env(WINTUN_CRASH_READY_ENV, fixture_dir.marker_path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn exact Wintun crash child: {error}"));
    let mut child = ExactChild::new(child);
    let expected_marker = format!("{adapter_name_string}\n{}\n", child.id());

    wait_for_child_ready(&mut child, fixture_dir.marker_path(), &expected_marker)
        .unwrap_or_else(|error| panic!("Wintun crash child readiness: {error}"));
    api.require_adapter_present(&adapter_name, "before exact child termination")
        .unwrap_or_else(|error| panic!("Wintun crash live proof: {error}"));

    let status = child
        .terminate_and_wait()
        .unwrap_or_else(|error| panic!("terminate exact Wintun crash child: {error}"));
    assert!(!status.success(), "crash child exited gracefully: {status}");
    api.wait_for_adapter_absent(&adapter_name, ADAPTER_REMOVAL_TIMEOUT)
        .unwrap_or_else(|error| panic!("Wintun post-crash cleanup proof: {error}"));

    drop(api);
    assert_eq!(
        admission
            .retained_dll_length()
            .expect("revalidate retained admitted Wintun DLL after child termination"),
        admission.evidence().dll_length
    );
}

#[test]
fn native_wintun_crash_child_holds_owned_adapter_and_session() {
    if std::env::var(DISPOSABLE_CI_ENV).as_deref() != Ok("1")
        || std::env::var(WINTUN_CRASH_CI_ENV).as_deref() != Ok("1")
        || std::env::var(WINTUN_CRASH_CHILD_ENV).as_deref() != Ok("1")
    {
        return;
    }

    let adapter_name_string = std::env::var(WINTUN_CRASH_ADAPTER_ENV)
        .expect("crash child requires its exact adapter name");
    assert!(
        adapter_name_string.starts_with("SlipstreamCI-Crash-"),
        "crash child rejected an unowned adapter name"
    );
    let ready_path = required_path(WINTUN_CRASH_READY_ENV);
    let (admission, api) = load_admitted_wintun()
        .unwrap_or_else(|error| panic!("prepare admitted child Wintun DLL: {error}"));
    let adapter_name = wide(&adapter_name_string);
    let tunnel_type = wide("Slipstream CI Crash");
    api.require_adapter_absent(&adapter_name, "inside crash child before creation")
        .unwrap_or_else(|error| panic!("Wintun crash child preflight: {error}"));

    let mut lifecycle = OwnedWintunLifecycle::create(&api, &adapter_name, &tunnel_type)
        .unwrap_or_else(|error| panic!("create crash-child adapter: {error}"));
    lifecycle
        .start_session()
        .unwrap_or_else(|error| panic!("start crash-child session: {error}"));
    write_ready_marker(
        &ready_path,
        &format!("{adapter_name_string}\n{}\n", std::process::id()),
    )
    .unwrap_or_else(|error| panic!("publish crash-child readiness: {error}"));

    // The parent terminates this exact process handle. Keep every owned handle
    // live so process termination, rather than Rust Drop, performs the cleanup.
    std::hint::black_box((&admission, &api, &lifecycle));
    thread::sleep(CHILD_FAILSAFE_LIFETIME);
    std::process::exit(86);
}

fn load_admitted_wintun() -> Result<(WindowsCollectedPacketAdapterAdmission, LoadedWintun), String>
{
    let architecture = current_architecture();
    let archive = required_path("SLIPSTREAM_WINTUN_ARCHIVE");
    let license = required_path("SLIPSTREAM_WINTUN_LICENSE");
    let dll = required_path("SLIPSTREAM_WINTUN_DLL");
    let collected = collect_windows_packet_adapter_artifact(architecture, &archive, &license, &dll)
        .map_err(|error| format!("collect pinned {} Wintun: {error:?}", architecture.as_str()))?;
    let admission = collected
        .admit()
        .map_err(|error| format!("admit pinned {} Wintun: {error:?}", architecture.as_str()))?;
    let api = LoadedWintun::load(admission.dll_path())
        .map_err(|error| format!("load admitted Wintun DLL: {error}"))?;
    Ok((admission, api))
}

fn current_architecture() -> WindowsPacketAdapterArchitecture {
    #[cfg(target_arch = "x86_64")]
    {
        WindowsPacketAdapterArchitecture::Amd64
    }
    #[cfg(target_arch = "aarch64")]
    {
        WindowsPacketAdapterArchitecture::Arm64
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("the disposable Wintun lifecycle gate supports only AMD64 and ARM64");
}

fn required_path(name: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("{name} must point to the pinned Wintun fixture"))
}

fn unique_adapter_name(fixture: &str) -> String {
    let run_id = std::env::var("GITHUB_RUN_ID").unwrap_or_else(|_| "local".to_owned());
    let attempt = std::env::var("GITHUB_RUN_ATTEMPT").unwrap_or_else(|_| "0".to_owned());
    format!(
        "SlipstreamCI-{fixture}-{run_id}-{attempt}-{}",
        std::process::id()
    )
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

struct LoadedWintun {
    module: HMODULE,
    create_adapter: WintunCreateAdapter,
    open_adapter: WintunOpenAdapter,
    close_adapter: WintunCloseAdapter,
    get_running_driver_version: WintunGetRunningDriverVersion,
    start_session: WintunStartSession,
    end_session: WintunEndSession,
}

impl LoadedWintun {
    fn load(path: &Path) -> Result<Self, String> {
        let path_wide = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let module = unsafe {
            LoadLibraryExW(
                path_wide.as_ptr(),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return Err(format!("LoadLibraryExW failed with {}", last_error()));
        }

        let resolved = unsafe {
            (|| {
                Ok(Self {
                    module,
                    create_adapter: resolve_create_adapter(module)?,
                    open_adapter: resolve_open_adapter(module)?,
                    close_adapter: resolve_close_adapter(module)?,
                    get_running_driver_version: resolve_driver_version(module)?,
                    start_session: resolve_start_session(module)?,
                    end_session: resolve_end_session(module)?,
                })
            })()
        };
        if resolved.is_err() {
            unsafe {
                FreeLibrary(module);
            }
        }
        resolved
    }

    fn require_adapter_absent(&self, name: &[u16], phase: &str) -> Result<(), String> {
        match self.adapter_presence(name)? {
            AdapterPresence::Absent => Ok(()),
            AdapterPresence::Present => Err(format!("test adapter still exists {phase}")),
        }
    }

    fn require_adapter_present(&self, name: &[u16], phase: &str) -> Result<(), String> {
        match self.adapter_presence(name)? {
            AdapterPresence::Present => Ok(()),
            AdapterPresence::Absent => Err(format!("test adapter is absent {phase}")),
        }
    }

    fn wait_for_adapter_absent(&self, name: &[u16], timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.adapter_presence(name)? {
                AdapterPresence::Absent => return Ok(()),
                AdapterPresence::Present if Instant::now() < deadline => {
                    thread::sleep(PROBE_INTERVAL);
                }
                AdapterPresence::Present => {
                    return Err(format!(
                        "test adapter remained present after {} ms",
                        timeout.as_millis()
                    ));
                }
            }
        }
    }

    fn adapter_presence(&self, name: &[u16]) -> Result<AdapterPresence, String> {
        let adapter = unsafe { (self.open_adapter)(name.as_ptr()) };
        if adapter.is_null() {
            let error = last_error();
            return if matches!(error, ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND) {
                Ok(AdapterPresence::Absent)
            } else {
                Err(format!(
                    "adapter presence could not be proven: WintunOpenAdapter failed with {error}"
                ))
            };
        }
        unsafe {
            (self.close_adapter)(adapter);
        }
        Ok(AdapterPresence::Present)
    }
}

impl Drop for LoadedWintun {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.module);
        }
    }
}

struct OwnedWintunLifecycle<'a> {
    api: &'a LoadedWintun,
    adapter: WintunAdapterHandle,
    session: WintunSessionHandle,
}

impl<'a> OwnedWintunLifecycle<'a> {
    fn create(api: &'a LoadedWintun, name: &[u16], tunnel_type: &[u16]) -> Result<Self, String> {
        let adapter =
            unsafe { (api.create_adapter)(name.as_ptr(), tunnel_type.as_ptr(), ptr::null()) };
        if adapter.is_null() {
            return Err(format!("WintunCreateAdapter failed with {}", last_error()));
        }
        let version = unsafe { (api.get_running_driver_version)() };
        if version == 0 {
            let error = last_error();
            unsafe {
                (api.close_adapter)(adapter);
            }
            return Err(format!("WintunGetRunningDriverVersion failed with {error}"));
        }
        Ok(Self {
            api,
            adapter,
            session: ptr::null_mut(),
        })
    }

    fn start_session(&mut self) -> Result<(), String> {
        let session = unsafe { (self.api.start_session)(self.adapter, WINTUN_MIN_RING_CAPACITY) };
        if session.is_null() {
            return Err(format!("WintunStartSession failed with {}", last_error()));
        }
        self.session = session;
        Ok(())
    }

    fn end_session(&mut self) {
        if self.session.is_null() {
            return;
        }
        unsafe {
            (self.api.end_session)(self.session);
        }
        self.session = ptr::null_mut();
    }

    fn close_adapter(&mut self) {
        if self.adapter.is_null() {
            return;
        }
        unsafe {
            (self.api.close_adapter)(self.adapter);
        }
        self.adapter = ptr::null_mut();
    }
}

impl Drop for OwnedWintunLifecycle<'_> {
    fn drop(&mut self) {
        self.end_session();
        self.close_adapter();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdapterPresence {
    Absent,
    Present,
}

struct ExactChild {
    child: Option<Child>,
}

impl ExactChild {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn id(&self) -> u32 {
        self.child.as_ref().expect("child handle is present").id()
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("child handle is present")
    }

    fn terminate_and_wait(&mut self) -> Result<ExitStatus, String> {
        let child = self.child_mut();
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("inspect exact child before termination: {error}"))?
        {
            return Err(format!("crash child exited before termination: {status}"));
        }
        child
            .kill()
            .map_err(|error| format!("terminate exact child handle: {error}"))?;
        let status = child
            .wait()
            .map_err(|error| format!("wait for exact terminated child: {error}"))?;
        self.child = None;
        Ok(status)
    }
}

impl Drop for ExactChild {
    fn drop(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        let _ = child.kill();
        let _ = child.wait();
    }
}

struct OwnedFixtureDirectory {
    directory: PathBuf,
    marker: PathBuf,
}

impl OwnedFixtureDirectory {
    fn create() -> Result<Self, String> {
        let base = std::env::var_os("RUNNER_TEMP")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let run_id = std::env::var("GITHUB_RUN_ID").unwrap_or_else(|_| "local".to_owned());
        let attempt = std::env::var("GITHUB_RUN_ATTEMPT").unwrap_or_else(|_| "0".to_owned());
        let directory = base.join(format!(
            "slipstream-wintun-crash-{run_id}-{attempt}-{}",
            std::process::id()
        ));
        fs::create_dir(&directory)
            .map_err(|error| format!("create {}: {error}", directory.display()))?;
        let marker = directory.join("ready.txt");
        Ok(Self { directory, marker })
    }

    fn marker_path(&self) -> &Path {
        &self.marker
    }
}

impl Drop for OwnedFixtureDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.marker);
        let _ = fs::remove_dir(&self.directory);
    }
}

fn wait_for_child_ready(
    child: &mut ExactChild,
    marker: &Path,
    expected: &str,
) -> Result<(), String> {
    let deadline = Instant::now() + CHILD_READY_TIMEOUT;
    loop {
        if let Some(status) = child
            .child_mut()
            .try_wait()
            .map_err(|error| format!("inspect crash child readiness: {error}"))?
        {
            return Err(format!("crash child exited before readiness: {status}"));
        }
        match fs::read_to_string(marker) {
            Ok(contents) if contents == expected => return Ok(()),
            Ok(contents) => {
                return Err(format!(
                    "crash child published unexpected marker {contents:?}"
                ));
            }
            Err(error) if error.kind() == ErrorKind::NotFound && Instant::now() < deadline => {
                thread::sleep(PROBE_INTERVAL);
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Err(format!(
                    "crash child did not publish readiness within {} ms",
                    CHILD_READY_TIMEOUT.as_millis()
                ));
            }
            Err(error) => {
                return Err(format!(
                    "read crash child marker {}: {error}",
                    marker.display()
                ));
            }
        }
    }
}

fn write_ready_marker(path: &Path, contents: &str) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))?;
    file.write_all(contents.as_bytes())
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("sync {}: {error}", path.display()))
}

fn last_error() -> u32 {
    unsafe { GetLastError() }
}

unsafe fn resolve_create_adapter(module: HMODULE) -> Result<WintunCreateAdapter, String> {
    let function = GetProcAddress(module, c"WintunCreateAdapter".as_ptr().cast())
        .ok_or_else(|| format!("WintunCreateAdapter is missing ({})", last_error()))?;
    Ok(std::mem::transmute::<
        unsafe extern "system" fn() -> isize,
        WintunCreateAdapter,
    >(function))
}

unsafe fn resolve_open_adapter(module: HMODULE) -> Result<WintunOpenAdapter, String> {
    let function = GetProcAddress(module, c"WintunOpenAdapter".as_ptr().cast())
        .ok_or_else(|| format!("WintunOpenAdapter is missing ({})", last_error()))?;
    Ok(std::mem::transmute::<
        unsafe extern "system" fn() -> isize,
        WintunOpenAdapter,
    >(function))
}

unsafe fn resolve_close_adapter(module: HMODULE) -> Result<WintunCloseAdapter, String> {
    let function = GetProcAddress(module, c"WintunCloseAdapter".as_ptr().cast())
        .ok_or_else(|| format!("WintunCloseAdapter is missing ({})", last_error()))?;
    Ok(std::mem::transmute::<
        unsafe extern "system" fn() -> isize,
        WintunCloseAdapter,
    >(function))
}

unsafe fn resolve_driver_version(module: HMODULE) -> Result<WintunGetRunningDriverVersion, String> {
    let function = GetProcAddress(module, c"WintunGetRunningDriverVersion".as_ptr().cast())
        .ok_or_else(|| {
            format!(
                "WintunGetRunningDriverVersion is missing ({})",
                last_error()
            )
        })?;
    Ok(std::mem::transmute::<
        unsafe extern "system" fn() -> isize,
        WintunGetRunningDriverVersion,
    >(function))
}

unsafe fn resolve_start_session(module: HMODULE) -> Result<WintunStartSession, String> {
    let function = GetProcAddress(module, c"WintunStartSession".as_ptr().cast())
        .ok_or_else(|| format!("WintunStartSession is missing ({})", last_error()))?;
    Ok(std::mem::transmute::<
        unsafe extern "system" fn() -> isize,
        WintunStartSession,
    >(function))
}

unsafe fn resolve_end_session(module: HMODULE) -> Result<WintunEndSession, String> {
    let function = GetProcAddress(module, c"WintunEndSession".as_ptr().cast())
        .ok_or_else(|| format!("WintunEndSession is missing ({})", last_error()))?;
    Ok(std::mem::transmute::<
        unsafe extern "system" fn() -> isize,
        WintunEndSession,
    >(function))
}
