#![cfg(all(windows, feature = "disposable-windows-packet-fixture"))]

use slipstream_windows_adapter::packet_adapter::{
    collect_windows_packet_adapter_artifact, WindowsPacketAdapterArchitecture,
};
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    FreeLibrary, GetLastError, ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND, HMODULE,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

const DISPOSABLE_CI_ENV: &str = "SLIPSTREAM_WINDOWS_DISPOSABLE_CI";
const WINTUN_LIFECYCLE_CI_ENV: &str = "SLIPSTREAM_WINDOWS_WINTUN_LIFECYCLE_CI";
const WINTUN_MIN_RING_CAPACITY: u32 = 0x2_0000;

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

    let architecture = current_architecture();
    let archive = required_path("SLIPSTREAM_WINTUN_ARCHIVE");
    let license = required_path("SLIPSTREAM_WINTUN_LICENSE");
    let dll = required_path("SLIPSTREAM_WINTUN_DLL");
    let collected = collect_windows_packet_adapter_artifact(architecture, &archive, &license, &dll)
        .unwrap_or_else(|error| {
            panic!("collect pinned {} Wintun: {error:?}", architecture.as_str())
        });
    let admission = collected
        .admit()
        .unwrap_or_else(|error| panic!("admit pinned {} Wintun: {error:?}", architecture.as_str()));

    let api = LoadedWintun::load(admission.dll_path())
        .unwrap_or_else(|error| panic!("load admitted Wintun DLL: {error}"));
    let adapter_name = wide(&unique_adapter_name());
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

fn unique_adapter_name() -> String {
    let run_id = std::env::var("GITHUB_RUN_ID").unwrap_or_else(|_| "local".to_owned());
    let attempt = std::env::var("GITHUB_RUN_ATTEMPT").unwrap_or_else(|_| "0".to_owned());
    format!("SlipstreamCI-{run_id}-{attempt}-{}", std::process::id())
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
        let adapter = unsafe { (self.open_adapter)(name.as_ptr()) };
        if adapter.is_null() {
            let error = last_error();
            return if matches!(error, ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND) {
                Ok(())
            } else {
                Err(format!(
                    "adapter absence could not be proven {phase}: WintunOpenAdapter failed with {error}"
                ))
            };
        }
        unsafe {
            (self.close_adapter)(adapter);
        }
        Err(format!("test adapter still exists {phase}"))
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
