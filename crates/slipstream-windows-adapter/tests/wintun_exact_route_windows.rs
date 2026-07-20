#![cfg(all(windows, feature = "disposable-windows-packet-fixture"))]

use slipstream_windows_adapter::packet_adapter::{
    collect_windows_packet_adapter_artifact, WindowsCollectedPacketAdapterAdmission,
    WindowsPacketAdapterArchitecture,
};
use slipstream_windows_adapter::packet_egress::{
    qualify_disposable_exact_host_route, WindowsOwnedRouteTransitionIssuer,
    WindowsPacketInterfaceIdentity, WINDOWS_DISPOSABLE_EXACT_ROUTE_OWNER_VERSION,
};
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    FreeLibrary, GetLastError, ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND, HMODULE,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToIndex, CreateUnicastIpAddressEntry,
    DeleteUnicastIpAddressEntry, GetUnicastIpAddressEntry, InitializeUnicastIpAddressEntry,
    MIB_UNICASTIPADDRESS_ROW,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    IpDadStatePreferred, AF_INET, IN_ADDR, IN_ADDR_0, IN_ADDR_0_0, SOCKADDR_IN, SOCKADDR_INET,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

const DISPOSABLE_CI_ENV: &str = "SLIPSTREAM_WINDOWS_DISPOSABLE_CI";
const EXACT_ROUTE_CI_ENV: &str = "SLIPSTREAM_WINDOWS_WINTUN_EXACT_ROUTE_CI";
const WINTUN_MIN_RING_CAPACITY: u32 = 0x2_0000;
const ADDRESS_READY_TIMEOUT: Duration = Duration::from_secs(5);
const ADDRESS_REMOVAL_TIMEOUT: Duration = Duration::from_secs(5);
const ADDRESS_PROBE_INTERVAL: Duration = Duration::from_millis(25);

type WintunAdapterHandle = *mut c_void;
type WintunSessionHandle = *mut c_void;
type WintunCreateAdapter = unsafe extern "system" fn(
    name: *const u16,
    tunnel_type: *const u16,
    requested_guid: *const GUID,
) -> WintunAdapterHandle;
type WintunOpenAdapter = unsafe extern "system" fn(name: *const u16) -> WintunAdapterHandle;
type WintunCloseAdapter = unsafe extern "system" fn(adapter: WintunAdapterHandle);
type WintunGetAdapterLuid =
    unsafe extern "system" fn(adapter: WintunAdapterHandle, luid: *mut NET_LUID_LH);
type WintunGetRunningDriverVersion = unsafe extern "system" fn() -> u32;
type WintunStartSession =
    unsafe extern "system" fn(adapter: WintunAdapterHandle, capacity: u32) -> WintunSessionHandle;
type WintunEndSession = unsafe extern "system" fn(session: WintunSessionHandle);

#[test]
fn native_wintun_exact_route_transition_is_owned_and_removed() {
    if std::env::var(DISPOSABLE_CI_ENV).as_deref() != Ok("1")
        || std::env::var(EXACT_ROUTE_CI_ENV).as_deref() != Ok("1")
    {
        return;
    }

    let (admission, api) = load_admitted_wintun()
        .unwrap_or_else(|error| panic!("prepare admitted Wintun DLL: {error}"));
    let adapter_name = wide(&unique_adapter_name());
    let tunnel_type = wide("Slipstream CI Route");
    api.require_adapter_absent(&adapter_name, "before exact-route fixture")
        .unwrap_or_else(|error| panic!("Wintun exact-route preflight: {error}"));

    let qualification_result = (|| {
        let mut adapter = OwnedWintunAdapter::create(&api, &adapter_name, &tunnel_type)?;
        adapter.start_session()?;
        let capture_interface = adapter.interface_identity()?;
        let mut issuer = WindowsOwnedRouteTransitionIssuer::new(1, capture_interface, 1)
            .map_err(|error| format!("construct exact-route issuer: {error}"))?;
        let mut address =
            OwnedUnicastAddress::create(capture_interface, Ipv4Addr::new(192, 0, 2, 1))?;
        let destination = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let route_result = qualify_disposable_exact_host_route(&mut issuer, destination)
            .map_err(|error| format!("qualify exact-route owner: {error}"));
        let address_cleanup = address.remove_and_verify();
        if let Err(cleanup_error) = address_cleanup {
            return Err(format!(
                "owned Wintun address cleanup failed: {cleanup_error}; route result: {route_result:?}"
            ));
        }
        let qualification = route_result?;

        if WINDOWS_DISPOSABLE_EXACT_ROUTE_OWNER_VERSION != 1
            || qualification.destination() != destination
            || qualification.exact_route_prefix() != "1.1.1.1/32"
            || qualification.capture_interface() != capture_interface
            || qualification.baseline_egress_interface() == capture_interface
            || qualification.recovered_egress_interface()
                != qualification.baseline_egress_interface()
            || qualification.route_epoch_after_removal() != 3
        {
            return Err("exact-route qualification returned inconsistent evidence".to_owned());
        }

        adapter.end_session();
        adapter.close_adapter();
        Ok::<(), String>(())
    })();

    let cleanup_result = api.require_adapter_absent(&adapter_name, "after exact-route fixture");
    if let Err(cleanup_error) = cleanup_result {
        panic!(
            "Wintun exact-route cleanup proof failed: {cleanup_error}; qualification result: {qualification_result:?}"
        );
    }
    if let Err(qualification_error) = qualification_result {
        panic!("disposable exact-route qualification failed after adapter cleanup: {qualification_error}");
    }

    drop(api);
    assert_eq!(
        admission
            .retained_dll_length()
            .expect("revalidate retained admitted Wintun DLL"),
        admission.evidence().dll_length
    );
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
    compile_error!("the disposable Wintun exact-route gate supports only AMD64 and ARM64");
}

fn required_path(name: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("{name} must point to the pinned Wintun fixture"))
}

fn unique_adapter_name() -> String {
    let run_id = std::env::var("GITHUB_RUN_ID").unwrap_or_else(|_| "local".to_owned());
    let attempt = std::env::var("GITHUB_RUN_ATTEMPT").unwrap_or_else(|_| "0".to_owned());
    format!(
        "SlipstreamCI-Route-{run_id}-{attempt}-{}",
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
    get_adapter_luid: WintunGetAdapterLuid,
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
                    create_adapter: resolve(module, c"WintunCreateAdapter")?,
                    open_adapter: resolve(module, c"WintunOpenAdapter")?,
                    close_adapter: resolve(module, c"WintunCloseAdapter")?,
                    get_adapter_luid: resolve(module, c"WintunGetAdapterLUID")?,
                    get_running_driver_version: resolve(module, c"WintunGetRunningDriverVersion")?,
                    start_session: resolve(module, c"WintunStartSession")?,
                    end_session: resolve(module, c"WintunEndSession")?,
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

    fn adapter_presence(&self, name: &[u16]) -> Result<bool, String> {
        let adapter = unsafe { (self.open_adapter)(name.as_ptr()) };
        if adapter.is_null() {
            let error = last_error();
            return if matches!(error, ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND) {
                Ok(false)
            } else {
                Err(format!(
                    "adapter presence could not be proven: WintunOpenAdapter failed with {error}"
                ))
            };
        }
        unsafe {
            (self.close_adapter)(adapter);
        }
        Ok(true)
    }

    fn require_adapter_absent(&self, name: &[u16], phase: &str) -> Result<(), String> {
        if self.adapter_presence(name)? {
            return Err(format!("test adapter still exists {phase}"));
        }
        Ok(())
    }
}

impl Drop for LoadedWintun {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.module);
        }
    }
}

struct OwnedWintunAdapter<'a> {
    api: &'a LoadedWintun,
    adapter: WintunAdapterHandle,
    session: WintunSessionHandle,
}

impl<'a> OwnedWintunAdapter<'a> {
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

    fn interface_identity(&self) -> Result<WindowsPacketInterfaceIdentity, String> {
        let mut luid = NET_LUID_LH::default();
        unsafe {
            (self.api.get_adapter_luid)(self.adapter, &mut luid);
        }
        let luid_value = unsafe { luid.Value };
        if luid_value == 0 {
            return Err("WintunGetAdapterLUID returned a zero LUID".to_owned());
        }
        let mut index = 0;
        let result = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
        if result != 0 || index == 0 {
            return Err(format!("ConvertInterfaceLuidToIndex failed with {result}"));
        }
        let mut round_trip = NET_LUID_LH::default();
        let result = unsafe { ConvertInterfaceIndexToLuid(index, &mut round_trip) };
        if result != 0 || unsafe { round_trip.Value } != luid_value {
            return Err(format!(
                "Wintun interface identity round trip failed with {result}"
            ));
        }
        Ok(WindowsPacketInterfaceIdentity {
            luid: luid_value,
            index,
        })
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

impl Drop for OwnedWintunAdapter<'_> {
    fn drop(&mut self) {
        self.end_session();
        self.close_adapter();
    }
}

struct OwnedUnicastAddress {
    row: MIB_UNICASTIPADDRESS_ROW,
    present: bool,
}

impl OwnedUnicastAddress {
    fn create(
        interface: WindowsPacketInterfaceIdentity,
        address: Ipv4Addr,
    ) -> Result<Self, String> {
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        unsafe {
            InitializeUnicastIpAddressEntry(&mut row);
        }
        row.InterfaceLuid = NET_LUID_LH {
            Value: interface.luid,
        };
        row.InterfaceIndex = interface.index;
        row.Address = ipv4_sockaddr(address);
        row.OnLinkPrefixLength = 32;
        row.SkipAsSource = false;
        row.DadState = IpDadStatePreferred;

        if lookup_unicast_address(row)?.is_some() {
            return Err("owned Wintun address already exists before creation".to_owned());
        }
        let result = unsafe { CreateUnicastIpAddressEntry(&row) };
        if result != 0 {
            return Err(format!("CreateUnicastIpAddressEntry failed with {result}"));
        }
        let mut owned = Self { row, present: true };
        if let Err(readiness_error) = owned.wait_until_preferred() {
            let cleanup_result = owned.remove_and_verify();
            return match cleanup_result {
                Ok(()) => Err(format!(
                    "owned Wintun address readiness failed after verified cleanup: {readiness_error}"
                )),
                Err(cleanup_error) => Err(format!(
                    "owned Wintun address readiness failed: {readiness_error}; exact cleanup failed: {cleanup_error}"
                )),
            };
        }
        Ok(owned)
    }

    fn wait_until_preferred(&self) -> Result<(), String> {
        let deadline = Instant::now() + ADDRESS_READY_TIMEOUT;
        loop {
            let Some(observed) = lookup_unicast_address(self.row)? else {
                return Err("owned Wintun address disappeared before becoming ready".to_owned());
            };
            if !same_unicast_address_key(observed, self.row) || observed.OnLinkPrefixLength != 32 {
                return Err("owned Wintun address identity or /32 prefix changed".to_owned());
            }
            if observed.DadState == IpDadStatePreferred && !observed.SkipAsSource {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "owned Wintun address did not become preferred within the bounded wait (dad_state={}, skip_as_source={})",
                    observed.DadState, observed.SkipAsSource
                ));
            }
            thread::sleep(ADDRESS_PROBE_INTERVAL);
        }
    }

    fn remove_and_verify(&mut self) -> Result<(), String> {
        let result = unsafe { DeleteUnicastIpAddressEntry(&self.row) };
        if result != 0 && !matches!(result, ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND) {
            return Err(format!("DeleteUnicastIpAddressEntry failed with {result}"));
        }

        let deadline = Instant::now() + ADDRESS_REMOVAL_TIMEOUT;
        loop {
            if lookup_unicast_address(self.row)?.is_none() {
                self.present = false;
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("owned Wintun address remained after bounded deletion".to_owned());
            }
            thread::sleep(ADDRESS_PROBE_INTERVAL);
        }
    }
}

impl Drop for OwnedUnicastAddress {
    fn drop(&mut self) {
        if self.present {
            unsafe {
                DeleteUnicastIpAddressEntry(&self.row);
            }
        }
    }
}

fn lookup_unicast_address(
    row: MIB_UNICASTIPADDRESS_ROW,
) -> Result<Option<MIB_UNICASTIPADDRESS_ROW>, String> {
    let mut observed = row;
    let result = unsafe { GetUnicastIpAddressEntry(&mut observed) };
    match result {
        0 => Ok(Some(observed)),
        ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND => Ok(None),
        error => Err(format!("GetUnicastIpAddressEntry failed with {error}")),
    }
}

fn same_unicast_address_key(
    left: MIB_UNICASTIPADDRESS_ROW,
    right: MIB_UNICASTIPADDRESS_ROW,
) -> bool {
    (unsafe { left.InterfaceLuid.Value }) == (unsafe { right.InterfaceLuid.Value })
        && left.InterfaceIndex == right.InterfaceIndex
        && ipv4_from_sockaddr(left.Address) == ipv4_from_sockaddr(right.Address)
}

fn ipv4_from_sockaddr(address: SOCKADDR_INET) -> Option<Ipv4Addr> {
    let address = unsafe { address.Ipv4 };
    if address.sin_family != AF_INET {
        return None;
    }
    let octets = unsafe { address.sin_addr.S_un.S_un_b };
    Some(Ipv4Addr::new(
        octets.s_b1,
        octets.s_b2,
        octets.s_b3,
        octets.s_b4,
    ))
}

fn ipv4_sockaddr(address: Ipv4Addr) -> SOCKADDR_INET {
    let [s_b1, s_b2, s_b3, s_b4] = address.octets();
    SOCKADDR_INET {
        Ipv4: SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_un_b: IN_ADDR_0_0 {
                        s_b1,
                        s_b2,
                        s_b3,
                        s_b4,
                    },
                },
            },
            sin_zero: [0; 8],
        },
    }
}

fn last_error() -> u32 {
    unsafe { GetLastError() }
}

unsafe fn resolve<T: Copy>(module: HMODULE, name: &std::ffi::CStr) -> Result<T, String> {
    let function = GetProcAddress(module, name.as_ptr().cast())
        .ok_or_else(|| format!("{} is missing ({})", name.to_string_lossy(), last_error()))?;
    Ok(std::mem::transmute_copy::<
        unsafe extern "system" fn() -> isize,
        T,
    >(&function))
}
