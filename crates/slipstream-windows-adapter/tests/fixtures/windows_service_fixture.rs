#[cfg(not(windows))]
fn main() {
    panic!("the disposable service fixture is Windows-only");
}

#[cfg(windows)]
fn main() {
    windows_service::run();
}

#[cfg(windows)]
mod windows_service {
    use std::path::PathBuf;
    use std::ptr::null_mut;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Duration;
    use windows_sys::Win32::System::Services::{
        RegisterServiceCtrlHandlerW, SetServiceStatus, StartServiceCtrlDispatcherW,
        SERVICE_ACCEPT_STOP, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
        SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING,
        SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    };

    const SERVICE_NAME: &str = "dev.slipstream.service";
    static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

    pub fn run() {
        let mut service_name = wide_null(SERVICE_NAME);
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: service_name.as_mut_ptr(),
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW {
                lpServiceName: null_mut(),
                lpServiceProc: None,
            },
        ];
        let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
        if ok == 0 {
            std::process::exit(2);
        }
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
        STOP_REQUESTED.store(false, Ordering::Release);
        let service_name = wide_null(SERVICE_NAME);
        let status_handle = unsafe {
            RegisterServiceCtrlHandlerW(service_name.as_ptr(), Some(service_control_handler))
        };
        if status_handle.is_null() {
            return;
        }
        if !report_status(status_handle, SERVICE_START_PENDING, 0, 1, 5_000) {
            return;
        }
        if start_failure_sentinel_path().is_file() {
            let _ = report_status(status_handle, SERVICE_STOPPED, 0, 0, 0);
            return;
        }
        if !report_status(status_handle, SERVICE_RUNNING, SERVICE_ACCEPT_STOP, 0, 0) {
            return;
        }

        let crash_sentinel = crash_sentinel_path();
        loop {
            if STOP_REQUESTED.load(Ordering::Acquire) {
                let _ = report_status(status_handle, SERVICE_STOP_PENDING, 0, 1, 5_000);
                let _ = report_status(status_handle, SERVICE_STOPPED, 0, 0, 0);
                return;
            }
            if crash_sentinel.is_file() {
                std::process::exit(23);
            }
            thread::sleep(Duration::from_millis(25));
        }
    }

    unsafe extern "system" fn service_control_handler(control: u32) {
        if control == SERVICE_CONTROL_STOP {
            STOP_REQUESTED.store(true, Ordering::Release);
        }
    }

    fn report_status(
        status_handle: SERVICE_STATUS_HANDLE,
        current_state: u32,
        controls_accepted: u32,
        checkpoint: u32,
        wait_hint: u32,
    ) -> bool {
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: current_state,
            dwControlsAccepted: controls_accepted,
            dwWin32ExitCode: 0,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: checkpoint,
            dwWaitHint: wait_hint,
        };
        unsafe { SetServiceStatus(status_handle, &status) != 0 }
    }

    fn crash_sentinel_path() -> PathBuf {
        std::env::current_exe()
            .expect("resolve disposable service executable")
            .with_extension("crash-v1")
    }

    fn start_failure_sentinel_path() -> PathBuf {
        std::env::current_exe()
            .expect("resolve disposable service executable")
            .with_extension("fail-start-v1")
    }

    fn wide_null(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
}
