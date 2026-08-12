// Thin desktop shim — all logic lives in lib.rs (shared with the future mobile
// entry point).
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

fn main() {
    if slipstream_lib::run_native_messaging_if_requested() {
        return;
    }
    if let Some(status) = slipstream_lib::run_browser_probe_if_requested() {
        std::process::exit(status);
    }
    slipstream_lib::run()
}
