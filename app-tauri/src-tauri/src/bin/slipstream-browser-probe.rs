// A console-only entry point for the bounded packaged browser probe.
//
// Keep this binary independent of `slipstream_lib`: linking the Tauri tray
// library would turn a background transport helper into an AppKit application
// and make macOS register it with LaunchServices.
#[path = "../browser_probe.rs"]
mod browser_probe;

fn main() {
    match browser_probe::run_browser_probe_if_requested() {
        Some(status) => std::process::exit(status),
        None => {
            eprintln!("slipstream browser probe failed: invalid_invocation");
            std::process::exit(64);
        }
    }
}
