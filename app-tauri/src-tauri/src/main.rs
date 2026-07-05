// Thin desktop shim — all logic lives in lib.rs (shared with the future mobile
// entry point).
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

fn main() {
    slipstream_lib::run()
}
