//! Non-AppKit durable updater watchdog.  This binary is copied verbatim from
//! the signed application to owner-private runtime storage before replacement.

#[path = "../updater_transaction.rs"]
mod updater_transaction;

use std::path::PathBuf;

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--journal")) {
        std::process::exit(64);
    }
    let Some(journal) = arguments.next().map(PathBuf::from) else {
        std::process::exit(64);
    };
    if arguments.next().is_some() {
        std::process::exit(64);
    }
    if let Err(error) = updater_transaction::run_watchdog(&journal) {
        eprintln!("durable update watchdog failed: {error}");
        std::process::exit(1);
    }
}
