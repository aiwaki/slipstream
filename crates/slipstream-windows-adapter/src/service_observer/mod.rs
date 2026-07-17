//! Versioned, read-only Windows Service Control Manager observation.

pub mod v1;

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;

pub use v1::*;

#[cfg(windows)]
pub use windows::WindowsScmObserver;
