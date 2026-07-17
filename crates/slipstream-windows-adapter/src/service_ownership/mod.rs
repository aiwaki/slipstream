//! Versioned Windows service ownership evidence.

mod evidence;
pub mod v1;

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;

pub use evidence::*;
pub use v1::*;

#[cfg(windows)]
pub use windows::WindowsServiceOwnershipCollector;
