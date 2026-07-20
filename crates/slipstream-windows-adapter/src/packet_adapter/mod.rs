//! Signed upstream packet-adapter admission for Windows.

mod v1;
pub mod v2;

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;

pub use v1::*;

#[cfg(windows)]
pub use windows::*;
