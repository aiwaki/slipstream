//! Production-facing Windows service controller.

pub mod v1;

pub use v1::*;

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;

#[cfg(windows)]
pub use windows::{WindowsServiceController, WindowsServiceControllerError};
