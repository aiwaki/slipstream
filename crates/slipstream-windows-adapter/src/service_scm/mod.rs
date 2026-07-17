//! Action-specific Windows Service Control Manager mutation boundary.

mod v1;

pub use v1::*;

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;

#[cfg(windows)]
pub use windows::{WindowsServiceScmEffects, WindowsServiceScmError};
