//! Composed native Windows service lifecycle effects.

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;

#[cfg(windows)]
pub use windows::{WindowsServiceNativeEffects, WindowsServiceNativeError};
