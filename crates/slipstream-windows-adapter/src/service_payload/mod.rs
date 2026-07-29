//! Native Windows payload staging behind lifecycle actions.

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;

#[cfg(windows)]
pub(crate) use windows::windows_payload_path;
#[cfg(windows)]
pub use windows::{WindowsServicePayloadEffects, WindowsServicePayloadError};
