//! Pure Windows packet-egress safety contracts.

mod transition_v1;
mod v1;

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;

pub use transition_v1::*;
pub use v1::*;

#[cfg(windows)]
pub use windows::*;
