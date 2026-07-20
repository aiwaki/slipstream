//! Pure Windows packet-egress safety contracts.

#[cfg(any(windows, test))]
mod transition_v1;
mod v1;

#[cfg(all(windows, feature = "disposable-windows-packet-fixture"))]
#[allow(unsafe_code)]
mod disposable_route_owner_v1;

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;

#[cfg(all(windows, feature = "disposable-windows-packet-fixture"))]
pub use disposable_route_owner_v1::*;
#[cfg(any(windows, test))]
pub use transition_v1::*;
pub use v1::*;

#[cfg(windows)]
pub use windows::*;
