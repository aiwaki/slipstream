//! No-network Windows adapter boundary for Slipstream.
//!
//! Version 1 intentionally contains no Windows API, socket, process, DNS,
//! proxy, VPN, service, installer, or filesystem effects. It consumes the
//! platform-neutral `slipstream-core` contracts and delegates every concrete
//! effect through an injected interface that can be recorded in tests.

#![forbid(unsafe_code)]

mod v1;

pub use v1::*;
