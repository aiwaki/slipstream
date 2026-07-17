//! Effect-injected Windows adapter boundary for Slipstream.
//!
//! The routing harness and service lifecycle v1 contracts intentionally contain
//! no native, network, service-manager, installer, or storage implementation.
//! They consume platform-neutral state and delegate every concrete effect
//! through injected interfaces that can be recorded in tests.

#![forbid(unsafe_code)]

pub mod service_lifecycle;
mod v1;

pub use v1::*;
