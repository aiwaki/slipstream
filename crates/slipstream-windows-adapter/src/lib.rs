//! Effect-injected Windows adapter boundary for Slipstream.
//!
//! The routing harness and service lifecycle v1 contracts intentionally contain
//! no native or network implementation. They consume platform-neutral state and
//! delegate every concrete effect through injected interfaces that can be
//! recorded in tests. The separate service observer contains one isolated,
//! read-only Windows SCM boundary; it cannot mutate services or networking.

#![deny(unsafe_code)]

pub mod service_lifecycle;
pub mod service_observer;
pub mod service_ownership;
mod v1;

pub use v1::*;
