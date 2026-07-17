//! Effect-injected Windows adapter boundary for Slipstream.
//!
//! The routing harness and service lifecycle v1 contracts intentionally contain
//! no native or network implementation. They consume platform-neutral state and
//! delegate every concrete effect through injected interfaces that can be
//! recorded in tests. The service observer is read-only; the separate SCM
//! effect admits only exact, evidence-gated service mutations and no networking.

#![deny(unsafe_code)]

pub mod service_controller;
pub mod service_lifecycle;
pub mod service_lifecycle_state;
pub mod service_native;
pub mod service_observer;
#[cfg(windows)]
#[allow(unsafe_code)]
mod service_operation_lock;
pub mod service_ownership;
pub mod service_payload;
pub mod service_scm;
mod v1;

pub use v1::*;
