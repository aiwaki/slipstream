//! Bounded client-stream ingress for the Windows direct connector.

mod v1;

pub use v1::*;

mod windows;

pub use windows::*;
