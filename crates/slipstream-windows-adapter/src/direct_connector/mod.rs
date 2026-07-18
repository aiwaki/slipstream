//! Bounded direct TCP connector for the Windows adapter.

mod v1;

pub use v1::*;

mod windows;

pub use windows::*;
