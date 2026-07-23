//! Versioned, test-only qualification of the Windows byte-owner effect boundary.
//!
//! The selected stack and Windows adapter are dev-dependencies. Nothing in this
//! crate is linked into a Slipstream runtime.

pub mod v1 {
    pub const CONTRACT_VERSION: u32 = 1;
    pub const STACK_SELECTION_CONTRACT_VERSION: u32 = 1;
    pub const BYTE_OWNER_CONTRACT_VERSION: u32 = 1;
    pub const STACK_NAME: &str = "smoltcp";
    pub const STACK_VERSION: &str = "0.13.1";
    pub const MAX_EFFECT_PAYLOAD_BYTES: usize = 512;
    pub const MAX_POLL_STEPS: usize = 5_000;
}
