//! Versioned, effect-free userspace network-stack qualification constants.
//!
//! This crate is not linked into a Slipstream runtime. Its dependencies are
//! test-only so selecting a candidate cannot silently compose production
//! packet, route, socket, adapter, service, or process effects.

pub mod ipv6_fragment_input_v1;

pub mod v1 {
    pub const CONTRACT_VERSION: u32 = 1;
    pub const STACK_NAME: &str = "smoltcp";
    pub const STACK_VERSION: &str = "0.13.1";
    pub const STACK_CRATE_SHA256: &str =
        "5f73d40463bba65efc9adc6370b56df76d563cc46e2482bba58351b4afb7535e";
    pub const REQUIRED_RUST_VERSION: &str = "1.91";

    pub const L3_MTU: usize = 1280;
    pub const MAX_LINK_FRAMES_PER_DIRECTION: usize = 8;
    pub const MAX_BURST_FRAMES: usize = 1;
    pub const MAX_SOCKETS_PER_STACK: usize = 2;
    pub const UDP_PACKET_SLOTS_PER_DIRECTION: usize = 4;
    pub const UDP_BYTES_PER_DIRECTION: usize = 4096;
    pub const TCP_BYTES_PER_DIRECTION: usize = 4096;
    pub const FRAGMENTATION_BUFFER_BYTES: usize = 4096;
    pub const REASSEMBLY_BUFFER_BYTES: usize = 4096;
    pub const REASSEMBLY_BUFFER_COUNT: usize = 2;
}
