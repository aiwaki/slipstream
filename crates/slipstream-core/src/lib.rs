//! Platform-neutral Slipstream routing contracts and state machines.
//!
//! This crate accepts clocks, addresses, and outcomes as data. Platform
//! adapters own every socket, timer, process, filesystem, and OS interaction.

#![forbid(unsafe_code)]

pub mod address_attempts;
pub mod connection_race;
pub mod route_circuit;
pub mod route_circuit_registry;
pub mod route_policy_activation;
pub mod route_policy_bundle;
pub mod route_policy_manifest;
pub mod routing_policy;
pub mod routing_recovery;
pub mod status_v2;
