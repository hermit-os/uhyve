//! # Uhyve Hypervisor Interface

#![cfg_attr(not(feature = "std"), no_std)]

pub mod elf;
/// Version 1 of the Hypercall Interface
pub mod v1;

pub use memory_addresses::{PhysAddr as GuestPhysAddr, VirtAddr as GuestVirtAddr};

#[cfg(not(target_pointer_width = "64"))]
compile_error!("Using uhyve-interface on a non-64-bit system is not (yet?) supported");

/// The version of the Uhyve interface. Note: This is not the same as the semver of the crate but
/// should be increased on every version bump that changes the API.
pub const UHYVE_INTERFACE_VERSION: u32 = 2;
