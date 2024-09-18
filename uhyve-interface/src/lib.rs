//! # Uhyve Hypervisor Interface

#![cfg_attr(not(feature = "std"), no_std)]

pub mod elf;
/// Version 1 of the Hypercall Interface
pub mod v1;
/// Version 2 of the Hypercall Interface
pub mod v2;

#[cfg(target_arch = "aarch64")]
pub use ::aarch64::paging::PhysAddr as GuestPhysAddr;
#[cfg(target_arch = "aarch64")]
pub use ::aarch64::paging::VirtAddr as GuestVirtAddr;
#[cfg(target_arch = "x86_64")]
pub use ::x86_64::addr::PhysAddr as GuestPhysAddr;
#[cfg(target_arch = "x86_64")]
pub use ::x86_64::addr::VirtAddr as GuestVirtAddr;

#[cfg(not(target_pointer_width = "64"))]
compile_error!("Using uhyve-interface on a non-64-bit system is not (yet?) supported");

/// The version of the Uhyve interface. Note: This is not the same as the semver of the crate but
/// should be increased on every version bump that changes the API.
pub const UHYVE_INTERFACE_VERSION: u32 = 2;
