#![warn(rust_2018_idioms)]
#![allow(unused_macros)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::useless_conversion)]

#[macro_use]
mod macros;

#[macro_use]
extern crate log;

mod arch;
pub mod consts;
mod fdt;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux as os;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos as os;
mod hypercall;
mod isolation;
pub mod mem;
pub mod paging;
pub mod params;
pub mod stats;
mod vcpu;
pub mod virtio;
pub mod virtqueue;
pub mod vm;

pub use arch::*;
pub use os::HypervisorError;
pub type HypervisorResult<T> = Result<T, HypervisorError>;
