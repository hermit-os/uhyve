#![warn(rust_2018_idioms)]
#![allow(unused_macros)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::useless_conversion)]

use thiserror::Error;

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
mod serial;
pub mod stats;
mod vcpu;
pub mod virtio;
pub mod virtqueue;
pub mod vm;

pub use arch::*;

#[derive(Debug, Error)]
pub enum HypervisorError {
	#[cfg(target_os = "linux")]
	#[error("The KVM backend reported an error: {0}")]
	BackendError(#[from] kvm_ioctls::Error),

	#[cfg(target_os = "macos")]
	#[error("The xhypervisor backend reported an error: {0}")]
	BackendError(#[from] xhypervisor::Error),

	#[error("IO Error: {0}")]
	IOError(#[from] std::io::Error),

	#[error("Kernel Loading Error: {0}")]
	LoadedKernelError(#[from] vm::LoadKernelError),
}

pub type HypervisorResult<T> = Result<T, HypervisorError>;
