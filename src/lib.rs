#![warn(rust_2018_idioms)]

use std::path::PathBuf;

use thiserror::Error;

#[macro_use]
extern crate log;

mod arch;
pub mod consts;
mod fdt;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
use linux as os;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
use macos as os;
mod hypercall;
mod isolation;
pub mod mem;
pub(crate) mod paging;
pub mod params;
mod serial;
pub mod stats;
mod vcpu;
mod virtio;
mod virtqueue;
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

	#[error("Invalid kernel path ({0})")]
	InvalidKernelPath(PathBuf),

	#[error("Kernel Loading Error: {0}")]
	LoadedKernelError(#[from] vm::LoadKernelError),
}

pub type HypervisorResult<T> = Result<T, HypervisorError>;
