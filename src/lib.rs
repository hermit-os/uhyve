#![warn(rust_2018_idioms)]
#![allow(clippy::useless_conversion)]

use std::path::PathBuf;

use thiserror::Error;

#[macro_use]
extern crate log;

mod arch;
pub mod consts;
mod fdt;
mod gdb;

#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(target_os = "macos", path = "macos/mod.rs")]
pub mod os;

mod hypercall;
mod isolation;
pub mod mem;
pub(crate) mod paging;
pub mod params;
mod parking;
mod serial;
pub mod stats;
mod vcpu;
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

	#[error(transparent)]
	HermitImageError(#[from] crate::isolation::filemap::HermitImageError),

	#[error("Unable to find Hermit image config in archive")]
	HermitImageConfigNotFound,

	#[error("Unable to parse Hermit image config: {0}")]
	HermitImageConfigParseError(#[from] toml::de::Error),

	#[error("Insufficient guest memory size: got = {got}, wanted = {wanted}")]
	InsufficientGuestMemorySize {
		got: byte_unit::Byte,
		wanted: byte_unit::Byte,
	},

	#[error("Insufficient guest CPU count: got = {got}, wanted = {wanted}")]
	InsufficientGuestCPUs { got: u32, wanted: u32 },

	#[error("Kernel Loading Error: {0}")]
	LoadedKernelError(#[from] vm::LoadKernelError),

	#[error("Kernel doesn't support the necessary features: {0}")]
	FeatureMismatch(&'static str),
}

impl HypervisorError {
	/// Report an (target independent) invalid value error e.g. during debug interactions
	fn backend_invalid_value() -> Self {
		Self::BackendError({
			#[cfg(target_os = "linux")]
			{
				kvm_ioctls::Error::new(libc::EINVAL)
			}
			#[cfg(target_os = "macos")]
			{
				xhypervisor::Error::BadArg
			}
		})
	}
}

pub type HypervisorResult<T> = Result<T, HypervisorError>;

pub mod net;
mod pci;
mod virtio;
