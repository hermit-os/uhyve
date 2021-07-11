use std::path::PathBuf;
use std::{fmt, result};

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, Clone)]
pub enum Error {
	OsError(i32),
	InvalidFile(PathBuf),
	NotEnoughMemory,
	ParseMemory,
	InvalidArgument(String),
	#[cfg(target_os = "linux")]
	UnknownExitReason,
	#[cfg(target_os = "macos")]
	InternalError,
	#[cfg(target_os = "macos")]
	UnhandledExitReason,
	#[cfg(target_os = "macos")]
	Hypervisor(xhypervisor::Error),
}

#[cfg(target_os = "linux")]
pub fn to_error<T>(err: kvm_ioctls::Error) -> Result<T> {
	Err(Error::OsError(err.errno()))
}

#[cfg(target_os = "macos")]
impl From<xhypervisor::Error> for Error {
	fn from(err: xhypervisor::Error) -> Self {
		Error::Hypervisor(err)
	}
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match *self {
			Error::OsError(ref err) => write!(f, "Error from OS: {}", err),
			Error::InvalidFile(ref file) => {
				write!(
					f,
					"The file {} was not found or is invalid.",
					file.display()
				)
			}
			Error::NotEnoughMemory => write!(
				f,
				"The host system has not enough memory, please check your memory usage."
			),
			Error::ParseMemory => write!(
				f,
				"Couldn't parse the guest memory size from the environment"
			),
			Error::InvalidArgument(ref arg) => write!(f, "Invalid argument passed: {}", arg),
			#[cfg(target_os = "linux")]
			Error::UnknownExitReason => write!(f, "Unknown exit reason."),
			#[cfg(target_os = "macos")]
			Error::InternalError => write!(f, "An internal error has occurred, please report."),
			#[cfg(target_os = "macos")]
			Error::UnhandledExitReason => write!(f, "Unhandled exit reason"),
			#[cfg(target_os = "macos")]
			Error::Hypervisor(ref err) => write!(f, "The hypervisor has failed: {:?}", err),
		}
	}
}
