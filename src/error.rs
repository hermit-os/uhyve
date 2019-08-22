use std::{fmt, result};

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, Clone)]
pub enum Error {
	FileMissing,
	InternalError,
	LibcError(i32),
	InvalidFile(String),
	NotEnoughMemory,
	MissingFrequency,
	UnknownExitReason,
	KVMInitFailed,
	KVMUnableToCreateVM,
	KVMUnableToCreateIrqChip,
	KVMUnableToCreatePit2,
	Shutdown,
	ParseMemory,
	UnhandledExitReason,
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			Error::FileMissing => write!(f, "No execution file given"),
			Error::InternalError => write!(f, "An internal error has occurred, please report."),
			Error::LibcError(ref err) => write!(f, "Error from libc: {}", err),
			Error::InvalidFile(ref file) => {
				write!(f, "The file {} was not found or is invalid.", file)
			}
			Error::NotEnoughMemory => write!(
				f,
				"The host system has not enough memory, please check your memory usage."
			),
			Error::MissingFrequency => write!(
				f,
				"Couldn't get the CPU frequency from your system. (is /proc/cpuinfo missing?)"
			),
			Error::UnknownExitReason => write!(f, "Unknown exit reason."),
			Error::Shutdown => write!(f, "Receives shutdown command"),
			Error::KVMInitFailed => write!(f, "Unable to initialize KVM"),
			Error::KVMUnableToCreateVM => write!(f, "Unable to create VM"),
			Error::KVMUnableToCreateIrqChip => write!(f, "Unable to create irqchip"),
			Error::KVMUnableToCreatePit2 => write!(f, "Unable to create pit2"),
			Error::ParseMemory => write!(
				f,
				"Couldn't parse the guest memory size from the environment"
			),
			Error::UnhandledExitReason => write!(f, "Unhandled exit reason"),
		}
	}
}
