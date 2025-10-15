//! # Uhyve Hypervisor Interface V2
//!
//! The Uhyve hypercall interface works as follows:
//!
//! - The guest writes (or reads) to the respective [`HypercallAddress`](v2::HypercallAddress). The 64-bit value written to that location is the guest's physical memory address of the hypercall's parameter.
//! - The hypervisor handles the hypercall. Depending on the Hypercall, the hypervisor might change the parameters struct in the guest's memory.

// TODO: Throw this out, once https://github.com/rust-lang/rfcs/issues/2783 or https://github.com/rust-lang/rust/issues/86772 is resolved
use num_enum::TryFromPrimitive;

pub mod parameters;
use crate::v2::parameters::*;

/// Enum containing all valid MMIO addresses for hypercalls.
///
/// The discriminants of this enum are the respective addresses, so one can get the code by calling
/// e.g., `HypercallAddress::Exit as u64`.
#[non_exhaustive]
#[repr(u64)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
pub enum HypercallAddress {
	Exit = 0x1010,
	SerialWriteByte = 0x1020,
	SerialWriteBuffer = 0x1030,
	SerialReadByte = 0x1040,
	SerialReadBuffer = 0x1050,
	GetTime = 0x1060,
	Sleep = 0x1070,
	FileWrite = 0x1100,
	FileOpen = 0x1110,
	FileClose = 0x1120,
	FileRead = 0x1130,
	FileLseek = 0x1140,
	FileUnlink = 0x1150,
	SharedMemOpen = 0x1200,
	SharedMemClose = 0x1210,
}
impl From<Hypercall<'_>> for HypercallAddress {
	fn from(value: Hypercall) -> Self {
		match value {
			Hypercall::Exit(_) => Self::Exit,
			Hypercall::FileClose(_) => Self::FileClose,
			Hypercall::FileLseek(_) => Self::FileLseek,
			Hypercall::FileOpen(_) => Self::FileOpen,
			Hypercall::FileRead(_) => Self::FileRead,
			Hypercall::FileUnlink(_) => Self::FileUnlink,
			Hypercall::FileWrite(_) => Self::FileWrite,
			Hypercall::GetTime(_) => Self::GetTime,
			Hypercall::SerialReadBuffer(_) => Self::SerialReadBuffer,
			Hypercall::SerialReadByte => Self::SerialReadByte,
			Hypercall::SerialWriteBuffer(_) => Self::SerialWriteBuffer,
			Hypercall::SerialWriteByte(_) => Self::SerialWriteByte,
			Hypercall::Sleep(_) => Self::Sleep,
			Hypercall::SharedMemOpen(_) => Self::SharedMemOpen,
			Hypercall::SharedMemClose(_) => Self::SharedMemClose,
		}
	}
}

/// Hypervisor calls available in Uhyve with their respective parameters. See the [module level documentation](crate) on how to invoke them.
#[non_exhaustive]
#[derive(Debug)]
pub enum Hypercall<'a> {
	/// Exit the VM and return a status code.
	Exit(i32),
	FileClose(&'a mut CloseParams),
	FileLseek(&'a mut LseekParams),
	FileOpen(&'a mut OpenParams),
	FileRead(&'a mut ReadPrams),
	FileWrite(&'a WriteParams),
	FileUnlink(&'a mut UnlinkParams),
	/// Write a char to the terminal.
	SerialWriteByte(u8),
	/// Write a buffer to the terminal
	SerialWriteBuffer(&'a SerialWriteBufferParams),
	/// Read a single byte from the terminal
	SerialReadByte,
	/// Read a buffer from the terminal
	SerialReadBuffer(&'a SerialReadBufferParams),
	SharedMemOpen(&'a SharedMemOpenParams),
	SharedMemClose(&'a SharedMemCloseParams),
	/// Get system time
	GetTime(&'a TimeParams),
	/// Suspend the vm for (at least) the specified duration.
	Sleep(&'a SleepParams),
}
impl<'a> Hypercall<'a> {
	/// Get a hypercall's port address.
	pub fn port(self) -> u16 {
		HypercallAddress::from(self) as u16
	}
}
