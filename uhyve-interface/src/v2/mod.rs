//! # Uhyve Hypervisor Interface V2
//!
//! The Uhyve hypercall interface works as follows:
//!
//! - The guest writes (or reads) to the respective [`HypercallAddress`](v2::HypercallAddress). The 64-bit value written to that location is the guest's physical memory address of the hypercall's parameter.
//! - The hypervisor handles the hypercall. Depending on the Hypercall, the hypervisor might change the parameters struct in the guest's memory.

pub mod parameters;
use crate::v2::parameters::*;

/// Enum containing all valid MMIO addresses for hypercalls.
///
/// The discriminants of this enum are the respective addresses, so one can get the code by calling
/// e.g., `HypercallAddress::Exit as u64`.
#[non_exhaustive]
#[repr(u64)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, num_enum::TryFromPrimitive, Hash)]
pub enum HypercallAddress {
	Exit = 0x1010,
	SerialWriteByte = 0x1020,
	SerialWriteBuffer = 0x1030,
	SerialReadByte = 0x1040,
	SerialReadBuffer = 0x1050,
	FileWrite = 0x1100,
	FileOpen = 0x1110,
	FileClose = 0x1120,
	FileRead = 0x1130,
	FileLseek = 0x1140,
	FileUnlink = 0x1150,
	SharedMemOpen = 0x1200,
	SharedMemClose = 0x1210,
}

into_hypercall_addresses! {
	impl From<Hypercall> for HypercallAddress {
		match {
			Exit,
			FileClose,
			FileLseek,
			FileOpen,
			FileRead,
			FileUnlink,
			FileWrite,
			SerialReadBuffer,
			SerialReadByte,
			SerialWriteBuffer,
			SerialWriteByte,
			SharedMemOpen,
			SharedMemClose,
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
	FileRead(&'a mut ReadParams),
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
}
impl<'a> Hypercall<'a> {
	/// Get a hypercall's port address.
	pub fn port(self) -> u16 {
		HypercallAddress::from(self) as u16
	}
}
