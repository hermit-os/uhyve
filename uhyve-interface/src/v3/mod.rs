//! # Uhyve Hypervisor Interface V3
//!
//! The Uhyve hypercall interface works as follows:
//!
//! - The guest writes (or reads) to the respective [`HypercallAddress`]. The 64-bit value written to that location is the guest's physical memory address of the hypercall's parameter.
//! - The hypervisor handles the hypercall. Depending on the Hypercall, the hypervisor might change the parameters struct in the guest's memory.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub mod parameters;
use parameters::*;
pub mod util;

/// Enum containing all valid MMIO addresses for hypercalls.
///
/// The discriminants of this enum are the respective addresses, so one can get the code by calling
/// e.g., `HypercallAddress::Exit as u64`.
#[non_exhaustive]
#[repr(u64)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, num_enum::TryFromPrimitive, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum HypercallAddress {
	Exit = 0x2010,
	SerialWriteByte = 0x2020,
	SerialWriteBuffer = 0x2030,
	SerialReadByte = 0x2040,
	SerialReadBuffer = 0x2050,
	FileWrite = 0x2100,
	FileOpen = 0x2110,
	FileClose = 0x2120,
	FileRead = 0x2130,
	FileLseek = 0x2140,
	FileUnlink = 0x2150,
	FileStat = 0x2160,
	Mkdir = 0x2200,
	Getdents = 0x2210,
	SharedMemOpen = 0x2300,
	SharedMemClose = 0x2310,
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
			Getdents,
			Mkdir,
			FileStat,
			SerialReadBuffer,
			SerialReadByte,
			SerialWriteBuffer,
			SerialWriteByte,
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
	FileWrite(&'a mut WriteParams),
	FileUnlink(&'a mut UnlinkParams),
	/// Get directory entries from a directory. Similar to linux getdents64.
	Getdents(&'a mut GetdentParams),
	/// Read file metadata. Similar to `stat(2)` / `lstat(2)` / `fstat(2)`.
	FileStat(&'a mut StatParams),
	/// Create a new directory.
	Mkdir(&'a mut MkdirParams),
	/// Write a char to the terminal.
	SerialWriteByte(u8),
	/// Write a buffer to the terminal
	SerialWriteBuffer(&'a SerialWriteBufferParams),
	/// Read a single byte from the terminal
	SerialReadByte,
	/// Read a buffer from the terminal
	SerialReadBuffer(&'a SerialReadBufferParams),
}
impl<'a> Hypercall<'a> {
	/// Get a hypercall's port address.
	pub fn port(self) -> u16 {
		HypercallAddress::from(self) as u16
	}
}
