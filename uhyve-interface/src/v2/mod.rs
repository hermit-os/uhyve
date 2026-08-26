//! # Uhyve Hypervisor Interface V2
//!
//! The Uhyve hypercall interface works as follows:
//!
//! - The guest writes (or reads) to the respective [`HypercallAddress`](v2::HypercallAddress). The 64-bit value written to that location is the guest's physical memory address of the hypercall's parameter.
//! - The hypervisor handles the hypercall. Depending on the Hypercall, the hypervisor might change the parameters struct in the guest's memory.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub mod parameters;
use parameters::*;

/// Enum containing all valid MMIO addresses for hypercalls.
///
/// The discriminants of this enum are the respective addresses, so one can get the code by calling
/// e.g., `HypercallAddress::Exit as u64`.
#[non_exhaustive]
#[repr(u64)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, num_enum::TryFromPrimitive, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
	Getdents = 0x1160,
	FileStat = 0x1170,
	FileFstat = 0x1180,
	Mkdir = 0x1190,
	FileFsync = 0x11A0,
	SharedMemOpen = 0x1200,
	SharedMemClose = 0x1210,
	Snapshot = 0x1400,
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
			FileFsync,
			Getdents,
			Mkdir,
			FileStat,
			FileFstat,
			SerialReadBuffer,
			SerialReadByte,
			SerialWriteBuffer,
			SerialWriteByte,
			Snapshot
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
	/// Read file metadata. Similar to `stat(2)` / `lstat(2)`.
	FileStat(&'a mut StatParams),
	/// Read file metadata for an open descriptor. Similar to `fstat(2)`.
	FileFstat(&'a mut FstatParams),
	/// Create a new directory.
	Mkdir(&'a mut MkdirParams),
	/// Flush a file to the storage it lives on.
	FileFsync(&'a mut FsyncParams),
	/// Write a char to the terminal.
	SerialWriteByte(u8),
	/// Write a buffer to the terminal
	SerialWriteBuffer(&'a SerialWriteBufferParams),
	/// Read a single byte from the terminal
	SerialReadByte,
	/// Read a buffer from the terminal
	SerialReadBuffer(&'a SerialReadBufferParams),
	/// Take a snapshot of the VM.
	///
	/// This is only allowed, once the Kernel has finished booting, as the hypervisor might assume some devices being fully initialized.
	Snapshot(&'a mut SnapshotParams),
}
impl<'a> Hypercall<'a> {
	/// Get a hypercall's port address.
	pub fn port(self) -> u16 {
		HypercallAddress::from(self) as u16
	}
}
