//! # Uhyve Hypercall Interface
//!
//! The uhyve hypercall interface works as follows:
//!
//! - On `x86_64` you use an out port instruction. The address of the `out`-port corresponds to the
//! hypercall you want to use. You can obtain it from the [`IoPorts`] enum. The data send to
//! that port is the physical memory address (of the VM) of the parameters of that hypercall.
//! - On `aarch64` you write to the respective [`HypercallAddress`]. The 64-bit value written to that location is the guest's physical memory address of the hypercall's parameter.

// TODO: only x86 allows io instructions. Other architectures should use MMIO

#![no_std]

// TODO: Throw this out, once https://github.com/rust-lang/rfcs/issues/2783 or https://github.com/rust-lang/rust/issues/86772 is resolved
use num_enum::TryFromPrimitive;

pub mod parameters;
use parameters::*;

/// Enum containing all valid port mappings for hypercalls.
///
/// The discriminants of this enum are the respective ports, so one can get the code by calling
/// e.g., `HypercallPorts::FileWrite as u16`.
#[non_exhaustive]
#[repr(u16)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
pub enum IoPorts {
	/// Port address = `0x400`
	FileWrite = 0x400,
	/// Port address = `0x440`
	FileOpen = 0x440,
	/// Port address = `0x480`
	FileClose = 0x480,
	/// Port address = `0x500`
	FileRead = 0x500,
	/// Port address = `0x540`
	Exit = 0x540,
	/// Port address = `0x580`
	FileLseek = 0x580,
	/// Port address = `0x640`
	Netwrite = 0x640,
	/// Port address = `0x680`
	Netread = 0x680,
	/// Port address = `0x700`
	Netstat = 0x700,
	/// Port address = `0x740`
	Cmdsize = 0x740,
	/// Port address = `0x780`
	Cmdval = 0x780,
	/// Port address = `0x800`
	Uart = 0x800,
	/// Port address = `0x840`
	FileUnlink = 0x840,
}
impl From<Hypercall<'_>> for IoPorts {
	fn from(value: Hypercall) -> Self {
		match value {
			Hypercall::Cmdsize(_) => Self::Cmdsize,
			Hypercall::Cmdval(_) => Self::Cmdval,
			Hypercall::Exit(_) => Self::Exit,
			Hypercall::FileClose(_) => Self::FileClose,
			Hypercall::FileLseek(_) => Self::FileLseek,
			Hypercall::FileOpen(_) => Self::FileOpen,
			Hypercall::FileRead(_) => Self::FileRead,
			Hypercall::FileWrite(_) => Self::FileWrite,
			Hypercall::FileUnlink(_) => Self::FileUnlink,
			Hypercall::SerialWrite(_) => Self::Uart,
		}
	}
}

/// Hypervisor calls available in uhyve with their respective parameters. See the [module level documentation](crate) on how to invoke them.
#[non_exhaustive]
#[derive(Debug)]
pub enum Hypercall<'a> {
	/// Get the size of the argument and environment strings. Used to allocate memory for
	/// [`Hypercall::Cmdval`].
	Cmdsize(&'a mut SysCmdsize),
	/// Copy the argument and environment strings into the VM. Usually preceeeded by
	/// [`Hypercall::Cmdsize`] so that the guest can allocate the memory for this call.
	Cmdval(&'a SysCmdval),
	/// Exit the VM and return a status.
	Exit(&'a SysExit),
	FileClose(&'a mut SysClose),
	FileLseek(&'a mut SysLseek),
	FileOpen(&'a mut SysOpen),
	FileRead(&'a mut SysRead),
	FileWrite(&'a SysWrite),
	FileUnlink(&'a mut SysUnlink),
	/// Write a buffer to the terminal.
	SerialWrite(&'a [u8]),
}
impl<'a> Hypercall<'a> {
	/// Get a hypercall's port address.
	pub fn port(self) -> u16 {
		IoPorts::from(self) as u16
	}
}

// Networkports (not used at the moment)
// TODO: Remove this
pub const UHYVE_PORT_NETWRITE: u16 = 0x640;

// FIXME: Do not use a fix number of arguments
pub const MAX_ARGC_ENVC: usize = 128;
