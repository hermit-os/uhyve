//! # Uhyve Hypercall Interface
//!
//! The uhyve hypercall interface works as follows:
//!
//! - On `x86_64` you use an out port instruction. The address of the `out`-port corresponds to the
//! hypercall you want to use. You can obtain it from the [`HypercallPorts`] enum. The data send to
//! that port is the physical memory address (of the VM) of the parameters of that hypercall.
//! - On `aarch64` you write to the respective [`HypercallAddress`]. The 64-bit value written to that location is the guest's physical memory address of the hypercall's parameter.

// TODO: only x86 allows io instructions. Other architectures should use MMIO

#![no_std]

// TODO: Throw this out, once https://github.com/rust-lang/rfcs/issues/2783 or https://github.com/rust-lang/rust/issues/86772 is resolved
use num_enum::TryFromPrimitive;
use x86_64::PhysAddr;

/// Enum containing all valid port mappings for hypercalls.
///
/// The discriminants of this enum are the respective ports, so one can get the code by calling
/// e.g., `HypercallPorts::FileWrite as u16`.
#[non_exhaustive]
#[repr(u16)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
pub enum HypercallPorts {
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
	/// Port address = `0x840`
	FileUnlink = 0x840,
}
impl From<Hypercall<'_>> for HypercallPorts {
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
}
impl<'a> Hypercall<'a> {
	/// Get a hypercall's port address.
	pub fn port(self) -> u16 {
		HypercallPorts::from(self) as u16
	}
}

pub const UHYVE_PORT_WRITE: u16 = 0x400;
pub const UHYVE_PORT_OPEN: u16 = 0x440;
pub const UHYVE_PORT_CLOSE: u16 = 0x480;
pub const UHYVE_PORT_READ: u16 = 0x500;
pub const UHYVE_PORT_EXIT: u16 = 0x540;
pub const UHYVE_PORT_LSEEK: u16 = 0x580;

// Networkports (not used at the moment)
// TODO: Update interface
pub const UHYVE_PORT_NETWRITE: u16 = 0x640;
pub const UHYVE_PORT_NETREAD: u16 = 0x680;
pub const UHYVE_PORT_NETSTAT: u16 = 0x700;

/* Ports and data structures for uhyve command line arguments and envp
 * forwarding */
pub const UHYVE_PORT_CMDSIZE: u16 = 0x740;
pub const UHYVE_PORT_CMDVAL: u16 = 0x780;

pub const UHYVE_UART_PORT: u16 = 0x800;
pub const UHYVE_PORT_UNLINK: u16 = 0x840;

// FIXME: Do not use a fix number of arguments
pub const MAX_ARGC_ENVC: usize = 128;

/// Parameters for a [`Cmdsize`](Hypercall::Cmdsize) hypercall which provides the lengths of the items in the argument end environment vector.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SysCmdsize {
	/// Nr of items in the kernel command line.
	pub argc: i32,
	/// Lengths of the items in the kernel command line.
	pub argsz: [i32; MAX_ARGC_ENVC],
	/// Nr of items in the environment.
	pub envc: i32,
	/// Length of the items in the environment.
	pub envsz: [i32; MAX_ARGC_ENVC],
}
impl SysCmdsize {
	// TODO: Default not new
	pub fn new() -> SysCmdsize {
		SysCmdsize {
			argc: 0,
			argsz: [0; MAX_ARGC_ENVC],
			envc: 0,
			envsz: [0; MAX_ARGC_ENVC],
		}
	}
}

/// Parameters for a [`Cmdval`](Hypercall::Cmdval) hypercall, which copies the arguments end environment of the application into the VM's memory.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SysCmdval {
	/// Pointer to a memory section in the VM memory large enough to store the argument string.
	pub argv: PhysAddr,
	/// Pointer to a memory section in the VM memory large enough to store the environment values.
	pub envp: PhysAddr,
}
impl SysCmdval {
	pub fn new(argv: PhysAddr, envp: PhysAddr) -> SysCmdval {
		SysCmdval { argv, envp }
	}
}

/// Parameters for a [`Exit`](Hypercall::Exit) hypercall.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SysExit {
	/// The return code of the guest.
	pub arg: i32,
}
impl SysExit {
	pub fn new(arg: i32) -> SysExit {
		SysExit { arg }
	}
}

/// Parameters for a [`FileUnlink`](Hypercall::FileUnlink) hypercall.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SysUnlink {
	/// Address of the file that should be unlinked.
	pub name: PhysAddr,
	/// On success, `0` is returned.  On error, `-1` is returned.
	pub ret: i32,
}
impl SysUnlink {
	pub fn new(name: PhysAddr) -> SysUnlink {
		SysUnlink { name, ret: -1 }
	}
}

/// Parameters for a [`FileWrite`](Hypercall::FileWrite) hypercall.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SysWrite {
	/// File descriptor of the file.
	pub fd: i32,
	/// Buffer to be written into the file.
	pub buf: *const u8,
	/// Number of bytes in the buffer to be written.
	pub len: usize,
}

/// Parameters for a [`FileRead`](Hypercall::FileRead) hypercall.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SysRead {
	/// File descriptor of the file.
	pub fd: i32,
	/// Buffer to read the file into.
	pub buf: *const u8,
	/// Number of bytes to read into the buffer.
	pub len: usize,
	/// Number of bytes read on success. `-1` on failure.
	pub ret: isize,
}

/// Parameters for a [`FileClose`](Hypercall::FileClose) hypercall
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SysClose {
	/// File descriptor of the file.
	pub fd: i32,
	/// Zero on success, `-1` on failure.
	pub ret: i32,
}

/// Parameters for a [`FileOpen`](Hypercall::FileOpen) hypercall
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SysOpen {
	/// Pathname of the file to be opened.
	// TODO PhysAddr???
	pub name: *const u8,
	/// Posix file access mode flags.
	pub flags: i32,
	/// Access permissions upon opening/creating a file.
	pub mode: i32,
	/// File descriptor upon successful opening or `-1` upon failure.
	pub ret: i32,
}

/// Parameters for a [`FileLseek`](Hypercall::FileLseek) hypercall
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SysLseek {
	/// File descriptor of the file.
	pub fd: i32,
	/// Offset in the file.
	pub offset: isize,
	/// `whence` value of the lseek call.
	pub whence: i32,
}
