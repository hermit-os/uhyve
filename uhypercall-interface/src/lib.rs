//! # Uhyve Hypercall Interface
//!
//! The uhyve hypercall interface works as follows:
//!
//! - On `x86_64` you use an out port instruction. The address of the `out`-port corresponds to the
//! hypercall you want to use. The data send to that port is the physical memory address (of the VM)
//! of the parameters of that hypercall.

#![no_std]

use x86_64::PhysAddr;

/// Enum containing all valid port mappings for hypercalls.
///
/// The discriminants of this enum are the respective ports, so one can get the code by calling
/// e.g., `HypercallPorts::FileWrite as u16`.
#[non_exhaustive]
#[repr(u16)]
pub enum HypercallPorts {
	FileWrite = 0x400,
	FileOpen = 0x440,
	FileClose = 0x480,
	FileRead = 0x500,
	Exit = 0x540,
	FileLseek = 0x580,
	Netwrite = 0x640,
	Netread = 0x680,
	Netstat = 0x700,
	Cmdsize = 0x740,
	Cmdval = 0x780,
	FileUnlink = 0x840,
}
impl From<Hypercall> for HypercallPorts {
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

/// Hypervisor calls available in uhyve with their respective parameters.
#[non_exhaustive]
#[derive(Debug, Copy, Clone)]
pub enum Hypercall {
	Cmdsize(SysCmdsize),
	Cmdval(SysCmdval),
	Exit(SysExit),
	FileClose(SysClose),
	FileLseek(SysLseek),
	FileOpen(SysOpen),
	FileRead(SysRead),
	FileWrite(SysWrite),
	FileUnlink(SysUnlink),
}
impl Hypercall {
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

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SysCmdsize {
	pub argc: i32,
	pub argsz: [i32; MAX_ARGC_ENVC],
	pub envc: i32,
	pub envsz: [i32; MAX_ARGC_ENVC],
}
impl SysCmdsize {
	pub fn new() -> SysCmdsize {
		SysCmdsize {
			argc: 0,
			argsz: [0; MAX_ARGC_ENVC],
			envc: 0,
			envsz: [0; MAX_ARGC_ENVC],
		}
	}
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SysCmdval {
	pub argv: PhysAddr,
	pub envp: PhysAddr,
}
impl SysCmdval {
	pub fn new(argv: PhysAddr, envp: PhysAddr) -> SysCmdval {
		SysCmdval { argv, envp }
	}
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SysExit {
	pub arg: i32,
}
impl SysExit {
	pub fn new(arg: i32) -> SysExit {
		SysExit { arg }
	}
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SysUnlink {
	pub name: PhysAddr,
	pub ret: i32,
}
impl SysUnlink {
	pub fn new(name: PhysAddr) -> SysUnlink {
		SysUnlink { name, ret: -1 }
	}
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SysWrite {
	pub fd: i32,
	pub buf: *const u8,
	pub len: usize,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SysRead {
	pub fd: i32,
	pub buf: *const u8,
	pub len: usize,
	pub ret: isize,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SysClose {
	pub fd: i32,
	pub ret: i32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SysOpen {
	pub name: *const u8,
	pub flags: i32,
	pub mode: i32,
	pub ret: i32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SysLseek {
	pub fd: i32,
	pub offset: isize,
	pub whence: i32,
}
