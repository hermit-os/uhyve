//! Parameters for hypercalls.

use crate::{GuestPhysAddr, GuestVirtAddr, v1::MAX_ARGC_ENVC};

/// Parameters for a [`Cmdsize`](crate::v1::Hypercall::Cmdsize) hypercall which provides the lengths of the items in the argument end environment vector.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct CmdsizeParams {
	/// Nr of items in the kernel command line.
	pub argc: i32,
	/// Lengths of the items in the kernel command line.
	pub argsz: [i32; MAX_ARGC_ENVC],
	/// Nr of items in the environment.
	pub envc: i32,
	/// Length of the items in the environment.
	pub envsz: [i32; MAX_ARGC_ENVC],
}
impl CmdsizeParams {
	#[cfg(feature = "std")]
	/// Update the struct with the lengths of the given command.
	/// - `path` is usually the path and name of the application. E.g., "/home/hermit/app"
	/// - `args` is a list of strings that form the parameters. (E.g., `["-v", "myarg"]`)
	///
	/// Note that this hypercall only transfers the sizes. It usually has to be followed up with the [`Cmdval` Hypercall](crate::v1::Hypercall::Cmdval).
	pub fn update(&mut self, path: &std::path::Path, args: &[String]) {
		self.argc = 0;

		self.argsz[0] = path.as_os_str().len() as i32 + 1;

		self.argc += 1;
		for argument in args {
			self.argsz[(self.argc) as usize] = argument.len() as i32 + 1;

			self.argc += 1;
		}

		self.envc = 0;
		// let mut counter = 0;
		for (key, value) in std::env::vars_os() {
			if self.envc < MAX_ARGC_ENVC.try_into().unwrap() {
				self.envsz[self.envc as usize] = (key.len() + value.len()) as i32 + 2;
				self.envc += 1;
			} else {
				log::warn!("Environment is too large! {key:?}={value:?} will not be passed!");
			}
		}
	}
}

/// Parameters for a [`Cmdval`](crate::v1::Hypercall::Cmdval) hypercall, which copies the arguments end environment of the application into the VM's memory.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct CmdvalParams {
	/// Pointer to a memory section in the VM memory which holds addresses for the destinations of the individual arguments
	pub argv: GuestPhysAddr,
	/// Pointer to a memory section in the VM memory which holds addresses for the destinations of the individual environment variables
	pub envp: GuestPhysAddr,
}

/// Parameters for a [`Exit`](crate::v1::Hypercall::Exit) hypercall.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct ExitParams {
	/// The return code of the guest.
	pub arg: i32,
}

/// Parameters for a [`FileUnlink`](crate::v1::Hypercall::FileUnlink) hypercall.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct UnlinkParams {
	/// Address of the file that should be unlinked.
	pub name: GuestPhysAddr,
	/// On success, `0` is returned.  On error, `-1` is returned.
	pub ret: i32,
}

/// Parameters for a [`FileWrite`](crate::v1::Hypercall::FileWrite) hypercall.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct WriteParams {
	/// File descriptor of the file.
	pub fd: i32,
	/// Buffer to be written into the file.
	pub buf: GuestVirtAddr,
	/// Number of bytes in the buffer to be written.
	pub len: usize,
}

/// Parameters for a [`FileRead`](crate::v1::Hypercall::FileRead) hypercall.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct ReadParams {
	/// File descriptor of the file.
	pub fd: i32,
	/// Buffer to read the file into.
	pub buf: GuestVirtAddr,
	/// Number of bytes to read into the buffer.
	pub len: usize,
	/// Number of bytes read on success. `-1` on failure.
	pub ret: isize,
}

/// Parameters for a [`FileClose`](crate::v1::Hypercall::FileClose) hypercall.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct CloseParams {
	/// File descriptor of the file.
	pub fd: i32,
	/// Zero on success, `-1` on failure.
	pub ret: i32,
}

/// Parameters for a [`FileOpen`](crate::v1::Hypercall::FileOpen) hypercall.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct OpenParams {
	/// Pathname of the file to be opened.
	pub name: GuestPhysAddr,
	/// Posix file access mode flags.
	pub flags: i32,
	/// Access permissions upon opening/creating a file.
	pub mode: i32,
	/// File descriptor upon successful opening or `-1` upon failure.
	pub ret: i32,
}

/// Parameters for a [`FileLseek`](crate::v1::Hypercall::FileLseek) hypercall
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct LseekParams {
	/// File descriptor of the file.
	pub fd: i32,
	/// Offset in the file.
	pub offset: isize,
	/// `whence` value of the lseek call.
	pub whence: i32,
}

/// Parameters for a [`SerialWriteBuffer`](crate::v1::Hypercall::SerialWriteBuffer) hypercall.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SerialWriteBufferParams {
	pub buf: GuestPhysAddr,
	pub len: usize,
}

// File operations supported by Hermit and Uhyve
pub const O_RDONLY: i32 = 0o0000;
pub const O_WRONLY: i32 = 0o0001;
pub const O_RDWR: i32 = 0o0002;
pub const O_CREAT: i32 = 0o0100;
pub const O_EXCL: i32 = 0o0200;
pub const O_TRUNC: i32 = 0o1000;
pub const O_APPEND: i32 = 0o2000;
pub const O_DIRECT: i32 = 0o40000;
pub const O_DIRECTORY: i32 = 0o200000;

pub const ALLOWED_OPEN_FLAGS: i32 =
	O_RDONLY | O_WRONLY | O_RDWR | O_CREAT | O_EXCL | O_TRUNC | O_APPEND | O_DIRECT | O_DIRECTORY;

pub const ENOENT: i32 = 2;
pub const EBADF: i32 = 9;
pub const EFAULT: i32 = 14;
pub const EINVAL: i32 = 22;
