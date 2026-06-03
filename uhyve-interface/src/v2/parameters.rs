//! Parameters for [Hypercalls](crate::v2::Hypercall).

use core::marker::PhantomData;

use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::GuestPhysAddr;
/// Re-export of all unchanged parameters and flags from v1.
pub use crate::parameters::*;
pub use crate::v1::parameters::{CloseParams, OpenParams, UnlinkParams};

/// Parameters for a [`FileWrite`](crate::v2::Hypercall::FileWrite) hypercall.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct WriteParams {
	/// Number of bytes in the buffer to be written.
	pub len: u64,
	/// Number of bytes written on success or errno.
	pub ret: i64,
	/// Buffer to be written into the file.
	pub buf: GuestPhysAddr,
	/// File descriptor of the file.
	pub fd: i32,
}

/// Parameters for a [`FileRead`](crate::v2::Hypercall::FileRead) hypercall.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ReadParams {
	/// Number of bytes to read into the buffer.
	pub len: u64,
	/// Number of bytes read on success or errno.
	pub ret: i64,
	/// Buffer to read the file into.
	pub buf: GuestPhysAddr,
	/// File descriptor of the file.
	pub fd: i32,
}

/// Parameters for a [`FileLseek`](crate::v2::Hypercall::FileLseek) hypercall
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LseekParams {
	/// Offset in the file.
	pub offset: i64,
	/// `whence` value of the lseek call.
	pub whence: u32,
	/// File descriptor of the file.
	pub fd: i32,
}

/// Parameters for a [`SerialWriteBuffer`](crate::v1::Hypercall::SerialWriteBuffer) hypercall.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SerialWriteBufferParams {
	/// Length of the buffer.
	pub len: u64,
	/// Address of the buffer to be printed.
	pub buf: GuestPhysAddr,
}

/// Parameters for a [`SerialReadBuffer`](crate::v2::Hypercall::SerialReadBuffer) hypercall.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SerialReadBufferParams {
	/// length of `buf`.
	pub maxlen: u64,
	/// Amount of bytes acutally written.
	pub len: u64,
	/// Address to write to.
	pub buf: GuestPhysAddr,
}

/// File type enum from Linux kernel
#[derive(TryFromPrimitive, IntoPrimitive, PartialEq, Eq, Clone, Copy, Debug)]
#[repr(u8)]
pub enum FileType {
	Unknown = 0,         // DT_UNKNOWN
	Fifo = 1,            // DT_FIFO
	CharacterDevice = 2, // DT_CHR
	Directory = 4,       // DT_DIR
	BlockDevice = 6,     // DT_BLK
	RegularFile = 8,     // DT_REG
	SymbolicLink = 10,   // DT_LNK
	Socket = 12,         // DT_SOCK
	Whiteout = 14,       // DT_WHT
}
/// Dirent64 struct from Linux kernel
#[repr(C)]
pub struct Dirent64 {
	/// 64-bit inode number
	pub d_ino: u64,
	/// Field without meaning. Kept for BW compatibility. Will not be used by Uhyve
	pub d_off: i64,
	/// Size of this dirent
	pub d_reclen: u16,
	/// File type
	pub d_type: FileType,
	/// Filename (null-terminated)
	pub d_name: PhantomData<u8>,
}
/// Result of a [`Getdent`](crate::v2::Hypercall::Getdent) hypercall.
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub enum GetdentResult {
	/// No result. Guests should set this value before calling the hypercall.
	None,
	/// Number of bytes written on success.
	Success(u64),
	/// End of directory.
	EndOfDirectory,
	/// Error with libc errno.
	Error(i32),
}
/// Parameters for a [`Getdent`](crate::v2::Hypercall::Getdent) hypercall.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct GetdentParams {
	/// Guest file descriptor of the directory (from [`FileOpen`](crate::v2::Hypercall::FileOpen) with `O_DIRECTORY`).
	pub fd: i32,
	/// Buffer to write to.
	pub buf: GuestPhysAddr,
	/// Length of the buffer.
	pub len: u64,
	/// Return value of the hypercall.
	pub ret: GetdentResult,
}
