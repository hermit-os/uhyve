//! Parameters for [Hypercalls](crate::v2::Hypercall).

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
