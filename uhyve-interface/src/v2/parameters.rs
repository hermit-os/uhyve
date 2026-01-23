//! Parameters for [Hypercalls](crate::v2::Hypercall).

use crate::GuestPhysAddr;
/// Re-export of all unchanged parameters and flags from v1.
pub use crate::parameters::*;
pub use crate::v1::parameters::{
	CloseParams, LseekParams, OpenParams, SerialWriteBufferParams, UnlinkParams,
};

/// Parameters for a [`FileWrite`](crate::v2::Hypercall::FileWrite) hypercall.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct WriteParams {
	/// File descriptor of the file.
	pub fd: i32,
	/// Buffer to be written into the file.
	pub buf: GuestPhysAddr,
	/// Number of bytes in the buffer to be written.
	pub len: u64,
}

/// Parameters for a [`FileRead`](crate::v2::Hypercall::FileRead) hypercall.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct ReadParams {
	/// File descriptor of the file.
	pub fd: i32,
	/// Buffer to read the file into.
	pub buf: GuestPhysAddr,
	/// Number of bytes to read into the buffer.
	pub len: u64,
	/// Number of bytes read on success. `-1` on failure.
	pub ret: i64,
}

/// Parameters for a [`SerialReadBuffer`](crate::v2::Hypercall::SerialReadBuffer) hypercall.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SerialReadBufferParams {
	/// Address to write to.
	pub buf: GuestPhysAddr,
	/// length of `buf`.
	pub maxlen: u64,
	/// Amount of bytes acutally written.
	pub len: u64,
}
