//! Parameters for [Hypercalls](crate::v2::Hypercall).

use bitflags::bitflags;

use crate::GuestPhysAddr;
/// Re-export of all unchanged parameters and flags from v1.
pub use crate::parameters::*;
pub use crate::v1::parameters::{
	CloseParams, ExitParams, LseekParams, OpenParams, SerialWriteBufferParams, UnlinkParams,
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
	pub len: usize,
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
	pub len: usize,
	/// Number of bytes read on success. `-1` on failure.
	pub ret: isize,
}

/// Parameters for a [`SerialReadBuffer`](crate::v2::Hypercall::SerialReadBuffer) hypercall.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SerialReadBufferParams {
	/// Address to write to.
	pub buf: GuestPhysAddr,
	/// length of `buf`.
	pub maxlen: usize,
	/// Amount of bytes acutally written.
	pub len: usize,
}

#[repr(u8)]
#[derive(Debug, Copy, Clone)]
pub enum SharedMemOpenError {
	/// The shared memory due to invalid parameters.
	InvalidParams,
	/// New shared memory creation was requested, but the shared memory already exists.
	AlreadyExisting,
	/// There limit of shared memories is exceeded.
	TooManySharedMems,
	/// Unspecified error
	Unspecified,
}

#[derive(Debug, Copy, Clone)]
pub struct SharedMemFlags(u8);
bitflags! {
	impl SharedMemFlags: u8 {
		/// The shared memory should be created if not present.
		const CREATE = 0b0000_0001;
		/// Return an error if the shared memory exists.
		const CREATE_EXCLUSIVE = 0b0000_0010;
		/// Map the shared memory in read-only mode.
		const READ_ONLY = 0b0000_0100;
		/// Experimental = Create a shared memory, that can only be written by the current VM.
		const CREATE_EXCLUSIVE_WRITE = 0b0000_1000;
	}
}

/// Parameters for a [`SharedMemOpen`](crate::v2::Hypercall::SharedMemOpen) hypercall.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SharedMemOpenParams {
	/// Address of the mapped shared memory in the guest. Is set by the host.
	pub buf: Result<GuestPhysAddr, SharedMemOpenError>,
	/// length of `buf`.
	pub len: usize,
	/// Address of the shared memory identifier utf8 string.
	pub identifier: GuestPhysAddr,
	/// length of `identifier` in bytes.
	pub identifier_len: usize,
	/// Flags for opening the shared memory.
	pub flags: SharedMemFlags,
}

#[repr(u8)]
#[derive(Debug, Copy, Clone)]
pub enum SharedMemCloseError {
	/// The identifier is not valid.
	InvalidIdentifier,
	/// The shared memory does not exist.
	NotExisting,
	/// Unspecified error.
	Unspecified,
}

/// Parameters for a [`SharedMemClose`](crate::v2::Hypercall::SharedMemOpen) hypercall.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SharedMemCloseParams {
	/// Address of the shared memory identifier utf8 string.
	pub identifier: GuestPhysAddr,
	/// length of `identifier` in bytes.
	pub identifier_len: usize,
	/// Flags for Closeing the shared memory.
	pub result: Result<(), SharedMemCloseError>,
}
