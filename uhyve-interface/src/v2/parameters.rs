//! Parameters for [Hypercalls](crate::v2::Hypercall).

use core::num::NonZeroU16;

use bitflags::bitflags;

use crate::GuestPhysAddr;
/// Re-export of all unchanged parameters and flags from v1.
pub use crate::v1::parameters::{
	ALLOWED_OPEN_FLAGS, CloseParams, EBADF, EFAULT, EINVAL, ENOENT, ExitParams, LseekParams,
	O_APPEND, O_CREAT, O_DIRECTORY, O_EXCL, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY, OpenParams,
	ReadParams, SerialWriteBufferParams, UnlinkParams, WriteParams,
};

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

/// Parameters for a [`GetTime`](crate::v2::Hypercall::GetTime) hypercall. This follows the semantics of POSIX's `struct timeval`
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct TimeParams {
	/// Seconds since the Unix Epoch.
	pub seconds: u64,
	/// Microseconds since the Unix Epoch (in addition to the `seconds`).
	pub u_seconds: u64,
}

/// Parameters for a [`Sleep`](crate::v2::Hypercall::Sleep) hypercall.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SleepParams {
	/// Desired seconds duration (seconds, milliseconds).
	pub sleep_duration: (u16, u16),
	/// Actual sleep duration. (Appoximately: does not include vm entry/exit duration). Might not be supported.
	pub actual_sleep_duration: Option<(NonZeroU16, NonZeroU16)>,
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
