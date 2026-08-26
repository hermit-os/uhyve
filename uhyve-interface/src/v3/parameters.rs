//! Parameters for [Hypercalls](crate::v3::Hypercall).

use core::marker::PhantomData;
pub use core::num::NonZero;

use num_enum::{IntoPrimitive, TryFromPrimitive};

/// Re-export of all unchanged parameters and flags from v1.
pub use crate::parameters::*;
pub use crate::v2::parameters::SerialWriteBufferParams;
use crate::{
	GuestPhysAddr,
	v3::util::{AbiResult, Errno, NotRepresentable, RawResult},
};

/// A buffer in guest memory that is only read by the host.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SizedGuestBuffer {
	pub addr: GuestPhysAddr,
	pub len: u64,
}
impl Default for SizedGuestBuffer {
	fn default() -> Self {
		Self {
			addr: GuestPhysAddr::zero(),
			len: 0,
		}
	}
}

/// A buffer in guest memory that the host may write to.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct MutSizedGuestBuffer {
	pub addr: GuestPhysAddr,
	pub len: u64,
}
impl Default for MutSizedGuestBuffer {
	fn default() -> Self {
		Self {
			addr: GuestPhysAddr::zero(),
			len: 0,
		}
	}
}

/// Parameters for a [`FileClose`](crate::v3::Hypercall::FileClose) hypercall.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct CloseParams {
	/// File descriptor of the file.
	pub fd: i32,
	/// Return value of the close.
	pub ret: RawResult<Result<(), Errno>>,
}

/// Parameters for a [`FileOpen`](crate::v3::Hypercall::FileOpen) hypercall.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct OpenParams {
	/// Pathname of the file to be opened.
	pub path: GuestPhysAddr,
	/// Posix file access mode flags.
	pub flags: i32,
	/// Access permissions upon opening/creating a file.
	pub mode: u32,
	/// File descriptor upon successful opening or negative value upon failure.
	pub ret: RawResult<Result<i32, Errno>>,
}

/// Parameters for a [`FileUnlink`](crate::v3::Hypercall::FileUnlink) hypercall.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct UnlinkParams {
	/// Address of the file that should be unlinked.
	pub path: GuestPhysAddr,
	pub ret: RawResult<Result<(), Errno>>,
}

/// Parameters for a [`FileWrite`](crate::v3::Hypercall::FileWrite) hypercall.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct WriteParams {
	/// Number of bytes written on success or errno.
	pub ret: RawResult<Result<u64, Errno>>,
	/// Buffer to be written into the file.
	pub buf: SizedGuestBuffer,
	/// File descriptor of the file.
	pub fd: i32,
}

/// Parameters for a [`FileRead`](crate::v3::Hypercall::FileRead) hypercall.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ReadParams {
	/// Number of bytes read on success or errno.
	pub ret: RawResult<Result<u64, Errno>>,
	/// Buffer to read the file into.
	pub buf: MutSizedGuestBuffer,
	/// File descriptor of the file.
	pub fd: i32,
}

/// Parameters for a [`SerialReadBuffer`](crate::v3::Hypercall::SerialReadBuffer) hypercall.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SerialReadBufferParams {
	/// Number of bytes read on success or errno.
	pub ret: RawResult<Result<u64, Errno>>,
	/// Buffer to read the serial input into.
	pub buf: SizedGuestBuffer,
}

/// Target position of a [`FileLseek`](crate::v3::Hypercall::FileLseek) hypercall.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum LseekWhence {
	/// The file offset is set to `offset` bytes.
	SeekSet { offset: u64 },
	/// The file offset is set to its current location plus `offset` bytes.
	SeekCur { offset: i64 },
	/// The file offset is set to the size of the file plus `offset` bytes.
	SeekEnd { offset: i64 },
	/// Adjust the file offset to the next location in the file greater than or equal to `offset`
	/// containing data.
	SeekData { offset: u64 },
	/// Adjust the file offset to the next hole in the file greater than or equal to `offset`.
	SeekHole { offset: u64 },
}

/// [`LseekWhenceRaw`] has an unknown tag or an absolute offset larger than `i64::MAX`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct InvalidWhence;

/// ABI representation of [`LseekWhence`]. The tag values match Linux' `SEEK_*` constants.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct RawLseekWhence {
	offset: u64,
	whence: u8,
}
impl From<LseekWhence> for RawLseekWhence {
	fn from(value: LseekWhence) -> Self {
		let (whence, offset) = match value {
			LseekWhence::SeekSet { offset } => (0, offset),
			LseekWhence::SeekCur { offset } => (1, offset as u64),
			LseekWhence::SeekEnd { offset } => (2, offset as u64),
			LseekWhence::SeekData { offset } => (3, offset),
			LseekWhence::SeekHole { offset } => (4, offset),
		};
		Self { offset, whence }
	}
}
impl TryFrom<RawLseekWhence> for LseekWhence {
	type Error = InvalidWhence;

	fn try_from(value: RawLseekWhence) -> Result<Self, Self::Error> {
		let RawLseekWhence { offset, whence } = value;
		match whence {
			// The host's `lseek` takes a signed `off_t`.
			0 | 3 | 4 if offset > i64::MAX as u64 => Err(InvalidWhence),
			0 => Ok(Self::SeekSet { offset }),
			1 => Ok(Self::SeekCur {
				offset: offset as i64,
			}),
			2 => Ok(Self::SeekEnd {
				offset: offset as i64,
			}),
			3 => Ok(Self::SeekData { offset }),
			4 => Ok(Self::SeekHole { offset }),
			_ => Err(InvalidWhence),
		}
	}
}

/// Parameters for a [`FileLseek`](crate::v3::Hypercall::FileLseek) hypercall.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LseekParams {
	/// Target position.
	pub whence: RawLseekWhence,
	/// File descriptor of the file.
	pub fd: i32,
	/// Resulting offset from the start of the file on success or errno.
	pub ret: RawResult<Result<u64, Errno>>,
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

/// Result of a [`Getdents`](crate::v3::Hypercall::Getdents) hypercall.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum GetdentResult {
	// /// No result. Guests should set this value before calling the hypercall.
	// None,
	/// Number of bytes written on success. May never exceed 63 bytes.
	Success(NonZero<u64>),
	/// End of directory.
	EndOfDirectory,
	/// Error with libc errno.
	Errno(Errno),
}
/// Encoded as the number of bytes on success, `0` at the end of the directory and `-errno` on
/// error.
impl AbiResult for GetdentResult {
	type Repr = i64;
	const UNSET: i64 = i64::MIN;

	fn encode(self) -> Result<i64, NotRepresentable> {
		match self {
			Self::Success(count) => count.get().try_into().map_err(|_| NotRepresentable),
			Self::EndOfDirectory => Ok(0),
			Self::Errno(errno) => Ok(-i64::from(errno.get())),
		}
	}

	fn decode(raw: i64) -> Option<Self> {
		match NonZero::new(raw) {
			None => Some(Self::EndOfDirectory),
			Some(count) if raw > 0 => Some(Self::Success(count.cast_unsigned())),
			Some(_) => Errno::from_raw(raw).map(Self::Errno),
		}
	}
}

/// Parameters for a [`Getdents`](crate::v3::Hypercall::Getdents) hypercall.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct GetdentParams {
	/// Guest file descriptor of the directory (from [`FileOpen`](crate::v3::Hypercall::FileOpen) with `O_DIRECTORY`).
	pub fd: i32,
	/// Buffer to write to.
	pub buf: MutSizedGuestBuffer,
	/// Return value of the hypercall.
	pub ret: RawResult<GetdentResult>,
}

/// Parameters for a [`Mkdir`](crate::v3::Hypercall::Mkdir) hypercall.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct MkdirParams {
	/// Path to create. Must be a null-terminated UTF-8 string.
	pub path: GuestPhysAddr,
	/// Access permissions of the new directory.
	pub mode: u32,
	/// Return value of the hypercall.
	pub ret: RawResult<Result<(), Errno>>,
}

/// What a [`FileStat`](crate::v3::Hypercall::FileStat) hypercall operates on.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum StatTarget {
	/// Path to a null-terminated UTF-8 string. Follows symlinks (like `stat(2)`).
	Path(GuestPhysAddr),
	/// Path to a null-terminated UTF-8 string. Does not follow symlinks (like `lstat(2)`).
	Link(GuestPhysAddr),
	/// Guest file descriptor from [`FileOpen`](crate::v3::Hypercall::FileOpen) (like `fstat(2)`).
	Fd(i32),
}

/// ABI representation of a [`StatTarget`].
///
/// Use `.into()` to create one from a [`StatTarget`] and `.try_into()` to validate and convert
/// it back.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RawStatTarget {
	tag: u32,
	_pad: u32,
	/// The guest address for paths, the sign-extended fd otherwise.
	payload: u64,
}
impl RawStatTarget {
	const PATH: u32 = 0;
	const LINK: u32 = 1;
	const FD: u32 = 2;
}
impl TryFrom<RawStatTarget> for StatTarget {
	type Error = NotRepresentable;

	/// Fails if the tag or payload is invalid.
	fn try_from(raw: RawStatTarget) -> Result<Self, NotRepresentable> {
		let addr = || GuestPhysAddr::try_new(raw.payload).map_err(|_| NotRepresentable);
		match raw.tag {
			RawStatTarget::PATH => addr().map(Self::Path),
			RawStatTarget::LINK => addr().map(Self::Link),
			RawStatTarget::FD => i32::try_from(raw.payload as i64)
				.map(Self::Fd)
				.map_err(|_| NotRepresentable),
			_ => Err(NotRepresentable),
		}
	}
}
impl From<StatTarget> for RawStatTarget {
	fn from(target: StatTarget) -> Self {
		let (tag, payload) = match target {
			StatTarget::Path(addr) => (Self::PATH, addr.as_u64()),
			StatTarget::Link(addr) => (Self::LINK, addr.as_u64()),
			StatTarget::Fd(fd) => (Self::FD, i64::from(fd) as u64),
		};
		Self {
			tag,
			_pad: 0,
			payload,
		}
	}
}

/// Time value used in [`FileAttr`].
#[repr(C)]
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct Timespec {
	/// Seconds since the Unix epoch.
	pub tv_sec: i64,
	/// Nanoseconds.
	pub tv_nsec: i32,
	_pad: u32,
}
impl Timespec {
	pub fn new(secs: i64, nsecs: i64) -> Option<Self> {
		nsecs.try_into().ok().map(|nsec| Self {
			tv_sec: secs,
			tv_nsec: nsec,
			_pad: 0,
		})
	}
}

/// File metadata returned by [`FileStat`](crate::v3::Hypercall::FileStat).
///
/// Layout-compatible with Hermit's `FileAttr`.
#[repr(C)]
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct FileAttr {
	pub st_dev: u64,
	pub st_ino: u64,
	pub st_nlink: u64,
	/// `st_mode` from POSIX (`S_IFMT` and permission bits).
	pub st_mode: u32,
	pub st_uid: u32,
	pub st_gid: u32,
	pub st_rdev: u64,
	pub st_size: i64,
	pub st_blksize: i64,
	pub st_blocks: i64,
	pub st_atim: Timespec,
	pub st_mtim: Timespec,
	pub st_ctim: Timespec,
}

/// Parameters for a [`FileStat`](crate::v3::Hypercall::FileStat) hypercall.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct StatParams {
	/// The file to stat.
	pub target: RawStatTarget,
	/// Guest buffer to write the resulting [`FileAttr`] into.
	pub attr: GuestPhysAddr,
	/// Return value of the hypercall.
	pub ret: RawResult<Result<(), Errno>>,
}

/// Parameters for a [`FileFsync`](crate::v2::Hypercall::FileFsync) hypercall.
///
/// Guest writes end up in the host's page cache, so this is the only place a
/// flush means anything: it is the host that owns the file.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FsyncParams {
	/// Guest file descriptor (from [`FileOpen`](crate::v2::Hypercall::FileOpen)).
	pub fd: i32,
	/// Return value of the hypercall.
	pub ret: RawResult<Result<(), Errno>>,
}
