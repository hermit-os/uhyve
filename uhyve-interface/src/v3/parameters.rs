//! Parameters for [Hypercalls](crate::v2::Hypercall).

pub use core::num::NonZero;
use core::{cmp::Ordering, fmt, marker::PhantomData};

use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::GuestPhysAddr;
/// Re-export of all unchanged parameters and flags from v1.
pub use crate::parameters::*;
pub use crate::v2::parameters::SerialWriteBufferParams;

/// Parameters for a [`FileClose`](crate::v3::Hypercall::FileClose) hypercall.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct CloseParams {
	/// File descriptor of the file.
	pub fd: i32,
	pub ret: TaggedNumber<i32, TristateResult>,
}

/// Parameters for a [`FileOpen`](crate::v3::Hypercall::FileOpen) hypercall.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct OpenParams {
	/// Pathname of the file to be opened.
	pub name: GuestPhysAddr,
	/// Posix file access mode flags.
	pub flags: i32,
	/// Access permissions upon opening/creating a file.
	pub mode: i32,
	/// File descriptor upon successful opening or negative value upon failure.
	pub ret: TaggedNumber<i32, IoResult32>,
}

/// Parameters for a [`FileUnlink`](crate::v3::Hypercall::FileUnlink) hypercall.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct UnlinkParams {
	/// Address of the file that should be unlinked.
	pub name: GuestPhysAddr,
	pub ret: TaggedNumber<i32, TristateResult>,
}

/// Parameters for a [`FileWrite`](crate::v3::Hypercall::FileWrite) hypercall.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct WriteParams {
	/// Number of bytes in the buffer to be written.
	pub len: u64,
	/// Number of bytes written on success or errno.
	pub ret: TaggedNumber<i64, IoResult64>,
	/// Buffer to be written into the file.
	pub buf: GuestPhysAddr,
	/// File descriptor of the file.
	pub fd: i32,
}

/// Parameters for a [`FileRead`](crate::v3::Hypercall::FileRead) hypercall.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ReadParams {
	/// Number of bytes to read into the buffer.
	pub len: u64,
	/// Number of bytes read on success or errno.
	pub ret: TaggedNumber<i64, IoResult64>,
	/// Buffer to read the file into.
	pub buf: GuestPhysAddr,
	/// File descriptor of the file.
	pub fd: i32,
}

/// Parameters for a [`FileLseek`](crate::v3::Hypercall::FileLseek) hypercall
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LseekParams {
	/// Offset in the file.
	pub offset: TaggedNumber<i64, IoResult64>,
	/// `whence` value of the lseek call.
	pub whence: u32,
	/// File descriptor of the file.
	pub fd: i32,
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
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
#[repr(C)]
pub enum GetdentResult {
	/// No result. Guests should set this value before calling the hypercall.
	#[default]
	None,
	/// Number of bytes written on success.
	Success(NonZero<u64>),
	/// End of directory.
	EndOfDirectory,
	/// Error with libc errno.
	Errno(NonZero<u32>),
}

impl From<TaggedNumber<i64, GetdentResult>> for GetdentResult {
	fn from(value: TaggedNumber<i64, Self>) -> Self {
		match 0.cmp(&value.num) {
			Ordering::Less if value.num == i64::MAX => Self::None,
			Ordering::Equal => Self::EndOfDirectory,
			Ordering::Less => Self::Success(NonZero::new(value.num as u64).unwrap()),
			Ordering::Greater => Self::Errno(NonZero::new((-value.num) as u32).unwrap()),
		}
	}
}

impl GetdentResult {
	/// Attempts to convert this result value into an integer.
	pub fn try_as_num(self) -> Option<TaggedNumber<i64, Self>> {
		match self {
			Self::None => Some(i64::MAX),
			Self::EndOfDirectory => Some(0),
			Self::Success(count) if count.get() == 0 || count.get() > (i64::MAX as u64) => None,
			Self::Success(count) => Some(count.get() as i64),
			Self::Errno(errno) => Some(-(errno.get() as i64)),
		}
		.map(|num| TaggedNumber {
			num,
			_phantom: PhantomData,
		})
	}
}

/// Parameters for a [`Getdents`](crate::v3::Hypercall::Getdents) hypercall.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct GetdentParams {
	/// Guest file descriptor of the directory (from [`FileOpen`](crate::v3::Hypercall::FileOpen) with `O_DIRECTORY`).
	pub fd: i32,
	/// Buffer to write to.
	pub buf: GuestPhysAddr,
	/// Length of the `buf`fer.
	pub len: u64,
	/// Return value of the hypercall.
	pub ret: TaggedNumber<i64, GetdentResult>,
}

/// Result of a [`Mkdir`](crate::v3::Hypercall::Mkdir) hypercall.
pub type MkdirResult = TristateResult;

/// Parameters for a [`Mkdir`](crate::v3::Hypercall::Mkdir) hypercall.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct MkdirParams {
	/// Path to create. Zero terminated C-String.
	pub path: GuestPhysAddr,
	/// Length of the path buffer.
	pub len: u64,
	/// Return value of the hypercall.
	pub ret: TaggedNumber<i32, TristateResult>,
}

/// Which stat-like operation to perform.
#[derive(TryFromPrimitive, IntoPrimitive, PartialEq, Eq, Clone, Copy, Debug)]
#[repr(u32)]
pub enum StatKind {
	/// Follow symlinks (like `stat(2)`).
	Stat = 0,
	/// Do not follow symlinks (like `lstat(2)`).
	LStat = 1,
}

/// Time value used in [`FileAttr`].
#[repr(C)]
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct Timespec {
	/// Seconds since the Unix epoch.
	pub tv_sec: i64,
	/// Nanoseconds.
	pub tv_nsec: i32,
}
impl Timespec {
	pub fn from_nsecs(secs: i64, nsecs: i64) -> Option<Self> {
		nsecs.try_into().ok().map(|nsec| Self {
			tv_sec: secs,
			tv_nsec: nsec,
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

/// Result of a [`FileStat`](crate::v3::Hypercall::FileStat) hypercall.
pub type StatResult = TristateResult;

/// Parameters for a [`FileStat`](crate::v3::Hypercall::FileStat) hypercall.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct StatParams {
	/// Path to stat. Must be a null-terminated UTF-8 string.
	pub name: GuestPhysAddr,
	/// Whether to follow symlinks on the host.
	pub kind: StatKind,
	/// Guest buffer to write the resulting [`FileAttr`] into.
	pub attr: GuestPhysAddr,
	/// Return value of the hypercall.
	pub ret: TaggedNumber<i32, StatResult>,
}

/// Parameters for a [`FileFstat`](crate::v3::Hypercall::FileFstat) hypercall.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FstatParams {
	/// Guest file descriptor (from [`FileOpen`](crate::v3::Hypercall::FileOpen)).
	pub fd: i32,
	/// Guest buffer to write the resulting [`FileAttr`] into.
	pub attr: GuestPhysAddr,
	/// Return value of the hypercall.
	pub ret: TaggedNumber<i32, StatResult>,
}

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaggedNumber<T, T2: From<TaggedNumber<T, T2>>> {
	pub num: T,
	_phantom: PhantomData<T2>,
}

impl<T, T2: From<TaggedNumber<T, T2>>> TaggedNumber<T, T2> {
	#[inline(always)]
	pub fn new(num: T) -> Self {
		Self {
			num,
			_phantom: PhantomData,
		}
	}
}

impl<T: fmt::Display, T2: From<TaggedNumber<T, T2>>> fmt::Display for TaggedNumber<T, T2> {
	#[inline(always)]
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.num)
	}
}

impl<T: fmt::Debug, T2: From<TaggedNumber<T, T2>>> fmt::Debug for TaggedNumber<T, T2> {
	#[inline(always)]
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{:?}", self.num)
	}
}

/// High-level representation of a 64-bit result, of a [`ReadParams::ret`], [`WriteParams::ret`], [`LseekParams::offset`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IoResult64 {
	/// INVARIANT: `Ok(x)` has `x` with value `<= i64::MAX as u64`.
	Ok(u64),
	/// INVARIANT: `Errno(x)` has `x` with value `<= -(i32::MIN + 1) as u32 + 1`.
	Errno(NonZero<u32>),
}

/// High-level representation of a 32-bit result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IoResult32 {
	/// INVARIANT: `Ok(x)` has `x` with value `<= i32::MAX as u64`.
	Ok(u32),
	/// INVARIANT: `Errno(x)` has `x` with value `<= -(i32::MIN + 1) as u32 + 1`.
	Errno(NonZero<u32>),
}

/// High-level representatzion of an [`MkdirParams::ret`], [`StatParams::ret`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TristateResult {
	/// No result. Guests should set this value before calling the hypercall.
	#[default]
	None,
	/// Data was committed on success.
	Success,
	/// Error with libc errno.
	Errno(NonZero<u32>),
}

// This is unfortunately necessary because `nonzero_internals` is an unstable feature
// which would be necessary to access the `core::num::ZeroablePrimitive` trait.
macro_rules! io_result_num_convert {
	($io_res_ty:ident, $signed_num_ty:ty, $unsigned_num_ty:ty) => {
		impl Default for $io_res_ty {
			fn default() -> Self {
				TaggedNumber::<$signed_num_ty, $io_res_ty>::default().into()
			}
		}
		impl Default for TaggedNumber<$signed_num_ty, $io_res_ty> {
			fn default() -> Self {
				Self {
					num: <$signed_num_ty>::MIN,
					_phantom: PhantomData,
				}
			}
		}
		impl From<TaggedNumber<$signed_num_ty, $io_res_ty>> for $io_res_ty {
			fn from(value: TaggedNumber<$signed_num_ty, $io_res_ty>) -> Self {
				if value.num < 0 {
					// UNWRAP: -x != 0
					// NOTE that this intentionally can't panic even if the error value exceeds the u32 range.
					Self::Errno(NonZero::new((-value.num) as u32).unwrap())
				} else {
					Self::Ok(value.num as $unsigned_num_ty)
				}
			}
		}

		impl $io_res_ty {
			/// Attempts to convert this result value into an integer.
			pub fn try_as_num(self) -> Option<TaggedNumber<$signed_num_ty, Self>> {
				match self {
					Self::Ok(x) => x.try_into().ok(),
					// The following complication is necessary to handle the result `Some($signed_num_ty::MIN)` correctly.
					Self::Errno(x) if x.get() > ((-(i32::MIN + 1)) as u32 + 1) => None,
					Self::Errno(x) => Some(-((x.get() - 1) as $signed_num_ty) - 1),
				}
				.map(TaggedNumber::new)
			}
		}
	};
}

io_result_num_convert!(IoResult32, i32, u32);
io_result_num_convert!(IoResult64, i64, u64);

impl From<TaggedNumber<i32, TristateResult>> for TristateResult {
	fn from(value: TaggedNumber<i32, Self>) -> Self {
		if value.num > 0 {
			Self::None
		} else if let Some(e) = NonZero::new((-value.num) as u32) {
			Self::Errno(e)
		} else {
			Self::Success
		}
	}
}

impl TristateResult {
	pub fn try_as_num(self) -> Option<TaggedNumber<i32, Self>> {
		match self {
			Self::None => Some(1),
			Self::Success => Some(0),
			Self::Errno(x) if x.get() > ((-(i32::MIN + 1)) as u32 + 1) => None,
			Self::Errno(x) => Some(-((x.get() - 1) as i32) - 1),
		}
		.map(TaggedNumber::new)
	}
}

#[cfg(test)]
mod tests {
	use super::{IoResult32, IoResult64, NonZero, PhantomData, TaggedNumber};

	#[test]
	fn test_io_result64_errno_i64_min() {
		const MAX_ERR_NUM: u32 = (-(i32::MIN + 1)) as u32 + 1;
		assert_eq!(
			IoResult64::Errno(NonZero::new(MAX_ERR_NUM - 1).unwrap()).try_as_num(),
			Some((i32::MIN + 1) as i64).map(|num| TaggedNumber {
				num,
				_phantom: PhantomData,
			})
		);
		assert_eq!(
			IoResult64::Errno(NonZero::new(MAX_ERR_NUM).unwrap()).try_as_num(),
			Some(i32::MIN as i64).map(|num| TaggedNumber {
				num,
				_phantom: PhantomData,
			})
		);
		assert_eq!(
			IoResult64::Errno(NonZero::new(MAX_ERR_NUM + 1).unwrap()).try_as_num(),
			None
		);
	}

	#[test]
	fn test_io_result64_ok_i64_max() {
		assert_eq!(
			IoResult64::Ok(i64::MAX as u64).try_as_num(),
			Some(i64::MAX).map(TaggedNumber::new)
		);
		assert_eq!(IoResult64::Ok(i64::MAX as u64 + 1).try_as_num(), None);
	}

	#[test]
	fn test_io_result32_errno_i32_min() {
		const MAX_ERR_NUM: u32 = (-(i32::MIN + 1)) as u32 + 1;
		assert_eq!(
			IoResult32::Errno(NonZero::new(MAX_ERR_NUM - 1).unwrap()).try_as_num(),
			Some(i32::MIN + 1).map(TaggedNumber::new)
		);
		assert_eq!(
			IoResult32::Errno(NonZero::new(MAX_ERR_NUM).unwrap()).try_as_num(),
			Some(i32::MIN).map(TaggedNumber::new)
		);
		assert_eq!(
			IoResult32::Errno(NonZero::new(MAX_ERR_NUM + 1).unwrap()).try_as_num(),
			None
		);
	}

	#[test]
	fn test_io_result32_ok_i32_max() {
		assert_eq!(
			IoResult32::Ok(i32::MAX as u32).try_as_num(),
			Some(i32::MAX).map(TaggedNumber::new)
		);
		assert_eq!(IoResult32::Ok(i32::MAX as u32 + 1).try_as_num(), None);
	}

	#[test]
	fn test_tristate_result_errno_i32_min() {
		use super::TristateResult;

		const MAX_ERR_NUM: u32 = (-(i32::MIN + 1)) as u32 + 1;
		assert_eq!(
			TristateResult::Errno(NonZero::new(MAX_ERR_NUM - 1).unwrap()).try_as_num(),
			Some(i32::MIN + 1).map(TaggedNumber::new)
		);
		assert_eq!(
			TristateResult::Errno(NonZero::new(MAX_ERR_NUM).unwrap()).try_as_num(),
			Some(i32::MIN).map(TaggedNumber::new)
		);
		assert_eq!(
			TristateResult::Errno(NonZero::new(MAX_ERR_NUM + 1).unwrap()).try_as_num(),
			None
		);
	}
}
