//! Parameters for hypercalls.

pub use hermit_abi::{
	O_APPEND, O_CREAT, O_DIRECTORY, O_EXCL, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY, SEEK_CUR,
	SEEK_END, SEEK_SET,
	errno::{EBADF, EFAULT, EINVAL, ENOENT, EROFS},
};

// File operations supported by Hermit and Uhyve
pub const ALLOWED_OPEN_FLAGS: i32 =
	O_RDONLY | O_WRONLY | O_RDWR | O_CREAT | O_EXCL | O_TRUNC | O_APPEND | O_DIRECTORY;
