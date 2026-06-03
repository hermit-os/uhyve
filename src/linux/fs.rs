use std::os::fd::RawFd;

use uhyve_interface::v2::parameters::{FileAttr, Timespec};

pub(crate) fn host_stat_to_file_attr(st: libc::stat) -> FileAttr {
	FileAttr {
		st_dev: st.st_dev,
		st_ino: st.st_ino,
		st_nlink: st.st_nlink,
		st_mode: st.st_mode,
		st_uid: st.st_uid,
		st_gid: st.st_gid,
		st_rdev: st.st_rdev,
		st_size: st.st_size,
		st_blksize: st.st_blksize,
		st_blocks: st.st_blocks,
		st_atim: Timespec::from_nsecs(st.st_atime, st.st_atime_nsec).unwrap(),
		st_mtim: Timespec::from_nsecs(st.st_mtime, st.st_mtime_nsec).unwrap(),
		st_ctim: Timespec::from_nsecs(st.st_ctime, st.st_ctime_nsec).unwrap(),
	}
}

/// Hermit uses the Linux getdents layout, so we can just forward the call.
pub(crate) unsafe fn raw_getdents(host_fd: RawFd, buf: &mut [u8]) -> isize {
	unsafe { libc::syscall(libc::SYS_getdents64, host_fd, buf.as_mut_ptr(), buf.len()) as isize }
}
