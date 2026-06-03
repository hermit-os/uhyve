use core::{
	mem::{align_of, offset_of},
	ptr,
};
use std::{io, os::fd::RawFd};

use align_address::Align;
use uhyve_interface::v2::parameters::{Dirent64, FileAttr, FileType, Timespec};

/// MacOS file attributes have slightly different types than Linux, so we need a separate conversion function.
pub(crate) fn host_stat_to_file_attr(st: libc::stat) -> FileAttr {
	FileAttr {
		st_dev: st.st_dev as u64,
		st_ino: st.st_ino,
		st_nlink: st.st_nlink as u64,
		st_mode: st.st_mode as u32,
		st_uid: st.st_uid,
		st_gid: st.st_gid,
		st_rdev: st.st_rdev as u64,
		st_size: st.st_size,
		st_blksize: st.st_blksize as i64,
		st_blocks: st.st_blocks,
		st_atim: Timespec::from_nsecs(st.st_atime, st.st_atime_nsec).unwrap(),
		st_mtim: Timespec::from_nsecs(st.st_mtime, st.st_mtime_nsec).unwrap(),
		st_ctim: Timespec::from_nsecs(st.st_ctime, st.st_ctime_nsec).unwrap(),
	}
}

fn dirent_reclen(name_len: usize) -> usize {
	let dirent_len = offset_of!(Dirent64, d_name) + name_len + 1;
	dirent_len.align_up(align_of::<Dirent64>())
}

fn host_dirent_type(d_type: u8) -> FileType {
	match d_type {
		1 => FileType::Fifo,
		2 => FileType::CharacterDevice,
		4 => FileType::Directory,
		6 => FileType::BlockDevice,
		8 => FileType::RegularFile,
		10 => FileType::SymbolicLink,
		12 => FileType::Socket,
		14 => FileType::Whiteout,
		_ => FileType::Unknown,
	}
}

unsafe extern "C" {
	fn getdirentries(
		fd: libc::c_int,
		buf: *mut libc::c_char,
		nbytes: libc::c_int,
		basep: *mut libc::c_long,
	) -> libc::c_int;
}

/// Reads host directory entries and writes Linux `dirent64` records into `buf`.
pub(crate) unsafe fn raw_getdents(host_fd: RawFd, buf: &mut [u8]) -> isize {
	let mut guest_off = 0usize;
	let mut host_buf = [0u8; 2048];

	loop {
		let mut entry_offset = 0i64;
		let bytes_read = unsafe {
			getdirentries(
				host_fd,
				host_buf.as_mut_ptr().cast(),
				host_buf.len() as i32,
				&mut entry_offset,
			)
		};
		if bytes_read < 0 {
			return if guest_off > 0 {
				guest_off as isize
			} else {
				bytes_read as isize
			};
		}
		if bytes_read == 0 {
			break;
		}

		let dent = unsafe { &*host_buf.as_ptr().cast::<libc::dirent>() };
		let namelen = dent.d_namlen as usize;
		let reclen = dirent_reclen(namelen);

		if guest_off + reclen > buf.len() {
			unsafe { libc::lseek(host_fd, entry_offset, libc::SEEK_SET) };
			if guest_off == 0 {
				let _ = io::Error::from_raw_os_error(libc::EINVAL);
				return -1;
			}
			break;
		}

		unsafe {
			let target = buf[guest_off..].as_mut_ptr().cast::<Dirent64>();
			target.write(Dirent64 {
				d_ino: dent.d_ino,
				d_off: 0,
				d_reclen: reclen.try_into().unwrap_or(u16::MAX),
				d_type: host_dirent_type(dent.d_type),
				d_name: core::marker::PhantomData,
			});
			let nameptr = ptr::from_mut(&mut (*target).d_name).cast::<u8>();
			ptr::copy_nonoverlapping(dent.d_name.as_ptr().cast(), nameptr, namelen);
			nameptr.add(namelen).write(0);
		}

		guest_off += reclen;
	}

	guest_off as isize
}
