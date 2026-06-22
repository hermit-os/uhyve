use std::{
	ffi::CString,
	os::{fd::RawFd, unix::ffi::OsStrExt},
};

use uhyve_interface::{GuestPhysAddr, v2::parameters::*};

use crate::{
	hypercall::{decode_guest_path, translate_last_errno},
	isolation::{
		fd::{FdData, GuestFd},
		filemap::{NodeStatRef, UhyveFileMap},
	},
	mem::MmapMemory,
};

fn virtual_file_attr(data: &[u8]) -> FileAttr {
	FileAttr {
		st_mode: (libc::S_IFREG | 0o444).into(),
		st_nlink: 1,
		st_size: data.len().try_into().unwrap_or(i64::MAX),
		st_blksize: 4096,
		st_blocks: (data.len() as i64).saturating_add(511) / 512,
		..Default::default()
	}
}

fn mapped_directory_attr() -> FileAttr {
	FileAttr {
		st_mode: (libc::S_IFDIR | 0o755).into(),
		st_nlink: 2,
		st_blksize: 4096,
		..Default::default()
	}
}

fn host_stat_path(path: &std::path::Path, kind: StatKind) -> Result<FileAttr, i32> {
	let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| EINVAL)?;
	let path = path.as_c_str().as_ptr();
	let mut st = unsafe { core::mem::zeroed() };
	let ret = unsafe {
		match kind {
			StatKind::Stat => libc::stat(path, &mut st),
			StatKind::LStat => libc::lstat(path, &mut st),
		}
	};
	if ret < 0 {
		return Err(translate_last_errno().unwrap_or(EIO));
	}
	Ok(crate::os::fs::host_stat_to_file_attr(st))
}

fn host_fstat(fd: RawFd) -> Result<FileAttr, i32> {
	let mut st = unsafe { core::mem::zeroed() };
	let ret = unsafe { libc::fstat(fd, &mut st) };
	if ret < 0 {
		return Err(translate_last_errno().unwrap_or(EIO));
	}
	Ok(crate::os::fs::host_stat_to_file_attr(st))
}

fn fstat_attr_for_fd_data(fdata: &FdData) -> Result<FileAttr, i32> {
	match fdata {
		FdData::Raw(fd) => host_fstat(*fd),
		FdData::Virtual { data, .. } => Ok(virtual_file_attr(data)),
		FdData::MappedDirectory { .. } => Ok(mapped_directory_attr()),
	}
}

fn write_stat_attr(mem: &MmapMemory, attr_addr: GuestPhysAddr, attr: FileAttr) -> StatResult {
	match unsafe { mem.get_ref_mut(attr_addr) } {
		Ok(guest_attr) => {
			*guest_attr = attr;
			StatResult::Success
		}
		Err(_) => {
			warn!("Unable to get host address for stat buffer");
			StatResult::Error(EFAULT)
		}
	}
}

/// Handles a stat/lstat hypercall.
pub(crate) fn stat(mem: &MmapMemory, sysstat: &mut StatParams, file_map: &UhyveFileMap) {
	sysstat.ret = unsafe { decode_guest_path(mem, sysstat.name) }
		.ok_or_else(|| {
			error!("The kernel requested stat() on a non-UTF8 path: Rejecting...");
			EINVAL
		})
		.and_then(|guest_path| {
			file_map
				.get_host_stat_node(guest_path, matches!(sysstat.kind, StatKind::Stat))
				.ok_or_else(|| {
					debug!("stat {guest_path:?}: path not found in file map");
					ENOENT
				})
		})
		.and_then(|node| match node {
			NodeStatRef::VirtualDirectory(_) => Ok(mapped_directory_attr()),
			NodeStatRef::VirtualFile(v) => Ok(virtual_file_attr(v)),
			NodeStatRef::OnHost(host_path) => host_stat_path(&host_path, sysstat.kind),
		})
		.map_or_else(StatResult::Error, |attr| {
			write_stat_attr(mem, sysstat.attr, attr)
		});
}

/// Handles an fstat hypercall.
pub(crate) fn fstat(mem: &MmapMemory, sysfstat: &mut FstatParams, file_map: &UhyveFileMap) {
	let gfd = GuestFd(sysfstat.fd);
	// Stdio fds are not guest-managed; fstat would leak host metadata (st_dev, st_rdev, …).
	if sysfstat.fd < 0 || gfd.is_standard() {
		sysfstat.ret = StatResult::Error(EBADF);
		return;
	}

	sysfstat.ret = file_map
		.fdmap
		.get(gfd)
		.ok_or_else(|| {
			debug!("fstat on invalid fd {gfd}");
			EBADF
		})
		.and_then(fstat_attr_for_fd_data)
		.map_or_else(StatResult::Error, |attr| {
			write_stat_attr(mem, sysfstat.attr, attr)
		});
}
