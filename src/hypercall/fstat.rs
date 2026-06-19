use std::{
	ffi::CString,
	os::{fd::RawFd, unix::ffi::OsStrExt},
};

use uhyve_interface::{GuestPhysAddr, v2::parameters::*};

use crate::{
	hypercall::{decode_guest_path, translate_last_errno},
	isolation::{
		fd::{FdData, GuestFd},
		filemap::{ResolvedDirectory, UhyveFileMap, UhyveMapLeaf},
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
	let mut st = unsafe { core::mem::zeroed() };
	let ret = unsafe {
		match kind {
			StatKind::Stat => libc::stat(path.as_c_str().as_ptr(), &mut st),
			StatKind::LStat => libc::lstat(path.as_c_str().as_ptr(), &mut st),
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
	let guest_path = if let Some(guest_path) = unsafe { decode_guest_path(mem, sysstat.name) } {
		guest_path
	} else {
		error!("The kernel requested stat() on a non-UTF8 path: Rejecting...");
		sysstat.ret = StatResult::Error(EINVAL);
		return;
	};

	let attr = match sysstat.kind {
		StatKind::Stat => file_map.get_host_path(guest_path, true),
		StatKind::LStat => file_map.get_host_path(guest_path, false),
	}
	.map(|leaf| match leaf {
		UhyveMapLeaf::OnHost(host_path) => host_stat_path(&host_path, sysstat.kind),
		UhyveMapLeaf::Virtual(data) => Ok(virtual_file_attr(&data)),
	})
	.or_else(|| {
		file_map
			.resolve_guest_directory(guest_path)
			.ok()
			.map(|resolved| match resolved {
				ResolvedDirectory::Host(host_path) => host_stat_path(&host_path, sysstat.kind),
				ResolvedDirectory::Mapped(_) => Ok(mapped_directory_attr()),
			})
	});

	match attr {
		Some(Ok(attr)) => sysstat.ret = write_stat_attr(mem, sysstat.attr, attr),
		Some(Err(errno)) => sysstat.ret = StatResult::Error(errno),
		None => {
			debug!("stat {guest_path:?}: path not found in file map");
			sysstat.ret = StatResult::Error(ENOENT);
		}
	}
}

/// Handles an fstat hypercall.
pub(crate) fn fstat(mem: &MmapMemory, sysfstat: &mut FstatParams, file_map: &UhyveFileMap) {
	if sysfstat.fd < 0 {
		sysfstat.ret = StatResult::Error(EBADF);
		return;
	}
	let gfd = GuestFd(sysfstat.fd);
	// Stdio fds are not guest-managed; fstat would leak host metadata (st_dev, st_rdev, …).
	if gfd.is_standard() {
		sysfstat.ret = StatResult::Error(EBADF);
		return;
	}
	let attr = file_map.fdmap.get(gfd).map(fstat_attr_for_fd_data);

	sysfstat.ret = match attr {
		Some(Ok(attr)) => write_stat_attr(mem, sysfstat.attr, attr),
		Some(Err(errno)) => StatResult::Error(errno),
		None => {
			debug!("fstat on invalid fd {gfd}");
			StatResult::Error(EBADF)
		}
	}
}
