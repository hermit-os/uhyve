use std::{
	ffi::CString,
	os::{fd::RawFd, unix::ffi::OsStrExt},
};

use uhyve_interface::{
	GuestPhysAddr, v2,
	v3::{parameters::*, util::RawResult},
};

use crate::{
	hypercall::{by_path::decode_guest_path, translate_last_errno, v3_errno},
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

fn host_stat_path(path: &std::path::Path, follow_symlinks: bool) -> Result<FileAttr, i32> {
	let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| EINVAL)?;
	let path = path.as_c_str().as_ptr();
	let mut st = unsafe { core::mem::zeroed() };
	let ret = unsafe {
		if follow_symlinks {
			libc::stat(path, &mut st)
		} else {
			libc::lstat(path, &mut st)
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

fn write_stat_attr(mem: &MmapMemory, attr_addr: GuestPhysAddr, attr: FileAttr) -> Result<(), i32> {
	let guest_attr = unsafe { mem.get_ref_mut(attr_addr) }.map_err(|_| {
		warn!("Unable to get host address for stat buffer");
		EFAULT
	})?;
	*guest_attr = attr;
	Ok(())
}

/// Writes the [`FileAttr`] of the guest path at `name` to the guest address `attr`.
///
/// `name` is the guest address of the null-terminated path. Returns the guest errno on failure.
fn stat(
	mem: &MmapMemory,
	name: GuestPhysAddr,
	follow_symlinks: bool,
	attr: GuestPhysAddr,
	file_map: &UhyveFileMap,
) -> Result<(), i32> {
	let guest_path = unsafe { decode_guest_path(mem, name) }?;
	let node = file_map
		.get_host_stat_node(guest_path, follow_symlinks)
		.ok_or_else(|| {
			debug!("stat {guest_path:?}: path not found in file map");
			ENOENT
		})?;
	let file_attr = match node {
		NodeStatRef::VirtualDirectory(_) => mapped_directory_attr(),
		NodeStatRef::VirtualFile(v) => virtual_file_attr(v),
		NodeStatRef::OnHost(host_path) => host_stat_path(&host_path, follow_symlinks)?,
	};
	write_stat_attr(mem, attr, file_attr)
}

/// Writes the [`FileAttr`] of the guest file descriptor `gfd` to the guest address `attr`.
///
/// Returns the guest errno on failure.
fn fstat(
	mem: &MmapMemory,
	gfd: GuestFd,
	attr: GuestPhysAddr,
	file_map: &UhyveFileMap,
) -> Result<(), i32> {
	// Stdio fds are not guest-managed; fstat would leak host metadata (st_dev, st_rdev, …).
	if gfd.0 < 0 || gfd.is_standard() {
		return Err(EBADF);
	}

	let file_attr = file_map
		.fdmap
		.get(gfd)
		.ok_or_else(|| {
			debug!("fstat on invalid fd {gfd}");
			EBADF
		})
		.and_then(fstat_attr_for_fd_data)?;
	write_stat_attr(mem, attr, file_attr)
}

fn stat_result_v2(result: Result<(), i32>) -> v2::parameters::StatResult {
	result.map_or_else(v2::parameters::StatResult::Error, |()| {
		v2::parameters::StatResult::Success
	})
}

/// Handler for a v2 [`FileStat`](v2::Hypercall::FileStat) hypercall.
///
/// Writes a [`v3::parameters::FileAttr`](FileAttr) to the guest, which is layout-compatible
/// with [`v2::parameters::FileAttr`], as only the padding was made explicit in v3.
pub(crate) fn stat_v2(
	mem: &MmapMemory,
	sysstat: &mut v2::parameters::StatParams,
	file_map: &UhyveFileMap,
) {
	let follow_symlinks = match sysstat.kind {
		v2::parameters::StatKind::Stat => true,
		v2::parameters::StatKind::LStat => false,
	};
	sysstat.ret = stat_result_v2(stat(
		mem,
		sysstat.name,
		follow_symlinks,
		sysstat.attr,
		file_map,
	));
}

/// Handler for a [`FileStat`](uhyve_interface::v3::Hypercall::FileStat) hypercall.
pub(crate) fn stat_v3(mem: &MmapMemory, sysstat: &mut StatParams, file_map: &UhyveFileMap) {
	let result = match sysstat.target.try_into() {
		Ok(StatTarget::Path(name)) => stat(mem, name, true, sysstat.attr, file_map),
		Ok(StatTarget::Link(name)) => stat(mem, name, false, sysstat.attr, file_map),
		Ok(StatTarget::Fd(fd)) => fstat(mem, GuestFd(fd), sysstat.attr, file_map),
		Err(_) => Err(EINVAL),
	};
	sysstat.ret = RawResult::encode(result.map_err(v3_errno)).unwrap();
}

/// Handler for a v2 [`FileFstat`](v2::Hypercall::FileFstat) hypercall.
///
/// See [`stat_v2`] for the [`FileAttr`] layout compatibility.
pub(crate) fn fstat_v2(
	mem: &MmapMemory,
	sysfstat: &mut v2::parameters::FstatParams,
	file_map: &UhyveFileMap,
) {
	sysfstat.ret = stat_result_v2(fstat(mem, GuestFd(sysfstat.fd), sysfstat.attr, file_map));
}
