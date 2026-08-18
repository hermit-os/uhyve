use std::{
	collections::BTreeMap,
	ffi::{CStr, CString},
	fs,
	os::unix::ffi::OsStrExt,
	path::Path,
	sync::Arc,
};

use uhyve_interface::{
	GuestPhysAddr,
	v2::parameters::{FileType, *},
};

use crate::{
	hypercall::translate_last_errno,
	isolation::{
		fd::{FdData, UhyveFileDescriptorLayer},
		filemap::{Directory, Node, NodeStatRef, UhyveFileMap, UhyveMapLeaf},
	},
	mem::MmapMemory,
};

/// Decodes a guest path given at address `path_addr` in `mem`.
///
/// # Safety
///
/// The calling convention of hypercalls ensures that the given address doesn't alias with anything mutable.
/// The return value is only valid for the duration of the hypercall.
pub(super) unsafe fn decode_guest_path(mem: &MmapMemory, path_addr: GuestPhysAddr) -> Option<&str> {
	let requested_path_ptr = mem.host_address(path_addr).unwrap() as *const i8;
	unsafe { CStr::from_ptr(requested_path_ptr) }.to_str().ok()
}

fn collect_dir_entries(dir: &Directory) -> BTreeMap<Box<str>, FileType> {
	fn host_file_type(path: &Path) -> FileType {
		match fs::symlink_metadata(path) {
			Ok(metadata) if metadata.is_dir() => FileType::Directory,
			Ok(metadata) if metadata.is_file() => FileType::RegularFile,
			Ok(metadata) if metadata.file_type().is_symlink() => FileType::SymbolicLink,
			Ok(_) => FileType::Unknown,
			Err(_) => FileType::RegularFile,
		}
	}

	dir.iter()
		.map(|(name, node)| {
			let file_type = match node {
				Node::Directory(_) => FileType::Directory,
				Node::Leaf(UhyveMapLeaf::Virtual(_)) => FileType::RegularFile,
				Node::Leaf(UhyveMapLeaf::OnHost(host_path)) => host_file_type(host_path),
			};
			(name.clone(), file_type)
		})
		.collect()
}

/// unlink deletes a name from the filesystem. This is used to handle `unlink` syscalls from the guest.
///
/// Note for when using Landlock: Unlinking files results in them being veiled. If a
/// file (that existed during initialization) called `log.txt` is unlinked, attempting to
/// open `log.txt` again will result in an error.
pub(super) fn unlink(mem: &MmapMemory, sysunlink: &mut UnlinkParams, file_map: &mut UhyveFileMap) {
	let guest_path = if let Some(guest_path) = unsafe { decode_guest_path(mem, sysunlink.name) } {
		guest_path
	} else {
		error!("The kernel requested to unlink() an non-UTF8 path: Rejecting...");
		sysunlink.ret = -EINVAL;
		return;
	};
	sysunlink.ret = match file_map.unlink(guest_path) {
		Ok(Some(host_path)) => {
			// We can safely unwrap here, as host_path.as_bytes will never contain internal \0 bytes
			// As host_path_c_string is a valid CString, this implementation is presumed to be safe.
			let host_path_c_string = CString::new(host_path.as_os_str().as_bytes()).unwrap();
			if unsafe { libc::unlink(host_path_c_string.as_c_str().as_ptr()) } < 0 {
				-translate_last_errno().unwrap_or(1)
			} else {
				0
			}
		}
		Ok(None) => {
			// Removed virtual entry
			0
		}
		Err(()) => {
			error!(
				"The kernel requested to unlink() an unknown path ({guest_path:?}): Rejecting..."
			);
			-ENOENT
		}
	};
}

/// Handles an open syscall by opening a file on the host.
pub(super) fn open(mem: &MmapMemory, sysopen: &mut OpenParams, file_map: &mut UhyveFileMap) {
	let guest_path = if let Some(guest_path) = unsafe { decode_guest_path(mem, sysopen.name) } {
		guest_path
	} else {
		error!("The kernel requested to open() an non-UTF8 path: Rejecting...");
		sysopen.ret = -EINVAL;
		return;
	};
	let mut flags = sysopen.flags & ALLOWED_OPEN_FLAGS;
	// See: https://lwn.net/Articles/926782/
	// See: https://github.com/hermit-os/kernel/commit/71bc629
	if (flags & (O_DIRECTORY | O_CREAT)) == (O_DIRECTORY | O_CREAT) {
		error!("An open() call used O_DIRECTORY and O_CREAT at the same time. Aborting...");
		sysopen.ret = -EINVAL;
		return;
	}

	/// Attempts to open `host_path_c_string` with `flags` and `mode`. Inserts the fd into `fdmap`
	/// on success and returns it, else returns the (negative) return value of the underlying `open` call.
	fn do_open(
		fdmap: &mut UhyveFileDescriptorLayer,
		host_path_c_string: CString,
		flags: i32,
		mode: i32,
	) -> i32 {
		let host_fd = unsafe { libc::open(host_path_c_string.as_c_str().as_ptr(), flags, mode) };
		if host_fd < 0 {
			let errno = translate_last_errno().unwrap_or(1);
			if host_fd != -1 {
				warn!("Unexpected return value {host_fd} from open(2)");
			}
			-errno
		} else if let Some(guest_fd) = fdmap.insert(FdData::Raw(host_fd)) {
			guest_fd.0
		} else {
			-ENOENT
		}
	}

	sysopen.ret = if let Some(host_node) = file_map.get_host_stat_node(guest_path, true) {
		debug!("{guest_path:#?} found in file map.");
		match host_node {
			NodeStatRef::OnHost(host_path) => {
				// We can safely unwrap here, as host_path.as_bytes will never contain internal \0 bytes
				// As host_path_c_string is a valid CString, this implementation is presumed to be safe.
				let host_path_c_string = CString::new(host_path.as_os_str().as_bytes()).unwrap();
				do_open(&mut file_map.fdmap, host_path_c_string, flags, sysopen.mode)
			}
			NodeStatRef::VirtualFile(data) => {
				if let Some(guest_fd) = file_map.fdmap.insert(FdData::Virtual {
					// The following only clones a pointer, and increases an `Arc` refcount.
					data: data.clone(),
					offset: 0,
				}) {
					guest_fd.0
				} else {
					-ENOENT
				}
			}
			NodeStatRef::VirtualDirectory(dir) => {
				if (flags & O_DIRECTORY) != 0 {
					if let Some(guest_fd) = file_map.fdmap.insert(FdData::MappedDirectory {
						entries: Arc::new(collect_dir_entries(dir)),
						offset: 0,
					}) {
						guest_fd.0
					} else {
						-ENOENT
					}
				} else {
					debug!("{guest_path:#?}: Tried to open directory as file...");
					-EINVAL
				}
			}
		}
	} else {
		debug!("{guest_path:#?} not found in file map.");
		if (flags & O_CREAT) == O_CREAT {
			debug!("Attempting to open a temp file for {guest_path:#?}...");
			// Existing files that already exist should be in the file map, not here.
			// If a supposed attacker can predict where we open a file and its filename,
			// this contigency, together with O_CREAT, will cause the write to fail.
			flags |= O_EXCL;
			#[cfg(target_os = "linux")]
			{
				flags |= file_map.get_io_mode_flags();
			}

			match file_map.create_temporary_file(guest_path) {
				Some(host_path_c_string) => {
					do_open(&mut file_map.fdmap, host_path_c_string, flags, sysopen.mode)
				}
				None => {
					debug!("Returning -EINVAL for {guest_path:#?}");
					-EINVAL
				}
			}
		} else {
			debug!("Returning -ENOENT for {guest_path:#?}");
			-ENOENT
		}
	}
}

/// Handles a mkdir hypercall by creating a directory on the host.
///
/// The guest path is resolved through the file map, so directories can only be created
/// within mapped host directories. Unmapped paths are redirected into the sandboxed
/// temporary directory. Virtual paths are rejected.
pub(super) fn mkdir(mem: &MmapMemory, sysmkdir: &mut MkdirParams, file_map: &mut UhyveFileMap) {
	let host_path_c_res = match unsafe { decode_guest_path(mem, sysmkdir.name) } {
		None => {
			error!("The kernel requested to mkdir() a non-UTF8 path: Rejecting...");
			Err(EINVAL)
		}
		Some(guest_path) => {
			match file_map.get_host_path(guest_path, false) {
				Some(UhyveMapLeaf::OnHost(host_path)) => {
					// We can safely unwrap, as a resolved host path never contains internal NUL bytes.
					Ok(CString::new(host_path.as_os_str().as_bytes()).unwrap())
				}
				Some(UhyveMapLeaf::Virtual(_)) => {
					debug!(
						"mkdir {guest_path:?}: target is a read-only virtual file, rejecting..."
					);
					Err(EROFS)
				}
				None => {
					debug!("mkdir {guest_path:?}: not mapped, creating a temporary directory...");
					file_map
						.create_temporary_directory(guest_path)
						.ok_or(EINVAL)
				}
			}
		}
	};

	sysmkdir.ret = match host_path_c_res {
		Err(errno) => -errno,
		// Attempts `mkdir(host_path)` on the host, mapping the outcome to guest errno value fit for [`MkdirParams::ret`].
		Ok(host_path_c) => {
			if unsafe { libc::mkdir(host_path_c.as_ptr(), sysmkdir.mode.into()) } < 0 {
				-translate_last_errno().unwrap_or(EIO)
			} else {
				0
			}
		}
	};
}
