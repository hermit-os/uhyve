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
	v3::{self, util::RawResult},
};

use crate::{
	hypercall::{translate_last_errno, v3_errno},
	isolation::{
		fd::{FdData, GuestFd, UhyveFileDescriptorLayer},
		filemap::{Directory, Node, NodeStatRef, UhyveFileMap, UhyveMapLeaf},
	},
	mem::MmapMemory,
};

/// Maximum length of a guest path in bytes, including the terminating NUL (the host's `PATH_MAX`).
const MAX_GUEST_PATH_LEN: u64 = libc::PATH_MAX as u64;

/// Decodes the null-terminated UTF-8 guest path at address `path_addr` in `mem`.
///
/// Returns the guest errno on failure: `EFAULT` if the path is not within guest memory,
/// `ENAMETOOLONG` if it is longer than [`MAX_GUEST_PATH_LEN`] and `EINVAL` if it is not UTF-8.
///
/// # Safety
///
/// The calling convention of hypercalls ensures that the given address doesn't alias with anything mutable.
/// The return value is only valid for the duration of the hypercall.
pub(super) unsafe fn decode_guest_path(
	mem: &MmapMemory,
	path_addr: GuestPhysAddr,
) -> Result<&str, i32> {
	let mem_range = mem.address_range_u64();
	if !mem_range.contains(&path_addr.as_u64()) {
		warn!("Guest path at {path_addr:?} is outside of guest memory");
		return Err(EFAULT);
	}
	let len = (mem_range.end - path_addr.as_u64()).min(MAX_GUEST_PATH_LEN);
	let bytes = unsafe { mem.slice_at::<u8>(path_addr, len as usize) }.map_err(|_| EFAULT)?;
	let path = CStr::from_bytes_until_nul(bytes).map_err(|_| {
		warn!("Guest path at {path_addr:?} is not null-terminated within {len} bytes");
		if len == MAX_GUEST_PATH_LEN {
			hermit_abi::errno::ENAMETOOLONG
		} else {
			EFAULT
		}
	})?;
	path.to_str().map_err(|_| {
		warn!("Guest path {path:?} is not valid UTF-8");
		EINVAL
	})
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
///
/// `name` is the guest address of the null-terminated path. Returns the guest errno on failure.
fn unlink(mem: &MmapMemory, name: GuestPhysAddr, file_map: &mut UhyveFileMap) -> Result<(), i32> {
	let guest_path = unsafe { decode_guest_path(mem, name) }?;
	match file_map.unlink(guest_path) {
		Ok(Some(host_path)) => {
			// We can safely unwrap here, as host_path.as_bytes will never contain internal \0 bytes
			// As host_path_c_string is a valid CString, this implementation is presumed to be safe.
			let host_path_c_string = CString::new(host_path.as_os_str().as_bytes()).unwrap();
			if unsafe { libc::unlink(host_path_c_string.as_c_str().as_ptr()) } < 0 {
				Err(translate_last_errno().unwrap_or(1))
			} else {
				Ok(())
			}
		}
		Ok(None) => {
			// Removed virtual entry
			Ok(())
		}
		Err(()) => {
			error!(
				"The kernel requested to unlink() an unknown path ({guest_path:?}): Rejecting..."
			);
			Err(ENOENT)
		}
	}
}

/// Handler for a v1/v2 [`FileUnlink`](uhyve_interface::v2::Hypercall::FileUnlink) hypercall.
pub(super) fn unlink_v2(
	mem: &MmapMemory,
	sysunlink: &mut UnlinkParams,
	file_map: &mut UhyveFileMap,
) {
	sysunlink.ret = unlink(mem, sysunlink.name, file_map).map_or_else(|errno| -errno, |()| 0);
}

/// Handler for a [`FileUnlink`](v3::Hypercall::FileUnlink) hypercall.
pub(super) fn unlink_v3(
	mem: &MmapMemory,
	sysunlink: &mut v3::parameters::UnlinkParams,
	file_map: &mut UhyveFileMap,
) {
	sysunlink.ret =
		RawResult::encode(unlink(mem, sysunlink.path, file_map).map_err(v3_errno)).unwrap();
}

/// Converts Hermit open flags (restricted to [`ALLOWED_OPEN_FLAGS`]) to the host's `libc` values.
fn guest_to_host_open_flags(flags: i32) -> i32 {
	let mut host_flags = 0;
	for (guest, host) in [
		(O_WRONLY, libc::O_WRONLY),
		(O_RDWR, libc::O_RDWR),
		(O_CREAT, libc::O_CREAT),
		(O_EXCL, libc::O_EXCL),
		(O_TRUNC, libc::O_TRUNC),
		(O_APPEND, libc::O_APPEND),
		(O_DIRECTORY, libc::O_DIRECTORY),
	] {
		if flags & guest != 0 {
			host_flags |= host;
		}
	}
	host_flags
}

/// Opens the guest path at `name` on the host and returns the new guest file descriptor.
///
/// `name` is the guest address of the null-terminated path. Returns the guest errno on failure.
fn open(
	mem: &MmapMemory,
	name: GuestPhysAddr,
	flags: i32,
	mode: u32,
	file_map: &mut UhyveFileMap,
) -> Result<GuestFd, i32> {
	let guest_path = unsafe { decode_guest_path(mem, name) }?;
	let flags = flags & ALLOWED_OPEN_FLAGS;
	// See: https://lwn.net/Articles/926782/
	// See: https://github.com/hermit-os/kernel/commit/71bc629
	if (flags & (O_DIRECTORY | O_CREAT)) == (O_DIRECTORY | O_CREAT) {
		error!("An open() call used O_DIRECTORY and O_CREAT at the same time. Aborting...");
		return Err(EINVAL);
	}

	/// Attempts to open `host_path_c_string` with `flags` and `mode`. Inserts the fd into `fdmap`
	/// on success and returns it, else returns the errno of the underlying `open` call.
	fn do_open(
		fdmap: &mut UhyveFileDescriptorLayer,
		host_path_c_string: CString,
		flags: i32,
		mode: u32,
	) -> Result<GuestFd, i32> {
		let host_fd = unsafe { libc::open(host_path_c_string.as_c_str().as_ptr(), flags, mode) };
		if host_fd < 0 {
			let errno = translate_last_errno().unwrap_or(1);
			if host_fd != -1 {
				warn!("Unexpected return value {host_fd} from open(2)");
			}
			Err(errno)
		} else {
			fdmap.insert(FdData::Raw(host_fd)).ok_or(ENOENT)
		}
	}

	if let Some(host_node) = file_map.get_host_stat_node(guest_path, true) {
		debug!("{guest_path:#?} found in file map.");
		match host_node {
			NodeStatRef::OnHost(host_path) => {
				// We can safely unwrap here, as host_path.as_bytes will never contain internal \0 bytes
				// As host_path_c_string is a valid CString, this implementation is presumed to be safe.
				let host_path_c_string = CString::new(host_path.as_os_str().as_bytes()).unwrap();
				do_open(
					&mut file_map.fdmap,
					host_path_c_string,
					guest_to_host_open_flags(flags),
					mode,
				)
			}
			NodeStatRef::VirtualFile(data) => file_map
				.fdmap
				.insert(FdData::Virtual {
					// The following only clones a pointer, and increases an `Arc` refcount.
					data: data.clone(),
					offset: 0,
				})
				.ok_or(ENOENT),
			NodeStatRef::VirtualDirectory(dir) => {
				if (flags & O_DIRECTORY) != 0 {
					file_map
						.fdmap
						.insert(FdData::MappedDirectory {
							entries: Arc::new(collect_dir_entries(dir)),
							offset: 0,
						})
						.ok_or(ENOENT)
				} else {
					debug!("{guest_path:#?}: Tried to open directory as file...");
					Err(EINVAL)
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
			#[allow(unused_mut)]
			let mut host_flags = guest_to_host_open_flags(flags | O_EXCL);
			#[cfg(target_os = "linux")]
			{
				host_flags |= file_map.get_io_mode_flags();
			}

			match file_map.create_temporary_file(guest_path) {
				Some(host_path_c_string) => {
					do_open(&mut file_map.fdmap, host_path_c_string, host_flags, mode)
				}
				None => {
					debug!("Returning -EINVAL for {guest_path:#?}");
					Err(EINVAL)
				}
			}
		} else {
			debug!("Returning -ENOENT for {guest_path:#?}");
			Err(ENOENT)
		}
	}
}

/// Handler for a v1/v2 [`FileOpen`](uhyve_interface::v2::Hypercall::FileOpen) hypercall.
pub(super) fn open_v2(mem: &MmapMemory, sysopen: &mut OpenParams, file_map: &mut UhyveFileMap) {
	sysopen.ret = open(
		mem,
		sysopen.name,
		sysopen.flags,
		sysopen.mode.try_into().unwrap(),
		file_map,
	)
	.map_or_else(|errno| -errno, |gfd| gfd.0);
}

/// Handler for a [`FileOpen`](v3::Hypercall::FileOpen) hypercall.
pub(super) fn open_v3(
	mem: &MmapMemory,
	sysopen: &mut v3::parameters::OpenParams,
	file_map: &mut UhyveFileMap,
) {
	let result = open(mem, sysopen.path, sysopen.flags, sysopen.mode, file_map);
	sysopen.ret = RawResult::encode(result.map(|gfd| gfd.0).map_err(v3_errno)).unwrap();
}

/// Attempts `mkdir(host_path)` on the host, mapping the outcome to a [`MkdirResult`].
fn host_mkdir(host_path_c: &CString) -> MkdirResult {
	// SAFETY: `host_path_c` is a valid, null-terminated C string.
	if unsafe { libc::mkdir(host_path_c.as_ptr(), 0o777) } < 0 {
		MkdirResult::Error(translate_last_errno().unwrap_or(EIO))
	} else {
		MkdirResult::Success
	}
}

/// Handles a mkdir hypercall by creating a directory on the host.
///
/// The guest path is resolved through the file map, so directories can only be created
/// within mapped host directories. Unmapped paths are redirected into the sandboxed
/// temporary directory. Virtual paths are rejected.
pub(super) fn mkdir(mem: &MmapMemory, sysmkdir: &mut MkdirParams, file_map: &mut UhyveFileMap) {
	let guest_path = match unsafe { decode_guest_path(mem, sysmkdir.path) } {
		Ok(guest_path) => guest_path,
		Err(errno) => {
			sysmkdir.ret = MkdirResult::Error(errno);
			return;
		}
	};

	sysmkdir.ret = match file_map.get_host_path(guest_path, false) {
		Some(UhyveMapLeaf::OnHost(host_path)) => {
			// We can safely unwrap, as a resolved host path never contains internal NUL bytes.
			let host_path_c = CString::new(host_path.as_os_str().as_bytes()).unwrap();
			host_mkdir(&host_path_c)
		}
		Some(UhyveMapLeaf::Virtual(_)) => {
			debug!("mkdir {guest_path:?}: target is a read-only virtual file, rejecting...");
			MkdirResult::Error(EROFS)
		}
		None => {
			debug!("mkdir {guest_path:?}: not mapped, creating a temporary directory...");
			match file_map.create_temporary_directory(guest_path) {
				Some(host_path_c) => host_mkdir(&host_path_c),
				None => MkdirResult::Error(EINVAL),
			}
		}
	};
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_decode_guest_path() {
		const SIZE: usize = 0x10000;
		const BASE: u64 = 0x10_0000;

		fn decode_at(mem: &MmapMemory, offset: u64) -> Result<&str, i32> {
			unsafe { decode_guest_path(mem, GuestPhysAddr::new(BASE + offset)) }
		}

		let mem = MmapMemory::new(SIZE, GuestPhysAddr::new(BASE), false, false);
		let mem_slice = unsafe { mem.as_slice_mut() };

		// valid path
		mem_slice[..10].copy_from_slice(b"/tmp/file\0");
		assert_eq!(decode_at(&mem, 0), Ok("/tmp/file"));

		// invalid UTF-8
		mem_slice[0x100..0x103].copy_from_slice(b"\xff\xfe\0");
		assert_eq!(decode_at(&mem, 0x100), Err(EINVAL));

		// Long but valid "path"
		let max_len = MAX_GUEST_PATH_LEN as usize;
		let longest = "a".repeat(max_len - 1);
		mem_slice[0x1000..0x1000 + max_len - 1].copy_from_slice(longest.as_bytes());
		assert_eq!(decode_at(&mem, 0x1000), Ok(longest.as_str()));

		// Path too long
		mem_slice[0x3000..0x3000 + max_len].fill(b'a');
		assert_eq!(
			decode_at(&mem, 0x3000),
			Err(hermit_abi::errno::ENAMETOOLONG)
		);

		// Untermintated bytes at the end of the "memory"
		mem_slice[SIZE - 10..].fill(b'a');
		assert_eq!(decode_at(&mem, SIZE as u64 - 10), Err(EFAULT));

		// NUL in the last byte of the "memory"
		mem_slice[SIZE - 1] = 0;
		assert_eq!(decode_at(&mem, SIZE as u64 - 10), Ok("aaaaaaaaa"));

		assert_eq!(decode_at(&mem, SIZE as u64), Err(EFAULT));
		assert_eq!(
			unsafe { decode_guest_path(&mem, GuestPhysAddr::new(BASE - 1)) },
			Err(EFAULT)
		);
	}
}
