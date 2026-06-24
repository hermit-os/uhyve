use std::{ffi::CString, os::unix::ffi::OsStrExt};

use uhyve_interface::v2::parameters::*;

use crate::{
	hypercall::{decode_guest_path, translate_last_errno},
	isolation::filemap::{UhyveFileMap, UhyveMapLeaf},
	mem::MmapMemory,
};

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
pub(crate) fn mkdir(mem: &MmapMemory, sysmkdir: &mut MkdirParams, file_map: &mut UhyveFileMap) {
	let Some(guest_path) = (unsafe { decode_guest_path(mem, sysmkdir.path) }) else {
		error!("The kernel requested to mkdir() a non-UTF8 path: Rejecting...");
		sysmkdir.ret = MkdirResult::Error(EINVAL);
		return;
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
