use std::{ffi::CString, os::unix::ffi::OsStrExt};

use uhyve_interface::v2::parameters::*;

use crate::{
	hypercall::{decode_guest_path, translate_last_errno},
	isolation::filemap::{UhyveFileMap, UhyveMapLeaf},
	mem::MmapMemory,
};

/// Handles a mkdir hypercall by creating a directory on the host.
///
/// The guest path is resolved through the file map, so directories can only be created
/// within mapped host directories. Unmapped paths are redirected into the sandboxed
/// temporary directory. Virtual paths are rejected.
pub(crate) fn mkdir(mem: &MmapMemory, sysmkdir: &mut MkdirParams, file_map: &mut UhyveFileMap) {
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
