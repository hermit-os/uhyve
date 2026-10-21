use core::{
	mem::{align_of, offset_of},
	ptr,
};
use std::collections::BTreeMap;

use align_address::Align;
use uhyve_interface::v3::parameters::*;

use crate::{
	hypercall::translate_last_errno_nonzero,
	isolation::{
		fd::{FdData, GuestFd},
		filemap::UhyveFileMap,
	},
	mem::MmapMemory,
	os::fs::raw_getdents,
};

fn dirent_reclen(name_len: usize) -> usize {
	let dirent_len = offset_of!(Dirent64, d_name) + name_len + 1;
	dirent_len.align_up(align_of::<Dirent64>())
}

/// # Safety
///
/// This wraps [`mem::slice_at_mut`]. Refer to the documentation of [`mem::slice_at_mut`] for more information.
#[expect(clippy::mut_from_ref)]
unsafe fn getdents_guest_buffer<'a>(
	mem: &'a MmapMemory,
	sysgetdents: &GetdentParams,
) -> Result<&'a mut [u8], GetdentResult> {
	unsafe { mem.slice_at_mut(sysgetdents.buf, sysgetdents.len as usize) }.map_err(|_| {
		warn!("Unable to get host address for getdents buffer");
		GetdentResult::Errno(NonZero::new(EFAULT as u32).unwrap())
	})
}

fn getdents_errno() -> GetdentResult {
	GetdentResult::Errno(
		translate_last_errno_nonzero().unwrap_or(NonZero::new(EIO as u32).unwrap()),
	)
}

/// Reads directory entries from a mapped (non-host) directory into the guest buffer.
fn getdents_mapped(
	mem: &MmapMemory,
	sysgetdents: &mut GetdentParams,
	entries: &BTreeMap<Box<str>, FileType>,
	offset: &mut u64,
) -> GetdentResult {
	let mut skip = *offset as usize;
	let mut iter = entries.iter();

	// Advance past already-read bytes.
	let first = loop {
		let Some(entry) = iter.next() else {
			return GetdentResult::EndOfDirectory;
		};
		let reclen = dirent_reclen(entry.0.len());
		if skip >= reclen {
			skip -= reclen;
		} else if skip > 0 {
			return GetdentResult::Errno(NonZero::new(EINVAL as u32).unwrap());
		} else {
			break entry;
		}
	};

	// SAFETY: if the guest provides proper parameters, we don't have multiple aliasing. If not, the guest breaks, but Uhyve is fine.
	let buf = match unsafe { getdents_guest_buffer(mem, sysgetdents) } {
		Ok(buf) => buf,
		Err(ret) => return ret,
	};

	let mut buf_offset = 0usize;
	for (name, file_type) in std::iter::once(first).chain(&mut iter) {
		let namelen = name.len();
		let next_dirent = buf_offset + dirent_reclen(namelen);

		if next_dirent > buf.len() {
			break;
		}

		// SAFETY: `buf` is guest-owned for the duration of the hypercall and does not overlap `name`.
		unsafe {
			let target_dirent = buf[buf_offset..].as_mut_ptr().cast::<Dirent64>();
			target_dirent.write(Dirent64 {
				d_ino: 1,
				d_off: 0,
				d_reclen: dirent_reclen(namelen).try_into().unwrap_or(u16::MAX),
				d_type: *file_type,
				d_name: core::marker::PhantomData,
			});
			let nameptr = ptr::from_mut(&mut (*target_dirent).d_name).cast::<u8>();
			ptr::copy_nonoverlapping(name.as_ptr(), nameptr, namelen);
			nameptr.add(namelen).write(0);
		}

		buf_offset = next_dirent;
	}

	if buf_offset == 0 {
		GetdentResult::Errno(NonZero::new(EINVAL as u32).unwrap())
	} else {
		*offset += buf_offset as u64;
		GetdentResult::Success(NonZero::new(buf_offset as u64).unwrap())
	}
}

/// Handles a getdents hypercall by proxying `getdents64(2)` on the mapped host directory fd.
pub(crate) fn getdents(
	mem: &MmapMemory,
	sysgetdents: &mut GetdentParams,
	file_map: &mut UhyveFileMap,
) {
	let gfd = GuestFd(sysgetdents.fd);

	sysgetdents.ret = match file_map.fdmap.get_mut(gfd) {
		Some(FdData::Raw(host_fd)) => {
			// SAFETY: if the guest provides proper parameters, we don't have multiple aliasing. If not, the guest breaks, but Uhyve is fine.
			let buf = match unsafe { getdents_guest_buffer(mem, sysgetdents) } {
				Ok(buf) => buf,
				Err(ret) => {
					sysgetdents.ret = ret.try_as_num().unwrap();
					return;
				}
			};

			let bytes_read = unsafe { raw_getdents(*host_fd, buf) };

			if bytes_read < 0 {
				getdents_errno()
			} else if bytes_read == 0 {
				GetdentResult::EndOfDirectory
			} else {
				GetdentResult::Success(NonZero::new(bytes_read as u64).unwrap())
			}
		}
		Some(FdData::MappedDirectory { entries, offset }) => {
			getdents_mapped(mem, sysgetdents, entries, offset)
		}
		_ => {
			warn!(
				"getdents on invalid fd {gfd} (param.fd={}, buf={:#x}, len={}): {:?}",
				sysgetdents.fd,
				sysgetdents.buf.as_u64(),
				sysgetdents.len,
				file_map.fdmap,
			);
			GetdentResult::Errno(NonZero::new(EBADF as u32).unwrap())
		}
	}
	.try_as_num()
	.unwrap()
}
