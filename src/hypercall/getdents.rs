use core::{
	mem::{align_of, offset_of},
	num::NonZero,
	ptr,
};
use std::collections::BTreeMap;

use align_address::Align;
use uhyve_interface::{
	GuestPhysAddr, v2,
	v3::{parameters::*, util::RawResult},
};

use crate::{
	hypercall::{translate_last_errno, v3_errno},
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
/// This wraps [`MmapMemory::slice_at_mut`]. Refer to its documentation for more information.
#[expect(clippy::mut_from_ref)]
unsafe fn getdents_guest_buffer(
	mem: &MmapMemory,
	buf: GuestPhysAddr,
	len: u64,
) -> Result<&mut [u8], i32> {
	unsafe { mem.slice_at_mut(buf, len as usize) }.map_err(|_| {
		warn!("Unable to get host address for getdents buffer");
		EFAULT
	})
}

/// Reads directory entries from a mapped (non-host) directory into the guest buffer.
fn getdents_mapped(
	mem: &MmapMemory,
	buf: GuestPhysAddr,
	len: u64,
	entries: &BTreeMap<Box<str>, FileType>,
	offset: &mut u64,
) -> Result<u64, i32> {
	let mut skip = *offset as usize;
	let mut iter = entries.iter();

	// Advance past already-read bytes.
	let first = loop {
		let Some(entry) = iter.next() else {
			return Ok(0);
		};
		let reclen = dirent_reclen(entry.0.len());
		if skip >= reclen {
			skip -= reclen;
		} else if skip > 0 {
			return Err(EINVAL);
		} else {
			break entry;
		}
	};

	// SAFETY: if the guest provides proper parameters, we don't have multiple aliasing. If not, the guest breaks, but Uhyve is fine.
	let buf = unsafe { getdents_guest_buffer(mem, buf, len) }?;

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
		Err(EINVAL)
	} else {
		*offset += buf_offset as u64;
		Ok(buf_offset as u64)
	}
}

/// Reads the directory entries of the guest file descriptor `gfd` into the guest buffer at `buf`
/// of `len` bytes, similar to `getdents64(2)`.
///
/// Returns the number of bytes written, `0` at the end of the directory, or the guest errno on
/// failure.
fn getdents(
	mem: &MmapMemory,
	gfd: GuestFd,
	buf: GuestPhysAddr,
	len: u64,
	file_map: &mut UhyveFileMap,
) -> Result<u64, i32> {
	match file_map.fdmap.get_mut(gfd) {
		Some(FdData::Raw(host_fd)) => {
			// SAFETY: if the guest provides proper parameters, we don't have multiple aliasing. If not, the guest breaks, but Uhyve is fine.
			let buf = unsafe { getdents_guest_buffer(mem, buf, len) }?;

			let bytes_read = unsafe { raw_getdents(*host_fd, buf) };
			if bytes_read < 0 {
				Err(translate_last_errno().unwrap_or(EIO))
			} else {
				Ok(bytes_read as u64)
			}
		}
		Some(FdData::MappedDirectory { entries, offset }) => {
			getdents_mapped(mem, buf, len, entries, offset)
		}
		_ => {
			warn!(
				"getdents on invalid fd {gfd} (buf={:#x}, len={len}): {:?}",
				buf.as_u64(),
				file_map.fdmap,
			);
			Err(EBADF)
		}
	}
}

/// Handler for a v2 [`Getdents`](v2::Hypercall::Getdents) hypercall.
pub(crate) fn getdents_v2(
	mem: &MmapMemory,
	sysgetdents: &mut v2::parameters::GetdentParams,
	file_map: &mut UhyveFileMap,
) {
	use v2::parameters::GetdentResult;
	let result = getdents(
		mem,
		GuestFd(sysgetdents.fd),
		sysgetdents.buf,
		sysgetdents.len,
		file_map,
	);
	sysgetdents.ret = match result {
		Ok(0) => GetdentResult::EndOfDirectory,
		Ok(bytes) => GetdentResult::Success(bytes),
		Err(errno) => GetdentResult::Error(errno),
	};
}

/// Handler for a [`Getdents`](uhyve_interface::v3::Hypercall::Getdents) hypercall.
pub(crate) fn getdents_v3(
	mem: &MmapMemory,
	sysgetdents: &mut GetdentParams,
	file_map: &mut UhyveFileMap,
) {
	let result = getdents(
		mem,
		GuestFd(sysgetdents.fd),
		sysgetdents.buf.addr,
		sysgetdents.buf.len,
		file_map,
	);
	let ret = match result {
		Ok(bytes) => {
			NonZero::new(bytes).map_or(GetdentResult::EndOfDirectory, GetdentResult::Success)
		}
		Err(errno) => GetdentResult::Errno(v3_errno(errno)),
	};
	sysgetdents.ret = RawResult::encode(ret).unwrap();
}
