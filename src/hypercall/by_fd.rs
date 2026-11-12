use core::{cmp, mem::MaybeUninit};

use uhyve_interface::{
	GuestPhysAddr, v1,
	v2::parameters::*,
	v3::{
		self,
		parameters::{FsyncParams, LseekWhence},
		util::RawResult,
	},
};

use crate::{
	hypercall::{translate_last_errno, v3_errno},
	isolation::{
		fd::{FdData, GuestFd},
		filemap::UhyveFileMap,
	},
	mem::MmapMemory,
	net::NetworkBackend,
	virt_to_phys,
	vm::VmPeripherals,
};

/// Closes the guest file descriptor `gfd` and the underlying host file. Returns the guest errno
/// on failure.
fn close(gfd: GuestFd, file_map: &mut UhyveFileMap) -> Result<(), i32> {
	debug!(
		"Guest tries to close fd {gfd} from fdmap {:?}",
		file_map.fdmap
	);
	if gfd.is_standard() {
		// ignore stdio closures
		warn!("Guest tried to close stdio fd: {gfd}");
		return Ok(());
	}
	match file_map.fdmap.remove(gfd) {
		Some(FdData::Raw(fd)) if unsafe { libc::close(fd) } < 0 => {
			Err(translate_last_errno().unwrap_or(1))
		}
		Some(_) => Ok(()),
		None => {
			warn!("Guest tried to close unknown fd: {gfd}");
			Err(EBADF)
		}
	}
}

/// Handler for a v1/v2 [`FileClose`](uhyve_interface::v2::Hypercall::FileClose) hypercall.
pub(super) fn close_v2(sysclose: &mut CloseParams, file_map: &mut UhyveFileMap) {
	sysclose.ret = close(GuestFd(sysclose.fd), file_map).map_or_else(|errno| -errno, |()| 0);
}

/// Handler for a [`FileClose`](v3::Hypercall::FileClose) hypercall.
pub(super) fn close_v3(sysclose: &mut v3::parameters::CloseParams, file_map: &mut UhyveFileMap) {
	sysclose.ret =
		RawResult::encode(close(GuestFd(sysclose.fd), file_map).map_err(v3_errno)).unwrap();
}

/// Reads up to `len` bytes from the guest file descriptor `gfd` into the guest buffer at `buf`.
/// Returns the number of bytes read or the guest errno on failure.
fn read(
	mem: &MmapMemory,
	gfd: GuestFd,
	buf: GuestPhysAddr,
	len: u64,
	file_map: &mut UhyveFileMap,
) -> Result<u64, i32> {
	let fdata = file_map.fdmap.get_mut(gfd).ok_or(EBADF)?;
	let len = len.try_into().map_err(|_| EINVAL)?;
	// Bound the destination to guest memory, as write/getdents/serialwrite do.
	let buf = unsafe { mem.slice_at_mut::<MaybeUninit<u8>>(buf, len) }.map_err(|_| {
		warn!("read buffer is not within guest memory");
		EFAULT
	})?;
	read_internal(fdata, buf)
}

fn read_internal(fdata: &mut FdData, out_bytes: &mut [MaybeUninit<u8>]) -> Result<u64, i32> {
	match fdata {
		FdData::Raw(rfd) => {
			let bytes_read = unsafe {
				libc::read(
					*rfd,
					out_bytes.as_mut_ptr().cast::<libc::c_void>(),
					out_bytes.len(),
				)
			};
			if bytes_read < 0 {
				Err(translate_last_errno().unwrap_or(1))
			} else {
				Ok(bytes_read as u64)
			}
		}
		FdData::Virtual { data, offset } => {
			let remaining = {
				let pos = cmp::min(*offset, data.len() as u64);
				&data[pos as usize..]
			};
			let amt = out_bytes
				.iter_mut()
				.zip(remaining.iter())
				.map(|(o, i)| {
					o.write(*i);
				})
				.count();
			*offset += amt as u64;
			Ok(amt as u64)
		}
		FdData::MappedDirectory { .. } => Err(EBADF),
	}
}

/// Handler for a v1 [`FileRead`](v1::Hypercall::FileRead) hypercall (for which a guest-provided
/// guest virtual address must be converted to a guest physical address by the host).
pub(super) fn read_v1(
	mem: &MmapMemory,
	sysread: &mut v1::parameters::ReadParams,
	root_pt: GuestPhysAddr,
	file_map: &mut UhyveFileMap,
) {
	sysread.ret = if let Ok(guest_phys_addr) = virt_to_phys(sysread.buf, mem, root_pt) {
		match read(
			mem,
			GuestFd(sysread.fd),
			guest_phys_addr,
			sysread.len as u64,
			file_map,
		) {
			Ok(count) => count
				.try_into()
				.unwrap_or_else(|ret| panic!("Unable to fit return value {} in read_v1.", ret)),
			Err(errno) => -errno as isize,
		}
	} else {
		warn!("Unable to convert guest virtual address into guest physical address");
		-EFAULT as isize
	}
}

/// Handler for a v2 [`FileRead`](uhyve_interface::v2::Hypercall::FileRead) hypercall.
pub(super) fn read_v2(mem: &MmapMemory, sysread: &mut ReadParams, file_map: &mut UhyveFileMap) {
	sysread.ret = match read(mem, GuestFd(sysread.fd), sysread.buf, sysread.len, file_map) {
		Ok(count) => count as i64,
		Err(errno) => -errno as i64,
	};
}

/// Handler for a [`FileRead`](v3::Hypercall::FileRead) hypercall.
pub(super) fn read_v3(
	mem: &MmapMemory,
	sysread: &mut v3::parameters::ReadParams,
	file_map: &mut UhyveFileMap,
) {
	let result = read(
		mem,
		GuestFd(sysread.fd),
		sysread.buf.addr,
		sysread.buf.len,
		file_map,
	);
	sysread.ret = RawResult::encode(result.map_err(v3_errno)).unwrap();
}

/// Writes `len` bytes from the guest buffer at `buf` to the guest file descriptor `gfd`.
/// Returns the number of bytes written or the guest errno on failure.
fn write<N: NetworkBackend>(
	peripherals: &VmPeripherals<N>,
	gfd: GuestFd,
	buf: GuestPhysAddr,
	len: u64,
	file_map: &mut UhyveFileMap,
) -> Result<u64, i32> {
	let mut bytes = unsafe {
		peripherals
			.mem
			.slice_at(buf, len.try_into().map_err(|_| EINVAL)?)
			.map_err(|e| {
				warn!("invalid write buffer: {e:?}");
				EFAULT
			})?
	};

	match file_map.fdmap.get_mut(gfd) {
		None => {
			warn!("Guest tried to write to unknown fd: {gfd}");
			Err(EBADF)
		}

		Some(FdData::Virtual { .. }) | Some(FdData::MappedDirectory { .. }) => {
			warn!("Unable to write to virtual file {gfd}");
			Err(EROFS)
		}

		// Handles to standard outputs differs to that of e.g. files.
		Some(FdData::Raw(1 | 2)) => {
			let len = bytes.len() as u64;
			peripherals.serial.output(bytes).map_err(|e| {
				warn!("Unable to write to serial output: {e}");
				EIO
			})?;
			Ok(len)
		}

		Some(FdData::Raw(r)) => {
			let mut written = 0;
			while !bytes.is_empty() {
				let step = unsafe {
					libc::write(
						*r,
						&bytes[0] as *const u8 as *const libc::c_void,
						bytes.len(),
					)
				};
				if step < 0 {
					return Err(translate_last_errno().unwrap_or(1));
				}
				written += step as u64;
				bytes = &bytes[step as usize..];
			}
			Ok(written)
		}
	}
}

/// Handler for a v1 [`FileWrite`](v1::Hypercall::FileWrite) hypercall (for which a
/// guest-provided guest virtual address must be converted to a guest physical address by the
/// host). Returns the guest errno on failure.
pub(super) fn write_v1<N: NetworkBackend>(
	peripherals: &VmPeripherals<N>,
	syswrite: &v1::parameters::WriteParams,
	root_pt: GuestPhysAddr,
	file_map: &mut UhyveFileMap,
) -> Result<(), i32> {
	let guest_phys_addr = virt_to_phys(syswrite.buf, &peripherals.mem, root_pt).map_err(|e| {
		warn!("invalid syswrite buffer: {e:?}");
		EFAULT
	})?;
	write(
		peripherals,
		GuestFd(syswrite.fd),
		guest_phys_addr,
		syswrite.len as u64,
		file_map,
	)
	.map(|_| ())
}

/// Handler for a v2 [`FileWrite`](uhyve_interface::v2::Hypercall::FileWrite) hypercall. Returns the guest errno
/// on failure.
pub(super) fn write_v2<N: NetworkBackend>(
	peripherals: &VmPeripherals<N>,
	syswrite: &mut WriteParams,
	file_map: &mut UhyveFileMap,
) -> Result<(), i32> {
	let result = write(
		peripherals,
		GuestFd(syswrite.fd),
		syswrite.buf,
		syswrite.len,
		file_map,
	);
	syswrite.ret = match result {
		Ok(count) => count as i64,
		Err(errno) => -errno as i64,
	};
	result.map(|_| ())
}

/// Handler for a [`FileWrite`](v3::Hypercall::FileWrite) hypercall.
pub(super) fn write_v3<N: NetworkBackend>(
	peripherals: &VmPeripherals<N>,
	syswrite: &mut v3::parameters::WriteParams,
	file_map: &mut UhyveFileMap,
) {
	let result = write(
		peripherals,
		GuestFd(syswrite.fd),
		syswrite.buf.addr,
		syswrite.buf.len,
		file_map,
	);
	syswrite.ret = RawResult::encode(result.map_err(v3_errno)).unwrap();
}

/// Repositions the file offset of the guest file descriptor `gfd`. Returns the resulting offset
/// or the guest errno on failure.
fn lseek(gfd: GuestFd, whence: LseekWhence, file_map: &mut UhyveFileMap) -> Result<u64, i32> {
	match file_map.fdmap.get_mut(gfd) {
		Some(FdData::Raw(r)) => {
			let (offset, whence) = match whence {
				LseekWhence::SeekSet { offset } => (offset as i64, libc::SEEK_SET),
				LseekWhence::SeekCur { offset } => (offset, libc::SEEK_CUR),
				LseekWhence::SeekEnd { offset } => (offset, libc::SEEK_END),
				LseekWhence::SeekData { offset } => (offset as i64, libc::SEEK_DATA),
				LseekWhence::SeekHole { offset } => (offset as i64, libc::SEEK_HOLE),
			};
			let ret = unsafe { libc::lseek(*r, offset, whence) };
			if ret < 0 {
				Err(translate_last_errno().unwrap_or(1))
			} else {
				Ok(ret as u64)
			}
		}
		Some(FdData::Virtual { data, offset: pos }) => {
			let new_pos = match whence {
				LseekWhence::SeekSet { offset } => Some(offset),
				LseekWhence::SeekCur { offset } => pos.checked_add_signed(offset),
				LseekWhence::SeekEnd { offset } => (data.len() as u64).checked_add_signed(offset),
				LseekWhence::SeekData { .. } | LseekWhence::SeekHole { .. } => return Err(EINVAL),
			}
			.filter(|new_pos| *new_pos <= i64::MAX as u64)
			.ok_or(EOVERFLOW)?;
			*pos = new_pos;
			Ok(new_pos)
		}
		Some(FdData::MappedDirectory { offset: pos, .. }) => {
			let new_pos = match whence {
				LseekWhence::SeekSet { offset } => offset,
				LseekWhence::SeekCur { offset } if offset >= 0 => {
					pos.saturating_add(offset as u64).min(i64::MAX as u64)
				}
				_ => return Err(EINVAL),
			};
			*pos = new_pos;
			Ok(new_pos)
		}
		None => {
			warn!("lseek attempted to use an unknown file descriptor");
			Err(EBADF)
		}
	}
}

/// Handler for a v1 [`FileLseek`](v1::Hypercall::FileLseek) hypercall, which has a different
/// struct format.
pub(super) fn lseek_v1(syslseek: &mut v1::parameters::LseekParams, file_map: &mut UhyveFileMap) {
	let mut tmp = LseekParams {
		offset: syslseek.offset as i64,
		whence: syslseek.whence as u32,
		fd: syslseek.fd,
	};
	lseek_v2(&mut tmp, file_map);
	if tmp.offset < 0 {
		tmp.offset = -1;
	}
	syslseek.offset = tmp
		.offset
		.try_into()
		.unwrap_or_else(|ret| panic!("Unable to fit return value {} in lseek_v1.", ret));
}

/// Handler for a v2 [`FileLseek`](uhyve_interface::v2::Hypercall::FileLseek) hypercall.
pub(super) fn lseek_v2(syslseek: &mut LseekParams, file_map: &mut UhyveFileMap) {
	let offset = syslseek.offset;
	let whence = match syslseek.whence as i32 {
		SEEK_SET => u64::try_from(offset)
			.map(|offset| LseekWhence::SeekSet { offset })
			.map_err(|_| EINVAL),
		SEEK_CUR => Ok(LseekWhence::SeekCur { offset }),
		SEEK_END => Ok(LseekWhence::SeekEnd { offset }),
		_ => Err(EINVAL),
	};
	syslseek.offset = match whence.and_then(|whence| lseek(GuestFd(syslseek.fd), whence, file_map))
	{
		Ok(offset) => offset as i64,
		Err(errno) => -errno as i64,
	};
}

/// Handler for a [`FileLseek`](v3::Hypercall::FileLseek) hypercall.
pub(super) fn lseek_v3(syslseek: &mut v3::parameters::LseekParams, file_map: &mut UhyveFileMap) {
	let result = LseekWhence::try_from(syslseek.whence)
		.map_err(|_| EINVAL)
		.and_then(|whence| lseek(GuestFd(syslseek.fd), whence, file_map));
	syslseek.ret = RawResult::encode(result.map_err(v3_errno)).unwrap();
}

/// Handler for a [`FileFsync`](v3::Hypercall::FileFsync) hypercall.
pub(super) fn fsync(sysfsync: &mut FsyncParams, file_map: &UhyveFileMap) {
	let Some(fddata) = file_map.fdmap.get(GuestFd(sysfsync.fd)) else {
		sysfsync.ret = RawResult::encode_err(EBADF).unwrap();
		return;
	};

	let FdData::Raw(host_fd) = fddata else {
		sysfsync.ret = RawResult::ok();
		return;
	};

	let result = unsafe { libc::fsync(*host_fd) };

	sysfsync.ret = if result < 0 {
		RawResult::encode_err(translate_last_errno().unwrap()).unwrap()
	} else {
		RawResult::ok()
	};
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use super::*;

	#[test]
	fn test_read_internal_on_virtual00() {
		let data: Arc<[u8]> = Arc::from(b"Hello!".to_vec().into_boxed_slice());
		let len = data.len() as u64;
		let mut fdata = FdData::Virtual { data, offset: 0 };
		let mut out = [MaybeUninit::new(0u8); 20];

		assert_eq!(read_internal(&mut fdata, &mut out), Ok(len));
		let FdData::Virtual { offset, .. } = &fdata else {
			unreachable!();
		};
		assert_eq!(*offset, len);
	}

	const SIZE: usize = 0x10000;
	const BASE: u64 = 0x10_0000;

	fn setup(fill: usize) -> (MmapMemory, UhyveFileMap, i32) {
		let mem = MmapMemory::new(SIZE, GuestPhysAddr::new(BASE), false, false);
		let mut fm = UhyveFileMap::new(
			&[],
			None,
			#[cfg(target_os = "linux")]
			Default::default(),
		);
		let data: Arc<[u8]> = Arc::from(vec![0x41u8; fill].into_boxed_slice());
		let fd = fm
			.fdmap
			.insert(FdData::Virtual { data, offset: 0 })
			.unwrap();
		(mem, fm, fd.0)
	}

	fn do_read(mem: &MmapMemory, fm: &mut UhyveFileMap, fd: i32, buf: u64, len: u64) -> i64 {
		let mut p = ReadParams {
			fd,
			buf: GuestPhysAddr::new(buf),
			len,
			ret: 0,
		};
		read_v2(mem, &mut p, fm);
		p.ret
	}

	#[test]
	fn in_bounds_read_succeeds() {
		let (mem, mut fm, fd) = setup(6);
		assert_eq!(do_read(&mem, &mut fm, fd, BASE, 6), 6);
	}

	#[test]
	fn buffer_crossing_end_is_rejected() {
		let (mem, mut fm, fd) = setup(16);
		assert_eq!(
			do_read(&mem, &mut fm, fd, BASE + SIZE as u64 - 4, 16),
			-EFAULT as i64
		);
	}

	#[test]
	fn buffer_past_memory_is_rejected() {
		let (mem, mut fm, fd) = setup(4);
		assert_eq!(
			do_read(&mem, &mut fm, fd, BASE + 2 * SIZE as u64, 4),
			-EFAULT as i64
		);
	}

	#[test]
	fn oversized_len_is_rejected() {
		let (mem, mut fm, fd) = setup(1 << 20);
		assert_eq!(do_read(&mem, &mut fm, fd, BASE, 1 << 20), -EFAULT as i64);
	}
}
