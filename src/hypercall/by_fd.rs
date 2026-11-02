use core::{cmp, mem::MaybeUninit};
use std::{io, os::fd::IntoRawFd};

use uhyve_interface::{GuestPhysAddr, v1, v2, v3::parameters::*};

use crate::{
	hypercall::{translate_last_errno, translate_last_errno_nonzero},
	isolation::{
		fd::{FdData, GuestFd},
		filemap::UhyveFileMap,
	},
	mem::MmapMemory,
	net::NetworkBackend,
	virt_to_phys,
	vm::VmPeripherals,
};

/// Handles an close syscall by closing the file on the host.
pub(super) fn close_v1(sysclose: &mut v1::parameters::CloseParams, file_map: &mut UhyveFileMap) {
	let gfd = GuestFd(sysclose.fd);
	debug!(
		"Guest tries to close fd {gfd} from fdmap {:?}",
		file_map.fdmap
	);
	sysclose.ret = if gfd.is_standard() {
		// ignore stdio closures
		warn!("Guest tried to close stdio fd: {gfd}");
		0
	} else if let Some(fddata) = file_map.fdmap.remove(gfd) {
		if let FdData::Raw(fd) = fddata
			&& unsafe { libc::close(fd) } < 0
		{
			-translate_last_errno().unwrap_or(1)
		} else {
			0
		}
	} else {
		warn!("Guest tried to close unknown fd: {gfd}");
		-EBADF
	};
}

/// Handles an close syscall by closing the file on the host.
pub(super) fn close(sysclose: &mut CloseParams, file_map: &mut UhyveFileMap) {
	let gfd = GuestFd(sysclose.fd);
	debug!(
		"Guest tries to close fd {gfd} from fdmap {:?}",
		file_map.fdmap
	);
	sysclose.ret = if gfd.is_standard() {
		// ignore stdio closures
		warn!("Guest tried to close stdio fd: {gfd}");
		TristateResult::Success
	} else if let Some(fddata) = file_map.fdmap.remove(gfd) {
		if let FdData::Raw(fd) = fddata
			&& unsafe { libc::close(fd) } < 0
		{
			TristateResult::Errno(NonZero::new(translate_last_errno().unwrap_or(1) as u32).unwrap())
		} else {
			TristateResult::Success
		}
	} else {
		warn!("Guest tried to close unknown fd: {gfd}");
		TristateResult::Errno(NonZero::new(EBADF as u32).unwrap())
	}
	.try_as_num()
	.unwrap();
}

/// Handles a v1 read hypercall (for which a guest-provided guest virtual address must be
/// converted to a guest physical address by the host).
pub(super) fn read_v1(
	mem: &MmapMemory,
	sysread: &mut v1::parameters::ReadParams,
	root_pt: GuestPhysAddr,
	file_map: &mut UhyveFileMap,
) {
	sysread.ret = if let Ok(guest_phys_addr) = virt_to_phys(sysread.buf, mem, root_pt) {
		let mut tmp = v2::parameters::ReadParams {
			fd: sysread.fd,
			buf: guest_phys_addr,
			len: sysread.len as u64,
			ret: 0i64,
		};
		read_v2(mem, &mut tmp, file_map);
		tmp.ret
			.try_into()
			.unwrap_or_else(|ret| panic!("Unable to fit return value {} in read_v1.", ret))
	} else {
		warn!("Unable to convert guest virtual address into guest physical address");
		-EFAULT as isize
	}
}

/// Handles a read syscall on the host.
pub(super) fn read_v2(
	mem: &MmapMemory,
	sysread: &mut v2::parameters::ReadParams,
	file_map: &mut UhyveFileMap,
) {
	sysread.ret = if let Some(fdata) = file_map.fdmap.get_mut(GuestFd(sysread.fd.into_raw_fd())) {
		match sysread.len.try_into() {
			// Bound the destination to guest memory, as write/getdents/serialwrite do.
			Ok(len) => match unsafe { mem.slice_at_mut::<MaybeUninit<u8>>(sysread.buf, len) } {
				Ok(buf) => read_internal(fdata, buf).try_as_num().unwrap().num,
				Err(_) => {
					warn!("read buffer is not within guest memory");
					-EFAULT as i64
				}
			},
			Err(_) => -EINVAL as i64,
		}
	} else {
		-EBADF as i64
	};
}

/// Handles a read syscall on the host.
pub(super) fn read(mem: &MmapMemory, sysread: &mut ReadParams, file_map: &mut UhyveFileMap) {
	sysread.ret = if let Some(fdata) = file_map.fdmap.get_mut(GuestFd(sysread.fd.into_raw_fd())) {
		match sysread.len.try_into() {
			// Bound the destination to guest memory, as write/getdents/serialwrite do.
			Ok(len) => match unsafe { mem.slice_at_mut::<MaybeUninit<u8>>(sysread.buf, len) } {
				Ok(buf) => read_internal(fdata, buf),
				Err(_) => {
					warn!("read buffer is not within guest memory");
					IoResult64::Errno(NonZero::new(EFAULT as u32).unwrap())
				}
			},
			Err(_) => IoResult64::Errno(NonZero::new(EINVAL as u32).unwrap()),
		}
	} else {
		IoResult64::Errno(NonZero::new(EBADF as u32).unwrap())
	}
	.try_as_num()
	.unwrap();
}

fn read_internal(fdata: &mut FdData, out_bytes: &mut [MaybeUninit<u8>]) -> IoResult64 {
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
				IoResult64::Errno(
					translate_last_errno_nonzero().unwrap_or(NonZero::new(1).unwrap()),
				)
			} else {
				IoResult64::Ok(bytes_read as u64)
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
				.count() as u64;
			*offset += amt;
			IoResult64::Ok(amt)
		}
		FdData::MappedDirectory { .. } => IoResult64::Errno(NonZero::new(EBADF as u32).unwrap()),
	}
}

/// Handles a v1 write hypercall (for which a guest-provided guest virtual address must be
/// converted to a guest physical address by the host).
pub(super) fn write_v1<N: NetworkBackend>(
	peripherals: &VmPeripherals<N>,
	syswrite: &v1::parameters::WriteParams,
	root_pt: GuestPhysAddr,
	file_map: &mut UhyveFileMap,
) -> io::Result<()> {
	let guest_phys_addr = virt_to_phys(syswrite.buf, &peripherals.mem, root_pt).map_err(|e| {
		io::Error::new(
			io::ErrorKind::InvalidInput,
			format!("invalid syswrite buffer: {e:?}"),
		)
	})?;
	let mut tmp = v2::parameters::WriteParams {
		fd: syswrite.fd,
		buf: guest_phys_addr,
		len: syswrite.len as u64,
		ret: 0i64,
	};
	write_v2(peripherals, &mut tmp, file_map)
}

/// Handles an write syscall on the host.
pub(super) fn write_v2<N: NetworkBackend>(
	peripherals: &VmPeripherals<N>,
	syswrite: &mut v2::parameters::WriteParams,
	file_map: &mut UhyveFileMap,
) -> io::Result<()> {
	let mut bytes = unsafe {
		let guest_phys_addr = syswrite.buf;
		peripherals
			.mem
			.slice_at(guest_phys_addr, syswrite.len.try_into().unwrap())
			.map_err(|e| {
				syswrite.ret = -EFAULT as i64;
				io::Error::new(
					io::ErrorKind::InvalidInput,
					format!("invalid syswrite buffer: {e:?}"),
				)
			})?
	};

	match file_map.fdmap.get_mut(GuestFd(syswrite.fd.into_raw_fd())) {
		None => {
			// We don't write anything if the file descriptor is not available,
			// but this is OK, as writes are not necessarily guaranteed to write
			// anything.
			syswrite.ret = -EBADF as i64;
			Err(io::Error::other("Bad file descriptor"))
		}

		Some(FdData::Virtual { .. }) | Some(FdData::MappedDirectory { .. }) => {
			// virtual fds are read-only
			syswrite.ret = -EROFS as i64;
			Err(io::Error::new(
				io::ErrorKind::ReadOnlyFilesystem,
				format!(
					"Unable to write to virtual file {}",
					GuestFd(syswrite.fd.into_raw_fd())
				),
			))
		}

		// Handles to standard outputs differs to that of e.g. files.
		Some(FdData::Raw(1 | 2)) => {
			// Assumption: Everything is printed successfully on the host.
			// We could assume that this will always succeed and leave it at zero, but:
			// - having some "write" scenarios that treat a zero as an error
			//   and some that don't is not very clean.
			// - there is a debug_assert in the kernel that depends on this,
			//   just in case.
			syswrite.ret = bytes.len().try_into().unwrap();
			peripherals.serial.output(bytes)
		}

		Some(FdData::Raw(r)) => {
			syswrite.ret = 0;
			while !bytes.is_empty() {
				let step = unsafe {
					libc::write(
						*r,
						&bytes[0] as *const u8 as *const libc::c_void,
						bytes.len(),
					)
				};
				if step >= 0 {
					syswrite.ret += step as i64;
					bytes = &bytes[step as usize..];
				} else {
					syswrite.ret = -translate_last_errno().unwrap_or(1) as i64;
					return Err(io::Error::last_os_error());
				}
			}

			Ok(())
		}
	}
}

pub(super) fn write<N: NetworkBackend>(
	peripherals: &VmPeripherals<N>,
	syswrite: &mut WriteParams,
	file_map: &mut UhyveFileMap,
) {
	let mut tmp = v2::parameters::WriteParams {
		fd: syswrite.fd,
		buf: syswrite.buf,
		len: syswrite.len,
		ret: syswrite.ret.num,
	};
	let _ = write_v2(peripherals, &mut tmp, file_map);
	syswrite.ret.num = tmp.ret;
}

/// Handles a v1 lseek syscall on the host, which has a different struct format.
pub(super) fn lseek_v1(syslseek: &mut v1::parameters::LseekParams, file_map: &mut UhyveFileMap) {
	let mut tmp = v2::parameters::LseekParams {
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

/// Handles an lseek syscall on the host.
pub(super) fn lseek_v2(syslseek: &mut v2::parameters::LseekParams, file_map: &mut UhyveFileMap) {
	syslseek.offset = match file_map.fdmap.get_mut(GuestFd(syslseek.fd.into_raw_fd())) {
		Some(FdData::Raw(r)) => {
			let ret = unsafe { libc::lseek(*r, syslseek.offset, syslseek.whence as i32) };
			if ret < 0 {
				-translate_last_errno().unwrap_or(1) as i64
			} else {
				ret
			}
		}
		Some(FdData::Virtual { data, offset }) => {
			#[forbid(unused_variables)]
			let tmp: i64 = match syslseek.whence as i32 {
				SEEK_SET => 0,
				SEEK_CUR => *offset as i64,
				SEEK_END => data.len() as i64,
				_ => -EINVAL as i64,
			};
			if tmp >= 0 {
				let tmp2 = tmp + syslseek.offset;
				match tmp2.try_into() {
					Ok(tmp3) => {
						*offset = tmp3;
						tmp2
					}
					_ => -EOVERFLOW as i64,
				}
			} else {
				tmp
			}
		}
		Some(FdData::MappedDirectory { offset, .. }) => match syslseek.whence as i32 {
			SEEK_SET if syslseek.offset >= 0 => {
				*offset = syslseek.offset as u64;
				syslseek.offset
			}
			SEEK_CUR if syslseek.offset >= 0 => {
				let ret = offset.saturating_add_signed(syslseek.offset);
				*offset = ret;
				ret as i64
			}
			_ => -EINVAL as i64,
		},
		None => {
			warn!("lseek attempted to use an unknown file descriptor");
			-EBADF as i64
		}
	};
}

pub(super) fn lseek(syslseek: &mut LseekParams, file_map: &mut UhyveFileMap) {
	let mut syslseek_v2 = v2::parameters::LseekParams {
		offset: syslseek.offset.num,
		whence: syslseek.whence,
		fd: syslseek.fd,
	};
	lseek_v2(&mut syslseek_v2, file_map);
	syslseek.offset = TaggedNumber::new(syslseek_v2.offset);
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

		assert_eq!(read_internal(&mut fdata, &mut out), IoResult64::Ok(len));
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
			ret: Default::default(),
		};
		read(mem, &mut p, fm);
		p.ret.num
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
