use core::cmp;
use std::{io, os::fd::IntoRawFd};

use uhyve_interface::{
	GuestPhysAddr, v1,
	v2::{self, parameters::*},
};

use crate::{
	hypercall::translate_last_errno,
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
pub(super) fn close(sysclose: &mut CloseParams, file_map: &mut UhyveFileMap) {
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
		read(mem, &mut tmp, file_map);
		tmp.ret
			.try_into()
			.unwrap_or_else(|ret| panic!("Unable to fit return value {} in read_v1.", ret))
	} else {
		warn!("Unable to convert guest virtual address into guest physical address");
		-EFAULT as isize
	}
}

/// Handles a read syscall on the host.
pub(super) fn read(
	mem: &MmapMemory,
	sysread: &mut v2::parameters::ReadParams,
	file_map: &mut UhyveFileMap,
) {
	sysread.ret = if let Some(fdata) = file_map.fdmap.get_mut(GuestFd(sysread.fd.into_raw_fd())) {
		if let Ok(host_address) = mem.host_address(sysread.buf) {
			match fdata {
				FdData::Raw(rfd) => {
					let bytes_read = unsafe {
						libc::read(
							*rfd,
							host_address as *mut libc::c_void,
							sysread.len as usize,
						)
					};
					if bytes_read < 0 {
						-translate_last_errno().unwrap_or(1) as i64
					} else {
						bytes_read as i64
					}
				}
				FdData::Virtual { data, offset } => {
					let remaining = {
						let pos = cmp::min(*offset, data.len() as u64);
						&data[pos as usize..]
					};
					let amt = cmp::min(remaining.len() as u64, sysread.len) as usize;
					assert!(amt <= isize::MAX as usize);

					// SAFETY: the input slices can't overlap, as `host_address` is owned by the guest
					// and `data` is owned by the host.
					unsafe {
						core::ptr::copy_nonoverlapping(
							remaining.as_ptr(),
							host_address as *mut u8,
							amt,
						)
					};
					*offset += amt as u64;
					amt as i64
				}
				FdData::MappedDirectory { .. } => -EBADF as i64,
			}
		} else {
			warn!("Unable to get host address for read buffer");
			-EFAULT as i64
		}
	} else {
		-EBADF as i64
	};
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
	write(peripherals, &mut tmp, file_map)
}

/// Handles an write syscall on the host.
pub(super) fn write<N: NetworkBackend>(
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

/// Handles a v1 lseek syscall on the host, which has a different struct format.
pub(super) fn lseek_v1(syslseek: &mut v1::parameters::LseekParams, file_map: &mut UhyveFileMap) {
	let mut tmp = LseekParams {
		offset: syslseek.offset as i64,
		whence: syslseek.whence as u32,
		fd: syslseek.fd,
	};
	lseek(&mut tmp, file_map);
	if tmp.offset < 0 {
		tmp.offset = -1;
	}
	syslseek.offset = tmp
		.offset
		.try_into()
		.unwrap_or_else(|ret| panic!("Unable to fit return value {} in lseek_v1.", ret));
}

/// Handles an lseek syscall on the host.
pub(super) fn lseek(syslseek: &mut LseekParams, file_map: &mut UhyveFileMap) {
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
			#[forbid(unused_variables, unreachable_patterns)]
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
