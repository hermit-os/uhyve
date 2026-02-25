use core::cmp;
use std::{
	ffi::{CStr, CString, OsStr},
	io,
	os::{fd::IntoRawFd, unix::ffi::OsStrExt},
};

use uhyve_interface::{
	GuestPhysAddr,
	v1::{self, MAX_ARGC_ENVC},
	v2::{self, parameters::*},
};

use crate::{
	HypervisorResult,
	isolation::{
		fd::{FdData, GuestFd, UhyveFileDescriptorLayer},
		filemap::{UhyveFileMap, UhyveMapLeaf},
	},
	mem::MmapMemory,
	params::EnvVars,
	vcpu::VcpuStopReason,
	virt_to_phys,
	vm::{KernelInfo, VmPeripherals},
};

/// `addr` is the address of the hypercall parameter in the guest's memory space. `data` is the
/// parameter that was sent to that address by the guest.
///
/// # Safety
///
/// - The return value is only valid, as long as the guest is halted.
/// - This fn must not be called multiple times on the same data, to avoid creating mutable aliasing.
pub unsafe fn address_to_hypercall_v1(
	mem: &MmapMemory,
	addr: u16,
	data: GuestPhysAddr,
) -> Option<v1::Hypercall<'_>> {
	use v1::{Hypercall, HypercallAddress};
	// Using a macro here is necessary because it:
	// - is used to reduce repetition,
	// - has to capture values from the environment (mem, data),
	// - has to be generic over its return type.
	//
	// So neither functions nor closures can serve this purpose alone.
	macro_rules! get_data {
		() => {{ unsafe { mem.get_ref_mut(data).unwrap() } }};
	}

	Some(match HypercallAddress::try_from(addr).ok()? {
		HypercallAddress::FileClose => Hypercall::FileClose(get_data!()),
		HypercallAddress::FileLseek => Hypercall::FileLseek(get_data!()),
		HypercallAddress::FileOpen => Hypercall::FileOpen(get_data!()),
		HypercallAddress::FileRead => Hypercall::FileRead(get_data!()),
		HypercallAddress::FileWrite => Hypercall::FileWrite(get_data!()),
		HypercallAddress::FileUnlink => Hypercall::FileUnlink(get_data!()),
		HypercallAddress::Exit => Hypercall::Exit(get_data!()),
		HypercallAddress::Cmdsize => Hypercall::Cmdsize(get_data!()),
		HypercallAddress::Cmdval => Hypercall::Cmdval(get_data!()),
		HypercallAddress::Uart => Hypercall::SerialWriteByte(data.as_u64() as u8),
		HypercallAddress::SerialBufferWrite => Hypercall::SerialWriteBuffer(get_data!()),
		_ => return None,
	})
}

/// `addr` is the address of the hypercall parameter in the guest's memory space. `data` is the
/// parameter that was sent to that address by the guest.
///
/// # Safety
///
/// - The return value is only valid, as long as the guest is halted.
/// - This fn must not be called multiple times on the same data, to avoid creating mutable aliasing.
pub unsafe fn address_to_hypercall_v2(
	mem: &MmapMemory,
	addr: u64,
	data: GuestPhysAddr,
) -> Option<v2::Hypercall<'_>> {
	use v2::{Hypercall, HypercallAddress};
	// Using a macro here is necessary because it:
	// - is used to reduce repetition,
	// - has to capture values from the environment (mem, data),
	// - has to be generic over its return type.
	//
	// So neither functions nor closures can serve this purpose alone.
	macro_rules! get_data {
		() => {{ unsafe { mem.get_ref_mut(data).unwrap() } }};
	}

	Some(match HypercallAddress::try_from(addr).ok()? {
		HypercallAddress::FileClose => Hypercall::FileClose(get_data!()),
		HypercallAddress::FileLseek => Hypercall::FileLseek(get_data!()),
		HypercallAddress::FileOpen => Hypercall::FileOpen(get_data!()),
		HypercallAddress::FileRead => Hypercall::FileRead(get_data!()),
		HypercallAddress::FileWrite => Hypercall::FileWrite(get_data!()),
		HypercallAddress::FileUnlink => Hypercall::FileUnlink(get_data!()),
		HypercallAddress::Exit => Hypercall::Exit(data.as_u64() as i32),
		HypercallAddress::SerialReadBuffer => Hypercall::SerialReadBuffer(get_data!()),
		HypercallAddress::SerialWriteBuffer => Hypercall::SerialWriteBuffer(get_data!()),
		HypercallAddress::SerialWriteByte => Hypercall::SerialWriteByte(data.as_u64() as u8),
		_ => return None,
	})
}

/// Given the `peripherals` of the vCPUs, handles an [`v2::Hypercall`], usually performing I/O.
///
/// # Panics
///
/// When a hypercall returns an error, or the hypercall is invalid, this function might panic
/// (particularly on failing write calls, due to historical legacy).
pub fn handle_hypercall_v2(
	peripherals: &VmPeripherals,
	hypercall: v2::Hypercall<'_>,
) -> Option<VcpuStopReason> {
	let file_mapping = || peripherals.file_mapping.lock().unwrap();
	match hypercall {
		v2::Hypercall::Exit(sysexit) => {
			return Some(VcpuStopReason::Exit(sysexit));
		}
		v2::Hypercall::FileClose(sysclose) => close(sysclose, &mut file_mapping()),
		v2::Hypercall::FileLseek(syslseek) => lseek(syslseek, &mut file_mapping()),
		v2::Hypercall::FileOpen(sysopen) => open(&peripherals.mem, sysopen, &mut file_mapping()),
		v2::Hypercall::FileRead(sysread) => read(&peripherals.mem, sysread, &mut file_mapping()),
		v2::Hypercall::FileWrite(syswrite) => {
			write(peripherals, syswrite, &mut file_mapping()).unwrap();
		}
		v2::Hypercall::FileUnlink(sysunlink) => {
			unlink(&peripherals.mem, sysunlink, &mut file_mapping())
		}
		v2::Hypercall::SerialWriteByte(buf) => peripherals
			.serial
			.output(&[buf])
			.unwrap_or_else(|e| error!("{e:?}")),
		v2::Hypercall::SerialWriteBuffer(sysserialwrite) => {
			// SAFETY: as this buffer is only read and not used afterwards, we don't create multiple aliasing
			let buf = unsafe {
				peripherals
					.mem
					.slice_at(sysserialwrite.buf, sysserialwrite.len as usize)
					.unwrap_or_else(|e| {
						panic!(
							"Error {e}: Systemcall parameters for SerialWriteBuffer are invalid: {sysserialwrite:?}"
						)
					})
			};

			peripherals
				.serial
				.output(buf)
				.unwrap_or_else(|e| error!("{e:?}"))
		}
		_ => panic!("Got unknown hypercall {hypercall:?}"),
	}

	None
}

/// Given the `peripherals` of the vCPUs, handles an [`v1::Hypercall`], usually performing I/O.
///
/// # Panics
///
/// When a hypercall returns an error, or the hypercall is invalid, this function might panic
/// (particularly on failing write calls).
pub fn handle_hypercall_v1(
	peripherals: &VmPeripherals,
	kernel_info: &KernelInfo,
	root_pt: impl FnOnce() -> HypervisorResult<GuestPhysAddr>,
	hypercall: v1::Hypercall<'_>,
) -> Option<HypervisorResult<VcpuStopReason>> {
	let file_mapping = || peripherals.file_mapping.lock().unwrap();

	match hypercall {
		v1::Hypercall::Cmdsize(syssize) => {
			syssize.update(&kernel_info.path, &kernel_info.params.kernel_args)
		}
		v1::Hypercall::Cmdval(syscmdval) => {
			copy_argv(
				kernel_info.path.as_os_str(),
				&kernel_info.params.kernel_args,
				syscmdval,
				&peripherals.mem,
			);
			copy_env(&kernel_info.params.env, syscmdval, &peripherals.mem);
		}
		v1::Hypercall::Exit(sysexit) => {
			return Some(Ok(VcpuStopReason::Exit(sysexit.arg)));
		}
		v1::Hypercall::FileClose(sysclose) => close(sysclose, &mut file_mapping()),
		v1::Hypercall::FileLseek(syslseek) => lseek_v1(syslseek, &mut file_mapping()),
		v1::Hypercall::FileOpen(sysopen) => open(&peripherals.mem, sysopen, &mut file_mapping()),
		v1::Hypercall::FileRead(sysread) => read_v1(
			&peripherals.mem,
			sysread,
			match root_pt() {
				Ok(root_pt) => root_pt,
				Err(e) => return Some(Err(e)),
			},
			&mut file_mapping(),
		),
		v1::Hypercall::FileWrite(syswrite) => write_v1(
			peripherals,
			syswrite,
			match root_pt() {
				Ok(root_pt) => root_pt,
				Err(e) => return Some(Err(e)),
			},
			&mut file_mapping(),
		)
		.unwrap(),
		v1::Hypercall::FileUnlink(sysunlink) => {
			unlink(&peripherals.mem, sysunlink, &mut file_mapping())
		}
		v1::Hypercall::SerialWriteByte(buf) => peripherals
			.serial
			.output(&[buf])
			.unwrap_or_else(|e| error!("{e:?}")),
		v1::Hypercall::SerialWriteBuffer(sysserialwrite) => {
			// safety: as this buffer is only read and not used afterwards, we don't create multiple aliasing
			let buf = unsafe {
				peripherals
					.mem
					.slice_at(sysserialwrite.buf, sysserialwrite.len)
					.unwrap_or_else(|e| {
						panic!(
							"Error {e}: Systemcall parameters for SerialWriteBuffer are invalid: {sysserialwrite:?}"
						)
					})
			};

			peripherals
				.serial
				.output(buf)
				.unwrap_or_else(|e| error!("{e:?}"))
		}
		_ => panic!("Got unknown hypercall {hypercall:?}"),
	}

	None
}

/// Translates the last error in `errno` to a value suitable to return from the hypercall.
fn translate_last_errno() -> Option<i32> {
	let errno = io::Error::last_os_error().raw_os_error()?;

	// A loop, because rust can't know for sure that errno numbers don't overlap on the host.
	macro_rules! error_pairs {
		($($x:ident),*) => {{[ $((libc::$x, hermit_abi::errno::$x)),* ]}}
	}
	for (e_host, e_guest) in error_pairs!(
		EBADF, EEXIST, EFAULT, EINVAL, EIO, EISDIR, EOVERFLOW, EPERM, ENOENT, EROFS
	) {
		if errno == e_host {
			return Some(e_guest);
		}
	}
	warn!(
		"No Hermit equivalent of host error {} (errno: {errno}), returning default to guest...",
		io::Error::from_raw_os_error(errno)
	);
	None
}

/// Decodes a guest path given at address `path_addr` in `mem`.
///
/// # Safety
///
/// The calling convention of hypercalls ensures that the given address doesn't alias with anything mutable.
/// The return value is only valid for the duration of the hypercall.
unsafe fn decode_guest_path(mem: &MmapMemory, path_addr: GuestPhysAddr) -> Option<&str> {
	let requested_path_ptr = mem.host_address(path_addr).unwrap() as *const i8;
	unsafe { CStr::from_ptr(requested_path_ptr) }.to_str().ok()
}

/// unlink deletes a name from the filesystem. This is used to handle `unlink` syscalls from the guest.
///
/// Note for when using Landlock: Unlinking files results in them being veiled. If a
/// file (that existed during initialization) called `log.txt` is unlinked, attempting to
/// open `log.txt` again will result in an error.
fn unlink(mem: &MmapMemory, sysunlink: &mut UnlinkParams, file_map: &mut UhyveFileMap) {
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
fn open(mem: &MmapMemory, sysopen: &mut OpenParams, file_map: &mut UhyveFileMap) {
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

	sysopen.ret = if let Some(host_path) = file_map.get_host_path(guest_path) {
		debug!("{guest_path:#?} found in file map.");
		match host_path {
			UhyveMapLeaf::OnHost(host_path) => {
				// We can safely unwrap here, as host_path.as_bytes will never contain internal \0 bytes
				// As host_path_c_string is a valid CString, this implementation is presumed to be safe.
				let host_path_c_string = CString::new(host_path.as_os_str().as_bytes()).unwrap();
				do_open(&mut file_map.fdmap, host_path_c_string, flags, sysopen.mode)
			}
			UhyveMapLeaf::Virtual(data) => {
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

/// Handles an close syscall by closing the file on the host.
fn close(sysclose: &mut CloseParams, file_map: &mut UhyveFileMap) {
	sysclose.ret = if file_map.fdmap.is_fd_present(GuestFd(sysclose.fd)) {
		match file_map.fdmap.remove(GuestFd(sysclose.fd)) {
			Some(FdData::Raw(fd)) => {
				if unsafe { libc::close(fd) } < 0 {
					-translate_last_errno().unwrap_or(1)
				} else {
					0
				}
			}
			// ignore other closures (fdmap's remove already handles stdio)
			_ => 0,
		}
	} else {
		-EBADF
	};
}

/// Handles a v1 read hypercall (for which a guest-provided guest virtual address must be
/// converted to a guest physical address by the host).
fn read_v1(
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
fn read(mem: &MmapMemory, sysread: &mut v2::parameters::ReadParams, file_map: &mut UhyveFileMap) {
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
					amt as i64
				}
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
fn write_v1(
	peripherals: &VmPeripherals,
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
fn write(
	peripherals: &VmPeripherals,
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

		Some(FdData::Virtual { .. }) => {
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
fn lseek_v1(syslseek: &mut v1::parameters::LseekParams, file_map: &mut UhyveFileMap) {
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
fn lseek(syslseek: &mut LseekParams, file_map: &mut UhyveFileMap) {
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
		None => {
			warn!("lseek attempted to use an unknown file descriptor");
			-EBADF as i64
		}
	};
}

/// Copies the arguments of the application into the VM's memory to the destinations specified in `syscmdval`.
fn copy_argv(
	path: &OsStr,
	argv: &[String],
	syscmdval: &v1::parameters::CmdvalParams,
	mem: &MmapMemory,
) {
	// copy kernel path as first argument
	let argvp = mem
		.host_address(syscmdval.argv)
		.expect("Systemcall parameters for Cmdval are invalid") as *const GuestPhysAddr;
	let arg_addrs = unsafe { std::slice::from_raw_parts(argvp, argv.len() + 1) };

	{
		let len = path.len();
		// Safety: we drop path_dest before anything else is done with mem
		let path_dest = unsafe {
			mem.slice_at_mut(arg_addrs[0], len + 1)
				.expect("Systemcall parameters for Cmdval are invalid")
		};

		path_dest[0..len].copy_from_slice(path.as_bytes());
		path_dest[len] = 0; // argv strings are zero terminated
	}

	// Copy the application arguments into the vm memory
	for (counter, argument) in argv.iter().enumerate() {
		let len = argument.len();
		let arg_dest = unsafe {
			mem.slice_at_mut(arg_addrs[counter], len + 1)
				.expect("Systemcall parameters for Cmdval are invalid")
		};
		arg_dest[0..len].copy_from_slice(argument.as_bytes());
		arg_dest[len] = 0;
	}
}

/// Copies the environment variables into the VM's memory to the destinations specified in `syscmdval`.
fn copy_env(env: &EnvVars, syscmdval: &v1::parameters::CmdvalParams, mem: &MmapMemory) {
	let envp = mem
		.host_address(syscmdval.envp)
		.expect("Systemcall parameters for Cmdval are invalid") as *const GuestPhysAddr;

	let env: Vec<(String, String)> = match env {
		EnvVars::Host => std::env::vars_os()
			.map(|(a, b)| (a.into_string().unwrap(), b.into_string().unwrap()))
			.collect(),
		EnvVars::Set(map) => map
			.iter()
			.map(|(a, b)| (a.to_owned(), b.to_owned()))
			.collect(),
	};
	if env.len() >= MAX_ARGC_ENVC {
		warn!(
			"Environment is larger than the maximum that can be copied to the VM. Remaining environment is ignored"
		);
	}
	let env_addrs = unsafe { std::slice::from_raw_parts(envp, env.len()) };

	// Copy the environment variables into the vm memory
	for (counter, (key, value)) in env.iter().enumerate().take(MAX_ARGC_ENVC) {
		let len = key.len() + value.len() + 1;
		let env_dest = unsafe {
			mem.slice_at_mut(env_addrs[counter], len + 1)
				.expect("Systemcall parameters for Cmdval are invalid")
		};
		//write_env_into_mem(env_dest, key.as_bytes(), value.as_bytes());
		let len = key.len() + value.len() + 1;
		env_dest[0..key.len()].copy_from_slice(key.as_bytes());
		env_dest[key.len()] = b'=';
		env_dest[key.len() + 1..len].copy_from_slice(value.as_bytes());
		env_dest[len] = 0;
	}
}
