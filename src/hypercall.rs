use std::{
	ffi::{CStr, CString, OsStr},
	io::{self, Error, ErrorKind},
	os::{fd::IntoRawFd, unix::ffi::OsStrExt},
};

use uhyve_interface::{
	GuestPhysAddr,
	v1::{Hypercall, HypercallAddress, MAX_ARGC_ENVC, parameters::*},
};

use crate::{
	isolation::filemap::UhyveFileMap,
	mem::{MemoryError, MmapMemory},
	params::EnvVars,
	virt_to_phys,
	vm::VmPeripherals,
};

/// `addr` is the address of the hypercall parameter in the guest's memory space. `data` is the
/// parameter that was send to that address by the guest.
///
/// # Safety
///
/// - The return value is only valid, as long as the guest is halted.
/// - This fn must not be called multiple times on the same data, to avoid creating mutable aliasing.
pub unsafe fn address_to_hypercall(
	mem: &MmapMemory,
	addr: u16,
	data: GuestPhysAddr,
) -> Option<Hypercall<'_>> {
	if let Ok(hypercall_port) = HypercallAddress::try_from(addr) {
		Some(match hypercall_port {
			HypercallAddress::FileClose => {
				let sysclose = unsafe { mem.get_ref_mut::<CloseParams>(data).unwrap() };
				// let sysclose = unsafe { &mut *(self.host_address(data) as *mut CloseParams) };
				Hypercall::FileClose(sysclose)
			}
			HypercallAddress::FileLseek => {
				let syslseek = unsafe { mem.get_ref_mut::<LseekParams>(data).unwrap() };
				Hypercall::FileLseek(syslseek)
			}
			HypercallAddress::FileOpen => {
				let sysopen = unsafe { mem.get_ref_mut::<OpenParams>(data).unwrap() };
				Hypercall::FileOpen(sysopen)
			}
			HypercallAddress::FileRead => {
				let sysread = unsafe { mem.get_ref_mut::<ReadParams>(data).unwrap() };
				Hypercall::FileRead(sysread)
			}
			HypercallAddress::FileWrite => {
				let syswrite = unsafe { mem.get_ref_mut(data).unwrap() };
				Hypercall::FileWrite(syswrite)
			}
			HypercallAddress::FileUnlink => {
				let sysunlink = unsafe { mem.get_ref_mut(data).unwrap() };
				Hypercall::FileUnlink(sysunlink)
			}
			HypercallAddress::Exit => {
				let sysexit = unsafe { mem.get_ref_mut(data).unwrap() };
				Hypercall::Exit(sysexit)
			}
			HypercallAddress::Cmdsize => {
				let syssize = unsafe { mem.get_ref_mut(data).unwrap() };
				Hypercall::Cmdsize(syssize)
			}
			HypercallAddress::Cmdval => {
				let syscmdval = unsafe { mem.get_ref_mut(data).unwrap() };
				Hypercall::Cmdval(syscmdval)
			}
			HypercallAddress::Uart => Hypercall::SerialWriteByte(data.as_u64() as u8),
			HypercallAddress::SerialBufferWrite => {
				let sysserialwrite = unsafe { mem.get_ref_mut(data).unwrap() };
				Hypercall::SerialWriteBuffer(sysserialwrite)
			}
			_ => unimplemented!(),
		})
	} else {
		None
	}
}

/// unlink deletes a name from the filesystem. This is used to handle `unlink` syscalls from the guest.
///
/// Note for when using Landlock: Unlinking files results in them being veiled. If a text
/// file (that existed during initialization) called `log.txt` is unlinked, attempting to
/// open `log.txt` again will result in an error.
pub fn unlink(mem: &MmapMemory, sysunlink: &mut UnlinkParams, file_map: &mut UhyveFileMap) {
	let requested_path_ptr = mem.host_address(sysunlink.name).unwrap() as *const i8;
	let guest_path = unsafe { CStr::from_ptr(requested_path_ptr) };
	sysunlink.ret = if let Some(host_path) = file_map.get_host_path(guest_path) {
		// We can safely unwrap here, as host_path.as_bytes will never contain internal \0 bytes
		// As host_path_c_string is a valid CString, this implementation is presumed to be safe.
		let host_path_c_string = CString::new(host_path.as_bytes()).unwrap();
		unsafe { libc::unlink(host_path_c_string.as_c_str().as_ptr()) }
	} else {
		error!("The kernel requested to unlink() an unknown path ({guest_path:?}): Rejecting...");
		-ENOENT
	};
}

/// Handles an open syscall by opening a file on the host.
pub fn open(mem: &MmapMemory, sysopen: &mut OpenParams, file_map: &mut UhyveFileMap) {
	let requested_path_ptr = mem.host_address(sysopen.name).unwrap() as *const i8;
	let mut flags = sysopen.flags & ALLOWED_OPEN_FLAGS;
	let guest_path = unsafe { CStr::from_ptr(requested_path_ptr) };
	// See: https://lwn.net/Articles/926782/
	// See: https://github.com/hermit-os/kernel/commit/71bc629
	if (flags & (O_DIRECTORY | O_CREAT)) == (O_DIRECTORY | O_CREAT) {
		error!("An open() call used O_DIRECTORY and O_CREAT at the same time. Aborting...");
		sysopen.ret = -EINVAL;
		return;
	}

	if let Some(host_path) = file_map.get_host_path(guest_path) {
		debug!("{guest_path:#?} found in file map.");
		// We can safely unwrap here, as host_path.as_bytes will never contain internal \0 bytes
		// As host_path_c_string is a valid CString, this implementation is presumed to be safe.
		let host_path_c_string = CString::new(host_path.as_bytes()).unwrap();

		sysopen.ret =
			unsafe { libc::open(host_path_c_string.as_c_str().as_ptr(), flags, sysopen.mode) };

		file_map.fdmap.insert_fd(sysopen.ret);
	} else {
		debug!("{guest_path:#?} not found in file map.");
		if (flags & O_CREAT) == O_CREAT {
			debug!("Attempting to open a temp file for {guest_path:#?}...");
			// Existing files that already exist should be in the file map, not here.
			// If a supposed attacker can predict where we open a file and its filename,
			// this contigency, together with O_CREAT, will cause the write to fail.
			flags |= O_EXCL;

			let host_path_c_string = file_map.create_temporary_file(guest_path);
			let new_host_path = host_path_c_string.as_c_str().as_ptr();
			sysopen.ret = unsafe { libc::open(new_host_path, flags, sysopen.mode) };
			file_map.fdmap.insert_fd(sysopen.ret.into_raw_fd());
		} else {
			debug!("Returning -ENOENT for {guest_path:#?}");
			sysopen.ret = -ENOENT;
		}
	}
}

/// Handles an close syscall by closing the file on the host.
pub fn close(sysclose: &mut CloseParams, file_map: &mut UhyveFileMap) {
	if file_map.fdmap.is_fd_present(sysclose.fd.into_raw_fd()) {
		if sysclose.fd > 2 {
			unsafe { sysclose.ret = libc::close(sysclose.fd) }
			file_map.fdmap.remove_fd(sysclose.fd)
		} else {
			// Ignore closes of stdin, stdout and stderr that would
			// otherwise affect Uhyve
			sysclose.ret = 0
		}
	} else {
		sysclose.ret = -EBADF
	}
}

/// Handles a read syscall on the host.
pub fn read(
	mem: &MmapMemory,
	sysread: &mut ReadParams,
	root_pt: GuestPhysAddr,
	file_map: &mut UhyveFileMap,
) {
	if file_map.fdmap.is_fd_present(sysread.fd.into_raw_fd()) {
		let guest_phys_addr = virt_to_phys(sysread.buf, mem, root_pt);
		if let Ok(guest_phys_addr) = guest_phys_addr
			&& let Ok(host_address) = mem.host_address(guest_phys_addr)
		{
			let bytes_read =
				unsafe { libc::read(sysread.fd, host_address as *mut libc::c_void, sysread.len) };
			if bytes_read >= 0 {
				sysread.ret = bytes_read;
			} else {
				sysread.ret = -1
			}
		} else {
			warn!("Unable to get host address for read buffer");
			sysread.ret = -EFAULT as isize;
		}
	} else {
		sysread.ret = -EBADF as isize;
	}
}

/// Handles an write syscall on the host.
pub fn write(
	peripherals: &VmPeripherals,
	syswrite: &WriteParams,
	root_pt: GuestPhysAddr,
	file_map: &mut UhyveFileMap,
) -> io::Result<()> {
	let mut bytes_written: usize = 0;
	while bytes_written != syswrite.len {
		let guest_phys_addr = virt_to_phys(
			syswrite.buf + bytes_written as u64,
			&peripherals.mem,
			root_pt,
		);

		if let Ok(guest_phys_addr) = guest_phys_addr {
			if syswrite.fd == 1 || syswrite.fd == 2 {
				let bytes = unsafe {
					peripherals
						.mem
						.slice_at(guest_phys_addr, syswrite.len)
						.map_err(|e| {
							io::Error::new(
								io::ErrorKind::InvalidInput,
								format!("invalid syswrite buffer: {e:?}"),
							)
						})?
				};
				return peripherals.serial.output(bytes);
			} else if !file_map.fdmap.is_fd_present(syswrite.fd.into_raw_fd()) {
				// We don't write anything if the file descriptor is not available,
				// but this is OK for now, as we have no means of returning an error code
				// and writes are not necessarily guaranteed to write anything.
				return Ok(());
			}
		} else {
			return Ok(());
		}

		unsafe {
			let step = libc::write(
				syswrite.fd,
				peripherals
					.mem
					.host_address(guest_phys_addr.unwrap())
					.map_err(|e| match e {
						MemoryError::BoundsViolation => {
							unreachable!("Bounds violation after host_address function")
						}
						MemoryError::WrongMemoryError => {
							Error::new(ErrorKind::AddrNotAvailable, e.to_string())
						}
					})? as *const libc::c_void,
				syswrite.len - bytes_written,
			);
			if step >= 0 {
				bytes_written += step as usize;
			} else {
				return Err(io::Error::last_os_error());
			}
		}
	}

	Ok(())
}

/// Handles an lseek syscall on the host.
pub fn lseek(syslseek: &mut LseekParams, file_map: &mut UhyveFileMap) {
	if file_map.fdmap.is_fd_present(syslseek.fd.into_raw_fd()) {
		unsafe {
			syslseek.offset =
				libc::lseek(syslseek.fd, syslseek.offset as i64, syslseek.whence) as isize;
		}
	} else {
		// TODO: Return -EBADF to the ret field, as soon as it is implemented for LseekParams
		warn!("lseek attempted to use an unknown file descriptor");
		syslseek.offset = -1
	}
}

/// Copies the arguments of the application into the VM's memory to the destinations specified in `syscmdval`.
pub fn copy_argv(path: &OsStr, argv: &[String], syscmdval: &CmdvalParams, mem: &MmapMemory) {
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
pub fn copy_env(env: &EnvVars, syscmdval: &CmdvalParams, mem: &MmapMemory) {
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
