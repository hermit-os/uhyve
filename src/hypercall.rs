use std::{
	ffi::{OsStr, OsString},
	io::{self, Error, ErrorKind, Write},
	os::unix::ffi::OsStrExt,
};

use uhyve_interface::{parameters::*, GuestPhysAddr, Hypercall, HypercallAddress, MAX_ARGC_ENVC};
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryMmap};

use crate::{
	consts::BOOT_PML4,
	mem::{mem_as_slice, mem_get_ref_mut},
	virt_to_phys,
};

/// `addr` is the address of the hypercall parameter in the guest's memory space. `data` is the
/// parameter that was send to that address by the guest.
///
/// # Safety
///
/// - The return value is only valid, as long as the guest is halted.
/// - This fn must not be called multiple times on the same data, to avoid creating mutable aliasing.
pub unsafe fn address_to_hypercall(
	mem: &GuestMemoryMmap,
	addr: u16,
	data: GuestPhysAddr,
) -> Option<Hypercall<'_>> {
	if let Ok(hypercall_port) = HypercallAddress::try_from(addr) {
		Some(match hypercall_port {
			HypercallAddress::FileClose => {
				let sysclose = mem_get_ref_mut::<CloseParams>(mem, data).unwrap();
				Hypercall::FileClose(sysclose)
			}
			HypercallAddress::FileLseek => {
				let syslseek = unsafe { mem_get_ref_mut::<LseekParams>(mem, data) }.unwrap();
				Hypercall::FileLseek(syslseek)
			}
			HypercallAddress::FileOpen => {
				let sysopen = unsafe { mem_get_ref_mut::<OpenParams>(mem, data) }.unwrap();
				Hypercall::FileOpen(sysopen)
			}
			HypercallAddress::FileRead => {
				let sysread = unsafe { mem_get_ref_mut::<ReadPrams>(mem, data) }.unwrap();
				Hypercall::FileRead(sysread)
			}
			HypercallAddress::FileWrite => {
				let syswrite = unsafe { mem_get_ref_mut(mem, data) }.unwrap();
				Hypercall::FileWrite(syswrite)
			}
			HypercallAddress::FileUnlink => {
				let sysunlink = unsafe { mem_get_ref_mut(mem, data) }.unwrap();
				Hypercall::FileUnlink(sysunlink)
			}
			HypercallAddress::Exit => {
				let sysexit = unsafe { mem_get_ref_mut(mem, data) }.unwrap();
				Hypercall::Exit(sysexit)
			}
			HypercallAddress::Cmdsize => {
				let syssize = unsafe { mem_get_ref_mut(mem, data) }.unwrap();
				Hypercall::Cmdsize(syssize)
			}
			HypercallAddress::Cmdval => {
				let syscmdval = unsafe { mem_get_ref_mut(mem, data) }.unwrap();
				Hypercall::Cmdval(syscmdval)
			}
			HypercallAddress::Uart => Hypercall::SerialWriteByte(data.as_u64() as u8),
			_ => unimplemented!(),
		})
	} else {
		None
	}
}

/// unlink deletes a name from the filesystem. This is used to handle `unlink` syscalls from the guest.
/// TODO: UNSAFE AS *%@#. It has to be checked that the VM is allowed to unlink that file!
pub fn unlink(mem: &GuestMemoryMmap, sysunlink: &mut UnlinkParams) {
	unsafe {
		sysunlink.ret = libc::unlink(
			mem.get_host_address(GuestAddress(sysunlink.name.as_u64()))
				.unwrap() as *const i8,
		);
	}
}

/// Handles an open syscall by opening a file on the host.
pub fn open(mem: &GuestMemoryMmap, sysopen: &mut OpenParams) {
	unsafe {
		sysopen.ret = libc::open(
			mem.get_host_address(GuestAddress(sysopen.name.as_u64()))
				.unwrap() as *const i8,
			sysopen.flags,
			sysopen.mode,
		);
	}
}

/// Handles an close syscall by closing the file on the host.
pub fn close(sysclose: &mut CloseParams) {
	unsafe {
		sysclose.ret = libc::close(sysclose.fd);
	}
}

/// Handles an read syscall on the host.
pub fn read(mem: &GuestMemoryMmap, sysread: &mut ReadPrams) {
	unsafe {
		let bytes_read = libc::read(
			sysread.fd,
			mem.get_host_address(GuestAddress(
				virt_to_phys(sysread.buf, mem, BOOT_PML4).unwrap().as_u64(),
			))
			.unwrap() as *mut libc::c_void,
			sysread.len,
		);
		if bytes_read >= 0 {
			sysread.ret = bytes_read;
		} else {
			sysread.ret = -1;
		}
	}
}

/// Handles an write syscall on the host.
pub fn write(mem: &GuestMemoryMmap, syswrite: &WriteParams) -> io::Result<()> {
	let mut bytes_written: usize = 0;
	while bytes_written != syswrite.len {
		unsafe {
			let step = libc::write(
				syswrite.fd,
				mem.get_host_address(GuestAddress(
					virt_to_phys(syswrite.buf + bytes_written as u64, mem, BOOT_PML4)
						.unwrap()
						.as_u64(),
				))
				.map_err(|e| match e {
					GuestMemoryError::InvalidGuestAddress(_) => {
						Error::new(ErrorKind::AddrNotAvailable, e.to_string())
					}
					e => Error::new(ErrorKind::Other, e.to_string()),
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

/// Handles an write syscall on the host.
pub fn lseek(syslseek: &mut LseekParams) {
	unsafe {
		syslseek.offset =
			libc::lseek(syslseek.fd, syslseek.offset as i64, syslseek.whence) as isize;
	}
}

/// Handles an UART syscall by writing to stdout.
pub fn uart(buf: &[u8]) -> io::Result<()> {
	io::stdout().write_all(buf)
}

/// Copies the arguments of the application into the VM's memory to the destinations specified in `syscmdval`.
pub fn copy_argv(path: &OsStr, argv: &[OsString], syscmdval: &CmdvalParams, mem: &GuestMemoryMmap) {
	// copy kernel path as first argument
	let argvp = mem
		.get_host_address(GuestAddress(syscmdval.argv.as_u64()))
		.expect("Systemcall parameters for Cmdval are invalid") as *const GuestPhysAddr;
	let arg_addrs = unsafe { std::slice::from_raw_parts(argvp, argv.len() + 1) };

	{
		let len = path.len();
		// Safety: we drop path_dest before anything else is done with mem
		let path_dest = unsafe {
			mem_as_slice(mem, arg_addrs[0], len + 1)
				.expect("Systemcall parameters for Cmdval are invalid")
		};

		path_dest[0..len].copy_from_slice(path.as_bytes());
		path_dest[len] = 0; // argv strings are zero terminated
	}

	// Copy the application arguments into the vm memory
	for (counter, argument) in argv.iter().enumerate() {
		let len = argument.as_bytes().len();
		let arg_dest = unsafe {
			mem_as_slice(mem, arg_addrs[counter], len + 1)
				.expect("Systemcall parameters for Cmdval are invalid")
		};
		arg_dest[0..len].copy_from_slice(argument.as_bytes());
		arg_dest[len] = 0;
	}
}

/// Copies the environment variables into the VM's memory to the destinations specified in `syscmdval`.
pub fn copy_env(syscmdval: &CmdvalParams, mem: &GuestMemoryMmap) {
	let env_len = std::env::vars_os().count();
	let envp = mem
		.get_host_address(GuestAddress(syscmdval.envp.as_u64()))
		.expect("Systemcall parameters for Cmdval are invalid") as *const GuestPhysAddr;
	let env_addrs = unsafe { std::slice::from_raw_parts(envp, env_len) };

	// Copy the environment variables into the vm memory
	for (counter, (key, value)) in std::env::vars_os().enumerate() {
		if counter >= MAX_ARGC_ENVC.try_into().unwrap() {
			warn!("Environment is larger than the maximum that can be copied to the VM. Remaining environment is ignored");
			break;
		}

		let len = key.len() + value.len() + 1;
		let env_dest = unsafe {
			mem_as_slice(mem, env_addrs[counter], len + 1)
				.expect("Systemcall parameters for Cmdval are invalid")
		};
		env_dest[0..key.len()].copy_from_slice(key.as_bytes());
		env_dest[key.len()] = b'=';
		env_dest[key.len() + 1..len].copy_from_slice(value.as_bytes());
		env_dest[len] = 0;
	}
}
