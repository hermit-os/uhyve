use std::{ffi::OsString, io, io::Write, mem, os::unix::ffi::OsStrExt, path::Path, slice};

use uhyve_interface::{
	parameters::*, GuestPhysAddr, GuestVirtAddr, Hypercall, HypercallAddress, MAX_ARGC_ENVC,
};

/// The trait and fns that a virtual cpu requires
use crate::{os::DebugExitInfo, HypervisorResult};

/// Reasons for vCPU exits.
pub enum VcpuStopReason {
	/// The vCPU stopped for debugging.
	Debug(DebugExitInfo),

	/// The vCPU exited with the specified exit code.
	Exit(i32),

	/// The vCPU got kicked.
	Kick,
}

/// Functionality a virtual CPU backend must provide to be used by uhyve
pub trait VirtualCPU {
	/// Initialize the cpu to start running the code ad entry_point.
	fn init(&mut self, entry_point: u64, stack_address: u64, cpu_id: u32) -> HypervisorResult<()>;

	/// Continues execution.
	fn r#continue(&mut self) -> HypervisorResult<VcpuStopReason>;

	/// Start the execution of the CPU. The function will run until it crashes (`Err`) or terminate with an exit code (`Ok`).
	fn run(&mut self) -> HypervisorResult<Option<i32>>;

	/// Prints the VCPU's registers to stdout.
	fn print_registers(&self);

	/// Translates an address from the VM's physical space into the hosts virtual space.
	fn host_address(&self, addr: GuestPhysAddr) -> usize;

	/// Looks up the guests pagetable and translates a guest's virtual address to a guest's physical address.
	fn virt_to_phys(&self, addr: GuestVirtAddr) -> GuestPhysAddr;

	/// Returns the (host) path of the kernel binary.
	fn kernel_path(&self) -> &Path;

	// TODO remove
	fn args(&self) -> &[OsString];

	/// `addr` is the address of the hypercall parameter in the guest's memory space. `data` is the
	/// parameter that was send to that address by the guest.
	///
	/// # Safety
	///
	/// - `data` must be a valid pointer to the data attached to the hypercall.
	/// - The return value is only valid, as long as the guest is halted.
	/// - This fn must not be called multiple times on the same data, to avoid creating mutable aliasing.
	unsafe fn address_to_hypercall(&self, addr: u16, data: GuestPhysAddr) -> Option<Hypercall<'_>> {
		if let Ok(hypercall_port) = HypercallAddress::try_from(addr) {
			Some(match hypercall_port {
				HypercallAddress::FileClose => {
					let sysclose = unsafe { &mut *(self.host_address(data) as *mut CloseParams) };
					Hypercall::FileClose(sysclose)
				}
				HypercallAddress::FileLseek => {
					let syslseek = unsafe { &mut *(self.host_address(data) as *mut LseekParams) };
					Hypercall::FileLseek(syslseek)
				}
				HypercallAddress::FileOpen => {
					let sysopen = unsafe { &mut *(self.host_address(data) as *mut OpenParams) };
					Hypercall::FileOpen(sysopen)
				}
				HypercallAddress::FileRead => {
					let sysread = unsafe { &mut *(self.host_address(data) as *mut ReadPrams) };
					Hypercall::FileRead(sysread)
				}
				HypercallAddress::FileWrite => {
					let syswrite = unsafe { &*(self.host_address(data) as *const WriteParams) };
					Hypercall::FileWrite(syswrite)
				}
				HypercallAddress::FileUnlink => {
					let sysunlink = unsafe { &mut *(self.host_address(data) as *mut UnlinkParams) };
					Hypercall::FileUnlink(sysunlink)
				}
				HypercallAddress::Exit => {
					let sysexit = unsafe { &*(self.host_address(data) as *const ExitParams) };
					Hypercall::Exit(sysexit)
				}
				HypercallAddress::Cmdsize => {
					let syssize = unsafe { &mut *(self.host_address(data) as *mut CmdsizeParams) };
					Hypercall::Cmdsize(syssize)
				}
				HypercallAddress::Cmdval => {
					let syscmdval = unsafe { &*(self.host_address(data) as *const CmdvalParams) };
					Hypercall::Cmdval(syscmdval)
				}
				HypercallAddress::Uart => Hypercall::SerialWriteByte(data.as_u64() as u8),
				_ => unimplemented!(),
			})
		} else {
			None
		}
	}

	fn cmdsize(&self, syssize: &mut CmdsizeParams) {
		syssize.argc = 0;
		syssize.envc = 0;

		let path = self.kernel_path();
		syssize.argsz[0] = path.as_os_str().len() as i32 + 1;

		let mut counter = 0;
		for argument in self.args() {
			syssize.argsz[(counter + 1) as usize] = argument.len() as i32 + 1;

			counter += 1;
		}

		syssize.argc = counter + 1;

		let mut counter = 0;
		for (key, value) in std::env::vars_os() {
			if counter < MAX_ARGC_ENVC.try_into().unwrap() {
				syssize.envsz[counter as usize] = (key.len() + value.len()) as i32 + 2;
				counter += 1;
			}
		}
		syssize.envc = counter;

		if counter >= MAX_ARGC_ENVC.try_into().unwrap() {
			warn!("Environment is too large!");
		}
	}

	/// Copies the arguments end environment of the application into the VM's memory.
	fn cmdval(&self, syscmdval: &CmdvalParams) {
		let argv = self.host_address(syscmdval.argv);

		// copy kernel path as first argument
		{
			let path = self.kernel_path().as_os_str();

			let argvptr =
				unsafe { self.host_address(GuestPhysAddr::new(*(argv as *mut *mut u8) as u64)) };
			let len = path.len();
			let slice = unsafe { slice::from_raw_parts_mut(argvptr as *mut u8, len + 1) };

			// Create string for environment variable
			slice[0..len].copy_from_slice(path.as_bytes());
			slice[len] = 0;
		}

		// Copy the application arguments into the vm memory
		for (counter, argument) in self.args().iter().enumerate() {
			let argvptr = unsafe {
				self.host_address(GuestPhysAddr::new(
					*((argv + (counter + 1) * mem::size_of::<usize>()) as *mut *mut u8) as u64,
				))
			};
			let len = argument.len();
			let slice = unsafe { slice::from_raw_parts_mut(argvptr as *mut u8, len + 1) };

			// Create string for environment variable
			slice[0..len].copy_from_slice(argument.as_bytes());
			slice[len] = 0;
		}

		// Copy the environment variables into the vm memory
		let mut counter = 0;
		let envp = self.host_address(syscmdval.envp);
		for (key, value) in std::env::vars_os() {
			if counter < MAX_ARGC_ENVC.try_into().unwrap() {
				let envptr = unsafe {
					self.host_address(GuestPhysAddr::new(
						*((envp + counter as usize * mem::size_of::<usize>()) as *mut *mut u8)
							as u64,
					))
				};
				let len = key.len() + value.len();
				let slice = unsafe { slice::from_raw_parts_mut(envptr as *mut u8, len + 2) };

				// Create string for environment variable
				slice[0..key.len()].copy_from_slice(key.as_bytes());
				slice[key.len()..(key.len() + 1)].copy_from_slice("=".as_bytes());
				slice[(key.len() + 1)..(len + 1)].copy_from_slice(value.as_bytes());
				slice[len + 1] = 0;
				counter += 1;
			}
		}
	}

	/// unlink deletes a name from the filesystem. This is used to handle `unlink` syscalls from the guest.
	/// TODO: UNSAFE AS *%@#. It has to be checked that the VM is allowed to unlink that file!
	fn unlink(&self, sysunlink: &mut UnlinkParams) {
		unsafe {
			sysunlink.ret = libc::unlink(self.host_address(sysunlink.name) as *const i8);
		}
	}

	/// Reads the exit code from an VM and returns it
	fn exit(&self, sysexit: &ExitParams) -> i32 {
		sysexit.arg
	}

	/// Handles an open syscall by opening a file on the host.
	fn open(&self, sysopen: &mut OpenParams) {
		unsafe {
			sysopen.ret = libc::open(
				self.host_address(sysopen.name) as *const i8,
				sysopen.flags,
				sysopen.mode,
			);
		}
	}

	/// Handles an close syscall by closing the file on the host.
	fn close(&self, sysclose: &mut CloseParams) {
		unsafe {
			sysclose.ret = libc::close(sysclose.fd);
		}
	}

	/// Handles an read syscall on the host.
	fn read(&self, sysread: &mut ReadPrams) {
		unsafe {
			let bytes_read = libc::read(
				sysread.fd,
				self.host_address(sysread.buf) as *mut libc::c_void,
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
	fn write(&self, syswrite: &WriteParams) -> io::Result<()> {
		let mut bytes_written: usize = 0;
		while bytes_written != syswrite.len {
			unsafe {
				let step = libc::write(
					syswrite.fd,
					self.host_address(syswrite.buf + bytes_written) as *const libc::c_void,
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
	fn lseek(&self, syslseek: &mut LseekParams) {
		unsafe {
			syslseek.offset =
				libc::lseek(syslseek.fd, syslseek.offset as i64, syslseek.whence) as isize;
		}
	}

	/// Handles an UART syscall by writing to stdout.
	fn uart(&self, buf: &[u8]) -> io::Result<()> {
		io::stdout().write_all(buf)
	}
}
