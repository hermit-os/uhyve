use hermit_entry::{
	boot_info::{BootInfo, HardwareInfo, PlatformInfo, RawBootInfo, SerialPortBase},
	elf::{KernelObject, LoadedKernel, ParseKernelError},
};
use log::{error, warn};
use std::ffi::OsString;
use std::io::Write;
use std::mem::MaybeUninit;
use std::num::NonZeroU32;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::SystemTime;
use std::{fs, io, mem, slice};
use thiserror::Error;

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::{
	detect_freq_from_cpuid, detect_freq_from_cpuid_hypervisor_info, get_cpu_frequency_from_os,
};

use crate::os::vcpu::UhyveCPU;
use crate::os::DebugExitInfo;
use crate::os::HypervisorError;
use crate::{arch, consts::*};

#[repr(C, packed)]
pub struct SysWrite {
	fd: i32,
	buf: *const u8,
	len: usize,
}

#[repr(C, packed)]
pub struct SysRead {
	fd: i32,
	buf: *const u8,
	len: usize,
	ret: isize,
}

#[repr(C, packed)]
pub struct SysClose {
	fd: i32,
	ret: i32,
}

#[repr(C, packed)]
pub struct SysOpen {
	name: *const u8,
	flags: i32,
	mode: i32,
	ret: i32,
}

#[repr(C, packed)]
pub struct SysLseek {
	fd: i32,
	offset: isize,
	whence: i32,
}

#[repr(C, packed)]
pub struct SysExit {
	arg: i32,
}

// FIXME: Do not use a fix number of arguments
const MAX_ARGC: usize = 128;
// FIXME: Do not use a fix number of environment variables
const MAX_ENVC: usize = 128;

#[repr(C, packed)]
pub struct SysCmdsize {
	argc: i32,
	argsz: [i32; MAX_ARGC],
	envc: i32,
	envsz: [i32; MAX_ENVC],
}

#[repr(C, packed)]
pub struct SysCmdval {
	argv: *const u8,
	envp: *const u8,
}

#[repr(C, packed)]
pub struct SysUnlink {
	name: *const u8,
	ret: i32,
}

pub type HypervisorResult<T> = Result<T, HypervisorError>;

#[derive(Error, Debug)]
pub enum LoadKernelError {
	#[error(transparent)]
	Io(#[from] io::Error),
	#[error("{0}")]
	ParseKernelError(ParseKernelError),
	#[error("guest memory size is not large enough")]
	InsufficientMemory,
}

pub type LoadKernelResult<T> = Result<T, LoadKernelError>;

/// Reasons for vCPU exits.
pub enum VcpuStopReason {
	/// The vCPU stopped for debugging.
	Debug(DebugExitInfo),

	/// The vCPU exited with the specified exit code.
	Exit(i32),

	/// The vCPU got kicked.
	Kick,
}

pub trait VirtualCPU {
	/// Initialize the cpu to start running the code ad entry_point.
	fn init(&mut self, entry_point: u64, cpu_id: u32) -> HypervisorResult<()>;

	/// Continues execution.
	fn r#continue(&mut self) -> HypervisorResult<VcpuStopReason>;

	/// Start the execution of the CPU. The function will run until it crashes (`Err`) or terminate with an exit code (`Ok`).
	fn run(&mut self) -> HypervisorResult<Option<i32>>;

	/// Prints the VCPU's registers to stdout.
	fn print_registers(&self);

	/// Translates an address from the VM's physical space into the hosts virtual space.
	fn host_address(&self, addr: usize) -> usize;

	/// Looks up the guests pagetable and translates a guest's virtual address to a guest's physical address.
	fn virt_to_phys(&self, addr: usize) -> usize;

	/// Returns the (host) path of the kernel binary.
	fn kernel_path(&self) -> &Path;

	fn args(&self) -> &[OsString];

	fn cmdsize(&self, syssize: &mut SysCmdsize) {
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
			if counter < MAX_ENVC.try_into().unwrap() {
				syssize.envsz[counter as usize] = (key.len() + value.len()) as i32 + 2;
				counter += 1;
			}
		}
		syssize.envc = counter;

		if counter >= MAX_ENVC.try_into().unwrap() {
			warn!("Environment is too large!");
		}
	}

	/// Copies the arguments end environment of the application into the VM's memory.
	fn cmdval(&self, syscmdval: &SysCmdval) {
		let argv = self.host_address(syscmdval.argv as usize);

		// copy kernel path as first argument
		{
			let path = self.kernel_path().as_os_str();

			let argvptr = unsafe { self.host_address(*(argv as *mut *mut u8) as usize) };
			let len = path.len();
			let slice = unsafe { slice::from_raw_parts_mut(argvptr as *mut u8, len + 1) };

			// Create string for environment variable
			slice[0..len].copy_from_slice(path.as_bytes());
			slice[len] = 0;
		}

		// Copy the application arguments into the vm memory
		for (counter, argument) in self.args().iter().enumerate() {
			let argvptr = unsafe {
				self.host_address(
					*((argv + (counter + 1) as usize * mem::size_of::<usize>()) as *mut *mut u8)
						as usize,
				)
			};
			let len = argument.len();
			let slice = unsafe { slice::from_raw_parts_mut(argvptr as *mut u8, len + 1) };

			// Create string for environment variable
			slice[0..len].copy_from_slice(argument.as_bytes());
			slice[len] = 0;
		}

		// Copy the environment variables into the vm memory
		let mut counter = 0;
		let envp = self.host_address(syscmdval.envp as usize);
		for (key, value) in std::env::vars_os() {
			if counter < MAX_ENVC.try_into().unwrap() {
				let envptr = unsafe {
					self.host_address(
						*((envp + counter as usize * mem::size_of::<usize>()) as *mut *mut u8)
							as usize,
					)
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
	fn unlink(&self, sysunlink: &mut SysUnlink) {
		unsafe {
			sysunlink.ret = libc::unlink(self.host_address(sysunlink.name as usize) as *const i8);
		}
	}

	/// Reads the exit code from an VM and returns it
	fn exit(&self, sysexit: &SysExit) -> i32 {
		sysexit.arg
	}

	/// Handles an open syscall by opening a file on the host.
	fn open(&self, sysopen: &mut SysOpen) {
		unsafe {
			sysopen.ret = libc::open(
				self.host_address(sysopen.name as usize) as *const i8,
				sysopen.flags,
				sysopen.mode,
			);
		}
	}

	/// Handles an close syscall by closing the file on the host.
	fn close(&self, sysclose: &mut SysClose) {
		unsafe {
			sysclose.ret = libc::close(sysclose.fd);
		}
	}

	/// Handles an read syscall on the host.
	fn read(&self, sysread: &mut SysRead) {
		unsafe {
			let buffer = self.virt_to_phys(sysread.buf as usize);

			let bytes_read = libc::read(
				sysread.fd,
				self.host_address(buffer) as *mut libc::c_void,
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
	fn write(&self, syswrite: &SysWrite) -> io::Result<()> {
		let mut bytes_written: usize = 0;
		let buffer = self.virt_to_phys(syswrite.buf as usize);

		while bytes_written != syswrite.len {
			unsafe {
				let step = libc::write(
					syswrite.fd,
					self.host_address(buffer + bytes_written) as *const libc::c_void,
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
	fn lseek(&self, syslseek: &mut SysLseek) {
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

pub trait Vm {
	/// Returns the number of cores for the vm.
	fn num_cpus(&self) -> u32;
	/// Returns a pointer to the address of the guest memory and the size of the memory in bytes.
	fn guest_mem(&self) -> (*mut u8, usize);
	#[doc(hidden)]
	fn set_offset(&mut self, offset: u64);
	/// Returns the section offsets relative to their base addresses
	fn get_offset(&self) -> u64;
	/// Sets the elf entry point.
	fn set_entry_point(&mut self, entry: u64);
	fn get_entry_point(&self) -> u64;
	fn kernel_path(&self) -> &Path;
	fn create_cpu(&self, id: u32) -> HypervisorResult<UhyveCPU>;
	fn set_boot_info(&mut self, header: *const RawBootInfo);
	fn verbose(&self) -> bool;
	fn init_guest_mem(&self);

	unsafe fn load_kernel(&mut self) -> LoadKernelResult<()> {
		let elf = fs::read(self.kernel_path())?;
		let object = KernelObject::parse(&elf).map_err(LoadKernelError::ParseKernelError)?;

		// TODO: should be a random start address, if we have a relocatable executable
		let start_address = object.start_addr().unwrap_or(0x400000);
		self.set_offset(start_address);

		let (vm_mem, vm_mem_len) = self.guest_mem();
		if start_address as usize + object.mem_size() > vm_mem_len {
			return Err(LoadKernelError::InsufficientMemory);
		}

		let vm_slice = {
			let vm_slice = slice::from_raw_parts_mut(vm_mem as *mut MaybeUninit<u8>, vm_mem_len);
			&mut vm_slice[start_address as usize..][..object.mem_size()]
		};

		let LoadedKernel {
			load_info,
			entry_point,
		} = object.load_kernel(vm_slice, start_address);
		self.set_entry_point(entry_point);

		let boot_info = BootInfo {
			hardware_info: HardwareInfo {
				phys_addr_range: arch::RAM_START..arch::RAM_START + vm_mem_len as u64,
				serial_port_base: self
					.verbose()
					.then(|| SerialPortBase::new(UHYVE_UART_PORT.into()).unwrap()),
			},
			load_info,
			platform_info: PlatformInfo::Uhyve {
				has_pci: cfg!(target_os = "linux"),
				num_cpus: u64::from(self.num_cpus()).try_into().unwrap(),
				cpu_freq: NonZeroU32::new(detect_cpu_freq() * 1000),
				boot_time: SystemTime::now().into(),
			},
		};
		let raw_boot_info_ptr = vm_mem.add(BOOT_INFO_ADDR as usize) as *mut RawBootInfo;
		*raw_boot_info_ptr = {
			let raw_boot_info = RawBootInfo::from(boot_info);
			raw_boot_info.store_current_stack_address(start_address - KERNEL_STACK_SIZE);
			raw_boot_info
		};
		self.set_boot_info(raw_boot_info_ptr);

		Ok(())
	}
}

fn detect_cpu_freq() -> u32 {
	#[cfg(target_arch = "aarch64")]
	let mhz: u32 = 0;
	#[cfg(target_arch = "x86_64")]
	let mhz = {
		let cpuid = raw_cpuid::CpuId::new();
		let mhz: u32 = detect_freq_from_cpuid(&cpuid).unwrap_or_else(|_| {
			debug!("Failed to detect from cpuid");
			detect_freq_from_cpuid_hypervisor_info(&cpuid).unwrap_or_else(|_| {
				debug!("Failed to detect from hypervisor_info");
				get_cpu_frequency_from_os().unwrap_or(0)
			})
		});
		debug!("detected a cpu frequency of {} Mhz", mhz);

		mhz
	};
	if mhz == 0 {
		warn!("Unable to determine processor frequency");
	}
	mhz
}
