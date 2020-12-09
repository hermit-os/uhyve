use super::paging::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::_rdtsc as rdtsc;
use goblin::elf;
use goblin::elf64::header::{EM_X86_64, ET_DYN};
use goblin::elf64::program_header::{PT_LOAD, PT_TLS};
use goblin::elf64::reloc::*;
use log::{debug, error, warn};
use nix::errno::errno;
use raw_cpuid::CpuId;
use std::convert::TryInto;
use std::fs;
use std::net::Ipv4Addr;
use std::ptr::write;
use std::time::{Duration, Instant, SystemTime};
use std::{fmt, mem, slice};

use crate::consts::*;
use crate::debug_manager::DebugManager;
use crate::error::*;
#[cfg(target_os = "linux")]
pub use crate::linux::uhyve::*;
#[cfg(target_os = "macos")]
pub use crate::macos::uhyve::*;

const MHZ_TO_HZ: u64 = 1000000;
const KHZ_TO_HZ: u64 = 1000;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BootInfo {
	pub magic_number: u32,
	pub version: u32,
	pub base: u64,
	pub limit: u64,
	pub image_size: u64,
	pub tls_start: u64,
	pub tls_filesz: u64,
	pub tls_memsz: u64,
	pub current_stack_address: u64,
	pub current_percore_address: u64,
	pub host_logical_addr: u64,
	pub boot_gtod: u64,
	pub mb_info: u64,
	pub cmdline: u64,
	pub cmdsize: u64,
	pub cpu_freq: u32,
	pub boot_processor: u32,
	pub cpu_online: u32,
	pub possible_cpus: u32,
	pub current_boot_id: u32,
	pub uartport: u16,
	pub single_kernel: u8,
	pub uhyve: u8,
	pub hcip: [u8; 4],
	pub hcgateway: [u8; 4],
	pub hcmask: [u8; 4],
}

impl BootInfo {
	pub fn new() -> Self {
		BootInfo {
			magic_number: 0xC0DE_CAFEu32,
			version: 1,
			base: 0,
			limit: 0,
			tls_start: 0,
			tls_filesz: 0,
			tls_memsz: 0,
			image_size: 0,
			current_stack_address: 0,
			current_percore_address: 0,
			host_logical_addr: 0,
			boot_gtod: 0,
			mb_info: 0,
			cmdline: 0,
			cmdsize: 0,
			cpu_freq: 0,
			boot_processor: !0,
			cpu_online: 0,
			possible_cpus: 0,
			current_boot_id: 0,
			uartport: 0,
			single_kernel: 1,
			uhyve: 0,
			hcip: [255, 255, 255, 255],
			hcgateway: [255, 255, 255, 255],
			hcmask: [255, 255, 255, 0],
		}
	}
}

impl fmt::Debug for BootInfo {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		writeln!(f, "magic_number 0x{:x}", self.magic_number)?;
		writeln!(f, "version 0x{:x}", self.version)?;
		writeln!(f, "base 0x{:x}", self.base)?;
		writeln!(f, "limit 0x{:x}", self.limit)?;
		writeln!(f, "tls_start 0x{:x}", self.tls_start)?;
		writeln!(f, "tls_filesz 0x{:x}", self.tls_filesz)?;
		writeln!(f, "tls_memsz 0x{:x}", self.tls_memsz)?;
		writeln!(f, "image_size 0x{:x}", self.image_size)?;
		writeln!(
			f,
			"current_stack_address 0x{:x}",
			self.current_stack_address
		)?;
		writeln!(
			f,
			"current_percore_address 0x{:x}",
			self.current_percore_address
		)?;
		writeln!(f, "host_logical_addr 0x{:x}", self.host_logical_addr)?;
		writeln!(f, "boot_gtod 0x{:x}", self.boot_gtod)?;
		writeln!(f, "mb_info 0x{:x}", self.mb_info)?;
		writeln!(f, "cmdline 0x{:x}", self.cmdline)?;
		writeln!(f, "cmdsize 0x{:x}", self.cmdsize)?;
		writeln!(f, "cpu_freq {}", self.cpu_freq)?;
		writeln!(f, "boot_processor {}", self.boot_processor)?;
		writeln!(f, "cpu_online {}", self.cpu_online)?;
		writeln!(f, "possible_cpus {}", self.possible_cpus)?;
		writeln!(f, "current_boot_id {}", self.current_boot_id)?;
		writeln!(f, "uartport 0x{:x}", self.uartport)?;
		writeln!(f, "single_kernel {}", self.single_kernel)?;
		writeln!(f, "uhyve {}", self.uhyve)
	}
}

#[derive(Debug, Copy, Clone)]
pub struct Parameter<'a> {
	pub mem_size: usize,
	pub num_cpus: u32,
	pub verbose: bool,
	pub hugepage: bool,
	pub mergeable: bool,
	pub ip: Option<&'a str>,
	pub gateway: Option<&'a str>,
	pub mask: Option<&'a str>,
	pub nic: Option<&'a str>,
	pub gdbport: Option<u32>,
}

impl<'a> Parameter<'a> {
	pub fn new(
		mem_size: usize,
		num_cpus: u32,
		verbose: bool,
		hugepage: bool,
		mergeable: bool,
		ip: Option<&'a str>,
		gateway: Option<&'a str>,
		mask: Option<&'a str>,
		nic: Option<&'a str>,
		gdbport: Option<u32>,
	) -> Self {
		Parameter {
			mem_size,
			num_cpus,
			verbose,
			hugepage,
			mergeable,
			ip,
			gateway,
			mask,
			nic,
			gdbport,
		}
	}
}

#[repr(C, packed)]
struct SysWrite {
	fd: i32,
	buf: *const u8,
	len: usize,
}

#[repr(C, packed)]
struct SysRead {
	fd: i32,
	buf: *const u8,
	len: usize,
	ret: isize,
}

#[repr(C, packed)]
struct SysClose {
	fd: i32,
	ret: i32,
}

struct SysOpen {
	name: *const u8,
	flags: i32,
	mode: i32,
	ret: i32,
}

#[repr(C, packed)]
struct SysLseek {
	fd: i32,
	offset: isize,
	whence: i32,
}

#[repr(C, packed)]
struct SysExit {
	arg: i32,
}

// FIXME: Do not use a fix number of arguments
const MAX_ARGC: usize = 128;
// FIXME: Do not use a fix number of environment variables
const MAX_ENVC: usize = 128;

#[repr(C, packed)]
struct SysCmdsize {
	argc: i32,
	argsz: [i32; MAX_ARGC],
	envc: i32,
	envsz: [i32; MAX_ENVC],
}

#[repr(C, packed)]
struct SysCmdval {
	argv: *const u8,
	envp: *const u8,
}

#[repr(C, packed)]
struct SysUnlink {
	name: *const u8,
	ret: i32,
}

pub trait VirtualCPU {
	fn init(&mut self, entry_point: u64) -> Result<()>;
	fn run(&mut self) -> Result<()>;
	fn print_registers(&self);
	fn host_address(&self, addr: usize) -> usize;
	fn virt_to_phys(&self, addr: usize) -> usize;
	fn kernel_path(&self) -> String;

	fn cmdsize(&self, args_ptr: usize) -> Result<()> {
		let syssize = unsafe { &mut *(args_ptr as *mut SysCmdsize) };
		syssize.argc = 0;
		syssize.envc = 0;

		let mut counter: i32 = 0;
		let mut separator_pos: i32 = 0;
		let path = self.kernel_path();
		let mut found_separator = false;
		syssize.argsz[0] = path.len() as i32 + 1;

		for argument in std::env::args() {
			if !found_separator && argument == "--" {
				separator_pos = counter + 1;
				found_separator = true;
			}

			if found_separator && counter >= separator_pos {
				syssize.argsz[(counter - separator_pos + 1) as usize] = argument.len() as i32 + 1;
			}

			counter += 1;
		}

		if found_separator && counter >= separator_pos {
			syssize.argc = counter - separator_pos + 1;
		} else {
			syssize.argc = 1;
		}

		counter = 0;
		for (key, value) in std::env::vars() {
			if counter < MAX_ENVC.try_into().unwrap() {
				syssize.envsz[counter as usize] = (key.len() + value.len()) as i32 + 2;
				counter += 1;
			}
		}
		syssize.envc = counter;

		if counter >= MAX_ENVC.try_into().unwrap() {
			warn!("Environment is too large!");
		}

		Ok(())
	}

	fn cmdval(&self, args_ptr: usize) -> Result<()> {
		let syscmdval = unsafe { &*(args_ptr as *const SysCmdval) };

		let mut counter: i32 = 0;
		let argv = self.host_address(syscmdval.argv as usize);
		let mut found_separator = false;
		let mut separator_pos: i32 = 0;

		// copy kernel path as first argument
		{
			let path = self.kernel_path();

			let argvptr = unsafe { self.host_address(*(argv as *mut *mut u8) as usize) };
			let len = path.len();
			let slice = unsafe { slice::from_raw_parts_mut(argvptr as *mut u8, len + 1) };

			// Create string for environment variable
			slice[0..len].copy_from_slice(path.as_bytes());
			slice[len] = 0;
		}

		for argument in std::env::args() {
			if !found_separator && argument == "--" {
				separator_pos = counter + 1;
				found_separator = true;
			}

			if found_separator && counter >= separator_pos {
				let argvptr = unsafe {
					self.host_address(
						*((argv + (counter - separator_pos + 1) as usize * mem::size_of::<usize>())
							as *mut *mut u8) as usize,
					)
				};
				let len = argument.len();
				let slice = unsafe { slice::from_raw_parts_mut(argvptr as *mut u8, len + 1) };

				// Create string for environment variable
				slice[0..len].copy_from_slice(argument.as_bytes());
				slice[len] = 0;
			}

			counter += 1;
		}

		counter = 0;
		let envp = self.host_address(syscmdval.envp as usize);
		for (key, value) in std::env::vars() {
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
				slice[key.len()..(key.len() + 1)].copy_from_slice(&"=".to_string().as_bytes());
				slice[(key.len() + 1)..(len + 1)].copy_from_slice(value.as_bytes());
				slice[len + 1] = 0;
				counter += 1;
			}
		}

		Ok(())
	}

	fn unlink(&self, args_ptr: usize) -> Result<()> {
		unsafe {
			let sysunlink = &mut *(args_ptr as *mut SysUnlink);
			sysunlink.ret = libc::unlink(self.host_address(sysunlink.name as usize) as *const i8);
		}

		Ok(())
	}

	fn exit(&self, args_ptr: usize) -> ! {
		let sysexit = unsafe { &*(args_ptr as *const SysExit) };
		std::process::exit(sysexit.arg);
	}

	fn open(&self, args_ptr: usize) -> Result<()> {
		unsafe {
			let sysopen = &mut *(args_ptr as *mut SysOpen);
			sysopen.ret = libc::open(
				self.host_address(sysopen.name as usize) as *const i8,
				sysopen.flags,
				sysopen.mode,
			);
		}

		Ok(())
	}

	fn close(&self, args_ptr: usize) -> Result<()> {
		unsafe {
			let sysclose = &mut *(args_ptr as *mut SysClose);
			sysclose.ret = libc::close(sysclose.fd);
		}

		Ok(())
	}

	fn read(&self, args_ptr: usize) -> Result<()> {
		unsafe {
			let sysread = &mut *(args_ptr as *mut SysRead);
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

		Ok(())
	}

	fn write(&self, args_ptr: usize) -> Result<()> {
		let syswrite = unsafe { &*(args_ptr as *const SysWrite) };
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
					return Err(Error::OsError(errno()));
				}
			}
		}

		Ok(())
	}

	fn lseek(&self, args_ptr: usize) -> Result<()> {
		unsafe {
			let syslseek = &mut *(args_ptr as *mut SysLseek);
			syslseek.offset =
				libc::lseek(syslseek.fd, syslseek.offset as i64, syslseek.whence) as isize;
		}

		Ok(())
	}

	fn uart(&self, message: String) -> Result<()> {
		print!("{}", message);
		//io::stdout().flush().ok().expect("Could not flush stdout");

		Ok(())
	}
}

// Constructor for a conventional segment GDT (or LDT) entry
fn create_gdt_entry(flags: u64, base: u64, limit: u64) -> u64 {
	((base & 0xff000000u64) << (56 - 24))
		| ((flags & 0x0000f0ffu64) << 40)
		| ((limit & 0x000f0000u64) << (48 - 16))
		| ((base & 0x00ffffffu64) << 16)
		| (limit & 0x0000ffffu64)
}

pub trait Vm {
	fn num_cpus(&self) -> u32;
	fn guest_mem(&self) -> (*mut u8, usize);
	fn set_entry_point(&mut self, entry: u64);
	fn get_entry_point(&self) -> u64;
	fn kernel_path(&self) -> &str;
	fn create_cpu(&self, id: u32) -> Result<Box<dyn VirtualCPU>>;
	fn set_boot_info(&mut self, header: *const BootInfo);
	fn cpu_online(&self) -> u32;
	fn get_ip(&self) -> Option<Ipv4Addr>;
	fn get_gateway(&self) -> Option<Ipv4Addr>;
	fn get_mask(&self) -> Option<Ipv4Addr>;
	fn verbose(&self) -> bool;

	/// Initialize the page tables for the guest
	fn init_guest_mem(&self) {
		debug!("Initialize guest memory");

		let (mem_addr, _) = self.guest_mem();

		unsafe {
			let pml4 = &mut *((mem_addr as u64 + BOOT_PML4) as *mut PageTable);
			let pdpte = &mut *((mem_addr as u64 + BOOT_PDPTE) as *mut PageTable);
			let pde = &mut *((mem_addr as u64 + BOOT_PDE) as *mut PageTable);
			let gdt_entry: u64 = mem_addr as u64 + BOOT_GDT;

			// initialize GDT
			*((gdt_entry) as *mut u64) = create_gdt_entry(0, 0, 0);
			*((gdt_entry + mem::size_of::<*mut u64>() as u64) as *mut u64) =
				create_gdt_entry(0xA09B, 0, 0xFFFFF); /* code */
			*((gdt_entry + 2 * mem::size_of::<*mut u64>() as u64) as *mut u64) =
				create_gdt_entry(0xC093, 0, 0xFFFFF); /* data */

			/* For simplicity we currently use 2MB pages and only a single
			PML4/PDPTE/PDE. */

			// per default is the memory zeroed, which we allocate by the system call mmap
			/*libc::memset(pml4 as *mut _ as *mut libc::c_void, 0x00, PAGE_SIZE);
			libc::memset(pdpte as *mut _ as *mut libc::c_void, 0x00, PAGE_SIZE);
			libc::memset(pde as *mut _ as *mut libc::c_void, 0x00, PAGE_SIZE);*/

			pml4.entries[0].set(
				BOOT_PDPTE as usize,
				PageTableEntryFlags::PRESENT | PageTableEntryFlags::WRITABLE,
			);
			pml4.entries[511].set(
				BOOT_PML4 as usize,
				PageTableEntryFlags::PRESENT | PageTableEntryFlags::WRITABLE,
			);
			pdpte.entries[0].set(
				BOOT_PDE as usize,
				PageTableEntryFlags::PRESENT | PageTableEntryFlags::WRITABLE,
			);

			for i in 0..512 {
				pde.entries[i].set(
					i * LargePageSize::SIZE,
					PageTableEntryFlags::PRESENT
						| PageTableEntryFlags::WRITABLE
						| PageTableEntryFlags::HUGE_PAGE,
				);
			}
		}
	}

	unsafe fn load_kernel(&mut self) -> Result<()> {
		debug!("Load kernel from {}", self.kernel_path());

		let buffer = fs::read(self.kernel_path())
			.map_err(|_| Error::InvalidFile(self.kernel_path().into()))?;
		let elf =
			elf::Elf::parse(&buffer).map_err(|_| Error::InvalidFile(self.kernel_path().into()))?;

		if elf.libraries.len() > 0 {
			warn!(
				"Error: file depends on following libraries: {:?}",
				elf.libraries
			);
			return Err(Error::InvalidFile(self.kernel_path().into()));
		}

		let is_dyn = elf.header.e_type == ET_DYN;
		if is_dyn {
			debug!("ELF file is a shared object file");
		}

		if elf.header.e_machine != EM_X86_64 {
			return Err(Error::InvalidFile(self.kernel_path().into()));
		}

		// acquire the slices of the user memory
		let (vm_mem, vm_mem_length) = self.guest_mem();

		// create default bootinfo
		#[allow(clippy::cast_ptr_alignment)]
		let boot_info = vm_mem.offset(BOOT_INFO_ADDR as isize) as *mut BootInfo;
		*boot_info = BootInfo::new();

		// forward IP address to kernel
		if let Some(ip) = self.get_ip() {
			write(&mut (*boot_info).hcip, ip.octets());
		}

		// forward gateway address to kernel
		if let Some(gateway) = self.get_gateway() {
			write(&mut (*boot_info).hcgateway, gateway.octets());
		}

		// forward mask to kernel
		if let Some(mask) = self.get_mask() {
			write(&mut (*boot_info).hcmask, mask.octets());
		}

		let (start_address, elf_entry) = if is_dyn {
			// TODO: should be a random start address, if we have a relocatable executable
			(0x400000u64, 0x400000u64 + elf.entry)
		} else {
			// default location of a non-relocatable binary
			(0x800000u64, elf.entry)
		};

		self.set_entry_point(elf_entry);
		debug!("ELF entry point at 0x{:x}", elf_entry);

		debug!("Set HermitCore header at 0x{:x}", BOOT_INFO_ADDR as usize);
		self.set_boot_info(boot_info);

		write(&mut (*boot_info).base, start_address);
		write(&mut (*boot_info).limit, vm_mem_length as u64); // memory size
		write(&mut (*boot_info).possible_cpus, 1);
		#[cfg(target_os = "linux")]
		write(&mut (*boot_info).uhyve, 0x3); // announce uhyve and pci support
		#[cfg(not(target_os = "linux"))]
		write(&mut (*boot_info).uhyve, 0x1); // announce uhyve
		write(&mut (*boot_info).current_boot_id, 0);
		if self.verbose() {
			write(&mut (*boot_info).uartport, UHYVE_UART_PORT);
		} else {
			write(&mut (*boot_info).uartport, 0);
		}

		debug!(
			"Set stack base to 0x{:x}",
			start_address - KERNEL_STACK_SIZE
		);
		write(
			&mut (*boot_info).current_stack_address,
			start_address - KERNEL_STACK_SIZE,
		);

		write(&mut (*boot_info).host_logical_addr, vm_mem.offset(0) as u64);

		match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
			Ok(n) => write(&mut (*boot_info).boot_gtod, n.as_secs() * 1000000),
			Err(err) => panic!("SystemTime before UNIX EPOCH! Error: {}", err),
		}

		let cpuid = CpuId::new();
		let mhz: u32 = detect_freq_from_cpuid(&cpuid).unwrap_or_else(|_| {
			debug!("Failed to detect from cpuid");
			detect_freq_from_cpuid_hypervisor_info(&cpuid).unwrap_or_else(|_| {
				debug!("Failed to detect from hypervisor_info");
				get_cpu_frequency_from_os().unwrap_or(0)
			})
		});
		debug!("detected a cpu frequency of {} Mhz", mhz);
		write(&mut (*boot_info).cpu_freq, mhz);
		if (*boot_info).cpu_freq == 0 {
			warn!("Unable to determine processor frequency");
		}

		// load kernel and determine image size
		let vm_slice = std::slice::from_raw_parts_mut(vm_mem, vm_mem_length);
		let mut image_size = 0;
		elf.program_headers
			.iter()
			.try_for_each(|program_header| match program_header.p_type {
				PT_LOAD => {
					let region_start = if is_dyn {
						(start_address + program_header.p_vaddr) as usize
					} else {
						program_header.p_vaddr as usize
					};
					let region_end = region_start + program_header.p_filesz as usize;
					let kernel_start = program_header.p_offset as usize;
					let kernel_end = kernel_start + program_header.p_filesz as usize;

					debug!(
						"Load segment with start addr 0x{:x} and size 0x{:x}, offset 0x{:x}",
						program_header.p_vaddr, program_header.p_filesz, program_header.p_offset
					);

					if region_start + program_header.p_memsz as usize > vm_mem_length {
						error!("Guest memory size isn't large enough");
						return Err(Error::NotEnoughMemory);
					}

					vm_slice[region_start..region_end]
						.copy_from_slice(&buffer[kernel_start..kernel_end]);
					for i in &mut vm_slice[region_end
						..region_end + (program_header.p_memsz - program_header.p_filesz) as usize]
					{
						*i = 0
					}

					image_size = if is_dyn {
						program_header.p_vaddr + program_header.p_memsz
					} else {
						image_size + program_header.p_memsz
					};
					write(&mut (*boot_info).image_size, image_size);

					Ok(())
				}
				PT_TLS => {
					// determine TLS section
					debug!("Found TLS section with size {}", program_header.p_memsz);
					let tls_start = if is_dyn {
						start_address + program_header.p_vaddr
					} else {
						program_header.p_vaddr
					};

					write(&mut (*boot_info).tls_start, tls_start);
					write(&mut (*boot_info).tls_filesz, program_header.p_filesz);
					write(&mut (*boot_info).tls_memsz, program_header.p_memsz);

					Ok(())
				}
				_ => Ok(()),
			})?;

		// relocate entries (strings, copy-data, etc.) with an addend
		elf.dynrelas.iter().for_each(|rela| match rela.r_type {
			R_X86_64_RELATIVE => {
				let offset = (vm_mem as u64 + start_address + rela.r_offset) as *mut u64;
				*offset = (start_address as i64 + rela.r_addend.unwrap_or(0)) as u64;
			}
			_ => {
				debug!("Unsupported relocation type {}", rela.r_type);
			}
		});

		// debug!("Boot header: {:?}", *boot_info);

		debug!("Kernel loaded");

		Ok(())
	}
}

fn detect_freq_from_cpuid(cpuid: &CpuId) -> std::result::Result<u32, ()> {
	debug!("Trying to detect CPU frequency by tsc info");

	let has_invariant_tsc = cpuid
		.get_extended_function_info()
		.map_or(false, |efinfo| efinfo.has_invariant_tsc());
	if !has_invariant_tsc {
		warn!("TSC frequency varies with speed-stepping")
	}

	let tsc_frequency_hz = cpuid.get_tsc_info().map(|tinfo| {
		if tinfo.tsc_frequency().is_some() {
			tinfo.tsc_frequency()
		} else {
			// Skylake and Kabylake don't report the crystal clock, approximate with base frequency:
			cpuid
				.get_processor_frequency_info()
				.map(|pinfo| pinfo.processor_base_frequency() as u64 * MHZ_TO_HZ)
				.map(|cpu_base_freq_hz| {
					let crystal_hz =
						cpu_base_freq_hz * tinfo.denominator() as u64 / tinfo.numerator() as u64;
					crystal_hz * tinfo.numerator() as u64 / tinfo.denominator() as u64
				})
		}
	});

	let hz = match tsc_frequency_hz {
		Some(x) => x.unwrap_or(0),
		None => {
			return Err(());
		}
	};

	if hz > 0 {
		Ok((hz / MHZ_TO_HZ).try_into().unwrap())
	} else {
		Err(())
	}
}

fn detect_freq_from_cpuid_hypervisor_info(cpuid: &CpuId) -> std::result::Result<u32, ()> {
	debug!("Trying to detect CPU frequency by hypervisor info");
	let hypervisor_info = cpuid.get_hypervisor_info().ok_or(())?;
	debug!(
		"cpuid detected hypervisor: {:?}",
		hypervisor_info.identify()
	);
	let hz = hypervisor_info.tsc_frequency().ok_or(())? as u64 * KHZ_TO_HZ;
	let mhz: u32 = (hz / MHZ_TO_HZ).try_into().unwrap();
	if mhz > 0 {
		Ok(mhz)
	} else {
		Err(())
	}
}

fn get_cpu_frequency_from_os() -> std::result::Result<u32, ()> {
	// Determine TSC frequency by measuring it (loop for a second, record ticks)
	let duration = Duration::from_millis(10);
	let now = Instant::now();
	let start = unsafe { rdtsc() };
	if start > 0 {
		loop {
			if now.elapsed() >= duration {
				break;
			}
		}
		let end = unsafe { rdtsc() };
		Ok((((end - start) * 100) / MHZ_TO_HZ).try_into().unwrap())
	} else {
		Err(())
	}
}

#[cfg(test)]
mod tests {
	#[cfg(target_os = "linux")]
	use crate::linux::tests::has_vm_support;

	use super::*;

	// test is derived from
	// https://github.com/gz/rust-cpuid/blob/master/examples/tsc_frequency.rs
	#[test]
	fn test_detect_freq_from_cpuid() {
		let cpuid = CpuId::new();
		let has_tsc = cpuid
			.get_feature_info()
			.map_or(false, |finfo| finfo.has_tsc());

		let has_invariant_tsc = cpuid
			.get_extended_function_info()
			.map_or(false, |efinfo| efinfo.has_invariant_tsc());

		let tsc_frequency_hz = cpuid.get_tsc_info().map(|tinfo| {
			if tinfo.tsc_frequency().is_some() {
				tinfo.tsc_frequency()
			} else {
				// Skylake and Kabylake don't report the crystal clock, approximate with base frequency:
				cpuid
					.get_processor_frequency_info()
					.map(|pinfo| pinfo.processor_base_frequency() as u64 * MHZ_TO_HZ)
					.map(|cpu_base_freq_hz| {
						let crystal_hz = cpu_base_freq_hz * tinfo.denominator() as u64
							/ tinfo.numerator() as u64;
						crystal_hz * tinfo.numerator() as u64 / tinfo.denominator() as u64
					})
			}
		});

		if has_tsc {
			// Try to figure out TSC frequency with CPUID
			println!(
				"TSC Frequency is: {} ({})",
				match tsc_frequency_hz {
					Some(x) => format!("{} Hz", x.unwrap_or(0)),
					None => String::from("unknown"),
				},
				if has_invariant_tsc {
					"invariant"
				} else {
					"TSC frequency varies with speed-stepping"
				}
			);

			// Check if we run in a VM and the hypervisor can give us the TSC frequency
			cpuid.get_hypervisor_info().map(|hv| {
				hv.tsc_frequency().map(|tsc_khz| {
					let virtual_tsc_frequency_hz = tsc_khz as u64 * KHZ_TO_HZ;
					println!(
						"Hypervisor reports TSC Frequency at: {} Hz",
						virtual_tsc_frequency_hz
					);
				})
			});

			// Determine TSC frequency by measuring it (loop for a second, record ticks)
			let one_second = Duration::from_secs(1);
			let now = Instant::now();
			let start = unsafe { rdtsc() };
			if start > 0 {
				loop {
					if now.elapsed() >= one_second {
						break;
					}
				}
				let end = unsafe { rdtsc() };
				println!(
					"Empirical measurement of TSC frequency was: {} Hz",
					(end - start)
				);
			} else {
				panic!("Don't have rdtsc on stable!");
			}
		} else {
			panic!("System does not have a TSC.");
		}
	}

	#[test]
	fn test_get_cpu_frequency_from_os() {
		let freq_res = get_cpu_frequency_from_os();
		assert!(freq_res.is_ok());
		let freq = freq_res.unwrap();
		assert!(freq > 0);
		assert!(freq < 10000); //More than 10Ghz is probably wrong
	}

	#[cfg(target_os = "linux")]
	#[test]
	fn test_vm_load_min_size_1024() {
		if !has_vm_support() {
			return;
		}

		let path =
			env!("CARGO_MANIFEST_DIR").to_string() + &"/benches_data/hello_world".to_string();
		let vm = create_vm(
			path,
			&Parameter::new(
				1024,
				1,
				false,
				true,
				false,
				std::option::Option::None,
				std::option::Option::None,
				std::option::Option::None,
				std::option::Option::None,
				std::option::Option::None,
			),
		);
		assert_eq!(vm.is_err(), true);
	}

	#[cfg(target_os = "linux")]
	#[test]
	fn test_vm_load_min_size_102400() {
		if !has_vm_support() {
			return;
		}

		let path =
			env!("CARGO_MANIFEST_DIR").to_string() + &"/benches_data/hello_world".to_string();
		let mut vm = create_vm(
			path,
			&Parameter::new(
				102400,
				1,
				false,
				true,
				false,
				std::option::Option::None,
				std::option::Option::None,
				std::option::Option::None,
				std::option::Option::None,
				std::option::Option::None,
			),
		)
		.expect("Unable to create VM");
		unsafe {
			let res = vm.load_kernel();

			assert_eq!(res.is_err(), true);
		}
	}
}

#[cfg(not(target_os = "windows"))]
pub fn create_vm(path: String, specs: &super::vm::Parameter) -> Result<Uhyve> {
	// If we are given a port, create new DebugManager.
	let gdb = specs.gdbport.map(|port| DebugManager::new(port).unwrap());

	let vm = Uhyve::new(path, &specs, gdb)?;

	Ok(vm)
}

#[cfg(target_os = "windows")]
pub fn create_vm(path: String, specs: &super::vm::Parameter) -> Result<Uhyve> {
	let vm = Uhyve::new(path.clone(), &specs)?;

	Ok(vm)
}
