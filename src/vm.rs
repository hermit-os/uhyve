use super::paging::*;
use elf;
use elf::types::{ELFCLASS64, EM_X86_64, ET_EXEC, PT_LOAD, PT_TLS};
use libc;
use memmap::Mmap;
use nix::errno::errno;
use raw_cpuid::CpuId;
use regex::Regex;
use std;
use std::fs::File;
use std::io::Cursor;
use std::io::Read;
use std::net::Ipv4Addr;
use std::process::Command;
use std::ptr::write_volatile;
use std::time::SystemTime;
use std::{fmt, mem, slice};

use crate::consts::*;
use crate::debug_manager::DebugManager;
use crate::error::*;
#[cfg(target_os = "linux")]
pub use crate::linux::uhyve::*;
#[cfg(target_os = "macos")]
pub use crate::macos::uhyve::*;

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
pub struct VmParameter<'a> {
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

impl<'a> VmParameter<'a> {
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
		VmParameter {
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

const MAX_ARGC_ENVC: usize = 128;

#[repr(C, packed)]
struct SysCmdsize {
	argc: i32,
	argsz: [i32; MAX_ARGC_ENVC],
	envc: i32,
	envsz: [i32; MAX_ARGC_ENVC],
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
			syssize.envsz[counter as usize] = (key.len() + value.len()) as i32 + 2;
			counter += 1;
		}
		syssize.envc = counter;

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
			let envptr = unsafe {
				self.host_address(
					*((envp + counter as usize * mem::size_of::<usize>()) as *mut *mut u8) as usize,
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

	fn netinfo(&self, args_ptr: usize) -> Result<()> {
		let mut mac: [u8; 6] = [0; 6];

		match &(*crate::MAC_ADDRESS.lock().unwrap()) {
			Some(mac_str) => {
				let mut nth = 0;
				for byte in mac_str.split(|c| c == ':' || c == '-') {
					if nth == 6 {
						return Err(Error::InvalidMacAddress);
					}

					mac[nth] = u8::from_str_radix(byte, 16).map_err(|_| Error::ParseIntError)?;

					nth += 1;
				}

				if nth != 6 {
					return Err(Error::InvalidMacAddress);
				}
			}
			_ => {
				let mut urandom = File::open("/dev/urandom").expect("Unable to open urandom");
				urandom
					.read_exact(&mut mac)
					.expect("Unable to read random numbers");

				mac[0] &= 0xfe; // creats a random MAC-address in the locally administered
				mac[0] |= 0x02; // address range which can be used without conflict with other public devices
			}
		};

		debug!(
			"Create random MAC address {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
		);

		let netinfo_addr = unsafe { std::slice::from_raw_parts_mut(args_ptr as *mut u8, 6) };
		netinfo_addr[0..].clone_from_slice(&mac);
		*crate::MAC_ADDRESS.lock().unwrap() = Some(format!(
			"{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
		));

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

		// open the file in read only
		let kernel_file = File::open(self.kernel_path())
			.map_err(|_| Error::InvalidFile(self.kernel_path().into()))?;
		let file =
			Mmap::map(&kernel_file).map_err(|_| Error::InvalidFile(self.kernel_path().into()))?;

		// parse the header with ELF module
		let file_elf = {
			let mut data = Cursor::new(file.as_ref());

			elf::File::open_stream(&mut data)
				.map_err(|_| Error::InvalidFile(self.kernel_path().into()))
		}?;

		if file_elf.ehdr.class != ELFCLASS64
			|| file_elf.ehdr.elftype != ET_EXEC
			|| file_elf.ehdr.machine != EM_X86_64
		{
			return Err(Error::InvalidFile(self.kernel_path().into()));
		}

		// acquire the slices of the user memory and kernel file
		let (vm_mem, vm_mem_length) = self.guest_mem();
		let kernel_file = file.as_ref();

		// create default bootinfo
		let boot_info = vm_mem.offset(BOOT_INFO_ADDR as isize) as *mut BootInfo;
		*boot_info = BootInfo::new();

		// forward IP address to kernel
		match self.get_ip() {
			Some(ip) => {
				write_volatile(&mut (*boot_info).hcip, ip.octets());
			}

			None => {}
		}

		// forward gateway address to kernel
		match self.get_gateway() {
			Some(gateway) => {
				write_volatile(&mut (*boot_info).hcgateway, gateway.octets());
			}

			None => {}
		}

		// forward mask to kernel
		match self.get_mask() {
			Some(mask) => {
				write_volatile(&mut (*boot_info).hcmask, mask.octets());
			}

			None => {}
		}

		let mut pstart: Option<u64> = None;

		for header in file_elf.phdrs {
			if header.progtype == PT_TLS {
				write_volatile(&mut (*boot_info).tls_start, header.paddr);
				write_volatile(&mut (*boot_info).tls_filesz, header.filesz);
				write_volatile(&mut (*boot_info).tls_memsz, header.memsz);
			} else if header.progtype == PT_LOAD {
				let vm_start = header.paddr as usize;
				let vm_end = vm_start + header.filesz as usize;

				let kernel_start = header.offset as usize;
				let kernel_end = kernel_start + header.filesz as usize;

				debug!(
					"Load segment with start addr 0x{:x} and size 0x{:x}, offset 0x{:x}",
					header.paddr, header.filesz, header.offset
				);

				if vm_start + header.memsz as usize > vm_mem_length {
					error!("Guest memory size isn't large enough");
					return Err(Error::NotEnoughMemory);
				}

				let vm_slice = std::slice::from_raw_parts_mut(vm_mem, vm_mem_length);
				vm_slice[vm_start..vm_end].copy_from_slice(&kernel_file[kernel_start..kernel_end]);
				for i in &mut vm_slice[vm_end..vm_end + (header.memsz - header.filesz) as usize] {
					*i = 0
				}

				if pstart.is_none() {
					self.set_entry_point(file_elf.ehdr.entry);
					debug!("ELF entry point at 0x{:x}", file_elf.ehdr.entry);

					pstart = Some(header.paddr as u64);

					debug!("Set HermitCore header at 0x{:x}", BOOT_INFO_ADDR as usize);
					self.set_boot_info(boot_info);

					write_volatile(&mut (*boot_info).base, header.paddr);
					write_volatile(&mut (*boot_info).limit, vm_mem_length as u64); // memory size
					write_volatile(&mut (*boot_info).possible_cpus, 1);
					#[cfg(target_os = "linux")]
					write_volatile(&mut (*boot_info).uhyve, 0x3); // announce uhyve and pci support
					#[cfg(not(target_os = "linux"))]
					write_volatile(&mut (*boot_info).uhyve, 0x1); // announce uhyve
					write_volatile(&mut (*boot_info).current_boot_id, 0);
					if self.verbose() {
						write_volatile(&mut (*boot_info).uartport, UHYVE_UART_PORT);
					} else {
						write_volatile(&mut (*boot_info).uartport, 0);
					}

					debug!("Set stack base to 0x{:x}", header.paddr - KERNEL_STACK_SIZE);
					write_volatile(
						&mut (*boot_info).current_stack_address,
						header.paddr - KERNEL_STACK_SIZE,
					);

					write_volatile(&mut (*boot_info).host_logical_addr, vm_mem.offset(0) as u64);

					match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
						Ok(n) => write_volatile(&mut (*boot_info).boot_gtod, n.as_secs() * 1000000),
						Err(err) => panic!("SystemTime before UNIX EPOCH! Error: {}", err),
					}

					let cpuid = CpuId::new();
					let mhz: u32 = detect_freq_from_cpuid(&cpuid).unwrap_or_else(|_| {
						debug!("Failed to detect from cpuid");
						detect_freq_from_cpuid_hypervisor_info(&cpuid).unwrap_or_else(|_| {
							debug!("Failed to detect from hypervisor_info");
							detect_freq_from_cpu_brand_string(&cpuid).unwrap_or_else(|_| {
								debug!("Failed to detect from brand string");
								get_cpu_frequency_from_os().unwrap_or(0)
							})
						})
					});
					debug!("detected a cpu frequency of {} Mhz", mhz);
					write_volatile(&mut (*boot_info).cpu_freq, mhz);
					if (*boot_info).cpu_freq == 0 {
						warn!("Unable to determine processor frequency");
					}
				}

				// store total kernel size
				let start = pstart.unwrap();
				write_volatile(
					&mut (*boot_info).image_size,
					header.paddr + header.memsz - start,
				);
				//debug!("Kernel header: {:?}", *boot_info);
			}
		}

		debug!("Kernel loaded");

		Ok(())
	}
}

fn detect_freq_from_cpuid(cpuid: &CpuId) -> std::result::Result<u32, ()> {
	let freq_info = cpuid.get_processor_frequency_info().ok_or(())?;
	let mhz = freq_info.processor_base_frequency() as u32;
	if mhz > 0 {
		Ok(mhz)
	} else {
		Err(())
	}
}

fn detect_freq_from_cpuid_hypervisor_info(cpuid: &CpuId) -> std::result::Result<u32, ()> {
	debug!("Trying to detect CPU frequency via cpuid hypervisor info");
	let hypervisor_info = cpuid.get_hypervisor_info().ok_or(())?;
	debug!(
		"cpuid detected hypervisor: {:?}",
		hypervisor_info.identify()
	);
	let freq = hypervisor_info.tsc_frequency().ok_or(())?;
	debug!("cpuid detected frequency of {} Hz from hypervisor", freq);
	let mhz: u32 = freq / 1000000u32;
	if mhz > 0 {
		Ok(mhz)
	} else {
		Err(())
	}
}

fn detect_freq_from_cpu_brand_string(cpuid: &CpuId) -> std::result::Result<u32, ()> {
	let extended_function_info = cpuid.get_extended_function_info().ok_or(())?;
	let brand_string = extended_function_info.processor_brand_string().ok_or(())?;

	let ghz_find = brand_string.find("GHz").ok_or(())?;
	let index = ghz_find - 4;
	let thousand_char = brand_string.chars().nth(index).unwrap();
	let decimal_char = brand_string.chars().nth(index + 1).unwrap();
	let hundred_char = brand_string.chars().nth(index + 2).unwrap();
	let ten_char = brand_string.chars().nth(index + 3).unwrap();

	if let (Some(thousand), '.', Some(hundred), Some(ten)) = (
		thousand_char.to_digit(10),
		decimal_char,
		hundred_char.to_digit(10),
		ten_char.to_digit(10),
	) {
		Ok((thousand * 1000 + hundred * 100 + ten * 10) as u32)
	} else {
		Err(())
	}
}

#[cfg(target_os = "linux")]
fn get_cpu_frequency_from_os() -> std::result::Result<u32, ()> {
	let res_output = Command::new("lscpu").output();
	if res_output.is_err() {
		return Err(());
	}
	let output = res_output.unwrap();
	if !output.status.success() {
		return Err(());
	}
	let lscpu_res = std::string::String::from_utf8(output.stdout);
	let regex_res = Regex::new(r"(?im:^CPU MHz:\s+(?P<frequency>\d+))");
	if lscpu_res.is_err() || regex_res.is_err() {
		return Err(());
	}
	let lscpu_str = lscpu_res.unwrap();
	let re = regex_res.unwrap();
	let freq_str_opt = re
		.captures(&lscpu_str)
		.and_then(|cap| cap.name("frequency"));
	match freq_str_opt {
		Some(freq_match) => {
			let freq_res = freq_match.as_str().parse::<u32>();
			if freq_res.is_err() {
				return Err(());
			}
			let freq = freq_res.unwrap();
			// Sanity check - ToDo: Use a named constant for upper limit of frequency
			if freq > 0 && freq < 10000 {
				Ok(freq)
			} else {
				Err(())
			}
		}
		None => Err(()),
	}
}

#[cfg(not(target_os = "linux"))]
fn get_cpu_frequency_from_os() -> std::result::Result<u32, ()> {
	//Not implemented yet for other systems
	Err(())
}

#[cfg(test)]
mod tests {
	const MHZ_TO_HZ: u64 = 1000000;
	const KHZ_TO_HZ: u64 = 1000;

	#[cfg(target_os = "linux")]
	use crate::linux::tests::has_vm_support;
	#[cfg(target_arch = "x86_64")]
	use core::arch::x86_64::_rdtsc as rdtsc;
	use std::time;

	use super::*;

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
			if tinfo.nominal_frequency() != 0 {
				tinfo.tsc_frequency()
			} else if tinfo.numerator() != 0 && tinfo.denominator() != 0 {
				// Skylake and Kabylake don't report the crystal clock, approximate with base frequency:
				cpuid
					.get_processor_frequency_info()
					.map(|pinfo| pinfo.processor_base_frequency() as u64 * MHZ_TO_HZ)
					.map(|cpu_base_freq_hz| {
						let crystal_hz = cpu_base_freq_hz * tinfo.denominator() as u64
							/ tinfo.numerator() as u64;
						crystal_hz * tinfo.numerator() as u64 / tinfo.denominator() as u64
					})
			} else {
				None
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
			let one_second = time::Duration::from_secs(1);
			let now = time::Instant::now();
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
				println!("Don't have rdtsc on stable!");
				assert!(true);
			}
		} else {
			println!("System does not have a TSC.");
			assert!(true);
		}
	}

	#[cfg(target_os = "linux")]
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
		if has_vm_support() == false {
			return;
		}

		let path =
			env!("CARGO_MANIFEST_DIR").to_string() + &"/benches_data/hello_world".to_string();
		let vm = create_vm(
			path,
			&VmParameter::new(
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
		if has_vm_support() == false {
			return;
		}

		let path =
			env!("CARGO_MANIFEST_DIR").to_string() + &"/benches_data/hello_world".to_string();
		let mut vm = create_vm(
			path,
			&VmParameter::new(
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
pub fn create_vm(path: String, specs: &super::vm::VmParameter) -> Result<Uhyve> {
	// If we are given a port, create new DebugManager.
	let gdb = specs.gdbport.map(|port| DebugManager::new(port).unwrap());

	let vm = Uhyve::new(path, &specs, gdb)?;

	Ok(vm)
}

#[cfg(target_os = "windows")]
pub fn create_vm(path: String, specs: &super::vm::VmParameter) -> Result<Uhyve> {
	let vm = Uhyve::new(path.clone(), &specs)?;

	Ok(vm)
}
