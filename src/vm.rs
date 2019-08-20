use elf;
use elf::types::{ELFCLASS64, EM_X86_64, ET_EXEC, PT_LOAD};
use error::*;
use libc;
use memmap::Mmap;
use procfs;
use std;
use std::fs::File;
use std::io::Cursor;
use std::ptr;
use std::time::SystemTime;
use std::{fmt, mem, slice};

use consts::*;
pub use x86_64::uhyve::*;

#[repr(C)]
struct KernelHeaderV0 {
	magic_number: u32,
	version: u32,
	base: u64,
	limit: u64,
	image_size: u64,
	current_stack_address: u64,
	current_percore_address: u64,
	host_logical_addr: u64,
	boot_gtod: u64,
	mb_info: u64,
	cmdline: u64,
	cmdsize: u64,
	cpu_freq: u32,
	boot_processor: u32,
	cpu_online: u32,
	possible_cpus: u32,
	current_boot_id: u32,
	uartport: u16,
	single_kernel: u8,
	uhyve: u8,
	hcip: [u8; 4],
	hcgateway: [u8; 4],
	hcmask: [u8; 4],
}

impl fmt::Debug for KernelHeaderV0 {
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

#[derive(Debug, Clone)]
pub struct VmParameter {
	pub mem_size: usize,
	pub num_cpus: u32,
}

impl VmParameter {
	pub fn new(mem_size: usize, num_cpus: u32) -> Self {
		VmParameter {
			mem_size: mem_size,
			num_cpus: num_cpus,
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
	fn run(&mut self, verbose: bool) -> Result<()>;
	fn print_registers(&self);
	fn host_address(&self, addr: usize) -> usize;
	fn virt_to_phys(&self, addr: usize) -> usize;
	fn kernel_path(&self) -> String;

	fn cmdsize(&self, args_ptr: usize) -> Result<()> {
		let syssize = unsafe { &mut *(args_ptr as *mut SysCmdsize) };
		syssize.argc = 0;
		syssize.envc = 0;

		let mut counter: i32 = 0;
		let mut kernel_pos: i32 = 0;
		let path = self.kernel_path();
		let mut found_kernel = false;
		for argument in std::env::args() {
			if !found_kernel {
				if path == argument {
					kernel_pos = counter;
					found_kernel = true;
				}
			}

			if found_kernel {
				syssize.argsz[(counter - kernel_pos) as usize] = argument.len() as i32 + 1;
			}

			counter += 1;
		}
		syssize.argc = counter - kernel_pos;

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
		let mut found_kernel = false;
		let mut kernel_pos: i32 = 0;
		let path = self.kernel_path();
		for argument in std::env::args() {
			if !found_kernel {
				if argument == path {
					kernel_pos = counter;
					found_kernel = true;
				}
			}

			if found_kernel {
				let argvptr = unsafe {
					self.host_address(
						*((argv + (counter - kernel_pos) as usize * mem::size_of::<usize>())
							as *mut *mut u8) as usize,
					)
				};
				let len = argument.len();
				let slice = unsafe { slice::from_raw_parts_mut(argvptr as *mut u8, len + 1) };

				// Create string for environment variable
				slice[0..len].copy_from_slice(argument.as_bytes());
				slice[len..len + 1].copy_from_slice(&"\0".to_string().as_bytes());
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
			slice[key.len()..key.len() + 1].copy_from_slice(&"=".to_string().as_bytes());
			slice[key.len() + 1..len + 1].copy_from_slice(value.as_bytes());
			slice[len + 1..len + 2].copy_from_slice(&"\0".to_string().as_bytes());
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
			if bytes_read > 0 {
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
					let errloc = libc::__errno_location();
					return Err(Error::LibcError(*errloc as i32));
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

	fn uart(&self, message: String, verbose: bool) -> Result<()> {
		if verbose == true {
			print!("{}", message);
			//io::stdout().flush().ok().expect("Could not flush stdout");
		}
		Ok(())
	}
}

// Constructor for a conventional segment GDT (or LDT) entry
fn create_gdt_entry(flags: u64, base: u64, limit: u64) -> u64 {
	(((base & 0xff000000u64) << (56 - 24))
		| ((flags & 0x0000f0ffu64) << 40)
		| ((limit & 0x000f0000u64) << (48 - 16))
		| ((base & 0x00ffffffu64) << 16)
		| (limit & 0x0000ffffu64))
}

pub trait Vm {
	fn num_cpus(&self) -> u32;
	fn guest_mem(&self) -> (*mut u8, usize);
	fn set_entry_point(&mut self, entry: u64);
	fn get_entry_point(&self) -> u64;
	fn kernel_path(&self) -> &str;
	fn create_cpu(&self, id: u32) -> Result<Box<dyn VirtualCPU>>;

	fn init_guest_mem(&self) {
		debug!("Initialize guest memory");

		let (mem_addr, _) = self.guest_mem();

		let pml4_addr: u64 = BOOT_PML4;
		let pdpte_addr: u64 = BOOT_PDPTE;
		let pde_addr: u64 = BOOT_PDE;
		let pml4: u64 = mem_addr as u64 + pml4_addr;
		let pdpte: u64 = mem_addr as u64 + pdpte_addr;
		let mut pde: u64 = mem_addr as u64 + pde_addr;
		let gdt_entry: u64 = mem_addr as u64 + BOOT_GDT;

		unsafe {
			// initialize GDT
			*((gdt_entry + 0 * mem::size_of::<*mut u64>() as u64) as *mut u64) =
				create_gdt_entry(0, 0, 0);
			*((gdt_entry + 1 * mem::size_of::<*mut u64>() as u64) as *mut u64) =
				create_gdt_entry(0xA09B, 0, 0xFFFFF); /* code */
			*((gdt_entry + 2 * mem::size_of::<*mut u64>() as u64) as *mut u64) =
				create_gdt_entry(0xC093, 0, 0xFFFFF); /* data */

			/*
				* For simplicity we currently use 2MB pages and only a single
				* PML4/PDPTE/PDE.
				*/

			libc::memset(pml4 as *mut _, 0x00, PAGE_SIZE);
			libc::memset(pdpte as *mut _, 0x00, PAGE_SIZE);
			libc::memset(pde as *mut _, 0x00, PAGE_SIZE);

			*(pml4 as *mut u64) = BOOT_PDPTE | (X86_PDPT_P | X86_PDPT_RW);
			*((pml4 + 511 * mem::size_of::<*mut u64>() as u64) as *mut u64) =
				BOOT_PML4 | (X86_PDPT_P | X86_PDPT_RW);
			*(pdpte as *mut u64) = BOOT_PDE | (X86_PDPT_P | X86_PDPT_RW);

			let mut paddr = 0;
			loop {
				*(pde as *mut u64) = paddr | (X86_PDPT_P | X86_PDPT_RW | X86_PDPT_PS);

				paddr += GUEST_PAGE_SIZE;
				pde += mem::size_of::<*mut u64>() as u64;
				if paddr >= 0x20000000u64 {
					break;
				}
			}
		}
	}

	fn load_kernel(&mut self) -> Result<()> {
		debug!("Load kernel from {}", self.kernel_path());

		// open the file in read only
		let kernel_file = File::open(self.kernel_path())
			.map_err(|_| Error::InvalidFile(self.kernel_path().into()))?;
		let file = unsafe { Mmap::map(&kernel_file) }
			.map_err(|_| Error::InvalidFile(self.kernel_path().into()))?;

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

		self.set_entry_point(file_elf.ehdr.entry);
		debug!("ELF entry point at 0x{:x}", file_elf.ehdr.entry);

		// acquire the slices of the user memory and kernel file
		let (vm_mem, vm_mem_length) = self.guest_mem();
		let kernel_file = file.as_ref();

		let mut pstart: u64 = 0;

		for header in file_elf.phdrs {
			if header.progtype != PT_LOAD {
				continue;
			}

			let vm_start = header.paddr as usize;
			let vm_end = vm_start + header.filesz as usize;

			let kernel_start = header.offset as usize;
			let kernel_end = kernel_start + header.filesz as usize;

			debug!(
				"Load segment with start addr 0x{:x} and size 0x{:x}, offset 0x{:x}",
				header.paddr, header.filesz, header.offset
			);

			let vm_slice = unsafe { std::slice::from_raw_parts_mut(vm_mem, vm_mem_length) };
			vm_slice[vm_start..vm_end].copy_from_slice(&kernel_file[kernel_start..kernel_end]);

			unsafe {
				libc::memset(
					vm_mem.offset(vm_end as isize) as *mut libc::c_void,
					0x00,
					(header.memsz - header.filesz) as usize,
				);
			}

			unsafe {
				if pstart == 0 {
					pstart = header.paddr as u64;
					let kernel_header = vm_mem.offset(header.paddr as isize) as *mut KernelHeaderV0;

					if (*kernel_header).magic_number == 0xC0DECAFEu32 {
						debug!(
							"Found latest HermitCore header at 0x{:x}",
							header.paddr as usize
						);

						ptr::write_volatile(&mut (*kernel_header).base, header.paddr);
						ptr::write_volatile(&mut (*kernel_header).limit, vm_mem_length as u64); // memory size
						ptr::write_volatile(&mut (*kernel_header).possible_cpus, 1);
						ptr::write_volatile(&mut (*kernel_header).uhyve, 1);
						ptr::write_volatile(&mut (*kernel_header).current_boot_id, 0);
						ptr::write_volatile(&mut (*kernel_header).uartport, UHYVE_UART_PORT);
						ptr::write_volatile(
							&mut (*kernel_header).current_stack_address,
							header.paddr + mem::size_of::<KernelHeaderV0>() as u64,
						);

						ptr::write_volatile(
							&mut (*kernel_header).host_logical_addr,
							vm_mem.offset(0) as u64,
						);

						match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
							Ok(n) => ptr::write_volatile(
								&mut (*kernel_header).boot_gtod,
								n.as_secs() * 1000000,
							),
							Err(_) => panic!("SystemTime before UNIX EPOCH!"),
						}

						let cpuinfo = procfs::cpuinfo().unwrap();
						let info = cpuinfo.get_info(0).unwrap();
						let freq: u32 = info
							.get("cpu MHz")
							.expect("Unable to determine processor frequency")
							.split_ascii_whitespace()
							.next()
							.expect("Unable to determine processor frequency")
							.parse::<f32>()
							.expect("Unable to determine processor frequency") as u32;

						ptr::write_volatile(&mut (*kernel_header).cpu_freq, freq);
					} else {
						panic!("Unable to detect kernel");
					}
				}

				// store total kernel size
				let kernel_header = vm_mem.offset(pstart as isize) as *mut KernelHeaderV0;
				ptr::write_volatile(
					&mut (*kernel_header).image_size,
					header.paddr + header.memsz - pstart,
				);
				//debug!("Set kernel header to {:?}", *kernel_header);
			}
		}

		debug!("Kernel loaded");

		Ok(())
	}
}

pub fn create_vm(path: String, specs: super::vm::VmParameter) -> Result<Uhyve> {
	let vm = match specs {
		super::vm::VmParameter { mem_size, num_cpus } => {
			Uhyve::new(path.clone(), mem_size, num_cpus)?
		}
	};

	Ok(vm)
}
