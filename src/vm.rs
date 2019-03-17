use std;
use std::fs::File;
use std::io::Cursor;
use std::mem;
use std::intrinsics::{volatile_store, volatile_load};
use std::time::SystemTime;
use libc;
use memmap::Mmap;
use elf;
use elf::types::{ELFCLASS64, PT_LOAD, ET_EXEC, EM_X86_64};
use error::*;

#[cfg(target_os = "linux")]
pub use linux::ehyve::*;
#[cfg(target_os = "macos")]
pub use macos::ehyve::*;
#[cfg(target_os = "windows")]
pub use windows::ehyve::*;
use consts::*;

#[repr(C)]
struct KernelHeaderEduV0 {
	magic_number: u32,
	version: u32,
	mem_limit: u64,
	num_cpus: u32
}

#[repr(C)]
struct KernelHeaderEduV1 {
	magic_number: u32,
	version: u32,
	mem_limit: u64,
	num_cpus: u32,
	file_addr: u64,
	file_length: u64
}

#[repr(C)]
struct KernelHeaderHermitV0 {
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

#[derive(Debug, Clone)]
pub struct VmParameter {
	pub mem_size: usize,
	pub num_cpus: u32,
	pub file: Option<String>
}

impl VmParameter {
	pub fn new(mem_size: usize, num_cpus: u32, file: Option<String>) -> Self {
		VmParameter {
			mem_size: mem_size,
			num_cpus: num_cpus,
			file: file
		}
	}
}

pub trait VirtualCPU {
	fn init(&mut self, entry_point: u64) -> Result<()>;
	fn run(&mut self) -> Result<()>;
	fn print_registers(&self);

	fn io_exit(&self, port: u16, message: String) -> Result<()>
	{
		match port {
			COM_PORT => {
				print!("{}", message);
				//io::stdout().flush().ok().expect("Could not flush stdout");
				Ok(())
			},
			SHUTDOWN_PORT => {
				Err(Error::Shutdown)
			},
			_ => {
				Err(Error::UnknownIOPort(port))
			}
		}
	}
}

// Constructor for a conventional segment GDT (or LDT) entry
fn create_gdt_entry(flags: u64, base: u64, limit: u64) -> u64 {
    (((base  & 0xff000000u64) << (56-24)) |
     ((flags & 0x0000f0ffu64) << 40) |
     ((limit & 0x000f0000u64) << (48-16)) |
     ((base  & 0x00ffffffu64) << 16) |
     ((limit & 0x0000ffffu64)))
 }

pub trait Vm {
	fn num_cpus(&self) -> u32;
	fn guest_mem(&self) -> (*mut u8, usize);
	fn set_entry_point(&mut self, entry: u64);
	fn get_entry_point(&self) -> u64;
	fn kernel_path(&self) -> &str;
	fn create_cpu(&self, id: u32) -> Result<Box<VirtualCPU>>;
	fn file(&self) -> (u64, u64);

	fn init_guest_mem(&self)
	{
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
			*((gdt_entry+0*mem::size_of::<*mut u64>() as u64) as *mut u64) = create_gdt_entry(0,0,0);
			*((gdt_entry+1*mem::size_of::<*mut u64>() as u64) as *mut u64) = create_gdt_entry(0xA09B, 0, 0xFFFFF); /* code */
			*((gdt_entry+2*mem::size_of::<*mut u64>() as u64) as *mut u64) = create_gdt_entry(0xC093, 0, 0xFFFFF); /* data */

			/*
			* For simplicity we currently use 2MB pages and only a single
			* PML4/PDPTE/PDE.
			*/

			libc::memset(pml4 as *mut _, 0x00, PAGE_SIZE);
			libc::memset(pdpte as *mut _, 0x00, PAGE_SIZE);
			libc::memset(pde as *mut _, 0x00, PAGE_SIZE);

			*(pml4 as *mut u64) = BOOT_PDPTE | (X86_PDPT_P | X86_PDPT_RW | X86_PDPT_US);
			*(pdpte as *mut u64) = BOOT_PDE | (X86_PDPT_P | X86_PDPT_RW | X86_PDPT_US);

			let mut paddr = 0;
			loop {
				*(pde as *mut u64) = paddr | (X86_PDPT_P | X86_PDPT_RW | X86_PDPT_PS | X86_PDPT_US);

				paddr += GUEST_PAGE_SIZE;
				pde +=  mem::size_of::<*mut u64>() as u64;
				if paddr >= 0x20000000u64 {
					break;
				}
			}
		}
	}

	fn load_kernel(&mut self) -> Result<()> {
		debug!("Load kernel from {}", self.kernel_path());

		// open the file in read only
		let kernel_file = File::open(self.kernel_path()).map_err(|_| Error::InvalidFile(self.kernel_path().into()))?;
		let file = unsafe { Mmap::map(&kernel_file) }.map_err(|_| Error::InvalidFile(self.kernel_path().into()))?;

		// parse the header with ELF module
		let file_elf = {
			let mut data = Cursor::new(file.as_ref());

			elf::File::open_stream(&mut data).map_err(|_| Error::InvalidFile(self.kernel_path().into()))
		}?;

		if file_elf.ehdr.class != ELFCLASS64 || file_elf.ehdr.elftype != ET_EXEC || file_elf.ehdr.machine != EM_X86_64 {
			return Err(Error::InvalidFile(self.kernel_path().into()));
		}

		self.set_entry_point(file_elf.ehdr.entry);
		debug!("ELF entry point at 0x{:x}", file_elf.ehdr.entry);

		// acquire the slices of the user memory and kernel file
		let (vm_mem, vm_mem_length) = self.guest_mem();
		let kernel_file  = file.as_ref();

		let mut first_load = true;

		for header in file_elf.phdrs {
			if header.progtype != PT_LOAD {
				continue;
			}

			let vm_start = header.paddr as usize;
			let vm_end   = vm_start + header.filesz as usize;

			let kernel_start = header.offset as usize;
			let kernel_end   = kernel_start + header.filesz as usize;

			debug!("Load segment with start addr 0x{:x} and size 0x{:x}, offset 0x{:x}",
			header.paddr, header.filesz, header.offset);

			let vm_slice = unsafe { std::slice::from_raw_parts_mut(vm_mem, vm_mem_length) };
			vm_slice[vm_start..vm_end].copy_from_slice(&kernel_file[kernel_start..kernel_end]);

			unsafe {
				libc::memset(vm_mem.offset(vm_end as isize) as *mut libc::c_void, 0x00,
					(header.memsz - header.filesz) as usize);
			}

			unsafe {
				if !first_load {
					continue;
				} else {
					first_load = false;
				}

				let magic_number = volatile_load(vm_mem.offset(header.paddr as isize) as *const u32);

				if magic_number == 0xDEADC0DEu32 {
					debug!("Found latest eduOS-rs header at 0x{:x}", header.paddr as usize);

					let kernel_header = vm_mem.offset(header.paddr as isize) as *mut KernelHeaderEduV1;
					volatile_store(&mut (*kernel_header).mem_limit, vm_mem_length as u64);   // memory size
					volatile_store(&mut (*kernel_header).num_cpus, 1);
					volatile_store(&mut (*kernel_header).version, 1);   // memory size

					let (addr, len) = self.file();
					volatile_store(&mut (*kernel_header).file_addr, addr);
					volatile_store(&mut (*kernel_header).file_length, len);
				} else if magic_number == 0xC0DECAFEu32 {
					debug!("Found latest HermitCore header at 0x{:x}", header.paddr as usize);

					let kernel_header = vm_mem.offset(header.paddr as isize) as *mut KernelHeaderHermitV0;
					volatile_store(&mut (*kernel_header).base, header.paddr);
					volatile_store(&mut (*kernel_header).limit, vm_mem_length as u64);   // memory size
					volatile_store(&mut (*kernel_header).possible_cpus, 1);
					volatile_store(&mut (*kernel_header).uhyve, 1);
					volatile_store(&mut (*kernel_header).current_boot_id, 0);
					volatile_store(&mut (*kernel_header).uartport, 0x800);
					volatile_store(&mut (*kernel_header).current_stack_address,
						header.paddr + mem::size_of::<KernelHeaderHermitV0>() as u64);

					match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
						Ok(n) => volatile_store(&mut (*kernel_header).boot_gtod, n.as_secs() * 1000000),
						Err(_) => panic!("SystemTime before UNIX EPOCH!"),
					}

					volatile_store(&mut (*kernel_header).image_size, header.memsz);
				} else {
					panic!("Unable to detect kernel");
				}
			}
		}

		debug!("Kernel loaded");

		Ok(())
	}
}

pub fn create_vm(path: String, specs: super::vm::VmParameter) -> Result<Ehyve> {
	let vm = match specs {
		super::vm::VmParameter{ mem_size, num_cpus, file } => Ehyve::new(path, mem_size, num_cpus, file)?,
	};

	Ok(vm)
}
