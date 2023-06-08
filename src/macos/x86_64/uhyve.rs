use std::{
	ffi::OsString,
	mem,
	path::{Path, PathBuf},
	ptr,
	sync::{Arc, Mutex},
};

use hermit_entry::boot_info::RawBootInfo;
use libc::{self, c_void};
use log::debug;
use x86_64::{
	structures::paging::{Page, PageTable, PageTableFlags, Size2MiB},
	PhysAddr,
};

use crate::{
	consts::*,
	macos::{
		x86_64::{ioapic::IoApic, vcpu::*},
		xhyve::initialize_xhyve,
	},
	mem::MmapMemory,
	params::Params,
	vm::Vm,
	x86_64::create_gdt_entry,
	HypervisorResult,
};

pub struct Uhyve {
	offset: u64,
	entry_point: u64,
	stack_address: u64,
	mem: MmapMemory,
	num_cpus: u32,
	path: PathBuf,
	args: Vec<OsString>,
	boot_info: *const RawBootInfo,
	ioapic: Arc<Mutex<IoApic>>,
	verbose: bool,
}

impl std::fmt::Debug for Uhyve {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Uhyve")
			.field("entry_point", &self.entry_point)
			.field("stack_address", &self.stack_address)
			.field("mem", &self.mem)
			.field("num_cpus", &self.num_cpus)
			.field("path", &self.path)
			.field("boot_info", &self.boot_info)
			.field("ioapic", &self.ioapic)
			.field("verbose", &self.verbose)
			.finish()
	}
}

impl Uhyve {
	pub fn new(kernel_path: PathBuf, params: Params) -> HypervisorResult<Uhyve> {
		let memory_size = params.memory_size.get();

		let mem = MmapMemory::new(0, memory_size, 0, false, false);

		initialize_xhyve(&mut mem)?;

		let hyve = Uhyve {
			offset: 0,
			entry_point: 0,
			stack_address: 0,
			mem,
			num_cpus: params.cpu_count.get(),
			path: kernel_path,
			args: params.kernel_args,
			boot_info: ptr::null(),
			ioapic: Arc::new(Mutex::new(IoApic::new())),
			verbose: params.verbose,
		};

		hyve.init_guest_mem();

		Ok(hyve)
	}
}

impl Vm for Uhyve {
	fn verbose(&self) -> bool {
		self.verbose
	}

	fn set_offset(&mut self, offset: u64) {
		self.offset = offset;
	}

	fn get_offset(&self) -> u64 {
		self.offset
	}

	fn set_entry_point(&mut self, entry: u64) {
		self.entry_point = entry;
	}

	fn get_entry_point(&self) -> u64 {
		self.entry_point
	}

	fn set_stack_address(&mut self, stack_address: u64) {
		self.stack_address = stack_address;
	}

	fn stack_address(&self) -> u64 {
		self.stack_address
	}

	fn num_cpus(&self) -> u32 {
		self.num_cpus
	}

	fn guest_mem(&self) -> (*mut u8, usize) {
		(self.mem.host_address as *mut u8, self.mem.memory_size)
	}

	fn kernel_path(&self) -> &Path {
		self.path.as_path()
	}

	fn create_cpu(&self, id: u32) -> HypervisorResult<XhyveCpu> {
		Ok(XhyveCpu::new(
			id,
			self.path.clone(),
			self.args.clone(),
			self.guest_mem().0 as usize,
			self.ioapic.clone(),
		))
	}

	fn set_boot_info(&mut self, header: *const RawBootInfo) {
		self.boot_info = header;
	}

	/// Initialize the page tables for the guest
	fn init_guest_mem(&mut self) {
		debug!("Initialize guest memory");

		let (mem_addr, _) = self.guest_mem();

		unsafe {
			let pml4 = &mut *((mem_addr as u64 + BOOT_PML4.as_u64()) as *mut PageTable);
			let pdpte = &mut *((mem_addr as u64 + BOOT_PDPTE.as_u64()) as *mut PageTable);
			let pde = &mut *((mem_addr as u64 + BOOT_PDE.as_u64()) as *mut PageTable);
			let gdt_entry: u64 = mem_addr as u64 + BOOT_GDT.as_u64();

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

			pml4[0].set_addr(
				BOOT_PDPTE,
				PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
			);
			pml4[511].set_addr(
				BOOT_PML4,
				PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
			);
			pdpte[0].set_addr(BOOT_PDE, PageTableFlags::PRESENT | PageTableFlags::WRITABLE);

			for i in 0..512 {
				let addr = PhysAddr::new(i as u64 * Page::<Size2MiB>::SIZE);
				pde[i].set_addr(
					addr,
					PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::HUGE_PAGE,
				);
			}
		}
	}
}

unsafe impl Send for Uhyve {}
unsafe impl Sync for Uhyve {}
