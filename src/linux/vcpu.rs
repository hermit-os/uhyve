use consts::*;
use error::Error::*;
use error::*;
use kvm_bindings::*;
use kvm_ioctls::{VcpuExit, VcpuFd, MAX_KVM_CPUID_ENTRIES};
use libc::ioctl;
use linux::KVM;
use paging::*;
use std;
use std::os::unix::io::AsRawFd;
use vm::VirtualCPU;
use x86::*;

const CPUID_EXT_HYPERVISOR: u32 = 1 << 31;
const CPUID_TSC_DEADLINE: u32 = 1 << 24;
const CPUID_ENABLE_MSR: u32 = 1 << 5;
const MSR_IA32_MISC_ENABLE: u32 = 0x000001a0;

pub struct UhyveCPU {
	id: u32,
	vcpu: VcpuFd,
	vm_start: usize,
	kernel_path: String,
}

impl UhyveCPU {
	pub fn new(id: u32, kernel_path: String, vcpu: VcpuFd, vm_start: usize) -> UhyveCPU {
		UhyveCPU {
			id: id,
			vcpu: vcpu,
			vm_start: vm_start,
			kernel_path: kernel_path,
		}
	}

	fn setup_cpuid(&self) -> Result<()> {
		//debug!("Setup cpuid");

		let mut kvm_cpuid = KVM
			.get_supported_cpuid(MAX_KVM_CPUID_ENTRIES)
			.or_else(to_error)?;
		let kvm_cpuid_entries = kvm_cpuid.mut_entries_slice();
		let i = kvm_cpuid_entries
			.iter()
			.position(|&r| r.function == 0x80000002)
			.unwrap();

		// create own processor string (first part)
		let mut id_reg_values: [u32; 4] = [0; 4];
		let id = b"uhyve - unikerne";
		unsafe {
			std::ptr::copy_nonoverlapping(
				id.as_ptr(),
				id_reg_values.as_mut_ptr() as *mut u8,
				id.len(),
			);
		}
		kvm_cpuid_entries[i].eax = id_reg_values[0];
		kvm_cpuid_entries[i].ebx = id_reg_values[1];
		kvm_cpuid_entries[i].ecx = id_reg_values[2];
		kvm_cpuid_entries[i].edx = id_reg_values[3];

		let i = kvm_cpuid_entries
			.iter()
			.position(|&r| r.function == 0x80000003)
			.unwrap();

		// create own processor string (second part)
		let id = b"l hypervisor\0";
		unsafe {
			std::ptr::copy_nonoverlapping(
				id.as_ptr(),
				id_reg_values.as_mut_ptr() as *mut u8,
				id.len(),
			);
		}
		kvm_cpuid_entries[i].eax = id_reg_values[0];
		kvm_cpuid_entries[i].ebx = id_reg_values[1];
		kvm_cpuid_entries[i].ecx = id_reg_values[2];
		kvm_cpuid_entries[i].edx = id_reg_values[3];

		let i = kvm_cpuid_entries
			.iter()
			.position(|&r| r.function == 1)
			.unwrap();

		// CPUID to define basic cpu features
		kvm_cpuid_entries[i].ecx |= CPUID_EXT_HYPERVISOR; // propagate that we are running on a hypervisor
		kvm_cpuid_entries[i].ecx |= CPUID_TSC_DEADLINE; // enable TSC deadline feature
		kvm_cpuid_entries[i].edx |= CPUID_ENABLE_MSR; // enable msr support

		let i = kvm_cpuid_entries
			.iter()
			.position(|&r| r.function == 0x0A)
			.unwrap();

		// disable performance monitor
		kvm_cpuid_entries[i].eax = 0x00;

		self.vcpu.set_cpuid2(&kvm_cpuid).or_else(to_error)?;

		Ok(())
	}

	fn setup_msrs(&self) -> Result<()> {
		//debug!("Setup MSR");

		let msr_list = KVM.get_msr_index_list().or_else(to_error)?;

		let mut msr_entries = msr_list
			.iter()
			.map(|i| kvm_msr_entry {
				index: *i,
				data: 0,
				..Default::default()
			})
			.collect::<Vec<_>>();

		// enable fast string operations
		msr_entries[0].index = MSR_IA32_MISC_ENABLE;
		msr_entries[0].data = 1;

		let mut msrs: &mut kvm_msrs = unsafe { &mut *(msr_entries.as_ptr() as *mut kvm_msrs) };
		msrs.nmsrs = 1;

		self.vcpu.set_msrs(msrs).or_else(to_error)?;

		Ok(())
	}

	fn setup_long_mode(&self, entry_point: u64) -> Result<()> {
		//debug!("Setup long mode");

		let mut sregs = self.vcpu.get_sregs().or_else(to_error)?;

		let cr0 = (Cr0::CR0_PROTECTED_MODE
			| Cr0::CR0_ENABLE_PAGING
			| Cr0::CR0_EXTENSION_TYPE
			| Cr0::CR0_NUMERIC_ERROR)
			.bits() as u64;
		let cr4 = Cr4::CR4_ENABLE_PAE.bits() as u64;

		sregs.cr3 = BOOT_PML4;
		sregs.cr4 = cr4;
		sregs.cr0 = cr0;
		sregs.efer = EFER_LME | EFER_LMA | EFER_NXE;

		let mut seg = kvm_segment {
			base: 0,
			limit: 0xffffffff,
			selector: 1 << 3,
			present: 1,
			type_: 11,
			dpl: 0,
			db: 0,
			s: 1,
			l: 1,
			g: 1,
			..Default::default()
		};

		sregs.cs = seg;

		seg.type_ = 3;
		seg.selector = 2 << 3;
		seg.l = 0;
		sregs.ds = seg;
		sregs.es = seg;
		sregs.ss = seg;
		//sregs.fs = seg;
		//sregs.gs = seg;
		sregs.gdt.base = BOOT_GDT;
		sregs.gdt.limit = ((std::mem::size_of::<u64>() * BOOT_GDT_MAX as usize) - 1) as u16;

		self.vcpu.set_sregs(&sregs).or_else(to_error)?;

		let mut regs = self.vcpu.get_regs().or_else(to_error)?;
		regs.rflags = 2;
		regs.rip = entry_point;
		regs.rdi = BOOT_INFO_ADDR;

		self.vcpu.set_regs(&regs).or_else(to_error)?;

		Ok(())
	}

	fn show_dtable(name: &str, dtable: &kvm_dtable) {
		print!("{}                 {:?}\n", name, dtable);
	}

	fn show_segment(name: &str, seg: &kvm_segment) {
		print!("{}       {:?}\n", name, seg);
	}
}

impl VirtualCPU for UhyveCPU {
	fn init(&mut self, entry_point: u64) -> Result<()> {
		self.setup_long_mode(entry_point)?;
		self.setup_cpuid()?;

		// be sure that the multiprocessor is runable
		let mp_state = kvm_mp_state {
			mp_state: KVM_MP_STATE_RUNNABLE,
		};
		let ret = unsafe {
			ioctl(
				self.vcpu.as_raw_fd(),
				0x4004ae99, /* KVM_SET_MP_STATE */
				&mp_state,
			)
		};
		if ret < 0 {
			return Err(OsError(unsafe { *libc::__errno_location() }));
		}

		self.setup_msrs()?;

		Ok(())
	}

	fn kernel_path(&self) -> String {
		self.kernel_path.clone()
	}

	fn host_address(&self, addr: usize) -> usize {
		addr + self.vm_start
	}

	fn virt_to_phys(&self, addr: usize) -> usize {
		let executable_disable_mask: usize = !PageTableEntryFlags::EXECUTE_DISABLE.bits();
		let mut page_table = self.host_address(BOOT_PML4 as usize) as *const usize;
		let mut page_bits = 39;
		let mut entry: usize = 0;

		for _i in 0..4 {
			let index = (addr >> page_bits) & ((1 << PAGE_MAP_BITS) - 1);
			entry = unsafe { *page_table.offset(index as isize) & executable_disable_mask };

			// bit 7 is set if this entry references a 1 GiB (PDPT) or 2 MiB (PDT) page.
			if entry & PageTableEntryFlags::HUGE_PAGE.bits() != 0 {
				return (entry & ((!0usize) << page_bits)) | (addr & !((!0usize) << page_bits));
			} else {
				page_table = self.host_address(entry & !((1 << PAGE_BITS) - 1)) as *const usize;
				page_bits -= PAGE_MAP_BITS;
			}
		}

		(entry & ((!0usize) << PAGE_BITS)) | (addr & !((!0usize) << PAGE_BITS))
	}

	fn run(&mut self) -> Result<()> {
		//self.print_registers();

		loop {
			match self.vcpu.run().or_else(to_error)? {
				VcpuExit::Hlt => {
					debug!("Halt Exit");
					break;
				}
				VcpuExit::Shutdown => {
					self.print_registers();
					debug!("Shutdown Exit");
					break;
				}
				VcpuExit::MmioRead(addr, _) => {
					debug!("KVM: read at 0x{:x}", addr);
					break;
				}
				VcpuExit::MmioWrite(addr, _) => {
					debug!("KVM: write at 0x{:x}", addr);
					self.print_registers();
					break;
				}
				VcpuExit::IoOut(port, addr) => {
					match port {
						SHUTDOWN_PORT => {
							return Ok(());
						}
						UHYVE_UART_PORT => {
							self.uart(String::from_utf8_lossy(&addr).to_string())?;
						}
						UHYVE_PORT_CMDSIZE => {
							let data_addr: usize =
								unsafe { (*(addr.as_ptr() as *const u32)) as usize };
							self.cmdsize(self.host_address(data_addr))?;
						}
						UHYVE_PORT_CMDVAL => {
							let data_addr: usize =
								unsafe { (*(addr.as_ptr() as *const u32)) as usize };
							self.cmdval(self.host_address(data_addr))?;
						}
						//UHYVE_PORT_NETSTAT => {}
						UHYVE_PORT_EXIT => {
							let data_addr: usize =
								unsafe { (*(addr.as_ptr() as *const u32)) as usize };
							self.exit(self.host_address(data_addr));
						}
						UHYVE_PORT_OPEN => {
							let data_addr: usize =
								unsafe { (*(addr.as_ptr() as *const u32)) as usize };
							self.open(self.host_address(data_addr))?;
						}
						UHYVE_PORT_WRITE => {
							let data_addr: usize =
								unsafe { (*(addr.as_ptr() as *const u32)) as usize };
							self.write(self.host_address(data_addr))?;
						}
						UHYVE_PORT_READ => {
							let data_addr: usize =
								unsafe { (*(addr.as_ptr() as *const u32)) as usize };
							self.read(self.host_address(data_addr))?;
						}
						UHYVE_PORT_UNLINK => {
							let data_addr: usize =
								unsafe { (*(addr.as_ptr() as *const u32)) as usize };
							self.unlink(self.host_address(data_addr))?;
						}
						UHYVE_PORT_LSEEK => {
							let data_addr: usize =
								unsafe { (*(addr.as_ptr() as *const u32)) as usize };
							self.lseek(self.host_address(data_addr))?;
						}
						UHYVE_PORT_CLOSE => {
							let data_addr: usize =
								unsafe { (*(addr.as_ptr() as *const u32)) as usize };
							self.close(self.host_address(data_addr))?;
						}
						_ => {
							info!("Unhandled IO exit: 0x{:x}", port);
						}
					}
				}
				VcpuExit::InternalError => {
					error!("Internal error");
					//self.print_registers();

					return Err(Error::UnknownExitReason);
				}
				_ => {
					error!("Unknown exit reason");
					//self.print_registers();

					return Err(Error::UnknownExitReason);
				}
			}
		}

		Ok(())
	}

	fn print_registers(&self) {
		let regs = self.vcpu.get_regs().unwrap();
		let sregs = self.vcpu.get_sregs().unwrap();

		print!("\nDump state of CPU {}\n", self.id);
		print!("\nRegisters:\n");
		print!("----------\n");
		print!("{:?}{:?}", regs, sregs);

		print!("\nSegment registers:\n");
		print!("------------------\n");
		print!("register  selector  base              limit     type  p dpl db s l g avl\n");
		UhyveCPU::show_segment("cs ", &sregs.cs);
		UhyveCPU::show_segment("ss ", &sregs.ss);
		UhyveCPU::show_segment("ds ", &sregs.ds);
		UhyveCPU::show_segment("es ", &sregs.es);
		UhyveCPU::show_segment("fs ", &sregs.fs);
		UhyveCPU::show_segment("gs ", &sregs.gs);
		UhyveCPU::show_segment("tr ", &sregs.tr);
		UhyveCPU::show_segment("ldt", &sregs.ldt);
		UhyveCPU::show_dtable("gdt", &sregs.gdt);
		UhyveCPU::show_dtable("idt", &sregs.idt);

		print!("\nAPIC:\n");
		print!("-----\n");
		print!(
			"efer: {:016x}  apic base: {:016x}\n",
			sregs.efer, sregs.apic_base
		);
	}
}

impl Drop for UhyveCPU {
	fn drop(&mut self) {
		debug!("Drop vCPU {}", self.id);
		//self.print_registers();
	}
}
