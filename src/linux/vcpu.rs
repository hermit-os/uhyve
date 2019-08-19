use consts::*;
use error::*;
use libkvm::linux::kvm_bindings::*;
use libkvm::vcpu;
use linux::KVM;
use std;
use std::ffi::CStr;
use vm::VirtualCPU;
use x86::controlregs::*;

const CPUID_EXT_HYPERVISOR: u32 = 1 << 31;
const CPUID_ENABLE_MSR: u32 = 1 << 5;
const MSR_IA32_MISC_ENABLE: u32 = 0x000001a0;

pub struct EhyveCPU {
	id: u32,
	vcpu: vcpu::VirtualCPU,
	vm_start: usize,
	kernel_path: String,
}

impl EhyveCPU {
	pub fn new(id: u32, kernel_path: String, vcpu: vcpu::VirtualCPU, vm_start: usize) -> EhyveCPU {
		EhyveCPU {
			id: id,
			vcpu: vcpu,
			vm_start: vm_start,
			kernel_path: kernel_path,
		}
	}

	fn setup_cpuid(&self) {
		let mut kvm_cpuid_entries = KVM.get_supported_cpuid().unwrap();

		let i = kvm_cpuid_entries
			.iter()
			.position(|&r| r.function == 0x40000000)
			.unwrap();

		let mut id_reg_values: [u32; 3] = [0; 3];
		let id = "uhyve\0";
		unsafe {
			std::ptr::copy_nonoverlapping(
				id.as_ptr(),
				id_reg_values.as_mut_ptr() as *mut u8,
				id.len(),
			);
		}
		kvm_cpuid_entries[i].ebx = id_reg_values[0];
		kvm_cpuid_entries[i].ecx = id_reg_values[1];
		kvm_cpuid_entries[i].edx = id_reg_values[2];

		let i = kvm_cpuid_entries
			.iter()
			.position(|&r| r.function == 1)
			.unwrap();

		// CPUID to define basic cpu features
		kvm_cpuid_entries[i].ecx |= CPUID_EXT_HYPERVISOR; // propagate that we are running on a hypervisor
		kvm_cpuid_entries[i].edx |= CPUID_ENABLE_MSR; // enable msr support

		let i = kvm_cpuid_entries
			.iter()
			.position(|&r| r.function == 0x0A)
			.unwrap();

		// disable performance monitor
		kvm_cpuid_entries[i].eax = 0x00;

		self.vcpu.set_cpuid(&kvm_cpuid_entries).unwrap();
	}

	fn setup_msrs(&self) {
		let msr_list = KVM.get_msr_index_list().unwrap();

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

		self.vcpu.set_msrs(&msr_entries).unwrap();
	}

	fn setup_long_mode(&self, entry_point: u64) {
		debug!("Setup long mode");

		let mut sregs = self.vcpu.get_kvm_sregs().unwrap();

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
		sregs.fs = seg;
		sregs.gs = seg;
		sregs.ss = seg;
		sregs.gdt.base = BOOT_GDT;
		sregs.gdt.limit = ((std::mem::size_of::<u64>() * BOOT_GDT_MAX as usize) - 1) as u16;

		self.vcpu.set_kvm_sregs(&sregs).unwrap();

		let mut regs = self.vcpu.get_kvm_regs().unwrap();
		regs.rflags = 2;
		regs.rip = entry_point;
		regs.rsp = 0x200000u64 - 0x1000u64;

		self.vcpu.set_kvm_regs(&regs).unwrap();
	}

	fn show_dtable(name: &str, dtable: &kvm_dtable) {
		print!("{}                 {}\n", name, dtable);
	}

	fn show_segment(name: &str, seg: &kvm_segment) {
		print!("{}       {}\n", name, seg);
	}
}

impl VirtualCPU for EhyveCPU {
	fn init(&mut self, entry_point: u64) -> Result<()> {
		self.setup_long_mode(entry_point);
		self.setup_cpuid();

		// be sure that the multiprocessor is runable
		let mp_state = kvm_mp_state {
			mp_state: KVM_MP_STATE_RUNNABLE,
		};
		self.vcpu.set_mp_state(&mp_state).unwrap();

		self.setup_msrs();

		Ok(())
	}

	fn kernel_path(&self) -> String {
		self.kernel_path.clone()
	}

	fn host_address(&self, addr: usize) -> usize {
		addr + self.vm_start
	}

	fn virt_to_phys(&self, addr: usize) -> usize {
		self.vcpu.translate_address(addr as u64).unwrap() as usize
	}

	fn run(&mut self, verbose: bool) -> Result<()> {
		//self.print_registers();

		loop {
			self.vcpu.run().unwrap();
			let kvm_run = self.vcpu.kvm_run();

			//println!("reason {}", kvm_run.exit_reason);
			//self.print_registers();
			match kvm_run.exit_reason {
				KVM_EXIT_HLT => {
					info!("Halt Exit");
					break;
				}
				KVM_EXIT_SHUTDOWN => {
					self.print_registers();
					info!("Shutdown Exit");
					break;
				}
				KVM_EXIT_MMIO => {
					let mmio = unsafe { &kvm_run.__bindgen_anon_1.mmio };
					info!("KVM: handled KVM_EXIT_MMIO at 0x{:x}", mmio.phys_addr);

					if mmio.is_write != 0 {
						self.print_registers();
					}
					break;
				}
				KVM_EXIT_IO => {
					let io = unsafe { &kvm_run.__bindgen_anon_1.io };

					if io.direction == KVM_EXIT_IO_OUT as u8 {
						match io.port {
							SHUTDOWN_PORT | UHYVE_PORT_EXIT => return Ok(()),
							UHYVE_UART_PORT => unsafe {
								let data_addr = kvm_run as *const _ as u64 + io.data_offset;
								let message = CStr::from_ptr(data_addr as *const i8);
								self.io_exit(
									io.port,
									message.to_str().unwrap().to_string(),
									verbose,
								)?;
							},
							UHYVE_PORT_CMDSIZE => {
								let args_ptr = unsafe {
									*((kvm_run as *const _ as usize + io.data_offset as usize)
										as *const usize)
								};
								self.cmdsize(self.host_address(args_ptr))?;
							}
							UHYVE_PORT_CMDVAL => {
								let args_ptr = unsafe {
									*((kvm_run as *const _ as usize + io.data_offset as usize)
										as *const usize)
								};
								self.cmdval(self.host_address(args_ptr))?;
							}
							UHYVE_PORT_NETSTAT => {}
							UHYVE_PORT_EXIT => {
								let args_ptr = unsafe {
									*((kvm_run as *const _ as usize + io.data_offset as usize)
										as *const usize)
								};
								self.exit(self.host_address(args_ptr));
							}
							UHYVE_PORT_OPEN => {
								let args_ptr = unsafe {
									*((kvm_run as *const _ as usize + io.data_offset as usize)
										as *const usize)
								};
								self.open(self.host_address(args_ptr))?;
							}
							UHYVE_PORT_WRITE => {
								let args_ptr = unsafe {
									*((kvm_run as *const _ as usize + io.data_offset as usize)
										as *const usize)
								};
								self.write(self.host_address(args_ptr))?;
							}
							UHYVE_PORT_READ => {
								let args_ptr = unsafe {
									*((kvm_run as *const _ as usize + io.data_offset as usize)
										as *const usize)
								};
								self.read(self.host_address(args_ptr))?;
							}
							UHYVE_PORT_UNLINK => {
								let args_ptr = unsafe {
									*((kvm_run as *const _ as usize + io.data_offset as usize)
										as *const usize)
								};
								self.unlink(self.host_address(args_ptr))?;
							}
							UHYVE_PORT_LSEEK => {
								let args_ptr = unsafe {
									*((kvm_run as *const _ as usize + io.data_offset as usize)
										as *const usize)
								};
								self.lseek(self.host_address(args_ptr))?;
							}
							UHYVE_PORT_CLOSE => {
								let args_ptr = unsafe {
									*((kvm_run as *const _ as usize + io.data_offset as usize)
										as *const usize)
								};
								self.close(self.host_address(args_ptr))?;
							}
							_ => {
								info!("Unhandled IO exit: 0x{:x}", io.port);
							}
						}
					} else {
						info!("Unhandled IO exit: 0x{:x}", io.port);
					}
				}
				KVM_EXIT_INTERNAL_ERROR => {
					error!("Internal error: {:?}", kvm_run.exit_reason);
					self.print_registers();

					return Err(Error::UnknownExitReason(kvm_run.exit_reason));
				}
				_ => {
					error!("Unknown exit reason: {:?}", kvm_run.exit_reason);
					//self.print_registers();

					return Err(Error::UnknownExitReason(kvm_run.exit_reason));
				}
			}
		}

		Ok(())
	}

	fn print_registers(&self) {
		let regs = self.vcpu.get_kvm_regs().unwrap();
		let sregs = self.vcpu.get_kvm_sregs().unwrap();

		print!("\nDump state of CPU {}\n", self.id);
		print!("\nRegisters:\n");
		print!("----------\n");
		print!("{}{}", regs, sregs);

		print!("\nSegment registers:\n");
		print!("------------------\n");
		print!("register  selector  base              limit     type  p dpl db s l g avl\n");
		EhyveCPU::show_segment("cs ", &sregs.cs);
		EhyveCPU::show_segment("ss ", &sregs.ss);
		EhyveCPU::show_segment("ds ", &sregs.ds);
		EhyveCPU::show_segment("es ", &sregs.es);
		EhyveCPU::show_segment("fs ", &sregs.fs);
		EhyveCPU::show_segment("gs ", &sregs.gs);
		EhyveCPU::show_segment("tr ", &sregs.tr);
		EhyveCPU::show_segment("ldt", &sregs.ldt);
		EhyveCPU::show_dtable("gdt", &sregs.gdt);
		EhyveCPU::show_dtable("idt", &sregs.idt);

		print!("\nAPIC:\n");
		print!("-----\n");
		print!(
			"efer: {:016x}  apic base: {:016x}\n",
			sregs.efer, sregs.apic_base
		);
	}
}

impl Drop for EhyveCPU {
	fn drop(&mut self) {
		debug!("Drop vCPU {}", self.id);
		//self.print_registers();
	}
}
