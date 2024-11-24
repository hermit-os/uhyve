use std::sync::Arc;

use kvm_bindings::*;
use kvm_ioctls::{VcpuExit, VcpuFd, VmFd};
use uhyve_interface::{GuestPhysAddr, Hypercall, HypercallAddress};
use vmm_sys_util::eventfd::EventFd;
use x86_64::registers::control::{Cr0Flags, Cr4Flags};

use crate::{
	consts::*,
	hypercall,
	linux::KVM,
	mem::MmapMemory,
	params::Params,
	stats::{CpuStats, VmExit},
	vcpu::{VcpuStopReason, VirtualCPU},
	virtio::*,
	vm::{UhyveVm, VirtualizationBackend},
	HypervisorError, HypervisorResult,
};

const CPUID_EXT_HYPERVISOR: u32 = 1 << 31;
const CPUID_TSC_DEADLINE: u32 = 1 << 24;
const CPUID_ENABLE_MSR: u32 = 1 << 5;
const MSR_IA32_MISC_ENABLE: u32 = 0x000001a0;
const PCI_CONFIG_DATA_PORT: u16 = 0xCFC;
const PCI_CONFIG_ADDRESS_PORT: u16 = 0xCF8;

const KVM_32BIT_MAX_MEM_SIZE: usize = 1 << 32;
const KVM_32BIT_GAP_SIZE: usize = 768 << 20;
const KVM_32BIT_GAP_START: usize = KVM_32BIT_MAX_MEM_SIZE - KVM_32BIT_GAP_SIZE;

pub struct KvmVm {
	vm_fd: VmFd,
}
impl VirtualizationBackend for KvmVm {
	type VCPU = KvmCpu;
	const NAME: &str = "KvmVm";

	fn new_cpu(
		&self,
		id: u32,
		parent_vm: Arc<UhyveVm<KvmVm>>,
		enable_stats: bool,
	) -> HypervisorResult<KvmCpu> {
		let vcpu = self.vm_fd.create_vcpu(id as u64)?;
		let mut kvcpu = KvmCpu {
			id,
			vcpu,
			parent_vm: parent_vm.clone(),
			pci_addr: None,
			stats: if enable_stats {
				Some(CpuStats::new(id as usize))
			} else {
				None
			},
		};
		kvcpu.init(parent_vm.get_entry_point(), parent_vm.stack_address(), id)?;

		Ok(kvcpu)
	}

	fn new(mem: &MmapMemory, params: &Params) -> HypervisorResult<Self> {
		let vm = KVM.create_vm().unwrap();

		let sz = std::cmp::min(mem.memory_size, KVM_32BIT_GAP_START);

		let kvm_mem = kvm_userspace_memory_region {
			slot: 0,
			flags: mem.flags,
			memory_size: sz as u64,
			guest_phys_addr: mem.guest_address.as_u64(),
			userspace_addr: mem.host_address as u64,
		};

		unsafe { vm.set_user_memory_region(kvm_mem) }?;

		if mem.memory_size > KVM_32BIT_GAP_START + KVM_32BIT_GAP_SIZE {
			let kvm_mem = kvm_userspace_memory_region {
				slot: 1,
				flags: mem.flags,
				memory_size: (mem.memory_size - KVM_32BIT_GAP_START - KVM_32BIT_GAP_SIZE) as u64,
				guest_phys_addr: mem.guest_address.as_u64()
					+ (KVM_32BIT_GAP_START + KVM_32BIT_GAP_SIZE) as u64,
				userspace_addr: (mem.host_address as usize
					+ KVM_32BIT_GAP_START
					+ KVM_32BIT_GAP_SIZE) as u64,
			};

			unsafe { vm.set_user_memory_region(kvm_mem) }?;
		}

		debug!("Initialize interrupt controller");

		// create basic interrupt controller
		vm.create_irq_chip()?;

		if params.pit {
			vm.create_pit2(kvm_pit_config::default()).unwrap();
		}

		// enable x2APIC support
		let mut cap: kvm_enable_cap = kvm_bindings::kvm_enable_cap {
			cap: KVM_CAP_X2APIC_API,
			flags: 0,
			..Default::default()
		};
		cap.args[0] =
			(KVM_X2APIC_API_USE_32BIT_IDS | KVM_X2APIC_API_DISABLE_BROADCAST_QUIRK).into();
		vm.enable_cap(&cap)
			.expect("Unable to enable x2apic support");

		// currently, we support only system, which provides the
		// cpu feature TSC_DEADLINE
		let mut cap: kvm_enable_cap = kvm_bindings::kvm_enable_cap {
			cap: KVM_CAP_TSC_DEADLINE_TIMER,
			..Default::default()
		};
		cap.args[0] = 0;
		vm.enable_cap(&cap)
			.expect_err("Processor feature `tsc deadline` isn't supported!");

		let cap: kvm_enable_cap = kvm_bindings::kvm_enable_cap {
			cap: KVM_CAP_IRQFD,
			..Default::default()
		};
		vm.enable_cap(&cap)
			.expect_err("The support of KVM_CAP_IRQFD is currently required");

		let mut cap: kvm_enable_cap = kvm_bindings::kvm_enable_cap {
			cap: KVM_CAP_X86_DISABLE_EXITS,
			flags: 0,
			..Default::default()
		};
		cap.args[0] =
			(KVM_X86_DISABLE_EXITS_PAUSE | KVM_X86_DISABLE_EXITS_MWAIT | KVM_X86_DISABLE_EXITS_HLT)
				.into();
		vm.enable_cap(&cap)
			.expect("Unable to disable exists due pause instructions");

		let evtfd = EventFd::new(0).unwrap();
		vm.register_irqfd(&evtfd, UHYVE_IRQ_NET)?;

		Ok(Self { vm_fd: vm })
	}
}

pub struct KvmCpu {
	id: u32,
	vcpu: VcpuFd,
	parent_vm: Arc<UhyveVm<KvmVm>>,
	pci_addr: Option<u32>,
	stats: Option<CpuStats>,
}

impl KvmCpu {
	fn setup_cpuid(&self) -> Result<(), kvm_ioctls::Error> {
		//debug!("Setup cpuid");

		let mut kvm_cpuid = KVM.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?;
		let kvm_cpuid_entries = kvm_cpuid.as_mut_slice();
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
			.position(|&r| r.function == 0x80000004)
			.unwrap();

		// create own processor string (third part)
		kvm_cpuid_entries[i].eax = 0;
		kvm_cpuid_entries[i].ebx = 0;
		kvm_cpuid_entries[i].ecx = 0;
		kvm_cpuid_entries[i].edx = 0;

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

		self.vcpu.set_cpuid2(&kvm_cpuid)?;

		Ok(())
	}

	fn setup_msrs(&self) -> Result<(), kvm_ioctls::Error> {
		//debug!("Setup MSR");

		let msr_list = KVM.get_msr_index_list()?;

		let mut msr_entries = msr_list
			.as_slice()
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

		let msrs = Msrs::from_entries(&msr_entries)
			.expect("Unable to create initial values for the machine specific registers");
		self.vcpu.set_msrs(&msrs)?;

		Ok(())
	}

	fn setup_long_mode(
		&self,
		entry_point: u64,
		stack_address: u64,
		cpu_id: u32,
	) -> Result<(), kvm_ioctls::Error> {
		//debug!("Setup long mode");

		let mut sregs = self.vcpu.get_sregs()?;

		let cr0 = Cr0Flags::PROTECTED_MODE_ENABLE
			| Cr0Flags::EXTENSION_TYPE
			| Cr0Flags::NUMERIC_ERROR
			| Cr0Flags::PAGING;
		sregs.cr0 = cr0.bits();

		sregs.cr3 = BOOT_PML4.as_u64();

		let cr4 = Cr4Flags::PHYSICAL_ADDRESS_EXTENSION;
		sregs.cr4 = cr4.bits();

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
		sregs.gdt.base = BOOT_GDT.as_u64();
		sregs.gdt.limit = ((std::mem::size_of::<u64>() * BOOT_GDT_MAX) - 1) as u16;

		self.vcpu.set_sregs(&sregs)?;

		let mut regs = self.vcpu.get_regs()?;
		regs.rflags = 2;
		regs.rip = entry_point;
		regs.rdi = BOOT_INFO_ADDR.as_u64();
		regs.rsi = cpu_id.into();
		regs.rsp = stack_address;

		self.vcpu.set_regs(&regs)?;

		Ok(())
	}

	fn show_segment(name: &str, seg: &kvm_segment) {
		println!("{name}       {seg:?}");
	}

	pub fn get_vcpu(&self) -> &VcpuFd {
		&self.vcpu
	}

	pub fn get_vcpu_mut(&mut self) -> &mut VcpuFd {
		&mut self.vcpu
	}

	fn init(&mut self, entry_point: u64, stack_address: u64, cpu_id: u32) -> HypervisorResult<()> {
		self.setup_long_mode(entry_point, stack_address, cpu_id)?;
		self.setup_cpuid()?;

		// be sure that the multiprocessor is runable
		let mp_state = kvm_mp_state {
			mp_state: KVM_MP_STATE_RUNNABLE,
		};
		self.vcpu.set_mp_state(mp_state)?;

		self.setup_msrs()?;

		Ok(())
	}
}

impl VirtualCPU for KvmCpu {
	type VirtIf = KvmVm;

	fn r#continue(&mut self) -> HypervisorResult<VcpuStopReason> {
		loop {
			match self.vcpu.run() {
				Ok(vcpu_stop_reason) => match vcpu_stop_reason {
					VcpuExit::Hlt => {
						// Ignore `VcpuExit::Hlt`
						debug!("{:?}", VcpuExit::Hlt);
					}
					VcpuExit::Shutdown => {
						return Ok(VcpuStopReason::Exit(0));
					}
					VcpuExit::IoIn(port, addr) => {
						if let Some(s) = self.stats.as_mut() {
							s.increment_val(VmExit::PCIRead)
						}

						match port {
							PCI_CONFIG_DATA_PORT => {
								if let Some(pci_addr) = self.pci_addr {
									if pci_addr & 0x1ff800 == 0 {
										let virtio_device =
											self.parent_vm.virtio_device.lock().unwrap();
										virtio_device.handle_read(pci_addr & 0x3ff, addr);
									} else {
										unsafe { *(addr.as_ptr() as *mut u32) = 0xffffffff };
									}
								} else {
									unsafe { *(addr.as_ptr() as *mut u32) = 0xffffffff };
								}
							}
							PCI_CONFIG_ADDRESS_PORT => {}
							VIRTIO_PCI_STATUS => {
								let virtio_device = self.parent_vm.virtio_device.lock().unwrap();
								virtio_device.read_status(addr);
							}
							VIRTIO_PCI_HOST_FEATURES => {
								let virtio_device = self.parent_vm.virtio_device.lock().unwrap();
								virtio_device.read_host_features(addr);
							}
							VIRTIO_PCI_GUEST_FEATURES => {
								let mut virtio_device =
									self.parent_vm.virtio_device.lock().unwrap();
								virtio_device.read_requested_features(addr);
							}
							VIRTIO_PCI_CONFIG_OFF_MSIX_OFF..=VIRTIO_PCI_CONFIG_OFF_MSIX_OFF_MAX => {
								let virtio_device = self.parent_vm.virtio_device.lock().unwrap();
								virtio_device
									.read_mac_byte(addr, port - VIRTIO_PCI_CONFIG_OFF_MSIX_OFF);
							}
							VIRTIO_PCI_ISR => {
								let mut virtio_device =
									self.parent_vm.virtio_device.lock().unwrap();
								virtio_device.reset_interrupt()
							}
							VIRTIO_PCI_LINK_STATUS_MSIX_OFF => {
								let virtio_device = self.parent_vm.virtio_device.lock().unwrap();
								virtio_device.read_link_status(addr);
							}
							port => {
								warn!("guest read from unknown I/O port {port:#x}");
							}
						}
					}
					VcpuExit::IoOut(port, addr) => {
						let data_addr =
							GuestPhysAddr::new(unsafe { (*(addr.as_ptr() as *const u32)) as u64 });
						if let Some(hypercall) = unsafe {
							hypercall::address_to_hypercall(&self.parent_vm.mem, port, data_addr)
						} {
							if let Some(s) = self.stats.as_mut() {
								s.increment_val(VmExit::Hypercall(HypercallAddress::from(
									&hypercall,
								)))
							}

							match hypercall {
								Hypercall::Cmdsize(syssize) => syssize
									.update(self.parent_vm.kernel_path(), self.parent_vm.args()),
								Hypercall::Cmdval(syscmdval) => {
									hypercall::copy_argv(
										self.parent_vm.kernel_path().as_os_str(),
										self.parent_vm.args(),
										syscmdval,
										&self.parent_vm.mem,
									);
									hypercall::copy_env(syscmdval, &self.parent_vm.mem);
								}
								Hypercall::Exit(sysexit) => {
									return Ok(VcpuStopReason::Exit(sysexit.arg));
								}
								Hypercall::FileClose(sysclose) => hypercall::close(sysclose),
								Hypercall::FileLseek(syslseek) => hypercall::lseek(syslseek),
								Hypercall::FileOpen(sysopen) => hypercall::open(
									&self.parent_vm.mem,
									sysopen,
									&mut self.parent_vm.mount.lock().unwrap(),
									&self.parent_vm.tempdir,
								),
								Hypercall::FileRead(sysread) => {
									hypercall::read(&self.parent_vm.mem, sysread)
								}
								Hypercall::FileWrite(syswrite) => {
									hypercall::write(&self.parent_vm, syswrite)
										.map_err(|_e| HypervisorError::new(libc::EFAULT))?
								}
								Hypercall::FileUnlink(sysunlink) => hypercall::unlink(
									&self.parent_vm.mem,
									sysunlink,
									&mut self.parent_vm.mount.lock().unwrap(),
								),
								Hypercall::SerialWriteByte(buf) => self
									.parent_vm
									.serial_output(&[buf])
									.unwrap_or_else(|e| error!("{e:?}")),
								Hypercall::SerialWriteBuffer(sysserialwrite) => {
									// safety: as this buffer is only read and not used afterwards, we don't create multiple aliasing
									let buf = unsafe {
										self.parent_vm.mem.slice_at(sysserialwrite.buf, sysserialwrite.len)
			.expect("Systemcall parameters for SerialWriteBuffer are invalid")
									};

									self.parent_vm
										.serial_output(buf)
										.unwrap_or_else(|e| error!("{e:?}"))
								}
								_ => panic!("Got unknown hypercall {:?}", hypercall),
							};
						} else {
							if let Some(s) = self.stats.as_mut() {
								s.increment_val(VmExit::PCIWrite)
							}
							match port {
								//TODO:
								PCI_CONFIG_DATA_PORT => {
									if let Some(pci_addr) = self.pci_addr {
										if pci_addr & 0x1ff800 == 0 {
											let mut virtio_device =
												self.parent_vm.virtio_device.lock().unwrap();
											virtio_device.handle_write(pci_addr & 0x3ff, addr);
										}
									}
								}
								PCI_CONFIG_ADDRESS_PORT => {
									self.pci_addr = Some(unsafe { *(addr.as_ptr() as *const u32) });
								}
								VIRTIO_PCI_STATUS => {
									let mut virtio_device =
										self.parent_vm.virtio_device.lock().unwrap();
									virtio_device.write_status(addr);
								}
								VIRTIO_PCI_GUEST_FEATURES => {
									let mut virtio_device =
										self.parent_vm.virtio_device.lock().unwrap();
									virtio_device.write_requested_features(addr);
								}
								VIRTIO_PCI_QUEUE_NOTIFY => {
									let mut virtio_device =
										self.parent_vm.virtio_device.lock().unwrap();
									virtio_device.handle_notify_output(addr, &self.parent_vm.mem);
								}
								VIRTIO_PCI_QUEUE_SEL => {
									let mut virtio_device =
										self.parent_vm.virtio_device.lock().unwrap();
									virtio_device.write_selected_queue(addr);
								}
								VIRTIO_PCI_QUEUE_PFN => {
									let mut virtio_device =
										self.parent_vm.virtio_device.lock().unwrap();
									virtio_device.write_pfn(addr, &self.parent_vm.mem);
								}
								port => {
									warn!("guest wrote to unknown I/O port {port:#x}");
								}
							}
						}
					}
					VcpuExit::Debug(debug) => {
						if let Some(s) = self.stats.as_mut() {
							s.increment_val(VmExit::Debug)
						}
						info!("Caught Debug Interrupt!");
						return Ok(VcpuStopReason::Debug(debug));
					}
					VcpuExit::InternalError => {
						self.print_registers();
						panic!("{:?}", VcpuExit::InternalError)
					}
					vcpu_exit => {
						unimplemented!("{:?}", vcpu_exit)
					}
				},
				Err(err) => match err.errno() {
					libc::EINTR => return Ok(VcpuStopReason::Kick),
					_ => return Err(err),
				},
			}
		}
	}

	fn run(&mut self) -> HypervisorResult<(Option<i32>, Option<CpuStats>)> {
		if let Some(stats) = self.stats.as_mut() {
			stats.start_time_measurement();
		}
		let res = match self.r#continue()? {
			VcpuStopReason::Debug(_) => {
				unreachable!("reached debug exit without running in debugging mode")
			}
			VcpuStopReason::Exit(code) => Some(code),
			VcpuStopReason::Kick => None,
		};
		if let Some(stats) = self.stats.as_mut() {
			stats.stop_time_measurement();
		}
		Ok((res, self.stats.take()))
	}

	fn print_registers(&self) {
		let regs = self.vcpu.get_regs().unwrap();
		let sregs = self.vcpu.get_sregs().unwrap();

		println!();
		println!("Dump state of CPU {}", self.id);
		println!();
		println!("Registers:");
		println!("----------");
		println!(
			"rax: {:#18x}       r8: {:#18x}   cr0: {:#18x}",
			regs.rax, regs.r8, sregs.cr0
		);
		println!(
			"rbx: {:#18x}       r9: {:#18x}   cr2: {:#18x}",
			regs.rbx, regs.r9, sregs.cr2
		);
		println!(
			"rcx: {:#18x}      r10: {:#18x}   cr3: {:#18x}",
			regs.rcx, regs.r10, sregs.cr3
		);
		println!(
			"rdx: {:#18x}      r11: {:#18x}   cr4: {:#18x}",
			regs.rdx, regs.r11, sregs.cr4
		);
		println!(
			"rsi: {:#18x}      r12: {:#18x}   cr8: {:#18x}",
			regs.rsi, regs.r12, sregs.cr8
		);
		println!(
			"rdi: {:#18x}      r13: {:#18x}   efer:{:#18x}",
			regs.rdi, regs.r13, sregs.efer
		);
		println!("rsp: {:#18x}      r14: {:#18x}", regs.rsp, regs.r14);
		println!("rbp: {:#18x}      r15: {:#18x}", regs.rbp, regs.r15);
		println!("rip: {:#18x}   rflags: {:#18x}", regs.rip, regs.rflags);
		println!();
		println!("Segment registers:");
		println!("------------------");
		println!("register  selector  base              limit     type  p dpl db s l g avl");
		KvmCpu::show_segment("cs ", &sregs.cs);
		KvmCpu::show_segment("ss ", &sregs.ss);
		KvmCpu::show_segment("ds ", &sregs.ds);
		KvmCpu::show_segment("es ", &sregs.es);
		KvmCpu::show_segment("fs ", &sregs.fs);
		KvmCpu::show_segment("gs ", &sregs.gs);
		KvmCpu::show_segment("tr ", &sregs.tr);
		KvmCpu::show_segment("ldt", &sregs.ldt);
		println!("gtd: {:x?}", sregs.gdt);
		println!("gtd: {:x?}", sregs.gdt);

		println!();
		println!("\nAPIC:");
		println!("-----");
		println!("apic_base: {:#18x}", sregs.apic_base);
		println!("interrupt_bitmap: {:x?}", sregs.interrupt_bitmap);
	}
}
