use std::sync::{Arc, Mutex};

use kvm_bindings::*;
use kvm_ioctls::{VcpuExit, VcpuFd, VmFd};
use uhyve_interface::{GuestPhysAddr, Hypercall};
use vm_memory::{GuestMemory, GuestMemoryMmap, GuestMemoryRegion};
use vmm_sys_util::eventfd::EventFd;
use x86_64::registers::control::{Cr0Flags, Cr4Flags};

use crate::{
	consts::*,
	hypercall,
	linux::KVM,
	pci::PciDevice,
	vcpu::{VcpuStopReason, VirtualCPU},
	virtio::{
		capabilities::{ComCfg, IsrStatus, NetDevCfg},
		pci::{ConfigAddress, MEM_NOTIFY, MEM_NOTIFY_1},
	},
	vm::UhyveVm,
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

static KVM_ACCESS: Mutex<Option<VmFd>> = Mutex::new(None);

pub fn initialize_kvm(mem: &GuestMemoryMmap, use_pit: bool) -> HypervisorResult<()> {
	// TODO: Support multiple regions and iterate over them
	let mem_region = mem.iter().next().unwrap();
	let sz = std::cmp::min(mem_region.size(), KVM_32BIT_GAP_START);

	let start_addr = mem_region.start_addr();
	let region_addr = mem_region.to_region_addr(start_addr).unwrap();
	let kvm_mem = kvm_userspace_memory_region {
		slot: 0,
		flags: 0, // Can be KVM_MEM_LOG_DIRTY_PAGES and KVM_MEM_READONLY
		memory_size: sz as u64,
		guest_phys_addr: start_addr.0,
		userspace_addr: mem_region.get_host_address(region_addr).unwrap() as u64,
	};

	// TODO: make vm a global struct in linux blah
	let vm = KVM.create_vm()?;
	unsafe { vm.set_user_memory_region(kvm_mem) }?;

	if mem_region.size() > KVM_32BIT_GAP_START + KVM_32BIT_GAP_SIZE {
		let kvm_mem = kvm_userspace_memory_region {
			slot: 1,
			flags: mem_region.flags() as u32,
			memory_size: (mem_region.size() - KVM_32BIT_GAP_START - KVM_32BIT_GAP_SIZE) as u64,
			guest_phys_addr: mem_region.start_addr().0
				+ (KVM_32BIT_GAP_START + KVM_32BIT_GAP_SIZE) as u64,
			userspace_addr: (mem_region
				.get_host_address(mem_region.to_region_addr(mem_region.start_addr()).unwrap())
				.unwrap() as usize
				+ KVM_32BIT_GAP_START
				+ KVM_32BIT_GAP_SIZE) as u64,
		};

		unsafe { vm.set_user_memory_region(kvm_mem) }?;
	}

	debug!("Initialize interrupt controller");

	// create basic interrupt controller
	vm.create_irq_chip()?;

	if use_pit {
		vm.create_pit2(kvm_pit_config::default()).unwrap();
	}

	// enable x2APIC support
	let mut cap: kvm_enable_cap = kvm_bindings::kvm_enable_cap {
		cap: KVM_CAP_X2APIC_API,
		flags: 0,
		..Default::default()
	};
	cap.args[0] = (KVM_X2APIC_API_USE_32BIT_IDS | KVM_X2APIC_API_DISABLE_BROADCAST_QUIRK).into();
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
	vm.register_irqfd(&evtfd, UHYVE_IRQ_NET as u32)?;

	*KVM_ACCESS.lock().unwrap() = Some(vm);
	Ok(())
}

pub struct KvmCpu {
	id: u32,
	vcpu: VcpuFd,
	parent_vm: Arc<UhyveVm<Self>>,
	pci_addr: Option<u32>,
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

	fn show_dtable(name: &str, dtable: &kvm_dtable) {
		println!("{name}                 {dtable:?}");
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
	fn new(id: u32, parent_vm: Arc<UhyveVm<KvmCpu>>) -> HypervisorResult<KvmCpu> {
		let vcpu = KVM_ACCESS
			.lock()
			.unwrap()
			.as_mut()
			.expect("KVM is not initialized yet")
			.create_vcpu(id as u64)?;
		let mut kvcpu = KvmCpu {
			id,
			vcpu,
			parent_vm: parent_vm.clone(),
			pci_addr: None,
		};
		kvcpu.init(parent_vm.get_entry_point(), parent_vm.stack_address(), id)?;

		Ok(kvcpu)
	}

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
					VcpuExit::IoIn(port, addr) => match port {
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
						_ => {
							error!("Unhanded IO Exit")
						}
					},
					VcpuExit::IoOut(port, addr) => {
						let data_addr =
							GuestPhysAddr::new(unsafe { (*(addr.as_ptr() as *const u32)) as u64 });
						if let Some(hypercall) = unsafe {
							hypercall::address_to_hypercall(&self.parent_vm.mem, port, data_addr)
						} {
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
								Hypercall::FileOpen(sysopen) => {
									hypercall::open(&self.parent_vm.mem, sysopen)
								}
								Hypercall::FileRead(sysread) => {
									hypercall::read(&self.parent_vm.mem, sysread)
								}
								Hypercall::FileWrite(syswrite) => {
									hypercall::write(&self.parent_vm.mem, syswrite)
										.map_err(|_e| HypervisorError::new(libc::EFAULT))?
								}
								Hypercall::FileUnlink(sysunlink) => {
									hypercall::unlink(&self.parent_vm.mem, sysunlink)
								}
								Hypercall::SerialWriteByte(buf) => hypercall::uart(&[buf])?,
								_ => panic!("Got unknown hypercall {:?}", hypercall),
							};
						} else {
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
								_ => {
									panic!("Unhandled IO exit: 0x{:x}", port);
								}
							}
						}
					}
					VcpuExit::Debug(debug) => {
						// info!("Caught Debug Interrupt!");
						return Ok(VcpuStopReason::Debug(debug));
					}
					VcpuExit::InternalError => {
						panic!("{:?}", VcpuExit::InternalError)
					}

					VcpuExit::MmioRead(addr, data) => {
						let virtio_device = self.parent_vm.virtio_device.lock().unwrap();
						match ConfigAddress::from_guest_address(addr).unwrap() {
							IsrStatus::ISR_FLAGS => {
								virtio_device.read_isr_notify(data);
							}
							ComCfg::DEVICE_STATUS => {
								data[0] = virtio_device.read_status_reg();
							}
							ComCfg::DEVICE_FEATURE => {
								virtio_device.read_host_features(data);
							}
							ComCfg::QUEUE_SIZE => {
								virtio_device.read_queue_size(data);
							}
							ComCfg::QUEUE_NOTIFY_OFFSET => {
								virtio_device.read_queue_notify_offset(data);
							}
							NetDevCfg::MAC_ADDRESS => {
								virtio_device.read_mac_address(data);
							}
							NetDevCfg::NET_STATUS => {
								virtio_device.read_net_status(data);
							}
							NetDevCfg::MTU => {
								virtio_device.read_mtu(data);
							}
							ComCfg::QUEUE_RESET => {
								virtio_device.read_queue_reset(data);
							}
							_ => {
								warn!("unhandled read! {addr:#x?}")
							}
						}
					}

					VcpuExit::MmioWrite(addr, data) => {
						let mut virtio_device = self.parent_vm.virtio_device.lock().unwrap();
						match ConfigAddress::from_guest_address(addr).unwrap() {
							ComCfg::DEVICE_STATUS => {
								virtio_device.write_status(data);
							}
							ComCfg::DRIVER_FEATURE_SELECT => {
								virtio_device.write_driver_feature_select(data);
							}
							ComCfg::DEVICE_FEATURE_SELECT => {
								virtio_device.write_device_feature_select(data);
							}
							ComCfg::DRIVER_FEATURE => {
								virtio_device.write_requested_features(data);
							}
							ComCfg::QUEUE_SELECT => {
								virtio_device.write_selected_queue(data);
							}
							ComCfg::QUEUE_DESC => {
								// write descriptor address
								virtio_device.write_pfn(data);
							}
							ComCfg::QUEUE_ENABLE => {
								virtio_device.queue_enable(data);
							}
							ComCfg::QUEUE_DRIVER => {
								virtio_device.write_queue_driver(data);
							}
							ComCfg::QUEUE_DEVICE => {
								virtio_device.write_queue_driver(data);
							}
							ComCfg::QUEUE_RESET => {
								virtio_device.write_reset_queue();
							}
							IsrStatus::ISR_FLAGS => {
								panic!("Guest should not write to ISR!");
							}
							MEM_NOTIFY | MEM_NOTIFY_1 => {
								// TODO: are we only writing to two addresses or alerting/switching twice?
								panic!("Writing to MemNotify address! Is IOEventFD correctly configured?");
							}
							_ => warn!("writing to unhandled MMIO address {addr:#x?}"),
						}
					}
					vcpu_exit => {
						unimplemented!("{:#x?}", vcpu_exit)
					}
				},
				Err(err) => match err.errno() {
					libc::EINTR => return Ok(VcpuStopReason::Kick),
					_ => return Err(err),
				},
			}
		}
	}

	fn run(&mut self) -> HypervisorResult<Option<i32>> {
		match self.r#continue()? {
			VcpuStopReason::Debug(_) => {
				unreachable!("reached debug exit without running in debugging mode")
			}
			VcpuStopReason::Exit(code) => Ok(Some(code)),
			VcpuStopReason::Kick => Ok(None),
		}
	}

	fn print_registers(&self) {
		let regs = self.vcpu.get_regs().unwrap();
		let sregs = self.vcpu.get_sregs().unwrap();

		println!();
		println!("Dump state of CPU {}", self.id);
		println!();
		println!("Registers:");
		println!("----------");
		println!("{regs:?}{sregs:?}");

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
		KvmCpu::show_dtable("gdt", &sregs.gdt);
		KvmCpu::show_dtable("idt", &sregs.idt);

		println!();
		println!("\nAPIC:");
		println!("-----");
		println!(
			"efer: {:016x}  apic base: {:016x}",
			sregs.efer, sregs.apic_base
		);
	}
}
