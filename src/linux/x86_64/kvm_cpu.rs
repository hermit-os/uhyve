use std::{io, num::NonZero, ops::Add, sync::Arc};

use kvm_bindings::*;
use kvm_ioctls::{VcpuExit, VcpuFd, VmFd};
use uhyve_interface::GuestPhysAddr;
use x86_64::registers::control::{Cr0Flags, Cr4Flags};

use crate::{
	HypervisorResult,
	arch::{BOOT_GDT_MAX, GDT_OFFSET, PML4_OFFSET},
	hypercall,
	linux::{KVM, x86_64::virtio_device::KvmVirtioNetDevice},
	mem::MmapMemory,
	params::{NetworkMode, Params},
	pci::{IOBASE_U64, IOEND_U64, PciConfigurationAddress, PciDevice},
	stats::{CpuStats, VmExit},
	vcpu::{VcpuStopReason, VirtualCPU},
	virtio::net::VirtioNetPciDevice,
	vm::{
		BOOT_INFO_OFFSET, KernelInfo, VirtualizationBackend, VirtualizationBackendInternal,
		VmPeripherals,
	},
};

const CPUID_EXT_HYPERVISOR: u32 = 1 << 31;
const CPUID_TSC_DEADLINE: u32 = 1 << 24;
const CPUID_ENABLE_MSR: u32 = 1 << 5;
const MSR_IA32_APICBASE: u32 = 0x0000001b;
const MSR_IA32_MISC_ENABLE: u32 = 0x000001a0;
const PCI_CONFIG_DATA_PORT: u16 = 0xCFC;
const PCI_CONFIG_ADDRESS_PORT: u16 = 0xCF8;

const EFER_LME: u64 = 1 << 8; /* Long mode enable */
const EFER_LMA: u64 = 1 << 10; /* Long mode active (read-only) */
const EFER_NXE: u64 = 1 << 11; /* PTE No-Execute bit enable */

// First address that uses more than 32 bits.
const KVM_32BIT_MAX_MEM_SIZE: usize = 1 << 32;
// 1 GiB
const KVM_32BIT_GAP_SIZE: usize = 1024 << 20;
// 3 GiB, aka. 0xC000_0000
pub(crate) const KVM_32BIT_GAP_START: usize = KVM_32BIT_MAX_MEM_SIZE - KVM_32BIT_GAP_SIZE;

#[derive(Debug)]
pub struct KvmVm {
	vm_fd: VmFd,
	peripherals: Arc<VmPeripherals<<Self as VirtualizationBackendInternal>::VirtioNetImpl>>,
}

impl VirtualizationBackendInternal for KvmVm {
	type VCPU = KvmCpu;
	type VirtioNetImpl = KvmVirtioNetDevice;
	const NAME: &str = "KvmVm";

	fn new_cpu(
		&self,
		id: usize,
		kernel_info: Arc<KernelInfo>,
		enable_stats: bool,
	) -> HypervisorResult<KvmCpu> {
		let vcpu = self.vm_fd.create_vcpu(id as u64)?;
		let mut kvcpu = KvmCpu {
			id,
			vcpu,
			peripherals: self.peripherals.clone(),
			kernel_info,
			pci_addr: None,
			stats: if enable_stats {
				Some(CpuStats::new(id))
			} else {
				None
			},
		};
		kvcpu.init()?;

		Ok(kvcpu)
	}

	fn new(
		peripherals: Arc<VmPeripherals<Self::VirtioNetImpl>>,
		params: &Params,
	) -> HypervisorResult<Self> {
		let vm = KVM.create_vm().unwrap();

		// Double-check that neither the (first) guest address nor the end of the guest memory
		// overlap with the gap that we reserved between 3GiB and 4GiB.
		let guest_phys_addr = peripherals.mem.guest_addr();
		let memory_size = peripherals.mem.size();
		let guest_end_addr = peripherals.mem.guest_addr().add(memory_size).as_usize();
		assert!(
			!(KVM_32BIT_GAP_START..=KVM_32BIT_MAX_MEM_SIZE).contains(&(guest_phys_addr.as_usize())),
			"Provided guest address {guest_phys_addr:#X} is in reserved virtual memory region between 3 and 4GiB"
		);
		assert!(
			!(KVM_32BIT_GAP_START..=KVM_32BIT_MAX_MEM_SIZE)
				.contains(&guest_phys_addr.add(memory_size).as_usize()),
			"Guest end address {guest_end_addr:#X} is in reserved virtual memory region between 3 and 4GiB"
		);

		let kvm_mem = kvm_userspace_memory_region {
			slot: 0,
			flags: 0, // Can be KVM_MEM_LOG_DIRTY_PAGES and KVM_MEM_READONLY
			memory_size: memory_size as u64,
			guest_phys_addr: guest_phys_addr.as_u64(),
			userspace_addr: peripherals.mem.host_start() as u64,
		};
		unsafe { vm.set_user_memory_region(kvm_mem) }?;

		trace!("Initialize interrupt controller");

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
		cap = kvm_bindings::kvm_enable_cap {
			cap: KVM_CAP_TSC_DEADLINE_TIMER,
			..Default::default()
		};
		cap.args[0] = 0;
		vm.enable_cap(&cap)
			.expect_err("Processor feature `tsc deadline` isn't supported!");

		cap = kvm_bindings::kvm_enable_cap {
			cap: KVM_CAP_IRQFD,
			..Default::default()
		};
		vm.enable_cap(&cap)
			.expect_err("The support of KVM_CAP_IRQFD is currently required");

		if params.cpu_pm {
			let mut disable_exits = KVM
				.check_extension_raw(KVM_CAP_X86_DISABLE_EXITS.into())
				.cast_unsigned();
			disable_exits &= KVM_X86_DISABLE_EXITS_MWAIT
				| KVM_X86_DISABLE_EXITS_HLT
				| KVM_X86_DISABLE_EXITS_PAUSE
				| KVM_X86_DISABLE_EXITS_CSTATE;
			cap = kvm_bindings::kvm_enable_cap {
				cap: KVM_CAP_X86_DISABLE_EXITS,
				flags: 0,
				..Default::default()
			};
			cap.args[0] = disable_exits.into();
			if let Err(err) = vm.enable_cap(&cap) {
				error!("kvm: cannot disable KVM exits: {err}");
			}
		}

		if let Some(virtiodevice) = &peripherals.virtio_device {
			virtiodevice.lock().unwrap().setup(&vm);
		}

		Ok(Self {
			vm_fd: vm,
			peripherals,
		})
	}

	fn virtio_net_device(mode: NetworkMode, memory: Arc<MmapMemory>) -> Self::VirtioNetImpl {
		KvmVirtioNetDevice::new(VirtioNetPciDevice::new(mode, memory))
	}
}

impl VirtualizationBackend for KvmVm {}

pub struct KvmCpu {
	id: usize,
	vcpu: VcpuFd,
	peripherals: Arc<VmPeripherals<<KvmVm as VirtualizationBackendInternal>::VirtioNetImpl>>,
	// TODO: Remove once the getenv/getargs hypercalls are removed
	kernel_info: Arc<KernelInfo>,
	pci_addr: Option<u32>,
	stats: Option<CpuStats>,
}

impl KvmCpu {
	fn init(&mut self) -> HypervisorResult<()> {
		self.setup_long_mode(
			self.kernel_info.entry_point,
			self.kernel_info.stack_address,
			self.kernel_info.guest_address,
			self.id,
		)?;
		self.setup_cpuid()?;

		// be sure that the multiprocessor is runable
		let mp_state = kvm_mp_state {
			mp_state: KVM_MP_STATE_RUNNABLE,
		};
		self.vcpu.set_mp_state(mp_state)?;

		self.setup_msrs()?;

		Ok(())
	}

	fn setup_cpuid(&self) -> Result<(), kvm_ioctls::Error> {
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
		msr_entries[1].index = MSR_IA32_APICBASE;
		msr_entries[1].data = 1;

		let msrs = Msrs::from_entries(&msr_entries)
			.expect("Unable to create initial values for the machine specific registers");
		self.vcpu.set_msrs(&msrs)?;

		Ok(())
	}

	fn setup_long_mode(
		&self,
		entry_point: GuestPhysAddr,
		stack_address: GuestPhysAddr,
		guest_address: GuestPhysAddr,
		cpu_id: usize,
	) -> Result<(), kvm_ioctls::Error> {
		let mut sregs = self.vcpu.get_sregs()?;

		let cr0 = Cr0Flags::PROTECTED_MODE_ENABLE
			| Cr0Flags::EXTENSION_TYPE
			| Cr0Flags::NUMERIC_ERROR
			| Cr0Flags::PAGING;
		sregs.cr0 = cr0.bits();

		sregs.cr3 = (guest_address + PML4_OFFSET).as_u64();

		let cr4 = Cr4Flags::PHYSICAL_ADDRESS_EXTENSION;
		sregs.cr4 = cr4.bits();
		sregs.efer = EFER_LME | EFER_LMA | EFER_NXE;

		// Generate segments for code (cs), data (ds), strings (es), stacks (ss)
		// (See Section 3.4.5 from Intel Software Developer's Manual - Volume 3)
		//
		// segment selector layout crash-course:
		// - bits 0-1: requested privilege level
		// - bit 2: 0 for GDTs.
		// - bits 3-15: define the index bit
		let mut seg = kvm_segment {
			base: 0,           // 64-bit
			limit: 0xffffffff, // 4GByte
			selector: 1 << 3,  // first GDT entry
			type_: 11,         // Execute-Read, accessed (code segment)
			present: 1,
			dpl: 0, // most privileged descriptor privilege level
			s: 1,   // segment is either for code or data
			l: 1,   // long ("contains native 64-bit code")
			g: 1,   // granularity, "support 4GByte (limits) in 4Kbyte increments"
			..Default::default()
		};

		sregs.cs = seg;
		// DS, ES, SS: Data segments, using second GDT entry.
		// Read-Write, accessed. L bit must not be set.
		(seg.type_, seg.selector, seg.l) = (3, 1 << 4, 0);
		(sregs.ds, sregs.es, sregs.ss) = (seg, seg, seg);
		sregs.gdt.base = (guest_address + GDT_OFFSET).as_u64();
		sregs.gdt.limit = ((std::mem::size_of::<u64>() * BOOT_GDT_MAX) - 1) as u16;
		self.vcpu.set_sregs(&sregs)?;

		let regs = kvm_regs {
			rflags: 2,
			rip: entry_point.as_u64(),
			rdi: (guest_address + BOOT_INFO_OFFSET).as_u64(),
			rsi: cpu_id.try_into().unwrap(),
			rsp: stack_address.as_u64(),
			..Default::default()
		};
		self.vcpu.set_regs(&regs)?;

		Ok(())
	}

	fn show_segment(name: &str, seg: &kvm_segment) {
		println!("{name}       {seg:?}");
	}

	pub(crate) fn get_vcpu_id(&self) -> usize {
		self.id
	}

	pub(crate) fn get_vcpu(&self) -> &VcpuFd {
		&self.vcpu
	}

	/// This checks the pointer to the a hypercall's data struct provided
	/// by the Hermit unikernel when initiating a hypercall.
	///
	/// This is only intended to be used after a hypercall has taken place,
	/// i.e. when handling an IoOut exit.
	pub(crate) fn get_hypercall_data_addr_v2(&self) -> GuestPhysAddr {
		GuestPhysAddr::new(self.vcpu.sync_regs().regs.rdi)
	}

	pub fn get_root_pagetable(&self) -> GuestPhysAddr {
		GuestPhysAddr::new(self.vcpu.get_sregs().unwrap().cr3)
	}
}

impl VirtualCPU for KvmCpu {
	fn thread_local_init(&mut self) -> HypervisorResult<()> {
		// no thread-local initialization necessary
		Ok(())
	}

	fn r#continue(&mut self) -> HypervisorResult<VcpuStopReason> {
		loop {
			let virtio_device = || {
				self.peripherals
					.virtio_device
					.as_ref()
					.map(|vd| vd.lock().unwrap())
			};
			self.vcpu.set_sync_valid_reg(kvm_ioctls::SyncReg::Register);
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
								if let Some(pci_addr) = self.pci_addr
									&& pci_addr & 0x1ff800 == 0
								{
									if let Some(mut virtio_device) = virtio_device() {
										virtio_device.virtio.handle_read(
											PciConfigurationAddress(pci_addr & 0x3ff),
											addr,
										);
									} else {
										// The access here is fine, because the guest might just be scanning for devices
										trace!("Guest tries to access non-present virtio device");
									}
								} else {
									// The access here is fine, because the guest might just be scanning for devices
									trace!("Invalid pci config data port access");
									addr.fill(0xff);
								}
							}
							PCI_CONFIG_ADDRESS_PORT => {}
							port => {
								warn!("guest read from unknown I/O port {port:#x}");
							}
						}
					}
					VcpuExit::IoOut(port, addr) => {
						// The use of a mut ref would later render the non-mut ref
						// needed for getting the hypercall data adddress impossible.
						let addr = addr.to_owned();

						if let Some(hypercall) = unsafe {
							hypercall::address_to_hypercall_v2(
								&self.peripherals.mem,
								port as u64,
								self.get_hypercall_data_addr_v2(),
							)
						} {
							if let Some(s) = self.stats.as_mut() {
								s.increment_val((&hypercall).into())
							}

							if let Some(stop) =
								hypercall::handle_hypercall_v2(&self.peripherals, hypercall)
							{
								return Ok(stop);
							}
						} else if let Some(hypercall) = unsafe {
							// v1 images used to read the address from the 32-bit value written
							// into the virtual device register to perform an IoOut. Although
							// this was done for speed reasons, this implementation cannot
							// work for addresses containing more than 32 bits (which is to be
							// deemed as conventional in 64-bit environments), thus constraining
							// the memory size used by Uhyve.
							let data_addr =
								GuestPhysAddr::new((*(addr.as_ptr() as *const u32)) as u64);
							hypercall::address_to_hypercall_v1(
								&self.peripherals.mem,
								port,
								data_addr,
							)
						} {
							if let Some(s) = self.stats.as_mut() {
								s.increment_val((&hypercall).into())
							}

							if let Some(stop) = hypercall::handle_hypercall_v1(
								&self.peripherals,
								&self.kernel_info,
								|| Ok(self.get_root_pagetable()),
								hypercall,
							) {
								return stop;
							}
						} else {
							if let Some(s) = self.stats.as_mut() {
								s.increment_val(VmExit::PCIWrite)
							}
							match port {
								// Legacy PCI addressing method
								PCI_CONFIG_DATA_PORT => {
									if let Some(pci_addr) = self.pci_addr
										&& pci_addr & 0x1ff800 == 0 && let Some(mut virtio_device) =
										virtio_device()
									{
										virtio_device.virtio.handle_write(
											PciConfigurationAddress(pci_addr & 0x3ff),
											&addr,
										);
									}
								}
								PCI_CONFIG_ADDRESS_PORT => {
									if (addr.as_ptr() as usize).is_multiple_of(align_of::<usize>())
									{
										self.pci_addr = Some(
											// SAFETY: `pci_addr` is validated on read, so even if this is bogus uhyve is not affected.
											unsafe { *(addr.as_ptr() as *const u32) },
										);
									}
								}
								port => {
									warn!("guest wrote to unknown I/O port {port:#x}");
								}
							}
						};
					}
					VcpuExit::MmioRead(addr, data) => {
						match addr {
							0x9_F000..0xA_0000 | 0xF_0000..0x10_0000 => {} // Search for MP floating table
							IOBASE_U64..IOEND_U64 => virtio_device()
								.unwrap()
								.virtio
								.handle_read(PciConfigurationAddress(addr as u32), data),
							_ => {
								let l = data.len();
								self.print_registers();
								panic!(
									"undefined mmio read of {l} bytes to {addr:#x?} (ConfigAddress {:x?})",
									PciConfigurationAddress::from_guest_address(addr.into())
								);
							}
						}
					}
					VcpuExit::MmioWrite(addr, data) => match addr {
						IOBASE_U64..IOEND_U64 => virtio_device()
							.unwrap()
							.virtio
							.handle_write(PciConfigurationAddress(addr as u32), data),
						_ => {
							let l = data.len();
							self.print_registers();
							panic!("undefined mmio write of {l} bytes to {addr:#x?}");
						}
					},
					VcpuExit::Debug(debug) => {
						if let Some(s) = self.stats.as_mut() {
							s.increment_val(VmExit::Debug)
						}
						trace!("Caught debug interrupt: {debug:#?}");
						return Ok(VcpuStopReason::Debug(debug));
					}
					VcpuExit::InternalError => {
						self.print_registers();
						panic!("{:?}", VcpuExit::InternalError)
					}
					VcpuExit::FailEntry(hardware_entry_failure_reason, cpu) => {
						#[expect(dead_code)]
						#[derive(Debug)]
						struct VcpuExitFailEntry {
							hardware_entry_failure_reason: u64,
							cpu: u32,
						}

						let debug = VcpuExitFailEntry {
							hardware_entry_failure_reason,
							cpu,
						};

						let err = io::Error::other(format!("{debug:?}"));
						return Err(err.into());
					}
					vcpu_exit => {
						let err = io::Error::other(format!("not implemented: {vcpu_exit:?}"));
						return Err(err.into());
					}
				},
				Err(err) => match err.errno() {
					libc::EINTR => return Ok(VcpuStopReason::Kick),
					_ => return Err(err.into()),
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

	fn get_cpu_frequency(&self) -> Option<NonZero<u32>> {
		self.vcpu.get_tsc_khz().map(|f| f.try_into().unwrap()).ok()
	}
}
