use std::{num::NonZero, ops::Add};

use gdbstub::{common::Tid, stub::MultiThreadStopReason};
use kvm_bindings::{kvm_regs, *};
use kvm_ioctls::{VcpuFd, VmFd};
use libc::EFD_NONBLOCK;
use uhyve_interface::GuestPhysAddr;
use vmm_sys_util::eventfd::EventFd;
use x86_64::registers::control::{Cr0Flags, Cr4Flags};

use crate::{
	HypervisorError, HypervisorResult,
	arch::{BOOT_GDT_MAX, X86_64MemoryLayout, paging::initialize_pagetables},
	gdb::resume::ResumeMode,
	hypercall::{self, GuestHypercall},
	mem::MmapMemory,
	mem_layout::MemoryLayout,
	os::kvm::{KVM, KvmVm, breakpoints::AllBreakpoints},
	params::Params,
	pci::{PciConfigurationAddress, PciDevice},
	stats::VmExit,
	vm::{KernelInfo, VirtualizationBackendInternal, VmPeripherals},
};

pub(crate) mod regs;

const CPUID_EXT_HYPERVISOR: u32 = 1 << 31;
const CPUID_TSC_DEADLINE: u32 = 1 << 24;
const CPUID_ENABLE_MSR: u32 = 1 << 5;
const MSR_IA32_APICBASE: u32 = 0x0000001b;
const MSR_IA32_MISC_ENABLE: u32 = 0x000001a0;
const PCI_CONFIG_DATA_PORT: u16 = 0xCFC;
const PCI_CONFIG_ADDRESS_PORT: u16 = 0xCF8;
const UHYVE_IRQ_NET_PIC_PIN: u32 = 11; // Network is connected to PIC pin 11

const EFER_LME: u64 = 1 << 8; /* Long mode enable */
const EFER_LMA: u64 = 1 << 10; /* Long mode active (read-only) */
const EFER_NXE: u64 = 1 << 11; /* PTE No-Execute bit enable */

// First address that uses more than 32 bits.
const KVM_32BIT_MAX_MEM_SIZE: usize = 1 << 32;
// 1 GiB
const KVM_32BIT_GAP_SIZE: usize = 1024 << 20;
// 3 GiB, aka. 0xC000_0000
pub(super) const KVM_32BIT_GAP_START: usize = KVM_32BIT_MAX_MEM_SIZE - KVM_32BIT_GAP_SIZE;

pub type MemLayout = X86_64MemoryLayout;

/// Architecture specific state of a VM.
#[derive(Debug)]
pub struct VmState;

/// Sets up the interrupt controller, capabilities, etc. The guest memory is already registered.
pub fn setup_vm(vm: &VmFd, mem: &MmapMemory, params: &Params) -> HypervisorResult<VmState> {
	// Double-check that neither the (first) guest address nor the end of the guest memory
	// overlap with the gap that we reserved between 3GiB and 4GiB.
	let guest_phys_addr = mem.guest_addr();
	let memory_size = mem.size();
	let guest_end_addr = mem.guest_addr().add(memory_size).as_usize();
	assert!(
		!(KVM_32BIT_GAP_START..KVM_32BIT_MAX_MEM_SIZE).contains(&(guest_phys_addr.as_usize())),
		"Provided guest address {guest_phys_addr:#X} is in reserved virtual memory region between 3 and 4GiB"
	);
	assert!(
		!(KVM_32BIT_GAP_START..KVM_32BIT_MAX_MEM_SIZE)
			.contains(&guest_phys_addr.add(memory_size).as_usize()),
		"Guest end address {guest_end_addr:#X} is in reserved virtual memory region between 3 and 4GiB"
	);

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
	cap.args[0] = (KVM_X2APIC_API_USE_32BIT_IDS | KVM_X2APIC_API_DISABLE_BROADCAST_QUIRK).into();
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

	Ok(VmState)
}

/// Finishes the VM setup once all vCPUs have been created.
pub fn vcpus_created(_state: &VmState) -> HypervisorResult<()> {
	Ok(())
}

pub fn init_guest_mem(
	mem: &mut MmapMemory,
	layout: &MemLayout,
	memory_size: u64,
	legacy_mapping: bool,
) {
	initialize_pagetables(mem, layout, memory_size, legacy_mapping);
}

/// Sets the initial register state of the vCPU `id`.
pub fn init_vcpu(
	_state: &VmState,
	vcpu: &VcpuFd,
	kernel_info: &KernelInfo<MemLayout>,
	id: usize,
) -> HypervisorResult<()> {
	setup_cpuid(vcpu)?;
	setup_long_mode(vcpu, kernel_info.entry_point, kernel_info.layout, id)?;

	// be sure that the multiprocessor is runable
	let mp_state = kvm_mp_state {
		mp_state: KVM_MP_STATE_RUNNABLE,
	};
	vcpu.set_mp_state(mp_state)?;

	setup_msrs(vcpu)?;

	Ok(())
}

/// Routes the virtio network device's interrupt to the guest.
///
/// Returns the eventfd raising the interrupt and the interrupt line for the device's PCI header.
pub fn setup_virtio_interrupt(vm: &VmFd) -> (EventFd, u8) {
	let mut irqchip = kvm_irqchip {
		chip_id: KVM_IRQCHIP_IOAPIC,
		..Default::default()
	};
	vm.get_irqchip(&mut irqchip).unwrap();

	let gsi: u32 = 123; // Number doesn't matter, just needs to be the same for kvm route and irqfd

	let mut kvm_route = kvm_irq_routing_entry {
		gsi,
		type_: KVM_IRQ_ROUTING_IRQCHIP,
		..Default::default()
	};
	kvm_route.u.irqchip.irqchip = irqchip.chip_id;
	kvm_route.u.irqchip.pin = UHYVE_IRQ_NET_PIC_PIN;

	let mut irq_routing = KvmIrqRouting::new(0).unwrap();
	irq_routing.push(kvm_route).unwrap();
	vm.set_gsi_routing(&irq_routing).unwrap();

	let eventfd = EventFd::new(EFD_NONBLOCK).unwrap();

	vm.register_irqfd(&eventfd, gsi).unwrap();
	(eventfd, UHYVE_IRQ_NET_PIC_PIN as u8)
}

/// Returns `true` if an MMIO read of `addr` was handled by the architecture.
pub fn handle_mmio_read(addr: u64) -> bool {
	match addr {
		0x9_F000..0xA_0000 | 0xF_0000..0x10_0000 => true, // Search for MP floating table can be ignored

		_ => false, // Non arch-specific address
	}
}

pub fn set_guest_debug(
	vcpu: &VcpuFd,
	breakpoints: &AllBreakpoints,
	resume_mode: ResumeMode,
) -> HypervisorResult<()> {
	let debugreg = breakpoints.hard.registers();
	let mut control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP | KVM_GUESTDBG_USE_HW_BP;
	// SAFETY: we trust the value of `self.resume.mode`.
	if resume_mode == ResumeMode::Step {
		control |= KVM_GUESTDBG_SINGLESTEP;
	}
	let debug_struct = kvm_guest_debug {
		control,
		pad: 0,
		arch: kvm_guest_debug_arch { debugreg },
	};

	vcpu.set_guest_debug(&debug_struct)
		.map_err(HypervisorError::from)
}

pub(crate) fn debug_info_to_stop_reason(
	debug: kvm_debug_exit_arch,
	tid: Tid,
	breakpoints: &AllBreakpoints,
) -> MultiThreadStopReason<u64> {
	match debug.exception {
		DB_VECTOR => {
			use ::x86_64::registers::debug::Dr6Flags;
			let dr6 = Dr6Flags::from_bits_truncate(debug.dr6);
			breakpoints.hard.stop_reason(tid, dr6)
		}
		BP_VECTOR => MultiThreadStopReason::SwBreak(tid),
		vector => unreachable!("unknown KVM exception vector: {}", vector),
	}
}

pub fn get_root_pagetable(vcpu: &VcpuFd) -> GuestPhysAddr {
	GuestPhysAddr::new(vcpu.get_sregs().unwrap().cr3)
}

pub fn get_cpu_frequency(vcpu: &VcpuFd) -> Option<NonZero<u32>> {
	vcpu.get_tsc_khz().map(|f| f.try_into().unwrap()).ok()
}

pub fn print_registers(vcpu: &VcpuFd, id: usize) {
	let regs = vcpu.get_regs().unwrap();
	let sregs = vcpu.get_sregs().unwrap();

	println!();
	println!("Dump state of CPU {id}");
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
	show_segment("cs ", &sregs.cs);
	show_segment("ss ", &sregs.ss);
	show_segment("ds ", &sregs.ds);
	show_segment("es ", &sregs.es);
	show_segment("fs ", &sregs.fs);
	show_segment("gs ", &sregs.gs);
	show_segment("tr ", &sregs.tr);
	show_segment("ldt", &sregs.ldt);
	println!("gtd: {:x?}", sregs.gdt);

	println!();
	println!("\nAPIC:");
	println!("-----");
	println!("apic_base: {:#18x}", sregs.apic_base);
	println!("interrupt_bitmap: {:x?}", sregs.interrupt_bitmap);
}

fn setup_cpuid(vcpu: &VcpuFd) -> Result<(), kvm_ioctls::Error> {
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
		std::ptr::copy_nonoverlapping(id.as_ptr(), id_reg_values.as_mut_ptr() as *mut u8, id.len());
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
		std::ptr::copy_nonoverlapping(id.as_ptr(), id_reg_values.as_mut_ptr() as *mut u8, id.len());
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

	vcpu.set_cpuid2(&kvm_cpuid)?;

	Ok(())
}

fn setup_msrs(vcpu: &VcpuFd) -> Result<(), kvm_ioctls::Error> {
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
	vcpu.set_msrs(&msrs)?;

	Ok(())
}

fn setup_long_mode(
	vcpu: &VcpuFd,
	entry_point: GuestPhysAddr,
	layout: X86_64MemoryLayout,
	cpu_id: usize,
) -> Result<(), kvm_ioctls::Error> {
	let mut sregs = vcpu.get_sregs()?;

	let cr0 = Cr0Flags::PROTECTED_MODE_ENABLE
		| Cr0Flags::EXTENSION_TYPE
		| Cr0Flags::NUMERIC_ERROR
		| Cr0Flags::PAGING;
	sregs.cr0 = cr0.bits();

	sregs.cr3 = layout.pml4_address().as_u64();

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
	sregs.gdt.base = layout.gdt_address().as_u64();
	sregs.gdt.limit = ((std::mem::size_of::<u64>() * BOOT_GDT_MAX) - 1) as u16;
	vcpu.set_sregs(&sregs)?;

	let regs = kvm_regs {
		rflags: 2,
		rip: entry_point.as_u64(),
		rdi: layout.boot_info().0.addr.as_u64(),
		rsi: cpu_id.try_into().unwrap(),
		rsp: layout.stack().0.addr.as_u64(),
		..Default::default()
	};
	vcpu.set_regs(&regs)?;

	Ok(())
}

fn show_segment(name: &str, seg: &kvm_segment) {
	println!("{name}       {seg:?}");
}

/// This checks the pointer to the a hypercall's data struct provided
/// by the Hermit unikernel when initiating a hypercall.
///
/// This is only intended to be used after a hypercall has taken place.
pub fn hypercall_data_addr(vcpu: &VcpuFd) -> GuestPhysAddr {
	GuestPhysAddr::new(vcpu.sync_regs().regs.rdi)
}

/// A guest write to an I/O port.
pub(crate) enum PortWrite<'a> {
	Hypercall(GuestHypercall<'a>),
	PortIOAccess,
}

impl From<&PortWrite<'_>> for VmExit {
	fn from(write: &PortWrite<'_>) -> Self {
		match write {
			PortWrite::Hypercall(hypercall) => hypercall.into(),
			PortWrite::PortIOAccess => VmExit::PCIWrite,
		}
	}
}

/// Classifies the write of `data` to `port`. Must be called while handling the corresponding IoOut exit.
pub fn classify_port_write<'a>(
	mem: &'a MmapMemory,
	vcpu: &VcpuFd,
	port: u16,
	data: &[u8],
) -> PortWrite<'a> {
	if let Some(hypercall) =
		unsafe { hypercall::address_to_hypercall_v2(mem, port.into(), hypercall_data_addr(vcpu)) }
	{
		PortWrite::Hypercall(GuestHypercall::V2(hypercall))
	} else if let Some(hypercall) = unsafe {
		// v1 images used to read the address from the 32-bit value written
		// into the virtual device register to perform an IoOut. Although
		// this was done for speed reasons, this implementation cannot
		// work for addresses containing more than 32 bits (which is to be
		// deemed as conventional in 64-bit environments), thus constraining
		// the memory size used by Uhyve.
		let data_addr = GuestPhysAddr::new((*(data.as_ptr() as *const u32)) as u64);
		hypercall::address_to_hypercall_v1(mem, port, data_addr)
	} {
		PortWrite::Hypercall(GuestHypercall::V1(hypercall))
	} else {
		PortWrite::PortIOAccess
	}
}

/// Legacy PCI configuration access via the I/O ports `0xCF8`/`0xCFC`.
#[derive(Debug, Default)]
pub struct PciConfigPorts {
	addr: Option<u32>,
}

impl PciConfigPorts {
	pub fn read(
		&self,
		peripherals: &VmPeripherals<<KvmVm as VirtualizationBackendInternal>::VirtioNetImpl>,
		port: u16,
		data: &mut [u8],
	) {
		let pci_addr = self.addr.filter(|addr| addr & 0x1ff800 == 0);
		match (port, pci_addr) {
			(PCI_CONFIG_DATA_PORT, Some(pci_addr)) => {
				if let Some(mut vd) = peripherals.virtio_device() {
					vd.virtio
						.handle_read(PciConfigurationAddress(pci_addr & 0x3ff), data);
				} else {
					// The access here is fine, because the guest might just be scanning for devices
					trace!("Guest tries to access non-present virtio device");
				}
			}
			// The access here is fine, because the guest might just be scanning for devices
			(PCI_CONFIG_DATA_PORT, None) => data.fill(0xff),
			(PCI_CONFIG_ADDRESS_PORT, _) => {}
			(port, _) => {
				warn!("Guest read from unknown I/O port {port:#x}");
			}
		}
	}

	pub fn write(
		&mut self,
		peripherals: &VmPeripherals<<KvmVm as VirtualizationBackendInternal>::VirtioNetImpl>,
		port: u16,
		data: &[u8],
	) {
		match port {
			PCI_CONFIG_DATA_PORT => {
				if let Some(pci_addr) = self.addr
					&& pci_addr & 0x1ff800 == 0
					&& let Some(mut virtio_device) = peripherals.virtio_device()
				{
					virtio_device
						.virtio
						.handle_write(PciConfigurationAddress(pci_addr & 0x3ff), data);
				}
			}
			PCI_CONFIG_ADDRESS_PORT => {
				if (data.as_ptr() as usize).is_multiple_of(align_of::<usize>()) {
					self.addr = Some(
						// SAFETY: `addr` is validated on read, so even if this is bogus uhyve is not affected.
						unsafe { *(data.as_ptr() as *const u32) },
					);
				}
			}
			port => {
				warn!("Guest wrote to unknown I/O port {port:#x}");
			}
		}
	}
}
