use std::num::NonZero;

use gdbstub::{common::Tid, stub::MultiThreadStopReason};
use kvm_bindings::*;
use kvm_ioctls::{DeviceFd, VcpuFd, VmFd};
use uhyve_interface::GuestPhysAddr;
use vmm_sys_util::eventfd::EventFd;

use crate::{
	HypervisorError, HypervisorResult,
	arch::{
		Aarch64MemoryLayout, GICD_BASE_ADDRESS, GICR_BASE_ADDRESS, MT_DEVICE_GRE, MT_DEVICE_nGnRE,
		MT_DEVICE_nGnRnE, MT_NORMAL, MT_NORMAL_NC, PSR, TCR_FLAGS, TCR_TG1_4K, VA_BITS, mair,
		tcr_size,
	},
	gdb::resume::ResumeMode,
	mem::MmapMemory,
	mem_layout::MemoryLayout,
	os::kvm::breakpoints::AllBreakpoints,
	params::Params,
	vm::KernelInfo,
};

pub(crate) mod regs;

pub type MemLayout = Aarch64MemoryLayout;

/// Architecture specific state of a VM.
#[derive(Debug)]
pub struct VmState {
	gic: DeviceFd,
	vcpu_init: kvm_vcpu_init,
}

/// Sets up the interrupt controller. The guest memory is already registered.
///
/// The hypercall MMIO window sits below `RAM_START` and is deliberately left
/// unbacked, so accesses to it leave the guest as MMIO exits.
pub fn setup_vm(vm: &VmFd, _mem: &MmapMemory, _params: &Params) -> HypervisorResult<VmState> {
	trace!("Initialize interrupt controller");
	let mut gic_device = kvm_create_device {
		type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
		fd: 0,
		flags: 0,
	};
	let gic = vm.create_device(&mut gic_device)?;

	for (attr, addr) in [
		(KVM_VGIC_V3_ADDR_TYPE_DIST, GICD_BASE_ADDRESS),
		(KVM_VGIC_V3_ADDR_TYPE_REDIST, GICR_BASE_ADDRESS),
	] {
		gic.set_device_attr(&kvm_device_attr {
			group: KVM_DEV_ARM_VGIC_GRP_ADDR,
			attr: attr.into(),
			addr: &raw const addr as u64,
			flags: 0,
		})?;
	}

	let mut vcpu_init = kvm_vcpu_init::default();
	vm.get_preferred_target(&mut vcpu_init)?;

	Ok(VmState { gic, vcpu_init })
}

/// Finishes the VM setup once all vCPUs have been created.
///
/// The GIC's redistributor layout is derived from the vCPUs that exist when it
/// is initialized.
pub fn vcpus_created(state: &VmState) -> HypervisorResult<()> {
	state.gic.set_device_attr(&kvm_device_attr {
		group: KVM_DEV_ARM_VGIC_GRP_CTRL,
		attr: KVM_DEV_ARM_VGIC_CTRL_INIT.into(),
		addr: 0,
		flags: 0,
	})?;

	Ok(())
}

pub fn init_guest_mem(
	mem: &mut MmapMemory,
	layout: &MemLayout,
	memory_size: u64,
	_legacy_mapping: bool,
) {
	super::init_guest_mem(mem, layout, memory_size);
}

/// Sets the initial register state of the vCPU `id`.
pub fn init_vcpu(
	state: &VmState,
	vcpu: &VcpuFd,
	kernel_info: &KernelInfo<MemLayout>,
	id: usize,
) -> HypervisorResult<()> {
	vcpu.vcpu_init(&state.vcpu_init)?;

	setup_registers(vcpu, kernel_info, id)?;

	// be sure that the multiprocessor is runable
	let mp_state = kvm_mp_state {
		mp_state: KVM_MP_STATE_RUNNABLE,
	};
	vcpu.set_mp_state(mp_state)?;

	Ok(())
}

/// Routes the virtio network device's interrupt to the guest.
///
/// Returns the eventfd raising the interrupt and the interrupt line for the device's PCI header.
pub fn setup_virtio_interrupt(_vm: &VmFd) -> (EventFd, u8) {
	// This requires wiring the virtqueue interrupts up to the GIC.
	unimplemented!("Virtio devices are currently not supported on aarch64!");
}

/// Returns `true` if an MMIO read of `addr` was handled by the architecture.
pub fn handle_mmio_read(_addr: u64) -> bool {
	false
}

/// The address of a hypercall's data struct, which the guest passes in `X8`.
///
/// This is only intended to be used while handling the hypercall's MMIO exit.
pub fn hypercall_data_addr(vcpu: &VcpuFd) -> GuestPhysAddr {
	GuestPhysAddr::new(regs::x(8).get(vcpu).unwrap())
}

pub(crate) fn debug_info_to_stop_reason(
	debug: kvm_debug_exit_arch,
	tid: Tid,
	breakpoints: &AllBreakpoints,
) -> MultiThreadStopReason<u64> {
	// `hsr` holds the ESR value of the trapped exception; its top 6 bits are the
	// exception class. See ARM DDI 0487, "ESR_EL2, Exception Syndrome Register".
	const EC_BREAKPOINT: u32 = 0x30;
	const EC_SOFTWARE_STEP: u32 = 0x32;
	const EC_WATCHPOINT: u32 = 0x34;
	const EC_BRK: u32 = 0x3c;

	match debug.hsr >> 26 {
		EC_SOFTWARE_STEP => MultiThreadStopReason::DoneStep,
		EC_BREAKPOINT => MultiThreadStopReason::HwBreak(tid),
		EC_WATCHPOINT => breakpoints.hard.watch_stop_reason(tid, debug.far),
		EC_BRK => MultiThreadStopReason::SwBreak(tid),
		ec => unreachable!("unknown KVM debug exception class: {:#x}", ec),
	}
}

pub fn set_guest_debug(
	vcpu: &VcpuFd,
	breakpoints: &AllBreakpoints,
	resume_mode: ResumeMode,
) -> HypervisorResult<()> {
	let registers = breakpoints.hard.registers();
	let mut control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP | KVM_GUESTDBG_USE_HW;
	if resume_mode == ResumeMode::Step {
		control |= KVM_GUESTDBG_SINGLESTEP;
	}
	let debug_struct = kvm_guest_debug {
		control,
		pad: 0,
		arch: kvm_guest_debug_arch {
			dbg_bcr: registers.bcr,
			dbg_bvr: registers.bvr,
			dbg_wcr: registers.wcr,
			dbg_wvr: registers.wvr,
		},
	};

	vcpu.set_guest_debug(&debug_struct)
		.map_err(HypervisorError::from)
}

pub fn get_root_pagetable(vcpu: &VcpuFd) -> GuestPhysAddr {
	GuestPhysAddr::new(regs::TTBR0_EL1.get(vcpu).unwrap())
}

pub fn get_cpu_frequency(_vcpu: &VcpuFd) -> Option<NonZero<u32>> {
	warn!("CPU base frequency detection not implemented!");
	None
}

pub fn print_registers(vcpu: &VcpuFd, id: usize) {
	let get = |reg: regs::Reg<u64>| reg.get(vcpu).unwrap();

	println!();
	println!("Dump state of CPU {id}");
	println!();
	println!("Registers:");
	println!("----------");
	for n in 0..31 {
		println!("x{n:<2}: {:#18x}", get(regs::x(n)));
	}
	println!("sp:  {:#18x}", get(regs::SP_EL1));
	println!("pc:  {:#18x}", get(regs::PC));
	println!("pstate: {:#18x}", get(regs::PSTATE));
	println!();
	println!("System registers:");
	println!("-----------------");
	println!("sctlr_el1: {:#18x}", get(regs::SCTLR_EL1));
	println!("tcr_el1:   {:#18x}", get(regs::TCR_EL1));
	println!("mair_el1:  {:#18x}", get(regs::MAIR_EL1));
	println!("ttbr0_el1: {:#18x}", get(regs::TTBR0_EL1));
	println!("ttbr1_el1: {:#18x}", get(regs::TTBR1_EL1));
}

fn setup_registers(
	vcpu: &VcpuFd,
	kernel_info: &KernelInfo<MemLayout>,
	id: usize,
) -> Result<(), kvm_ioctls::Error> {
	let KernelInfo {
		entry_point,
		layout,
		..
	} = kernel_info;

	/* pstate = all interrupts masked */
	let pstate = PSR::D_BIT | PSR::A_BIT | PSR::I_BIT | PSR::F_BIT | PSR::MODE_EL1H;
	regs::PSTATE.set(vcpu, pstate.bits())?;
	regs::PC.set(vcpu, entry_point.as_u64())?;
	regs::SP_EL1.set(vcpu, layout.stack().0.addr.as_u64())?;
	regs::x(0).set(vcpu, layout.boot_info().0.addr.as_u64())?;
	regs::x(1).set(vcpu, id as u64)?;

	/*
	 * Setup memory attribute type tables
	 *
	 * Memory regioin attributes for LPAE:
	 *
	 *   n = AttrIndx[2:0]
	 *                      n       MAIR
	 *   DEVICE_nGnRnE      000     00000000 (0x00)
	 *   DEVICE_nGnRE       001     00000100 (0x04)
	 *   DEVICE_GRE         010     00001100 (0x0c)
	 *   NORMAL_NC          011     01000100 (0x44)
	 *   NORMAL             100     11111111 (0xff)
	 */
	let mair_el1 = mair(0x00, MT_DEVICE_nGnRnE)
		| mair(0x04, MT_DEVICE_nGnRE)
		| mair(0x0c, MT_DEVICE_GRE)
		| mair(0x44, MT_NORMAL_NC)
		| mair(0xff, MT_NORMAL);
	regs::MAIR_EL1.set(vcpu, mair_el1)?;

	/*
	 * Setup translation control register (TCR)
	 */
	let aa64mmfr0_el1 = regs::ID_AA64MMFR0_EL1.get(vcpu)?;
	let tcr = ((aa64mmfr0_el1 & 0xF) << 32) | (tcr_size(VA_BITS) | TCR_TG1_4K | TCR_FLAGS);
	let tcr_el1 = (tcr & 0xFFFFFFF0FFFFFFFFu64) | ((aa64mmfr0_el1 & 0xFu64) << 32);
	regs::TCR_EL1.set(vcpu, tcr_el1)?;

	/*
	 * Enable FP/ASIMD in Architectural Feature Access Control Register,
	 */
	let cpacr_el1 = regs::CPACR_EL1.get(vcpu)? | (3 << 20);
	regs::CPACR_EL1.set(vcpu, cpacr_el1)?;

	/*
	 * Reset debug control register
	 */
	regs::MDSCR_EL1.set(vcpu, 0)?;

	// Load TTBRx
	regs::TTBR1_EL1.set(vcpu, 0)?;
	regs::TTBR0_EL1.set(vcpu, layout.pgt_address().as_u64())?;

	/*
	* Prepare system control register (SCTRL)
	* Todo: - Verify if all of these bits actually should be explicitly set
		  - Link origin of this documentation and check to which instruction set versions
			it applies (if applicable)
		  - Fill in the missing Documentation for some of the bits and verify if we care about them
			or if loading and not setting them would be the appropriate action.
	*/
	#[expect(clippy::identity_op)]
	let sctrl_el1: u64 = 0
	 | (1 << 26) 	    /* UCI	Enables EL0 access in AArch64 for DC CVAU, DC CIVAC,
								DC CVAC and IC IVAU instructions */
	 | (0 << 25)		/* EE	Explicit data accesses at EL1 and Stage 1 translation
								table walks at EL1 & EL0 are little-endian */
	 | (0 << 24)		/* EOE	Explicit data accesses at EL0 are little-endian */
	 | (1 << 23)
	 | (1 << 22)
	 | (1 << 20)
	 | (0 << 19)		/* WXN	Regions with write permission are not forced to XN */
	 | (1 << 18)		/* nTWE	WFE instructions are executed as normal */
	 | (0 << 17)
	 | (1 << 16)		/* nTWI	WFI instructions are executed as normal */
	 | (1 << 15)		/* UCT	Enables EL0 access in AArch64 to the CTR_EL0 register */
	 | (1 << 14)		/* DZE	Execution of the DC ZVA instruction is allowed at EL0 */
	 | (0 << 13)
	 | (1 << 12)		/* I	Instruction caches enabled at EL0 and EL1 */
	 | (1 << 11)
	 | (0 << 10)
	 | (0 << 9)			/* UMA	Disable access to the interrupt masks from EL0 */
	 | (1 << 8)			/* SED	The SETEND instruction is available */
	 | (0 << 7)			/* ITD	The IT instruction functionality is available */
	 | (0 << 6)			/* THEE	ThumbEE is disabled */
	 | (0 << 5)			/* CP15BEN	CP15 barrier operations disabled */
	 | (1 << 4)			/* SA0	Stack Alignment check for EL0 enabled */
	 | (1 << 3)			/* SA	Stack Alignment check enabled */
	 | (1 << 2)			/* C	Data and unified enabled */
	 | (0 << 1)			/* A	Alignment fault checking disabled */
	 | (1 << 0)			/* M	MMU enable */
	;
	regs::SCTLR_EL1.set(vcpu, sctrl_el1)?;

	Ok(())
}
