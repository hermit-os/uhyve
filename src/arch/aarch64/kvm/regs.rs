//! Register IDs for KVM's `KVM_GET_ONE_REG`/`KVM_SET_ONE_REG` on AArch64.
//!
//! AArch64 KVM exposes no bulk register ioctl, so every register is addressed
//! individually by an ID encoding its size and location. Core registers are
//! identified by their 32-bit-word offset within [`kvm_regs`], system registers
//! by their `op0`/`op1`/`CRn`/`CRm`/`op2` encoding.
//!
//! [`read`] and [`write`] transfer the registers GDB knows about.

use std::{marker::PhantomData, mem::offset_of};

use gdbstub_arch::aarch64::reg::AArch64CoreRegs;
use kvm_bindings::{
	KVM_REG_ARM_CORE, KVM_REG_ARM64, KVM_REG_ARM64_SYSREG, KVM_REG_ARM64_SYSREG_CRM_SHIFT,
	KVM_REG_ARM64_SYSREG_CRN_SHIFT, KVM_REG_ARM64_SYSREG_OP0_SHIFT, KVM_REG_ARM64_SYSREG_OP1_SHIFT,
	KVM_REG_ARM64_SYSREG_OP2_SHIFT, KVM_REG_SIZE_SHIFT, kvm_regs,
};
use kvm_ioctls::VcpuFd;
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// A register ID whose value is a `T`. The ID's size field is derived from `T`.
#[derive(Clone, Copy, Debug)]
pub struct Reg<T>(u64, PhantomData<T>);

impl<T> Reg<T> {
	const fn new(id: u64) -> Self {
		let size = (size_of::<T>().trailing_zeros() as u64) << KVM_REG_SIZE_SHIFT;
		Self(KVM_REG_ARM64 | size | id, PhantomData)
	}

	const fn core(byte_offset: usize) -> Self {
		Self::new(KVM_REG_ARM_CORE as u64 | (byte_offset / 4) as u64)
	}
}

impl Reg<u64> {
	const fn sysreg(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> Self {
		Self::new(
			KVM_REG_ARM64_SYSREG as u64
				| (op0 << KVM_REG_ARM64_SYSREG_OP0_SHIFT)
				| (op1 << KVM_REG_ARM64_SYSREG_OP1_SHIFT)
				| (crn << KVM_REG_ARM64_SYSREG_CRN_SHIFT)
				| (crm << KVM_REG_ARM64_SYSREG_CRM_SHIFT)
				| (op2 << KVM_REG_ARM64_SYSREG_OP2_SHIFT),
		)
	}
}

impl<T: FromBytes + IntoBytes + Immutable> Reg<T> {
	pub fn get(self, vcpu: &VcpuFd) -> Result<T, kvm_ioctls::Error> {
		let mut value = T::new_zeroed();
		vcpu.get_one_reg(self.0, value.as_mut_bytes())?;
		Ok(value)
	}

	pub fn set(self, vcpu: &VcpuFd, value: T) -> Result<(), kvm_ioctls::Error> {
		vcpu.set_one_reg(self.0, value.as_bytes())?;
		Ok(())
	}
}

/// General purpose register `X<n>`.
pub const fn x(n: usize) -> Reg<u64> {
	Reg::core(offset_of!(kvm_regs, regs.regs) + n * size_of::<u64>())
}

/// FP/SIMD register `V<n>`.
pub const fn v(n: usize) -> Reg<u128> {
	Reg::core(offset_of!(kvm_regs, fp_regs.vregs) + n * size_of::<u128>())
}

pub const PC: Reg<u64> = Reg::core(offset_of!(kvm_regs, regs.pc));
pub const PSTATE: Reg<u64> = Reg::core(offset_of!(kvm_regs, regs.pstate));
pub const SP_EL0: Reg<u64> = Reg::core(offset_of!(kvm_regs, regs.sp));
pub const SP_EL1: Reg<u64> = Reg::core(offset_of!(kvm_regs, sp_el1));
pub const FPSR: Reg<u32> = Reg::core(offset_of!(kvm_regs, fp_regs.fpsr));
pub const FPCR: Reg<u32> = Reg::core(offset_of!(kvm_regs, fp_regs.fpcr));

pub const SCTLR_EL1: Reg<u64> = Reg::sysreg(3, 0, 1, 0, 0);
pub const CPACR_EL1: Reg<u64> = Reg::sysreg(3, 0, 1, 0, 2);
pub const TTBR0_EL1: Reg<u64> = Reg::sysreg(3, 0, 2, 0, 0);
pub const TTBR1_EL1: Reg<u64> = Reg::sysreg(3, 0, 2, 0, 1);
pub const TCR_EL1: Reg<u64> = Reg::sysreg(3, 0, 2, 0, 2);
pub const MAIR_EL1: Reg<u64> = Reg::sysreg(3, 0, 10, 2, 0);
pub const MDSCR_EL1: Reg<u64> = Reg::sysreg(2, 0, 0, 2, 2);
pub const ID_AA64MMFR0_EL1: Reg<u64> = Reg::sysreg(3, 0, 0, 7, 0);

/// The stack pointer currently selected by `PSTATE.SPSel` (`SP_EL0` in EL1t, `SP_EL1` in EL1h).
fn active_sp(vcpu: &VcpuFd) -> Result<Reg<u64>, kvm_ioctls::Error> {
	Ok(if PSTATE.get(vcpu)? & 1 == 0 {
		SP_EL0
	} else {
		SP_EL1
	})
}

pub fn read(vcpu: &VcpuFd, core_regs: &mut AArch64CoreRegs) -> Result<(), kvm_ioctls::Error> {
	for (n, reg) in core_regs.x.iter_mut().enumerate() {
		*reg = x(n).get(vcpu)?;
	}
	core_regs.sp = active_sp(vcpu)?.get(vcpu)?;
	core_regs.pc = PC.get(vcpu)?;
	// GDB calls PSTATE "cpsr". Its upper half is reserved.
	core_regs.cpsr = PSTATE.get(vcpu)? as _;

	for (n, reg) in core_regs.v.iter_mut().enumerate() {
		*reg = v(n).get(vcpu)?;
	}
	core_regs.fpcr = FPCR.get(vcpu)?;
	core_regs.fpsr = FPSR.get(vcpu)?;

	Ok(())
}

pub fn write(core_regs: &AArch64CoreRegs, vcpu: &VcpuFd) -> Result<(), kvm_ioctls::Error> {
	for (n, &reg) in core_regs.x.iter().enumerate() {
		x(n).set(vcpu, reg)?;
	}
	PC.set(vcpu, core_regs.pc)?;
	PSTATE.set(vcpu, core_regs.cpsr.into())?;
	active_sp(vcpu)?.set(vcpu, core_regs.sp)?;

	for (n, &reg) in core_regs.v.iter().enumerate() {
		v(n).set(vcpu, reg)?;
	}
	FPCR.set(vcpu, core_regs.fpcr)?;
	FPSR.set(vcpu, core_regs.fpsr)?;

	Ok(())
}
