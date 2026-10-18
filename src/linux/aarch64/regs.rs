//! Register IDs for KVM's `KVM_GET_ONE_REG`/`KVM_SET_ONE_REG` on AArch64.
//!
//! AArch64 KVM exposes no bulk register ioctl, so every register is addressed
//! individually by an ID encoding its size and location. Core registers are
//! identified by their 32-bit-word offset within [`kvm_regs`], system registers
//! by their `op0`/`op1`/`CRn`/`CRm`/`op2` encoding.

use std::mem::offset_of;

use kvm_bindings::{
	KVM_REG_ARM_CORE, KVM_REG_ARM64, KVM_REG_ARM64_SYSREG, KVM_REG_ARM64_SYSREG_CRM_SHIFT,
	KVM_REG_ARM64_SYSREG_CRN_SHIFT, KVM_REG_ARM64_SYSREG_OP0_SHIFT, KVM_REG_ARM64_SYSREG_OP1_SHIFT,
	KVM_REG_ARM64_SYSREG_OP2_SHIFT, KVM_REG_SIZE_U32, KVM_REG_SIZE_U64, KVM_REG_SIZE_U128,
	kvm_regs,
};
use kvm_ioctls::VcpuFd;

const fn core_reg(size: u64, byte_offset: usize) -> u64 {
	KVM_REG_ARM64 | size | KVM_REG_ARM_CORE as u64 | (byte_offset / 4) as u64
}

const fn sysreg(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> u64 {
	KVM_REG_ARM64
		| KVM_REG_SIZE_U64
		| KVM_REG_ARM64_SYSREG as u64
		| (op0 << KVM_REG_ARM64_SYSREG_OP0_SHIFT)
		| (op1 << KVM_REG_ARM64_SYSREG_OP1_SHIFT)
		| (crn << KVM_REG_ARM64_SYSREG_CRN_SHIFT)
		| (crm << KVM_REG_ARM64_SYSREG_CRM_SHIFT)
		| (op2 << KVM_REG_ARM64_SYSREG_OP2_SHIFT)
}

/// General purpose register `X<n>`.
pub const fn x(n: usize) -> u64 {
	core_reg(
		KVM_REG_SIZE_U64,
		offset_of!(kvm_regs, regs.regs) + n * size_of::<u64>(),
	)
}

/// FP/SIMD register `V<n>`.
pub const fn v(n: usize) -> u64 {
	core_reg(
		KVM_REG_SIZE_U128,
		offset_of!(kvm_regs, fp_regs.vregs) + n * size_of::<u128>(),
	)
}

pub const PC: u64 = core_reg(KVM_REG_SIZE_U64, offset_of!(kvm_regs, regs.pc));
pub const PSTATE: u64 = core_reg(KVM_REG_SIZE_U64, offset_of!(kvm_regs, regs.pstate));
pub const SP_EL1: u64 = core_reg(KVM_REG_SIZE_U64, offset_of!(kvm_regs, sp_el1));
pub const FPSR: u64 = core_reg(KVM_REG_SIZE_U32, offset_of!(kvm_regs, fp_regs.fpsr));
pub const FPCR: u64 = core_reg(KVM_REG_SIZE_U32, offset_of!(kvm_regs, fp_regs.fpcr));

pub const SCTLR_EL1: u64 = sysreg(3, 0, 1, 0, 0);
pub const CPACR_EL1: u64 = sysreg(3, 0, 1, 0, 2);
pub const TTBR0_EL1: u64 = sysreg(3, 0, 2, 0, 0);
pub const TTBR1_EL1: u64 = sysreg(3, 0, 2, 0, 1);
pub const TCR_EL1: u64 = sysreg(3, 0, 2, 0, 2);
pub const MAIR_EL1: u64 = sysreg(3, 0, 10, 2, 0);
pub const MDSCR_EL1: u64 = sysreg(2, 0, 0, 2, 2);
pub const ID_AA64MMFR0_EL1: u64 = sysreg(3, 0, 0, 7, 0);

pub fn get_u64(vcpu: &VcpuFd, id: u64) -> Result<u64, kvm_ioctls::Error> {
	let mut data = [0; size_of::<u64>()];
	vcpu.get_one_reg(id, &mut data)?;
	Ok(u64::from_ne_bytes(data))
}

pub fn set_u64(vcpu: &VcpuFd, id: u64, value: u64) -> Result<(), kvm_ioctls::Error> {
	vcpu.set_one_reg(id, &value.to_ne_bytes())?;
	Ok(())
}

pub fn get_u128(vcpu: &VcpuFd, id: u64) -> Result<u128, kvm_ioctls::Error> {
	let mut data = [0; size_of::<u128>()];
	vcpu.get_one_reg(id, &mut data)?;
	Ok(u128::from_ne_bytes(data))
}

pub fn set_u128(vcpu: &VcpuFd, id: u64, value: u128) -> Result<(), kvm_ioctls::Error> {
	vcpu.set_one_reg(id, &value.to_ne_bytes())?;
	Ok(())
}

pub fn get_u32(vcpu: &VcpuFd, id: u64) -> Result<u32, kvm_ioctls::Error> {
	let mut data = [0; size_of::<u32>()];
	vcpu.get_one_reg(id, &mut data)?;
	Ok(u32::from_ne_bytes(data))
}

pub fn set_u32(vcpu: &VcpuFd, id: u64, value: u32) -> Result<(), kvm_ioctls::Error> {
	vcpu.set_one_reg(id, &value.to_ne_bytes())?;
	Ok(())
}
