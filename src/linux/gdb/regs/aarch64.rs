use gdbstub_arch::aarch64::reg::AArch64CoreRegs;
use kvm_ioctls::VcpuFd;

use crate::os::aarch64::regs;

pub fn read(vcpu: &VcpuFd, core_regs: &mut AArch64CoreRegs) -> Result<(), kvm_ioctls::Error> {
	for (n, x) in core_regs.x.iter_mut().enumerate() {
		*x = regs::get_u64(vcpu, regs::x(n))?;
	}
	// The guest always runs in EL1h, so its stack pointer is `SP_EL1`.
	core_regs.sp = regs::get_u64(vcpu, regs::SP_EL1)?;
	core_regs.pc = regs::get_u64(vcpu, regs::PC)?;
	// GDB calls PSTATE "cpsr". Its upper half is reserved.
	core_regs.cpsr = regs::get_u64(vcpu, regs::PSTATE)? as _;

	for (n, v) in core_regs.v.iter_mut().enumerate() {
		*v = regs::get_u128(vcpu, regs::v(n))?;
	}
	core_regs.fpcr = regs::get_u32(vcpu, regs::FPCR)?;
	core_regs.fpsr = regs::get_u32(vcpu, regs::FPSR)?;

	Ok(())
}

pub fn write(core_regs: &AArch64CoreRegs, vcpu: &VcpuFd) -> Result<(), kvm_ioctls::Error> {
	for (n, &x) in core_regs.x.iter().enumerate() {
		regs::set_u64(vcpu, regs::x(n), x)?;
	}
	regs::set_u64(vcpu, regs::SP_EL1, core_regs.sp)?;
	regs::set_u64(vcpu, regs::PC, core_regs.pc)?;
	regs::set_u64(vcpu, regs::PSTATE, core_regs.cpsr.into())?;

	for (n, &v) in core_regs.v.iter().enumerate() {
		regs::set_u128(vcpu, regs::v(n), v)?;
	}
	regs::set_u32(vcpu, regs::FPCR, core_regs.fpcr)?;
	regs::set_u32(vcpu, regs::FPSR, core_regs.fpsr)?;

	Ok(())
}
