use gdbstub::{
	arch::Arch as GdbstubArch,
	common::Tid,
	target::{
		Target, TargetError, TargetResult,
		ext::base::multithread as target_multithread,
		{self},
	},
};
use uhyve_interface::GuestVirtAddr;

#[cfg(not(target_os = "macos"))]
use crate::os::gdb::regs;
use crate::{
	HypervisorError, gdb::GdbVcpuManager, vcpu::VirtualCPU, virt_to_phys, vm::DefaultBackend,
};

impl Target for GdbVcpuManager<DefaultBackend> {
	type Error = HypervisorError;

	#[cfg(target_arch = "aarch64")]
	type Arch = gdbstub_arch::aarch64::AArch64;
	#[cfg(target_arch = "x86_64")]
	type Arch = gdbstub_arch::x86::X86_64_SSE;

	// --------------- IMPORTANT NOTE ---------------
	// Always remember to annotate IDET enable methods with `inline(always)`!
	// Without this annotation, LLVM might fail to dead-code-eliminate nested IDET
	// implementations, resulting in unnecessary binary bloat.

	#[inline(always)]
	fn base_ops(&mut self) -> target::ext::base::BaseOps<'_, Self::Arch, Self::Error> {
		target::ext::base::BaseOps::MultiThread(self)
	}

	#[inline(always)]
	#[cfg(not(target_os = "macos"))]
	fn support_breakpoints(
		&mut self,
	) -> Option<target::ext::breakpoints::BreakpointsOps<'_, Self>> {
		Some(self)
	}

	#[inline(always)]
	#[cfg(not(target_os = "macos"))]
	fn support_section_offsets(
		&mut self,
	) -> Option<target::ext::section_offsets::SectionOffsetsOps<'_, Self>> {
		Some(self)
	}
}

#[cfg_attr(target_os = "macos", allow(unused_variables))]
impl target_multithread::MultiThreadBase for GdbVcpuManager<DefaultBackend> {
	fn read_registers(
		&mut self,
		regs: &mut <Self::Arch as GdbstubArch>::Registers,
		tid: Tid,
	) -> TargetResult<(), Self> {
		#[cfg(not(target_os = "macos"))]
		return regs::read(self.get_vm_cpu(tid).read().unwrap().get_vcpu(), regs)
			.map_err(|error| TargetError::Errno(error.errno().try_into().unwrap()));
		#[cfg(target_os = "macos")]
		todo!()
	}

	fn write_registers(
		&mut self,
		regs: &<Self::Arch as GdbstubArch>::Registers,
		tid: Tid,
	) -> TargetResult<(), Self> {
		#[cfg(not(target_os = "macos"))]
		return regs::write(regs, self.get_vm_cpu(tid).read().unwrap().get_vcpu())
			.map_err(|error| TargetError::Errno(error.errno().try_into().unwrap()));
		#[cfg(target_os = "macos")]
		todo!()
	}

	fn read_addrs(
		&mut self,
		start_addr: u64,
		data: &mut [u8],
		tid: Tid,
	) -> TargetResult<usize, Self> {
		let guest_addr = GuestVirtAddr::try_new(start_addr).map_err(|_e| TargetError::NonFatal)?;
		// Safety: mem is copied to data before mem can be modified.
		let src = unsafe {
			self.peripherals.mem.slice_at(
				virt_to_phys(
					guest_addr,
					&self.peripherals.mem,
					self.get_vm_cpu(tid).read().unwrap().get_root_pagetable(),
				)
				.map_err(|_| ())?,
				data.len(),
			)
		}
		.map_err(|_e| TargetError::NonFatal)?;
		data.copy_from_slice(src);
		Ok(data.len())
	}

	fn write_addrs(&mut self, start_addr: u64, data: &[u8], tid: Tid) -> TargetResult<(), Self> {
		// Safety: self.vm.mem is not altered during the lifetime of mem.
		let mem = unsafe {
			self.peripherals.mem.slice_at_mut(
				virt_to_phys(
					GuestVirtAddr::new(start_addr),
					&self.peripherals.mem,
					self.get_vm_cpu(tid).read().unwrap().get_root_pagetable(),
				)
				.map_err(|_err| ())?,
				data.len(),
			)
		}
		.unwrap();
		mem.copy_from_slice(data);
		Ok(())
	}

	fn list_active_threads(
		&mut self,
		thread_is_active: &mut dyn FnMut(Tid),
	) -> Result<(), Self::Error> {
		for i in &self.vcpus {
			if i.shared.is_stopped() && !self.is_initializing {
				continue;
			}
			thread_is_active(i.tid.try_into().unwrap());
		}
		Ok(())
	}

	fn is_thread_alive(&mut self, tid: Tid) -> Result<bool, Self::Error> {
		Ok(self.is_initializing || !self.get_vcpu_wrapper(tid).shared.is_stopped())
	}

	#[inline(always)]
	fn support_resume(&mut self) -> Option<target_multithread::MultiThreadResumeOps<'_, Self>> {
		Some(self)
	}
}
