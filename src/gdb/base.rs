#[cfg(not(target_os = "macos"))]
use gdbstub::target::TargetError;
use gdbstub::{
	arch::Arch as GdbstubArch,
	common::Tid,
	target::{
		self, Target, TargetResult,
		ext::{
			base::multithread as target_multithread,
			section_offsets::{Offsets, SectionOffsets},
		},
	},
};
#[cfg(not(target_os = "macos"))]
use uhyve_interface::GuestVirtAddr;

use crate::{HypervisorError, gdb::GdbVcpuManager, vm::DefaultBackend};
#[cfg(not(target_os = "macos"))]
use crate::{os::gdb::regs, vcpu::VirtualCPU, virt_to_phys};

impl Target for GdbVcpuManager<DefaultBackend> {
	type Error = HypervisorError;

	#[cfg(target_arch = "aarch64")]
	type Arch = gdbstub_arch::aarch64::AArch64;
	#[cfg(target_arch = "x86_64")]
	type Arch = gdbstub_arch::x86::X86_64_SSE;

	// --------------- IMPORTANT NOTE ---------------
	// Always remember to annotate [IDET] enabled methods with `inline(always)`!
	// Without this annotation, LLVM might fail to dead-code-eliminate nested IDET
	// implementations, resulting in unnecessary binary bloat.
	//
	// [IDET]: https://github.com/daniel5151/gdbstub/blob/1bc505ff9ef71b0c08f15dc7e6b910b21ce885eb/README.md#L102
	//         **Inlineable Dyn Extension Traits**

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

impl target_multithread::MultiThreadBase for GdbVcpuManager<DefaultBackend> {
	#[cfg(not(target_os = "macos"))]
	fn read_registers(
		&mut self,
		regs: &mut <Self::Arch as GdbstubArch>::Registers,
		tid: Tid,
	) -> TargetResult<(), Self> {
		return regs::read(self.get_vm_cpu(tid).read().unwrap().get_vcpu(), regs)
			.map_err(|error| TargetError::Errno(error.errno().try_into().unwrap()));
	}

	#[cfg(not(target_os = "macos"))]
	fn write_registers(
		&mut self,
		regs: &<Self::Arch as GdbstubArch>::Registers,
		tid: Tid,
	) -> TargetResult<(), Self> {
		return regs::write(regs, self.get_vm_cpu(tid).read().unwrap().get_vcpu())
			.map_err(|error| TargetError::Errno(error.errno().try_into().unwrap()));
	}

	#[cfg(not(target_os = "macos"))]
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

	#[cfg(not(target_os = "macos"))]
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

	#[cfg(target_os = "macos")]
	fn read_registers(
		&mut self,
		_regs: &mut <Self::Arch as GdbstubArch>::Registers,
		_tid: Tid,
	) -> TargetResult<(), Self> {
		todo!();
	}

	#[cfg(target_os = "macos")]
	fn write_registers(
		&mut self,
		_regs: &<Self::Arch as GdbstubArch>::Registers,
		_tid: Tid,
	) -> TargetResult<(), Self> {
		todo!();
	}

	#[cfg(target_os = "macos")]
	fn read_addrs(
		&mut self,
		_start_addr: u64,
		_data: &mut [u8],
		_tid: Tid,
	) -> TargetResult<usize, Self> {
		todo!();
	}

	#[cfg(target_os = "macos")]
	fn write_addrs(&mut self, _start_addr: u64, _data: &[u8], _tid: Tid) -> TargetResult<(), Self> {
		todo!();
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

impl SectionOffsets for crate::gdb::GdbVcpuManager<DefaultBackend> {
	fn get_section_offsets(&mut self) -> Result<Offsets<u64>, Self::Error> {
		let offset = self.kernel_info.kernel_address.as_u64();
		Ok(Offsets::Sections {
			text: offset,
			data: offset,
			bss: Some(offset),
		})
	}
}
