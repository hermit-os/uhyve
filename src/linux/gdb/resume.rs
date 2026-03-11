use std::sync::atomic::{AtomicU8, Ordering};

use event_listener::Event;
use gdbstub::{
	common::{Signal, Tid},
	target::ext::base::multithread as target_multithread,
};

use super::{GdbVcpuManager, VcpuWrapper, VcpuWrapperShared, breakpoints::AllBreakpoints};
use crate::{HypervisorError, HypervisorResult, linux::KickSignal};

pub(super) struct ResumeMarker {
	pub(super) mode: AtomicU8,
	pub(super) event: Event,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ResumeMode {
	/// The vCPU is stopped (r#continue won't get called while this is set)
	Stopped,
	/// The vCPU is single-stepped
	Step,
	/// The vCPU is uninterrupt-runnable
	FreeWheeling,
}

impl GdbVcpuManager {
	pub fn finished_initializing(&mut self) {
		if core::mem::replace(&mut self.is_initializing, false) {
			for i in &mut self.vcpus {
				i.free_wheel();
			}
		}
	}
}

impl VcpuWrapper {
	/// Kick the vCPU
	pub fn kick(&self) {
		trace!("vcpu: kick! {}", self.tid);
		KickSignal::pthread_kill(self.pthread.0).unwrap();
	}

	/// Resume the vCPU in free-wheeling / non-stepped mode
	fn free_wheel(&mut self) {
		// TODO: refactor to get rid of mutability
		let old_planned = self.planned_resume_mode.take();
		self.apply_resume_mode(ResumeMode::FreeWheeling);
		self.planned_resume_mode = old_planned;
	}

	fn apply_resume_mode(&self, default_mode: ResumeMode) {
		let mode = self.planned_resume_mode.unwrap_or(default_mode);

		// SAFETY: we trust the value of `self.resume.mode`.
		let old: ResumeMode = unsafe {
			core::mem::transmute(self.shared.resume.mode.swap(mode as u8, Ordering::AcqRel))
		};
		trace!("apply_resume_mode @ {}: {:?} -> {:?}", self.tid, old, mode);
		if mode != ResumeMode::Stopped {
			self.shared.resume.event.notify(usize::MAX);
		} else if old != ResumeMode::Stopped {
			self.kick()
		}
	}
}

impl VcpuWrapperShared {
	pub fn apply_current_guest_debug(&self, breakpoints: &AllBreakpoints) -> HypervisorResult<()> {
		use kvm_bindings::{
			KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_SINGLESTEP, KVM_GUESTDBG_USE_HW_BP,
			KVM_GUESTDBG_USE_SW_BP, kvm_guest_debug, kvm_guest_debug_arch,
		};
		let debugreg = breakpoints.hard.registers();
		let mut control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP | KVM_GUESTDBG_USE_HW_BP;
		// SAFETY: we trust the value of `self.resume.mode`.
		let mode: ResumeMode =
			unsafe { core::mem::transmute(self.resume.mode.load(Ordering::Acquire)) };
		if mode == ResumeMode::Step {
			control |= KVM_GUESTDBG_SINGLESTEP;
		}
		let debug_struct = kvm_guest_debug {
			control,
			pad: 0,
			arch: kvm_guest_debug_arch { debugreg },
		};

		self.vcpu
			.read()
			.unwrap()
			.get_vcpu()
			.set_guest_debug(&debug_struct)
			.map_err(HypervisorError::from)
	}

	pub fn is_stopped(&self) -> bool {
		// we trust the value of `self.resume.mode`.
		let mode: ResumeMode =
			unsafe { core::mem::transmute(self.resume.mode.load(Ordering::Acquire)) };
		mode == ResumeMode::Stopped
	}
}

impl target_multithread::MultiThreadResume for GdbVcpuManager {
	fn clear_resume_actions(&mut self) -> Result<(), Self::Error> {
		self.vcpus
			.iter_mut()
			.for_each(|i| i.planned_resume_mode = None);
		self.default_resume_mode = ResumeMode::FreeWheeling;
		Ok(())
	}

	fn set_resume_action_continue(
		&mut self,
		tid: Tid,
		signal: Option<Signal>,
	) -> Result<(), Self::Error> {
		if signal.is_some() {
			// cannot step with signal
			return Err(crate::HypervisorError::backend_invalid_value());
		}

		self.get_vcpu_wrapper_mut(tid).planned_resume_mode = Some(ResumeMode::FreeWheeling);

		Ok(())
	}

	fn resume(&mut self) -> Result<(), Self::Error> {
		for i in &self.vcpus {
			i.apply_resume_mode(self.default_resume_mode);
		}

		Ok(())
	}

	#[inline(always)]
	fn support_single_step(
		&mut self,
	) -> Option<target_multithread::MultiThreadSingleStepOps<'_, Self>> {
		Some(self)
	}

	#[inline(always)]
	fn support_scheduler_locking(
		&mut self,
	) -> Option<target_multithread::MultiThreadSchedulerLockingOps<'_, Self>> {
		Some(self)
	}
}

impl target_multithread::MultiThreadSingleStep for GdbVcpuManager {
	fn set_resume_action_step(
		&mut self,
		tid: Tid,
		signal: Option<Signal>,
	) -> Result<(), Self::Error> {
		if signal.is_some() {
			// cannot step with signal
			return Err(crate::HypervisorError::backend_invalid_value());
		}

		self.get_vcpu_wrapper_mut(tid).planned_resume_mode = Some(ResumeMode::Step);
		Ok(())
	}
}

impl target_multithread::MultiThreadSchedulerLocking for GdbVcpuManager {
	fn set_resume_action_scheduler_lock(&mut self) -> Result<(), Self::Error> {
		self.default_resume_mode = ResumeMode::Stopped;
		Ok(())
	}
}
