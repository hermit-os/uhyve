use std::sync::atomic::{AtomicU8, Ordering};

use event_listener::Event;
use gdbstub::{
	common::{Signal, Tid},
	target::{Target, ext::base::multithread as target_multithread},
};

use crate::{
	gdb::{GdbVcpuManager, VcpuWrapper, VcpuWrapperShared},
	linux::KickSignal,
	vm::VirtualizationBackend,
};

pub(crate) struct ResumeMarker {
	pub(crate) mode: AtomicU8,
	pub(crate) event: Event,
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

impl<Vm: VirtualizationBackend> GdbVcpuManager<Vm> {
	/// Signal to the vCPU manager that the `gdbstub` finished initializing,
	/// i.e. exited the `Idle` state and entered the `Running` state.
	pub fn set_finished_initializing(&mut self) {
		if core::mem::replace(&mut self.is_initializing, false) {
			for i in &mut self.vcpus {
				i.r#continue();
			}
		}
	}
}

impl<Vcpu> VcpuWrapper<Vcpu> {
	/// Kick the vCPU
	pub fn kick(&self) {
		trace!("vcpu: kick! {}", self.tid);
		KickSignal::pthread_kill(self.pthread.0).unwrap();
	}

	/// Resume the vCPU in free-wheeling / non-stepped mode
	fn r#continue(&mut self) {
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

impl<Vcpu> VcpuWrapperShared<Vcpu> {
	pub fn is_stopped(&self) -> bool {
		// we trust the value of `self.resume.mode`.
		let mode: ResumeMode =
			unsafe { core::mem::transmute(self.resume.mode.load(Ordering::Acquire)) };
		mode == ResumeMode::Stopped
	}
}

impl<Vm: VirtualizationBackend> target_multithread::MultiThreadResume for GdbVcpuManager<Vm>
where
	Self: Target<Error = crate::HypervisorError>,
{
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

impl<Vm: VirtualizationBackend> target_multithread::MultiThreadSingleStep for GdbVcpuManager<Vm>
where
	Self: Target<Error = crate::HypervisorError>,
{
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

impl<Vm: VirtualizationBackend> target_multithread::MultiThreadSchedulerLocking
	for GdbVcpuManager<Vm>
where
	Self: Target<Error = crate::HypervisorError>,
{
	fn set_resume_action_scheduler_lock(&mut self) -> Result<(), Self::Error> {
		self.default_resume_mode = ResumeMode::Stopped;
		Ok(())
	}
}
