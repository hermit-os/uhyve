mod breakpoints;
mod regs;
mod section_offsets;

use core::num::NonZero;
use std::{
	collections::HashMap,
	sync::{
		Arc, RwLock,
		atomic::{AtomicU8, Ordering},
	},
};

use async_io::block_on;
use core_affinity::CoreId;
use event_listener::{Event, Listener};
use gdbstub::{
	common::{Signal, Tid},
	stub::MultiThreadStopReason,
	target::{
		self, Target, TargetError, TargetResult, ext::base::multithread as target_multithread,
	},
};
use gdbstub_arch::x86::reg::X86_64CoreRegs;
use kvm_bindings::{
	BP_VECTOR, DB_VECTOR, KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_SINGLESTEP, KVM_GUESTDBG_USE_HW_BP,
	KVM_GUESTDBG_USE_SW_BP, kvm_guest_debug, kvm_guest_debug_arch,
};
use libc::EINVAL;
use nix::sys::pthread::pthread_self;
use uhyve_interface::GuestVirtAddr;
use x86_64::registers::debug::Dr6Flags;

use self::breakpoints::SwBreakpoints;
use super::{KickSignal, PthreadWrapper, x86_64::kvm_cpu::KvmCpu};
use crate::{
	HypervisorError, HypervisorResult,
	arch::x86_64::{registers::debug::HwBreakpoints, virt_to_phys},
	linux::x86_64::kvm_cpu::KvmVm,
	vcpu::{VcpuStopReason, VirtualCPU},
	vm::{KernelInfo, UhyveVm, VmPeripherals},
};

struct AllBreakpoints {
	hard: HwBreakpoints,
	soft: SwBreakpoints,
}

impl AllBreakpoints {
	pub fn new() -> Self {
		Self {
			hard: HwBreakpoints::new(),
			soft: SwBreakpoints::new(),
		}
	}
}

struct ResumeMarker {
	mode: AtomicU8,
	event: Event,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum ResumeMode {
	/// The vCPU is stopped (r#continue won't get called while this is set)
	Stopped,
	/// The vCPU is single-stepped
	Step,
	/// The vCPU is uninterrupt-runnable
	Freewheel,
}

#[derive(Clone)]
struct ResumeCycle {
	per_vcpu: Vec<ResumeMode>,
}

pub(crate) struct GdbUhyve {
	pub(crate) vm: UhyveVm<KvmVm>,
}

pub(crate) struct VcpuWrapperShared {
	pub(crate) vcpu: RwLock<KvmCpu>,
	resume: ResumeMarker,
}

#[derive(Clone)]
pub(crate) struct VcpuWrapper {
	pub(crate) shared: Arc<VcpuWrapperShared>,
	pthread: PthreadWrapper,
	tid: Tid,
}

#[derive(Clone)]
pub(crate) struct Freewheel {
	breakpoints: Arc<RwLock<AllBreakpoints>>,
	pub(crate) peripherals: Arc<VmPeripherals>,
	kernel_info: Arc<KernelInfo>,
	pub(crate) stops: async_channel::Receiver<MultiThreadStopReason<u64>>,
	pub(crate) vcpus: Vec<VcpuWrapper>,
	pub(crate) tid_to_vcpu: HashMap<NonZero<usize>, usize>,

	resume_cycle: Option<ResumeCycle>,
}

impl GdbUhyve {
	pub fn new(vm: UhyveVm<KvmVm>) -> Self {
		Self { vm }
	}
}

impl GdbUhyve {
	pub fn spawn_freewheel(self, cpu_affinity: Option<Vec<CoreId>>) -> Freewheel {
		use std::os::unix::thread::JoinHandleExt;
		let Self { vm } = self;

		let (stops_s, stops_r) = async_channel::unbounded();
		let peripherals = Arc::clone(&vm.peripherals);
		let kernel_info = Arc::clone(&vm.kernel_info);
		let breakpoints = Arc::new(RwLock::new(AllBreakpoints::new()));

		let vcpus = vm
			.vcpus
			.into_iter()
			.map(|vcpu| {
				let vcpu = RwLock::new(vcpu);
				let stops_s = stops_s.clone();
				let breakpoints = Arc::clone(&breakpoints);
				let shared = Arc::new(VcpuWrapperShared {
					resume: ResumeMarker {
						mode: AtomicU8::new(ResumeMode::Freewheel as u8),
						event: Event::new(),
					},
					vcpu,
				});
				let shared2 = Arc::clone(&shared);
				let cpu_affinity = cpu_affinity.clone();
				let join_handle = std::thread::spawn(move || {
					let tid = NonZero::new(pthread_self().try_into().unwrap()).unwrap();
					let vcpu_id = shared.vcpu.read().unwrap().get_vcpu_id();
					let local_cpu_affinity = cpu_affinity
						.as_ref()
						.and_then(|core_ids| core_ids.get(vcpu_id).copied());

					match local_cpu_affinity {
						Some(core_id) => {
							debug!("Trying to pin thread {} to CPU {}", vcpu_id, core_id.id);
							core_affinity::set_for_current(core_id); // This does not return an error if it fails :(
						}
						None => debug!("No affinity specified, not binding thread"),
					}

					shared
						.vcpu
						.write()
						.unwrap()
						.thread_local_init()
						.expect("Unable to initialize vCPU");

					loop {
						shared
							.apply_current_guest_debug(&(*breakpoints).read().unwrap())
							.expect("GDB target error");
						let stop_reason = match shared
							.vcpu
							.try_write()
							.expect("GDB target lock error")
							.r#continue()
							.expect("GDB target error")
						{
							VcpuStopReason::Debug(debug) => match debug.exception {
								DB_VECTOR => {
									let dr6 = Dr6Flags::from_bits_truncate(debug.dr6);
									breakpoints.read().unwrap().hard.stop_reason(tid, dr6)
								}
								BP_VECTOR => MultiThreadStopReason::SwBreak(tid),
								vector => unreachable!("unknown KVM exception vector: {}", vector),
							},
							VcpuStopReason::Exit(code) => {
								MultiThreadStopReason::Exited(code.try_into().unwrap())
							}
							VcpuStopReason::Kick => MultiThreadStopReason::SignalWithThread {
								tid,
								signal: Signal::SIGINT,
							},
						};
						block_on(stops_s.send(stop_reason)).expect("unable to send info to GDB");
						loop {
							if !shared.is_stopped() {
								break;
							}

							let listener = shared.resume.event.listen();

							if !shared.is_stopped() {
								break;
							}

							listener.wait();
						}
					}
				});
				let pthread = join_handle.as_pthread_t();
				VcpuWrapper {
					shared: shared2,
					pthread: PthreadWrapper(pthread),
					tid: NonZero::new(pthread.try_into().unwrap()).unwrap(),
				}
			})
			.collect::<Vec<_>>();

		let tid_to_vcpu = vcpus
			.iter()
			.enumerate()
			.map(|(vcpu_id, vcpu)| (vcpu.tid, vcpu_id))
			.collect();
		trace!("tid2vcpu = {tid_to_vcpu:?}");

		Freewheel {
			breakpoints,
			peripherals,
			kernel_info,
			stops: stops_r,
			vcpus,
			tid_to_vcpu,

			resume_cycle: None,
		}
	}
}

impl Freewheel {
	pub fn tid_to_vcpuw(&self, tid: Tid) -> &VcpuWrapper {
		trace!("tid_to_vcpuw({tid:?})");
		&self.vcpus[self.tid_to_vcpu[&tid]]
	}

	pub fn tid_to_kvm_cpu(&self, tid: Tid) -> &RwLock<KvmCpu> {
		&self.tid_to_vcpuw(tid).shared.vcpu
	}
}

impl VcpuWrapper {
	/// Kick the vCPU
	pub fn kick(&self) {
		KickSignal::pthread_kill(self.pthread.0).unwrap();
	}

	fn apply_resume_mode(&self, mode: ResumeMode) {
		// SAFETY: we trust the value of `self.resume.mode`.
		let old: ResumeMode = unsafe {
			core::mem::transmute(self.shared.resume.mode.swap(mode as u8, Ordering::Release))
		};
		if !matches!(mode, ResumeMode::Stopped) {
			self.shared.resume.event.notify(usize::MAX);
		} else if !matches!(old, ResumeMode::Stopped) {
			self.kick()
		}
	}
}

impl VcpuWrapperShared {
	fn apply_current_guest_debug(&self, breakpoints: &AllBreakpoints) -> HypervisorResult<()> {
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

	fn is_stopped(&self) -> bool {
		// we trust the value of `self.resume.mode`.
		let mode: ResumeMode =
			unsafe { core::mem::transmute(self.resume.mode.load(Ordering::Acquire)) };
		mode == ResumeMode::Stopped
	}
}

impl ResumeCycle {
	pub fn new(vcpus: usize, scheduler_locking: bool) -> Self {
		let default_mode = if scheduler_locking {
			ResumeMode::Stopped
		} else {
			ResumeMode::Freewheel
		};

		Self {
			per_vcpu: vec![default_mode; vcpus],
		}
	}
}

impl Target for Freewheel {
	type Arch = gdbstub_arch::x86::X86_64_SSE;
	type Error = HypervisorError;

	// --------------- IMPORTANT NOTE ---------------
	// Always remember to annotate IDET enable methods with `inline(always)`!
	// Without this annotation, LLVM might fail to dead-code-eliminate nested IDET
	// implementations, resulting in unnecessary binary bloat.

	#[inline(always)]
	fn base_ops(&mut self) -> target::ext::base::BaseOps<'_, Self::Arch, Self::Error> {
		target::ext::base::BaseOps::MultiThread(self)
	}

	#[inline(always)]
	fn support_breakpoints(
		&mut self,
	) -> Option<target::ext::breakpoints::BreakpointsOps<'_, Self>> {
		Some(self)
	}

	#[inline(always)]
	fn support_section_offsets(
		&mut self,
	) -> Option<target::ext::section_offsets::SectionOffsetsOps<'_, Self>> {
		Some(self)
	}
}

impl target_multithread::MultiThreadBase for Freewheel {
	fn read_registers(&mut self, regs: &mut X86_64CoreRegs, tid: Tid) -> TargetResult<(), Self> {
		regs::read(self.tid_to_kvm_cpu(tid).read().unwrap().get_vcpu(), regs)
			.map_err(|error| TargetError::Errno(error.errno().try_into().unwrap()))
	}

	fn write_registers(&mut self, regs: &X86_64CoreRegs, tid: Tid) -> TargetResult<(), Self> {
		regs::write(regs, self.tid_to_kvm_cpu(tid).read().unwrap().get_vcpu())
			.map_err(|error| TargetError::Errno(error.errno().try_into().unwrap()))
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
					self.tid_to_kvm_cpu(tid)
						.read()
						.unwrap()
						.get_root_pagetable(),
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
					self.tid_to_kvm_cpu(tid)
						.read()
						.unwrap()
						.get_root_pagetable(),
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
			if i.shared.is_stopped() {
				continue;
			}
			thread_is_active(i.tid);
		}
		Ok(())
	}

	fn is_thread_alive(&mut self, tid: Tid) -> Result<bool, Self::Error> {
		Ok(!self.tid_to_vcpuw(tid).shared.is_stopped())
	}

	#[inline(always)]
	fn support_resume(&mut self) -> Option<target_multithread::MultiThreadResumeOps<'_, Self>> {
		Some(self)
	}
}

impl target_multithread::MultiThreadResume for Freewheel {
	fn clear_resume_actions(&mut self) -> Result<(), Self::Error> {
		self.resume_cycle = None;
		Ok(())
	}

	fn set_resume_action_continue(
		&mut self,
		tid: Tid,
		signal: Option<Signal>,
	) -> Result<(), Self::Error> {
		if signal.is_some() {
			// cannot step with signal
			return Err(kvm_ioctls::Error::new(EINVAL).into());
		}

		let resume_cycle = self
			.resume_cycle
			.get_or_insert_with(|| ResumeCycle::new(self.vcpus.len(), false));

		resume_cycle.per_vcpu[self.tid_to_vcpu[&tid]] = ResumeMode::Freewheel;
		Ok(())
	}

	fn resume(&mut self) -> Result<(), Self::Error> {
		let resume_cycle = self
			.resume_cycle
			.clone()
			.unwrap_or_else(|| ResumeCycle::new(self.vcpus.len(), false));

		for (vcpuw, resume_mode) in self.vcpus.iter().zip(resume_cycle.per_vcpu.iter()) {
			vcpuw.apply_resume_mode(*resume_mode);
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

impl target_multithread::MultiThreadSingleStep for Freewheel {
	fn set_resume_action_step(
		&mut self,
		tid: Tid,
		signal: Option<Signal>,
	) -> Result<(), Self::Error> {
		if signal.is_some() {
			// cannot step with signal
			return Err(kvm_ioctls::Error::new(EINVAL).into());
		}

		let resume_cycle = self
			.resume_cycle
			.get_or_insert_with(|| ResumeCycle::new(self.vcpus.len(), false));

		resume_cycle.per_vcpu[self.tid_to_vcpu[&tid]] = ResumeMode::Step;
		Ok(())
	}
}

impl target_multithread::MultiThreadSchedulerLocking for Freewheel {
	fn set_resume_action_scheduler_lock(&mut self) -> Result<(), Self::Error> {
		self.resume_cycle = Some(ResumeCycle::new(self.vcpus.len(), true));
		Ok(())
	}
}
