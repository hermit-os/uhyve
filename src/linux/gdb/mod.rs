mod breakpoints;
mod regs;
mod resume;
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
use kvm_bindings::{BP_VECTOR, DB_VECTOR};
use nix::sys::pthread::pthread_self;
use uhyve_interface::GuestVirtAddr;
use x86_64::registers::debug::Dr6Flags;

use self::{
	breakpoints::AllBreakpoints,
	resume::{ResumeMarker, ResumeMode},
};
use crate::{
	HypervisorError,
	arch::virt_to_phys,
	linux::{
		PthreadWrapper,
		x86_64::kvm_cpu::{KvmCpu, KvmVm},
	},
	vcpu::{VcpuStopReason, VirtualCPU},
	vm::{KernelInfo, UhyveVm, VmPeripherals},
};

pub(crate) struct VcpuWrapperShared {
	pub(crate) vcpu: RwLock<KvmCpu>,
	resume: ResumeMarker,
}

#[derive(Clone)]
pub(crate) struct VcpuWrapper {
	pub(crate) shared: Arc<VcpuWrapperShared>,
	pthread: PthreadWrapper,

	// This does look odd, but GDB appears to truncate thread-ids to 32bit.
	//
	// See also upstream issue: https://sourceware.org/bugzilla/show_bug.cgi?id=33979
	tid: NonZero<u32>,

	planned_resume_mode: Option<ResumeMode>,
}

#[derive(Clone)]
pub(crate) struct GdbVcpuManager {
	breakpoints: Arc<RwLock<AllBreakpoints>>,
	pub(crate) peripherals: Arc<VmPeripherals>,
	kernel_info: Arc<KernelInfo>,
	pub(crate) stops: async_channel::Receiver<MultiThreadStopReason<u64>>,
	pub(crate) vcpus: Vec<VcpuWrapper>,
	/// This does look odd, but GDB appears to truncate thread-ids to 32bit
	pub(crate) tid_to_vcpu: HashMap<NonZero<u32>, usize>,

	is_initializing: bool,
	default_resume_mode: ResumeMode,
}

/// Compute a thread ID from a pthread ID
///
/// This deals with the particularities of GDB which truncates thread IDs to signed 32bit,
/// and gdbstub can't deal with negative thread IDs.
///
/// Therefore, we truncate to 31bit.
fn derive_tid(pthread: libc::pthread_t) -> NonZero<u32> {
	NonZero::new((pthread as u32) & !(1u32 << 31)).unwrap()
}

impl UhyveVm<KvmVm> {
	pub fn spawn_cpu_manager_for_gdb(self, cpu_affinity: Option<Vec<CoreId>>) -> GdbVcpuManager {
		use std::os::unix::thread::JoinHandleExt;

		let (stops_s, stops_r) = async_channel::unbounded();
		let peripherals = Arc::clone(&self.peripherals);
		let kernel_info = Arc::clone(&self.kernel_info);
		let breakpoints = Arc::new(RwLock::new(AllBreakpoints::new()));
		let cpu_affinity: Option<Arc<[_]>> = cpu_affinity.map(Arc::from);

		let vcpus = self
			.vcpus
			.into_iter()
			.map(|vcpu| {
				let vcpu_id = vcpu.get_vcpu_id();
				let vcpu = RwLock::new(vcpu);
				let stops_s = stops_s.clone();
				let breakpoints = Arc::clone(&breakpoints);
				let shared = Arc::new(VcpuWrapperShared {
					resume: ResumeMarker {
						mode: AtomicU8::new(ResumeMode::Stopped as u8),
						event: Event::new(),
					},
					vcpu,
				});
				let shared2 = Arc::clone(&shared);
				let cpu_affinity = cpu_affinity.clone();
				let join_handle = std::thread::spawn(move || {
					let tid = derive_tid(pthread_self());
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

					drop(cpu_affinity);

					shared
						.vcpu
						.write()
						.unwrap()
						.thread_local_init()
						.expect("Unable to initialize vCPU");

					loop {
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
									breakpoints
										.read()
										.unwrap()
										.hard
										.stop_reason(tid.try_into().unwrap(), dr6)
								}
								BP_VECTOR => {
									MultiThreadStopReason::SwBreak(tid.try_into().unwrap())
								}
								vector => unreachable!("unknown KVM exception vector: {}", vector),
							},
							VcpuStopReason::Exit(code) => {
								MultiThreadStopReason::Exited(code.try_into().unwrap())
							}
							VcpuStopReason::Kick => {
								trace!("vcpu {} got kicked (recv)", tid);
								MultiThreadStopReason::SignalWithThread {
									tid: tid.try_into().unwrap(),
									signal: Signal::SIGINT,
								}
							}
						};
						// Make sure that no matter the reason, we have to be explicitly resumed after this
						// e.g. for breakpoints to work
						shared
							.resume
							.mode
							.store(ResumeMode::Stopped as u8, Ordering::Release);
						block_on(stops_s.send(stop_reason)).expect("unable to send info to GDB");
					}
				});
				let pthread = join_handle.as_pthread_t();
				VcpuWrapper {
					shared: shared2,
					pthread: PthreadWrapper(pthread),
					tid: derive_tid(pthread),
					planned_resume_mode: None,
				}
			})
			.collect::<Vec<_>>();

		let tid_to_vcpu = vcpus
			.iter()
			.enumerate()
			.map(|(vcpu_id, vcpu)| (vcpu.tid, vcpu_id))
			.collect();
		trace!("tid2vcpu = {tid_to_vcpu:?}");

		GdbVcpuManager {
			breakpoints,
			peripherals,
			kernel_info,
			stops: stops_r,
			vcpus,
			tid_to_vcpu,

			is_initializing: true,
			default_resume_mode: ResumeMode::FreeWheeling,
		}
	}
}

impl GdbVcpuManager {
	/// Resolves a [`Tid`] from GDB to the associated [`VcpuWrapper`].
	pub fn get_vcpu_wrapper(&self, tid: Tid) -> &VcpuWrapper {
		match self.tid_to_vcpu.get(&(tid.try_into().unwrap())) {
			Some(&vcpu_id) => &self.vcpus[vcpu_id],
			None => panic!("unable to resolve thread-id from GDB: {tid}"),
		}
	}

	/// Resolves a [`Tid`] from GDB to the associated [`VcpuWrapper`]. Mutable version.
	pub fn get_vcpu_wrapper_mut(&mut self, tid: Tid) -> &mut VcpuWrapper {
		match self.tid_to_vcpu.get(&(tid.try_into().unwrap())) {
			Some(&vcpu_id) => &mut self.vcpus[vcpu_id],
			None => panic!("unable to resolve thread-id from GDB: {tid}"),
		}
	}

	/// Resolves a [`Tid`] from GDB to the lock around the associated [`KvmCpu`].
	pub fn get_vm_cpu(&self, tid: Tid) -> &RwLock<KvmCpu> {
		&self.get_vcpu_wrapper(tid).shared.vcpu
	}
}

impl Target for GdbVcpuManager {
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

impl target_multithread::MultiThreadBase for GdbVcpuManager {
	fn read_registers(&mut self, regs: &mut X86_64CoreRegs, tid: Tid) -> TargetResult<(), Self> {
		regs::read(self.get_vm_cpu(tid).read().unwrap().get_vcpu(), regs)
			.map_err(|error| TargetError::Errno(error.errno().try_into().unwrap()))
	}

	fn write_registers(&mut self, regs: &X86_64CoreRegs, tid: Tid) -> TargetResult<(), Self> {
		regs::write(regs, self.get_vm_cpu(tid).read().unwrap().get_vcpu())
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
