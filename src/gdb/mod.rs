pub mod base;
pub mod resume;

use core::{
	fmt,
	num::NonZero,
	sync::atomic::{AtomicU8, Ordering},
};
use std::{
	collections::HashMap,
	io,
	net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream},
	sync::{Arc, RwLock},
};

use async_io::block_on;
use core_affinity::CoreId;
use event_listener::{Event, Listener as _};
use gdbstub::{
	arch,
	common::{Signal, Tid},
	conn::ConnectionExt as _,
	stub::{DisconnectReason, GdbStub, MultiThreadStopReason, state_machine::GdbStubStateMachine},
	target::Target,
};
use nix::sys::pthread::{Pthread, pthread_self};

use crate::{
	HypervisorResult,
	gdb::resume::{ResumeMarker, ResumeMode},
	os::Breakpoints,
	serial::Destination,
	vcpu::{VcpuStopReason, VirtualCPU},
	vm::{
		KernelInfo, UhyveVm, VirtualizationBackend, VirtualizationBackendInternal, VmPeripherals,
		VmResult,
	},
};

/// A way of sending pthread IDs reliably across threads.
///
/// # Platform-specific behavior
///
/// This is particularly necessary for musl, as `Pthread` is eq
/// which can't be passed to thread as easily
///
/// # Safety
///
/// This can be safely sent across threads because pthread IDs
/// and thread-safety is ensured by the pthread library.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PthreadWrapper(pub Pthread);

unsafe impl Send for PthreadWrapper {}
unsafe impl Sync for PthreadWrapper {}

pub(crate) struct VcpuWrapperShared<VCpu> {
	pub(crate) vcpu: RwLock<VCpu>,
	pub(crate) resume: ResumeMarker,
}

pub(crate) struct VcpuWrapper<VCpu> {
	pub(crate) shared: Arc<VcpuWrapperShared<VCpu>>,

	pub(crate) pthread: PthreadWrapper,
	/// This does look odd, but GDB appears to truncate thread-ids to 32bit
	pub(crate) tid: NonZero<u32>,

	pub(crate) planned_resume_mode: Option<ResumeMode>,
}

#[cfg_attr(target_os = "macos", allow(dead_code))]
pub struct GdbVcpuManager<Vm: VirtualizationBackend> {
	pub(crate) breakpoints: Arc<RwLock<Breakpoints>>,

	pub(crate) peripherals: Arc<VmPeripherals>,
	pub(crate) kernel_info: Arc<KernelInfo>,
	pub(crate) stops: async_channel::Receiver<MultiThreadStopReason<u64>>,
	pub(crate) vcpus: Vec<VcpuWrapper<<Vm as VirtualizationBackendInternal>::VCPU>>,
	/// This does look odd, but GDB appears to truncate thread-ids to 32bit
	pub(crate) tid_to_vcpu: HashMap<NonZero<u32>, usize>,

	pub(crate) is_initializing: bool,
	pub(crate) default_resume_mode: ResumeMode,
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

impl<Vm: VirtualizationBackend> UhyveVm<Vm> {
	pub(crate) fn run_gdb(self, cpu_affinity: Option<Vec<CoreId>>) -> VmResult
	where
		GdbVcpuManager<Vm>: Target,
		<GdbVcpuManager<Vm> as Target>::Error: fmt::Debug,
		<GdbVcpuManager<Vm> as Target>::Arch: arch::Arch<Usize = u64>,
	{
		let connection =
			wait_for_gdb_connection(self.kernel_info.params.gdb_port.unwrap()).unwrap();
		let debugger = GdbStub::new(connection);
		let mut vcpu_manager = self.spawn_cpu_manager_for_gdb(cpu_affinity);

		let mut gdb = debugger
			.run_state_machine(&mut vcpu_manager)
			.expect("GDB run_state_machine initialization failed");

		let exit_code = loop {
			gdb = match gdb {
				GdbStubStateMachine::Idle(mut gdb) => {
					// needs more data, so perform a blocking read on the connection
					let byte = gdb.borrow_conn().read().expect("GDB connection read error");
					gdb.incoming_data(&mut vcpu_manager, byte)
						.expect("GDB incoming_data error")
				}

				GdbStubStateMachine::Disconnected(gdb) => {
					// we keep things simple, and doesn't expose a way to re-use the
					// state machine
					break match gdb.get_reason() {
						DisconnectReason::TargetExited(exit_code) => exit_code.into(),
						DisconnectReason::TargetTerminated(_) => unreachable!(),
						DisconnectReason::Disconnect => {
							eprintln!("Debugger disconnected.");
							0
						}
						DisconnectReason::Kill => {
							eprintln!("Kill command received.");
							0
						}
					};
				}

				GdbStubStateMachine::CtrlCInterrupt(gdb) => {
					// defer to the implementation on how it wants to handle the interrupt

					// Kick VCPU out of KVM_RUN
					for i in &vcpu_manager.vcpus {
						i.kick();
					}

					gdb.interrupt_handled(&mut vcpu_manager, None::<MultiThreadStopReason<u64>>)
						.expect("GDB interrupt_handled packet write failed")
				}

				GdbStubStateMachine::Running(mut gdb) => {
					use futures_lite::AsyncReadExt;
					// block waiting either for stop reason or new data from GDB
					enum UhyveOrGdb<X, Y> {
						Uhyve(X),
						Gdb(Y),
					}

					vcpu_manager.set_finished_initializing();

					let borrow_conn = gdb.borrow_conn();
					let inp = block_on(futures_lite::future::or(
						async move {
							let mut gdb_conn_async = async_io::Async::new(borrow_conn)
								.expect("unable to asynchronize gdb connection");
							let mut data_from_gdb_buf = [0u8];
							let ret = gdb_conn_async
								.read_exact(&mut data_from_gdb_buf)
								.await
								.map(|_| data_from_gdb_buf[0]);
							let _ = gdb_conn_async.into_inner();
							UhyveOrGdb::Gdb(ret)
						},
						async { UhyveOrGdb::Uhyve(vcpu_manager.stops.recv().await) },
					));

					match inp {
						UhyveOrGdb::Gdb(byte) => {
							let byte = byte.expect("error during GDB recv");
							gdb.incoming_data(&mut vcpu_manager, byte)
								.expect("GDB incoming_data error")
						}
						UhyveOrGdb::Uhyve(stop_reason) => {
							let stop_reason = stop_reason.expect("error during stop packet recv");
							gdb.report_stop(&mut vcpu_manager, stop_reason)
								.expect("GDB report_stop error")
						}
					}
				}
			}
		};

		for i in &vcpu_manager.vcpus {
			i.kick();
		}

		let output = if let Destination::Buffer(b) = &vcpu_manager.peripherals.serial.destination {
			Some(String::from_utf8_lossy(&b.lock().unwrap()).into_owned())
		} else {
			None
		};

		VmResult {
			code: exit_code,
			output,
			stats: None,
		}
	}

	fn spawn_cpu_manager_for_gdb(self, cpu_affinity: Option<Vec<CoreId>>) -> GdbVcpuManager<Vm> {
		use std::os::unix::thread::JoinHandleExt;

		let (stops_s, stops_r) = async_channel::unbounded();
		let peripherals = Arc::clone(&self.peripherals);
		let kernel_info = Arc::clone(&self.kernel_info);
		let breakpoints = Arc::new(RwLock::new(Breakpoints::default()));
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
							#[cfg(target_os = "macos")]
							VcpuStopReason::Debug(_debug) => todo!(),
							#[cfg(not(target_os = "macos"))]
							VcpuStopReason::Debug(debug) => crate::os::debug_info_to_stop_reason(
								debug,
								tid.try_into().unwrap(),
								&(*breakpoints).read().unwrap(),
							),
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

impl<Vm: VirtualizationBackend> GdbVcpuManager<Vm> {
	/// Resolves a [`Tid`] from GDB to the associated [`VcpuWrapper`].
	pub(crate) fn get_vcpu_wrapper(
		&self,
		tid: Tid,
	) -> &VcpuWrapper<<Vm as VirtualizationBackendInternal>::VCPU> {
		match self.tid_to_vcpu.get(&(tid.try_into().unwrap())) {
			Some(&vcpu_id) => &self.vcpus[vcpu_id],
			None => panic!("unable to resolve thread-id from GDB: {tid}"),
		}
	}

	/// Resolves a [`Tid`] from GDB to the associated [`VcpuWrapper`]. Mutable version.
	pub(crate) fn get_vcpu_wrapper_mut(
		&mut self,
		tid: Tid,
	) -> &mut VcpuWrapper<<Vm as VirtualizationBackendInternal>::VCPU> {
		match self.tid_to_vcpu.get(&(tid.try_into().unwrap())) {
			Some(&vcpu_id) => &mut self.vcpus[vcpu_id],
			None => panic!("unable to resolve thread-id from GDB: {tid}"),
		}
	}

	/// Resolves a [`Tid`] from GDB to the lock around the associated [`KvmCpu`].
	pub(crate) fn get_vm_cpu(
		&self,
		tid: Tid,
	) -> &RwLock<<Vm as VirtualizationBackendInternal>::VCPU> {
		&self.get_vcpu_wrapper(tid).shared.vcpu
	}
}

impl<VCpu: VirtualCPU> VcpuWrapperShared<VCpu> {
	/// Updates the vCPU debug context to correspond to the currently active
	/// `ResumeMode`, and `breakpoints`.
	///
	/// This handles e.g. single-stepping of the vCPU.
	pub fn apply_current_guest_debug(&self, breakpoints: &Breakpoints) -> HypervisorResult<()> {
		// SAFETY: we trust the value of `self.resume.mode`.
		let mode: ResumeMode =
			unsafe { core::mem::transmute(self.resume.mode.load(Ordering::Acquire)) };
		self.vcpu
			.write()
			.unwrap()
			.apply_current_guest_debug(breakpoints, mode)
	}
}

const LOCALHOST: [IpAddr; 2] = [
	IpAddr::V4(Ipv4Addr::LOCALHOST),
	IpAddr::V6(Ipv6Addr::LOCALHOST),
];

fn wait_for_gdb_connection(port: u16) -> io::Result<TcpStream> {
	let sock = TcpListener::bind(
		[
			SocketAddr::new(LOCALHOST[0], port),
			SocketAddr::new(LOCALHOST[1], port),
		]
		.as_ref(),
	)?;
	eprintln!(
		"Waiting for a local GDB connection on port {}...",
		sock.local_addr().unwrap().port()
	);
	let (stream, addr) = sock.accept()?;

	// Blocks until a GDB client connects via TCP.
	// i.e: Running `target remote localhost:<port>` from the GDB prompt.

	eprintln!("Debugger connected from {addr}");
	Ok(stream) // `TcpStream` implements `gdbstub::Connection`
}
