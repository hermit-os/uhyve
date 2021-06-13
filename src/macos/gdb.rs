use ::x86::bits64::rflags::RFlags;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use log::{debug, error};
use rustc_serialize::hex::ToHex;
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::slice;
use xhypervisor::{vCPU, x86Reg};

use crate::arch::x86;
use crate::error;
use crate::gdb_parser::{
	Breakpoint, Error, FileData, Handler, Id, MemoryRegion, ProcessInfo, ProcessType, StopReason,
	ThreadId, VCont, VContFeature, Watchpoint,
};
use crate::macos::vcpu::UhyveCPU;
use crate::utils::get_max_subslice;
use crate::vm::VirtualCPU;

/// Debugging Stub for linux/x64
/// Currently supported features:
/// - Register read/write
/// - Memory read/write
/// - Software breakpoints (int3)
/// - Hardware breakpoints
///    - Execute / Write / Read-Write
/// - Singlestepping / Continue
/// - LLDB support (transmit info about arch/reg layout)
///    - read of feature target.xml [i386-64bit.xml]
///    - qHostInfo triple sends x86_64-unknown-hermit

const INT3: &[u8] = &[0xcc];

impl UhyveCPU {
	/// Called on Trap. Creates Handler.
	/// Enter gdb-event-loop until gdb tells us to continue. Set singlestep mode if necessary and return
	pub fn gdb_handle_exception<'a>(&mut self, signal: bool) {
		debug!("Handling debug exception!");
		if let Some(dbg) = &mut self.dbg {
			let dbgarc = dbg.clone();
			let dbg = dbgarc.lock().expect("No gdb available!");

			let (mut cmdhandler, signal) = if signal {
				// send signal with which we are stopped. Hardcoded to 5 for now (TODO)
				(
					CmdHandler::new(self, &dbg.state),
					Some(StopReason::Signal(5)),
				)
			} else {
				// target stopped on boot. No signal recv'd yet. Pretend debug singal..? Not used rn anyways
				(CmdHandler::new(self, &dbg.state), None)
			};

			// enter command-handler, stay there until we receive a continue signal
			let vcont = dbg
				.handle_commands(&mut cmdhandler, signal)
				.unwrap_or_else(|error| {
					error!("Cannot handle debugging commands: {:?}", error);
					// always continue
					VCont::Continue
				});

			let hwbr = dbg.state.borrow().get_hardware_breakpoints();

			// handler returned with a continuation command,
			// determine if we should continue single-stepped or until next trap
			match vcont {
				VCont::Continue | VCont::ContinueWithSignal(_) => {
					debug!("Continuing execution..");
					self.change_guestdbg(false, hwbr.as_ref())
						.expect("Could not change KVM debugging state"); // TODO: optimize this, dont call too often?
				}
				VCont::Step | VCont::StepWithSignal(_) => {
					debug!("Starting Single Stepping..");
					self.change_guestdbg(true, hwbr.as_ref())
						.expect("Could not change KVM debugging state"); // TODO: optimize this, dont call too often?
				}
				_ => error!("Unknown Handler exit reason!"),
			}
		} else {
			debug!("Debugging disabled, ignoring exception {:?}.", signal);
		};
	}

	unsafe fn read_mem(&self, guest_addr: usize, len: usize) -> &[u8] {
		let phys = self.virt_to_phys(guest_addr);
		let host = self.host_address(phys);

		slice::from_raw_parts(host as *mut u8, len)
	}

	unsafe fn write_mem(&self, guest_addr: usize, data: &[u8]) {
		let phys = self.virt_to_phys(guest_addr);
		let host = self.host_address(phys);

		let mem: &mut [u8] = slice::from_raw_parts_mut(host as *mut u8, data.len());

		mem.copy_from_slice(data);
	}

	pub fn change_guestdbg(
		&mut self,
		single_step: bool,
		hwbr: Option<&x86::HWBreakpoints>, /*&HashMap<usize, Breakpoint>*/
	) -> Result<(), error::Error> {
		debug!(
			"xhypervisor: Enable guest debug. single_step:{}",
			single_step
		);

		debug!("Setting guestdbg");
		let vcpu = self.get_vcpu();
		let mut rflags = vcpu.read_register(&x86Reg::RFLAGS).unwrap();
		if single_step {
			rflags |= RFlags::FLAGS_TF.bits();
		} else {
			rflags &= !RFlags::FLAGS_TF.bits();
		}
		vcpu.write_register(&x86Reg::RFLAGS, rflags).unwrap();

		if let Some(hwbr) = hwbr {
			vcpu.write_register(&x86Reg::DR0, hwbr.get_addr(0).unwrap())
				.unwrap();
			vcpu.write_register(&x86Reg::DR1, hwbr.get_addr(1).unwrap())
				.unwrap();
			vcpu.write_register(&x86Reg::DR2, hwbr.get_addr(2).unwrap())
				.unwrap();
			vcpu.write_register(&x86Reg::DR3, hwbr.get_addr(3).unwrap())
				.unwrap();
			vcpu.write_register(&x86Reg::DR7, hwbr.get_dr7()).unwrap();
		}

		Ok(())
	}
}

#[derive(Default)]
pub struct State {
	breakpoints: HashMap<usize, SWBreakpoint>,
	breakpoints_hw: HashMap<usize, HWBreakpoint>,
}

#[derive(Debug)]
enum BreakpointKind {
	Breakpoint,
	WatchWrite,
	WatchAccess,
}

#[derive(Debug)]
struct SWBreakpoint {
	bp: Breakpoint,
	insn: u8,
}

#[derive(Debug)]
struct HWBreakpoint {
	kind: BreakpointKind,
	addr: u64,
	n_bytes: u64,
}

impl State {
	pub fn new() -> Self {
		Self::default()
	}

	pub fn get_hardware_breakpoints(&self) -> Option<x86::HWBreakpoints> {
		if self.breakpoints_hw.is_empty() {
			return None;
		}

		if self.breakpoints_hw.len() > 4 {
			error!("Cannot set more than 4 hardware breakpoints!")
		}

		let mut hwbr = x86::HWBreakpoints::default();

		for (i, (addr, bp)) in self.breakpoints_hw.iter().take(4).enumerate() {
			hwbr.0[i].addr = *addr as _;
			hwbr.0[i].is_local = true;
			hwbr.0[i].is_global = true;
			hwbr.0[i].trigger = match bp.kind {
				BreakpointKind::Breakpoint => x86::BreakTrigger::Ex,
				BreakpointKind::WatchWrite => x86::BreakTrigger::W,
				BreakpointKind::WatchAccess => x86::BreakTrigger::RW,
			};
			hwbr.0[i].size = match bp.n_bytes {
				1 => x86::BreakSize::B1,
				2 => x86::BreakSize::B2,
				4 => x86::BreakSize::B4,
				8 => x86::BreakSize::B8,
				_ => {
					error!("Unknown watchpoint size!");
					x86::BreakSize::B1
				}
			};
		}

		Some(hwbr)
	}
}

pub struct CmdHandler<'a> {
	// use RefCells to not break existing api of gdb_parser (no mutability in handler)
	resume: RefCell<Option<VCont>>,
	current_cpu: RefCell<&'a mut UhyveCPU>,
	state: &'a RefCell<State>,
}

impl<'a> CmdHandler<'a> {
	pub fn new(cpu: &'a mut UhyveCPU, state: &'a RefCell<State>) -> CmdHandler<'a> {
		CmdHandler {
			resume: RefCell::new(None),
			current_cpu: RefCell::new(cpu),
			state,
		}
	}

	pub fn continue_execution(&self, reason: VCont) {
		debug!("Continuing..");
		*self.resume.borrow_mut() = Some(reason);
	}

	fn register_hardware_trap(&self, bp: HWBreakpoint) -> Result<(), Error> {
		{
			let brhw = &self.state.borrow().breakpoints_hw;
			// bail if breakpoint already exists
			if brhw.contains_key(&(bp.addr as _)) {
				return Err(Error::Error(6));
			}

			if brhw.len() >= 4 {
				error!("Cannot set more than 4 hardware breakpoints!");
				return Err(Error::Error(6));
			}
		}

		// HW BREAKPOINTS get set/removed during KVM update on cmd-loop exit! (kvm_change_guestdbg)

		self.state
			.borrow_mut()
			.breakpoints_hw
			.insert(bp.addr as _, bp);
		debug!(
			"Add breakpoints_hw: {:?}",
			self.state.borrow().breakpoints_hw
		);
		Ok(())
	}

	fn deregister_hardware_trap(&self, breakpoint: HWBreakpoint) -> Result<(), Error> {
		debug!(
			"Remove breakpoints_hw: {:?}",
			self.state.borrow().breakpoints_hw
		);
		if let Some(_bp) = self
			.state
			.borrow_mut()
			.breakpoints_hw
			.remove(&(breakpoint.addr as _))
		{
			// HW BREAKPOINTS get set/removed during KVM update on cmd-loop exit! (kvm_change_guestdbg)

			Ok(())
		} else {
			Err(Error::Error(4))
		}
	}
}

impl<'a> Handler for CmdHandler<'a> {
	fn should_cont(&self) -> Option<VCont> {
		self.resume.borrow().clone()
	}

	fn attached(&self, _pid: Option<u64>) -> Result<ProcessType, Error> {
		Ok(ProcessType::Attached)
	}

	fn halt_reason(&self) -> Result<StopReason, Error> {
		//Ok(StopReason::Exited(23, 0))
		// TODO make this dynamic based on VcpuExit reason.
		Ok(StopReason::Signal(5))
	}

	fn query_supported_features(&self) -> Vec<String> {
		vec!["qXfer:features:read+".to_string()]
	}

	fn query_supported_vcont(&self) -> Result<Cow<'static, [VContFeature]>, Error> {
		Ok(Cow::Borrowed(&[
			VContFeature::Continue,
			VContFeature::ContinueWithSignal,
			VContFeature::Step,
			VContFeature::StepWithSignal,
			//VContFeature::RangeStep,
		]))
	}

	/// TODO: actually implement thread switching for multithread support
	fn set_current_thread(&self, id: ThreadId) -> Result<(), Error> {
		debug!("Setting current thread to {:?}", id);
		Ok(())
	}

	/// Return the identifier of the current thread.
	fn current_thread(&self) -> Result<Option<ThreadId>, Error> {
		Ok(Some(ThreadId {
			pid: Id::Id(1),
			tid: Id::Id(1),
		}))
	}

	fn read_general_registers(&self) -> Result<Vec<u8>, Error> {
		let out = Registers::from_xhypervisor(self.current_cpu.borrow().get_vcpu()).encode();
		Ok(out)
	}

	fn write_general_registers(&self, contents: &[u8]) -> Result<(), Error> {
		let regs = Registers::decode(contents);
		regs.to_xhypervisor(self.current_cpu.borrow().get_vcpu());
		Ok(())
	}

	fn read_memory(&self, mem: MemoryRegion) -> Result<Vec<u8>, Error> {
		Ok(unsafe {
			self.current_cpu
				.borrow()
				.read_mem(mem.address as _, mem.length as _)
		}
		.to_vec())
	}

	fn write_memory(&self, address: u64, bytes: &[u8]) -> Result<(), Error> {
		unsafe { self.current_cpu.borrow().write_mem(address as _, bytes) }
		Ok(())
	}

	fn insert_software_breakpoint(&self, bp: Breakpoint) -> Result<(), Error> {
		// bail if breakpoint already exists
		if self
			.state
			.borrow()
			.breakpoints
			.contains_key(&(bp.addr as _))
		{
			return Err(Error::Error(6));
		}

		// save original instruction byte
		let insn = unsafe { self.current_cpu.borrow().read_mem(bp.addr as _, 1) }[0];
		// overwrite with int3
		unsafe { self.current_cpu.borrow().write_mem(bp.addr as _, INT3) }

		let bp = SWBreakpoint { bp, insn };
		self.state
			.borrow_mut()
			.breakpoints
			.insert(bp.bp.addr as _, bp);
		debug!("Add breakpoints: {:?}", self.state.borrow().breakpoints);
		Ok(())
	}

	fn remove_software_breakpoint(&self, breakpoint: Breakpoint) -> Result<(), Error> {
		debug!("Remove breakpoints: {:?}", self.state.borrow().breakpoints);
		if let Some(bp) = self
			.state
			.borrow_mut()
			.breakpoints
			.remove(&(breakpoint.addr as _))
		{
			// restore original instruction byte
			unsafe {
				self.current_cpu
					.borrow()
					.write_mem(breakpoint.addr as _, &[bp.insn])
			};
			Ok(())
		} else {
			Err(Error::Error(4))
		}
	}

	fn insert_hardware_breakpoint(&self, bp: Breakpoint) -> Result<(), Error> {
		self.register_hardware_trap(HWBreakpoint {
			kind: BreakpointKind::Breakpoint,
			addr: bp.addr as _,
			n_bytes: 1,
		})
	}

	fn remove_hardware_breakpoint(&self, bp: Breakpoint) -> Result<(), Error> {
		self.deregister_hardware_trap(HWBreakpoint {
			kind: BreakpointKind::Breakpoint,
			addr: bp.addr as _,
			n_bytes: 1,
		})
	}

	/// Insert a write watchpoint.
	fn insert_write_watchpoint(&self, watchpoint: Watchpoint) -> Result<(), Error> {
		self.register_hardware_trap(HWBreakpoint {
			kind: BreakpointKind::WatchWrite,
			addr: watchpoint.addr as _,
			n_bytes: watchpoint.n_bytes,
		})
	}

	/// Insert a read watchpoint.
	fn insert_read_watchpoint(&self, watchpoint: Watchpoint) -> Result<(), Error> {
		self.register_hardware_trap(HWBreakpoint {
			kind: BreakpointKind::WatchAccess,
			addr: watchpoint.addr as _,
			n_bytes: watchpoint.n_bytes,
		})
	}

	/// Insert an access watchpoint.
	fn insert_access_watchpoint(&self, watchpoint: Watchpoint) -> Result<(), Error> {
		self.register_hardware_trap(HWBreakpoint {
			kind: BreakpointKind::WatchAccess,
			addr: watchpoint.addr as _,
			n_bytes: watchpoint.n_bytes,
		})
	}

	/// Remove a write watchpoint.
	fn remove_write_watchpoint(&self, watchpoint: Watchpoint) -> Result<(), Error> {
		self.deregister_hardware_trap(HWBreakpoint {
			kind: BreakpointKind::WatchWrite,
			addr: watchpoint.addr as _,
			n_bytes: watchpoint.n_bytes,
		})
	}

	/// Remove a read watchpoint.
	fn remove_read_watchpoint(&self, watchpoint: Watchpoint) -> Result<(), Error> {
		self.deregister_hardware_trap(HWBreakpoint {
			kind: BreakpointKind::WatchAccess,
			addr: watchpoint.addr as _,
			n_bytes: watchpoint.n_bytes,
		})
	}

	/// Remove an access watchpoint.
	fn remove_access_watchpoint(&self, watchpoint: Watchpoint) -> Result<(), Error> {
		self.deregister_hardware_trap(HWBreakpoint {
			kind: BreakpointKind::WatchAccess,
			addr: watchpoint.addr as _,
			n_bytes: watchpoint.n_bytes,
		})
	}

	/// TODO: currently ignores tid/pid, and just continues/steps currently running cpu according to first command
	/// At most apply one action per thread. GDB likes to send default action for other threads,
	/// even if it knows only about 1: "vCont;s:1;c" (step thread 1, continue others)
	fn vcont(&self, actions: Vec<(VCont, Option<ThreadId>)>) -> Result<StopReason, Error> {
		for (cmd, id) in &actions {
			let _id = id.unwrap_or(ThreadId {
				pid: Id::All,
				tid: Id::All,
			});
			//debug!("{:?}", id);
			//println!(self.tracee.pid());
			/*match (id.pid, id.tid) {
				(Id::Id(pid), _) if pid != self.tracee.pid() => continue,
				(_, Id::Id(tid)) if tid != self.tracee.pid() => continue,
				(_, _) => (),
			}*/
			debug!("vcont: {:?}", *cmd);
			// need to clone, since std::ops::Range<T: Copy> should probably also be Copy, but it isn't.
			self.continue_execution(cmd.clone());

			break;
		}

		// this reason should not matter, since we dont send it when continuing.
		Ok(StopReason::Signal(0))
	}

	/// TODO: return actual number of threads, not just one
	fn thread_list(&self, reset: bool) -> Result<Vec<ThreadId>, Error> {
		if reset {
			Ok(vec![
				ThreadId {
					pid: Id::Id(1),
					tid: Id::Id(1),
				},
				/*ThreadId{pid: Id::Id(1), tid: Id::Id(2)},
				ThreadId{pid: Id::Id(1), tid: Id::Id(3)},
				ThreadId{pid: Id::Id(1), tid: Id::Id(4)},*/
			])
		} else {
			Ok(Vec::new())
		}
	}

	fn process_list(&self, reset: bool) -> Result<Vec<ProcessInfo>, Error> {
		if reset {
			Ok(vec![ProcessInfo {
				pid: Id::Id(1),
				name: "hermitcore app".to_string(),
				triple: "x86_64-unknown-hermit".to_string(),
			}])
		} else {
			Ok(Vec::new())
		}
	}

	fn read_feature(&self, name: String, offset: u64, length: u64) -> Result<FileData, Error> {
		let targetxml = include_str!("i386-64bit.xml");
		match name.as_ref() {
			"target.xml" => Ok(FileData(
				get_max_subslice(targetxml, offset as _, length as _).to_string(),
			)),
			_ => {
				debug!(
					"Error: emote tried to read {}, which is unimplemented",
					name
				);
				Err(Error::Unimplemented)
			}
		}
	}

	fn host_info(&self) -> Result<String, Error> {
		Ok(format!("triple:{};", b"x86_64-unknown-hermit".to_hex()))
	}
}

#[derive(Default)]
pub struct Registers {
	// Gotten from gnu-binutils/gdb/regformats/i386/amd64-linux.dat
	pub rax: Option<u64>,
	pub rbx: Option<u64>,
	pub rcx: Option<u64>,
	pub rdx: Option<u64>,
	pub rsi: Option<u64>,
	pub rdi: Option<u64>,
	pub rbp: Option<u64>,
	pub rsp: Option<u64>,
	pub r8: Option<u64>,
	pub r9: Option<u64>,
	pub r10: Option<u64>,
	pub r11: Option<u64>,
	pub r12: Option<u64>,
	pub r13: Option<u64>,
	pub r14: Option<u64>,
	pub r15: Option<u64>,
	pub rip: Option<u64>,
	pub eflags: Option<u32>,
	pub cs: Option<u32>,
	pub ss: Option<u32>,
	pub ds: Option<u32>,
	pub es: Option<u32>,
	pub fs: Option<u32>,
	pub gs: Option<u32>,
	/*pub st0: Option<u128>,
	pub st1: Option<u128>,
	pub st2: Option<u128>,
	pub st3: Option<u128>,
	pub st4: Option<u128>,
	pub st5: Option<u128>,
	pub st6: Option<u128>,
	pub st7: Option<u128>,
	pub fctrl: Option<u32>,
	pub fstat: Option<u32>,
	pub ftag: Option<u32>,
	pub fiseg: Option<u32>,
	pub fioff: Option<u32>,
	pub foseg: Option<u32>,
	pub fooff: Option<u32>,
	pub fop: Option<u32>,
	pub xmm0: Option<u128>,
	pub xmm1: Option<u128>,
	pub xmm2: Option<u128>,
	pub xmm3: Option<u128>,
	pub xmm4: Option<u128>,
	pub xmm5: Option<u128>,
	pub xmm6: Option<u128>,
	pub xmm7: Option<u128>,
	pub xmm8: Option<u128>,
	pub xmm9: Option<u128>,
	pub xmm10: Option<u128>,
	pub xmm11: Option<u128>,
	pub xmm12: Option<u128>,
	pub xmm13: Option<u128>,
	pub xmm14: Option<u128>,
	pub xmm15: Option<u128>,
	pub mxcsr: Option<u32>,
	pub orig_rax: Option<u64>,
	pub fs_base: Option<u64>,
	pub gs_base: Option<u64>,*/
}

impl Registers {
	/// Loads the register set from xhypervisor into the register struct
	pub fn from_xhypervisor(vcpu: &vCPU) -> Self {
		Self {
			r15: Some(vcpu.read_register(&x86Reg::R15).unwrap()),
			r14: Some(vcpu.read_register(&x86Reg::R14).unwrap()),
			r13: Some(vcpu.read_register(&x86Reg::R13).unwrap()),
			r12: Some(vcpu.read_register(&x86Reg::R12).unwrap()),
			r11: Some(vcpu.read_register(&x86Reg::R11).unwrap()),
			r10: Some(vcpu.read_register(&x86Reg::R10).unwrap()),
			r9: Some(vcpu.read_register(&x86Reg::R9).unwrap()),
			r8: Some(vcpu.read_register(&x86Reg::R8).unwrap()),
			rax: Some(vcpu.read_register(&x86Reg::RAX).unwrap()),
			rbx: Some(vcpu.read_register(&x86Reg::RBX).unwrap()),
			rcx: Some(vcpu.read_register(&x86Reg::RCX).unwrap()),
			rdx: Some(vcpu.read_register(&x86Reg::RDX).unwrap()),
			rsi: Some(vcpu.read_register(&x86Reg::RSI).unwrap()),
			rdi: Some(vcpu.read_register(&x86Reg::RDI).unwrap()),
			rsp: Some(vcpu.read_register(&x86Reg::RSP).unwrap()),
			rbp: Some(vcpu.read_register(&x86Reg::RBP).unwrap()),
			rip: Some(vcpu.read_register(&x86Reg::RIP).unwrap()),
			eflags: Some(vcpu.read_register(&x86Reg::RFLAGS).unwrap() as u32),
			cs: Some(vcpu.read_register(&x86Reg::CS).unwrap() as u32),
			ss: Some(vcpu.read_register(&x86Reg::SS).unwrap() as u32),
			ds: Some(vcpu.read_register(&x86Reg::DS).unwrap() as u32),
			es: Some(vcpu.read_register(&x86Reg::ES).unwrap() as u32),
			fs: Some(vcpu.read_register(&x86Reg::FS).unwrap() as u32),
			gs: Some(vcpu.read_register(&x86Reg::GS).unwrap() as u32),
		}
	}

	/// Saves a register struct (only where non-None values are) into xhypervisor.
	pub fn to_xhypervisor(&self, vcpu: &vCPU) {
		if let Some(r15) = self.r15 {
			vcpu.write_register(&x86Reg::R15, r15).unwrap();
		}
		if let Some(r14) = self.r14 {
			vcpu.write_register(&x86Reg::R14, r14).unwrap();
		}
		if let Some(r13) = self.r13 {
			vcpu.write_register(&x86Reg::R13, r13).unwrap();
		}
		if let Some(r12) = self.r12 {
			vcpu.write_register(&x86Reg::R12, r12).unwrap();
		}
		if let Some(r11) = self.r11 {
			vcpu.write_register(&x86Reg::R11, r11).unwrap();
		}
		if let Some(r10) = self.r10 {
			vcpu.write_register(&x86Reg::R10, r10).unwrap();
		}
		if let Some(r9) = self.r9 {
			vcpu.write_register(&x86Reg::R9, r9).unwrap();
		}
		if let Some(r8) = self.r8 {
			vcpu.write_register(&x86Reg::R8, r8).unwrap();
		}
		if let Some(rax) = self.rax {
			vcpu.write_register(&x86Reg::RAX, rax).unwrap();
		}
		if let Some(rbx) = self.rbx {
			vcpu.write_register(&x86Reg::RBX, rbx).unwrap();
		}
		if let Some(rcx) = self.rcx {
			vcpu.write_register(&x86Reg::RCX, rcx).unwrap();
		}
		if let Some(rdx) = self.rdx {
			vcpu.write_register(&x86Reg::RDX, rdx).unwrap();
		}
		if let Some(rdi) = self.rdi {
			vcpu.write_register(&x86Reg::RDI, rdi).unwrap();
		}
		if let Some(rsi) = self.rsi {
			vcpu.write_register(&x86Reg::RSI, rsi).unwrap();
		}
		if let Some(rsp) = self.rsp {
			vcpu.write_register(&x86Reg::RSP, rsp).unwrap();
		}
		if let Some(rbp) = self.rbp {
			vcpu.write_register(&x86Reg::RBP, rbp).unwrap();
		}
		if let Some(rip) = self.rip {
			vcpu.write_register(&x86Reg::RIP, rip).unwrap();
		}
		if let Some(rflags) = self.eflags {
			vcpu.write_register(&x86Reg::RFLAGS, rflags as u64).unwrap();
		}
		if let Some(cs) = self.cs {
			vcpu.write_register(&x86Reg::CS, cs as u64).unwrap();
		}
		if let Some(ss) = self.ss {
			vcpu.write_register(&x86Reg::SS, ss as u64).unwrap();
		}
		if let Some(ds) = self.ds {
			vcpu.write_register(&x86Reg::DS, ds as u64).unwrap();
		}
		if let Some(es) = self.es {
			vcpu.write_register(&x86Reg::ES, es as u64).unwrap();
		}
		if let Some(fs) = self.fs {
			vcpu.write_register(&x86Reg::FS, fs as u64).unwrap();
		}
		if let Some(gs) = self.gs {
			vcpu.write_register(&x86Reg::GS, gs as u64).unwrap();
		}
	}

	/// take the serialized register set send by gdb and decodes it into a register structure.
	/// uses little endian, order as specified by gdb arch i386:x86-64
	pub fn decode(mut raw: &[u8]) -> Self {
		Self {
			rax: raw.read_u64::<LittleEndian>().ok(),
			rbx: raw.read_u64::<LittleEndian>().ok(),
			rcx: raw.read_u64::<LittleEndian>().ok(),
			rdx: raw.read_u64::<LittleEndian>().ok(),
			rsi: raw.read_u64::<LittleEndian>().ok(),
			rdi: raw.read_u64::<LittleEndian>().ok(),
			rbp: raw.read_u64::<LittleEndian>().ok(),
			rsp: raw.read_u64::<LittleEndian>().ok(),
			r8: raw.read_u64::<LittleEndian>().ok(),
			r9: raw.read_u64::<LittleEndian>().ok(),
			r10: raw.read_u64::<LittleEndian>().ok(),
			r11: raw.read_u64::<LittleEndian>().ok(),
			r12: raw.read_u64::<LittleEndian>().ok(),
			r13: raw.read_u64::<LittleEndian>().ok(),
			r14: raw.read_u64::<LittleEndian>().ok(),
			r15: raw.read_u64::<LittleEndian>().ok(),
			rip: raw.read_u64::<LittleEndian>().ok(),
			eflags: raw.read_u32::<LittleEndian>().ok(),
			cs: raw.read_u32::<LittleEndian>().ok(),
			ss: raw.read_u32::<LittleEndian>().ok(),
			ds: raw.read_u32::<LittleEndian>().ok(),
			es: raw.read_u32::<LittleEndian>().ok(),
			fs: raw.read_u32::<LittleEndian>().ok(),
			gs: raw.read_u32::<LittleEndian>().ok(),
		}
	}

	/// take the register set and encode it as a u8-vector by concatenating the values
	/// uses little endian, order as specified by gdb arch i386:x86-64
	pub fn encode(&self) -> Vec<u8> {
		let mut out: Vec<u8> = vec![];

		out.write_u64::<LittleEndian>(self.rax.unwrap_or(0))
			.unwrap();
		out.write_u64::<LittleEndian>(self.rbx.unwrap_or(0))
			.unwrap();
		out.write_u64::<LittleEndian>(self.rcx.unwrap_or(0))
			.unwrap();
		out.write_u64::<LittleEndian>(self.rdx.unwrap_or(0))
			.unwrap();
		out.write_u64::<LittleEndian>(self.rsi.unwrap_or(0))
			.unwrap();
		out.write_u64::<LittleEndian>(self.rdi.unwrap_or(0))
			.unwrap();
		out.write_u64::<LittleEndian>(self.rbp.unwrap_or(0))
			.unwrap();
		out.write_u64::<LittleEndian>(self.rsp.unwrap_or(0))
			.unwrap();
		out.write_u64::<LittleEndian>(self.r8.unwrap_or(0)).unwrap();
		out.write_u64::<LittleEndian>(self.r9.unwrap_or(0)).unwrap();
		out.write_u64::<LittleEndian>(self.r10.unwrap_or(0))
			.unwrap();
		out.write_u64::<LittleEndian>(self.r11.unwrap_or(0))
			.unwrap();
		out.write_u64::<LittleEndian>(self.r12.unwrap_or(0))
			.unwrap();
		out.write_u64::<LittleEndian>(self.r13.unwrap_or(0))
			.unwrap();
		out.write_u64::<LittleEndian>(self.r14.unwrap_or(0))
			.unwrap();
		out.write_u64::<LittleEndian>(self.r15.unwrap_or(0))
			.unwrap();
		out.write_u64::<LittleEndian>(self.rip.unwrap_or(0))
			.unwrap();

		out.write_u32::<LittleEndian>(self.eflags.unwrap_or(0))
			.unwrap();
		out.write_u32::<LittleEndian>(self.cs.unwrap_or(0)).unwrap();
		out.write_u32::<LittleEndian>(self.ss.unwrap_or(0)).unwrap();
		out.write_u32::<LittleEndian>(self.ds.unwrap_or(0)).unwrap();
		out.write_u32::<LittleEndian>(self.es.unwrap_or(0)).unwrap();
		out.write_u32::<LittleEndian>(self.fs.unwrap_or(0)).unwrap();
		out.write_u32::<LittleEndian>(self.gs.unwrap_or(0)).unwrap();

		out
	}
}
