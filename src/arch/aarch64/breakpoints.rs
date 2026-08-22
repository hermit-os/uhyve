//! Hardware breakpoint and watchpoint registers of the ARMv8 debug architecture.
//!
//! See ARM DDI 0487, "DBGBCR<n>_EL1" and "DBGWCR<n>_EL1".

use gdbstub::{common::Tid, stub::MultiThreadStopReason, target::ext::breakpoints::WatchKind};

/// Number of breakpoint and watchpoint slots exposed to the guest.
///
/// This matches the fixed size of the register arrays in KVM's
/// `kvm_guest_debug_arch`. Implementations with fewer slots than this simply
/// ignore the surplus registers.
const SLOTS: usize = 16;

/// AArch64 instructions are always four bytes wide and four byte aligned.
const INSTRUCTION_LEN: usize = 4;

/// Watchpoint address registers ignore the low three address bits, so the byte
/// address select field is relative to the enclosing doubleword.
const WATCHPOINT_ALIGN: u64 = 8;

/// `E`, plus `PMC` selecting both EL1 and EL0.
const ENABLE_EL1_EL0: u64 = 1 | (0b11 << 1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Condition {
	InstructionExecution,
	Data { kind: WatchKind, len: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HwBreakpoint {
	addr: u64,
	condition: Condition,
}

impl HwBreakpoint {
	pub fn new_breakpoint(addr: u64, kind: usize) -> Option<Self> {
		if kind != INSTRUCTION_LEN || !addr.is_multiple_of(INSTRUCTION_LEN as u64) {
			return None;
		}

		Some(Self {
			addr,
			condition: Condition::InstructionExecution,
		})
	}

	pub fn new_watchpoint(addr: u64, len: u64, kind: WatchKind) -> Option<Self> {
		// A single watchpoint only covers bytes within one doubleword.
		if len == 0 || len > WATCHPOINT_ALIGN || (addr % WATCHPOINT_ALIGN) + len > WATCHPOINT_ALIGN
		{
			return None;
		}

		Some(Self {
			addr,
			condition: Condition::Data { kind, len },
		})
	}

	fn is_watchpoint(&self) -> bool {
		matches!(self.condition, Condition::Data { .. })
	}

	/// The `DBGBCR<n>_EL1`/`DBGWCR<n>_EL1` value configuring this slot.
	fn control(&self) -> u64 {
		match self.condition {
			Condition::InstructionExecution => {
				// `BAS` covering all four bytes of the instruction.
				ENABLE_EL1_EL0 | (0b1111 << 5)
			}
			Condition::Data { kind, len } => {
				let lsc = match kind {
					WatchKind::Read => 0b01,
					WatchKind::Write => 0b10,
					WatchKind::ReadWrite => 0b11,
				};
				// `BAS` selects the watched bytes within the doubleword.
				let bas = ((1u64 << len) - 1) << (self.addr % WATCHPOINT_ALIGN);
				ENABLE_EL1_EL0 | (lsc << 3) | (bas << 5)
			}
		}
	}

	/// The `DBGBVR<n>_EL1`/`DBGWVR<n>_EL1` value for this slot.
	fn value(&self) -> u64 {
		match self.condition {
			Condition::InstructionExecution => self.addr,
			Condition::Data { .. } => self.addr - (self.addr % WATCHPOINT_ALIGN),
		}
	}

	fn covers(&self, addr: u64) -> bool {
		match self.condition {
			Condition::InstructionExecution => self.addr == addr,
			Condition::Data { len, .. } => (self.addr..self.addr + len).contains(&addr),
		}
	}
}

/// The contents of KVM's `kvm_guest_debug_arch`.
#[derive(Debug)]
pub struct DebugRegisters {
	pub bcr: [u64; SLOTS],
	pub bvr: [u64; SLOTS],
	pub wcr: [u64; SLOTS],
	pub wvr: [u64; SLOTS],
}

#[derive(Clone, Copy, Debug)]
pub struct HwBreakpoints {
	breakpoints: [Option<HwBreakpoint>; SLOTS],
	watchpoints: [Option<HwBreakpoint>; SLOTS],
}

#[derive(Debug)]
pub struct CapacityExceededError(());

impl HwBreakpoints {
	pub const fn new() -> Self {
		Self {
			breakpoints: [None; SLOTS],
			watchpoints: [None; SLOTS],
		}
	}

	fn slots_mut(&mut self, watchpoint: bool) -> &mut [Option<HwBreakpoint>; SLOTS] {
		if watchpoint {
			&mut self.watchpoints
		} else {
			&mut self.breakpoints
		}
	}

	pub fn try_insert(&mut self, hw_breakpoint: HwBreakpoint) -> Result<(), CapacityExceededError> {
		let slots = self.slots_mut(hw_breakpoint.is_watchpoint());

		if let Some(entry) = slots.iter_mut().find(|entry| entry.is_none()) {
			*entry = Some(hw_breakpoint);
			Ok(())
		} else {
			Err(CapacityExceededError(()))
		}
	}

	pub fn take(&mut self, hw_breakpoint: &HwBreakpoint) -> Option<HwBreakpoint> {
		self.slots_mut(hw_breakpoint.is_watchpoint())
			.iter_mut()
			.find(|slot| slot.as_ref() == Some(hw_breakpoint))?
			.take()
	}

	pub fn registers(&self) -> DebugRegisters {
		let control = |slots: &[Option<HwBreakpoint>; SLOTS]| {
			slots.map(|slot| slot.map(|bp| bp.control()).unwrap_or(0))
		};
		let value = |slots: &[Option<HwBreakpoint>; SLOTS]| {
			slots.map(|slot| slot.map(|bp| bp.value()).unwrap_or(0))
		};

		DebugRegisters {
			bcr: control(&self.breakpoints),
			bvr: value(&self.breakpoints),
			wcr: control(&self.watchpoints),
			wvr: value(&self.watchpoints),
		}
	}

	/// The stop reason for a watchpoint exception whose `FAR_EL2` reported `addr`.
	pub fn watch_stop_reason(&self, tid: Tid, addr: u64) -> MultiThreadStopReason<u64> {
		let watchpoint = self
			.watchpoints
			.iter()
			.flatten()
			.find(|watchpoint| watchpoint.covers(addr));

		match watchpoint.map(|watchpoint| watchpoint.condition) {
			Some(Condition::Data { kind, .. }) => MultiThreadStopReason::Watch { tid, kind, addr },
			// The guest trapped on a watchpoint we no longer track. Report the
			// access rather than dropping the stop on the floor.
			_ => MultiThreadStopReason::Watch {
				tid,
				kind: WatchKind::ReadWrite,
				addr,
			},
		}
	}
}

impl Default for HwBreakpoints {
	fn default() -> Self {
		Self::new()
	}
}
