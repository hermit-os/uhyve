//! Functions to read and write debug registers.

use gdbstub::{stub::SingleThreadStopReason, target::ext::breakpoints::WatchKind};
use x86_64::{
	VirtAddr,
	registers::debug::{
		BreakpointCondition, BreakpointSize, DebugAddressRegisterNumber, Dr6Flags, Dr7Flags,
		Dr7Value,
	},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HwBreakpoint {
	addr: VirtAddr,
	size: BreakpointSize,
	condition: BreakpointCondition,
}

impl HwBreakpoint {
	pub fn new_breakpoint(addr: u64, kind: usize) -> Option<Self> {
		Some(Self {
			addr: VirtAddr::new(addr),
			size: BreakpointSize::new(kind)?,
			condition: BreakpointCondition::InstructionExecution,
		})
	}

	pub fn new_watchpoint(addr: u64, len: u64, kind: WatchKind) -> Option<Self> {
		let condition = match kind {
			WatchKind::Write => Some(BreakpointCondition::DataWrites),
			WatchKind::Read => None,
			WatchKind::ReadWrite => Some(BreakpointCondition::DataReadsWrites),
		}?;

		let ret = Self {
			addr: VirtAddr::new(addr),
			size: BreakpointSize::new(len.try_into().ok()?)?,
			condition,
		};

		Some(ret)
	}
}

#[derive(Clone, Copy, Debug)]
pub struct HwBreakpoints([Option<HwBreakpoint>; 4]);

#[derive(Debug)]
pub struct CapacityExceededError(());

impl HwBreakpoints {
	pub const fn new() -> Self {
		Self([None; 4])
	}

	pub fn try_insert(&mut self, hw_breakpoint: HwBreakpoint) -> Result<(), CapacityExceededError> {
		if let Some(entry) = self.0.iter_mut().find(|entry| entry.is_none()) {
			*entry = Some(hw_breakpoint);
			Ok(())
		} else {
			Err(CapacityExceededError(()))
		}
	}

	pub fn take(&mut self, hw_breakpoint: &HwBreakpoint) -> Option<HwBreakpoint> {
		self.0
			.iter_mut()
			.find(|slot| slot.as_ref() == Some(hw_breakpoint))?
			.take()
	}

	fn control_value(&self) -> Dr7Value {
		let dr7_flags = Dr7Flags::LOCAL_EXACT_BREAKPOINT_ENABLE
			| Dr7Flags::GLOBAL_EXACT_BREAKPOINT_ENABLE
			| Dr7Flags::GENERAL_DETECT_ENABLE;
		let mut dr7_value = Dr7Value::from(dr7_flags);

		for (i, hw_breakpoint) in
			self.0.iter().enumerate().filter_map(|(i, hw_breakpoint)| {
				hw_breakpoint.map(|hw_breakpoint| (i, hw_breakpoint))
			}) {
			let n = DebugAddressRegisterNumber::new(i.try_into().unwrap()).unwrap();

			dr7_value.insert_flags(Dr7Flags::global_breakpoint_enable(n));
			dr7_value.set_condition(n, hw_breakpoint.condition);
			dr7_value.set_size(n, hw_breakpoint.size);
		}

		dr7_value
	}

	pub fn registers(self) -> [u64; 8] {
		let control_value = self.control_value();
		let address = |hw_breakpoint: Option<HwBreakpoint>| {
			hw_breakpoint
				.map(|hw_breakpoint| hw_breakpoint.addr.as_u64())
				.unwrap_or(0)
		};
		[
			address(self.0[0]),
			address(self.0[1]),
			address(self.0[2]),
			address(self.0[3]),
			0,
			0,
			0,
			control_value.bits(),
		]
	}

	pub fn stop_reason(&self, dr6: Dr6Flags) -> SingleThreadStopReason<u64> {
		if dr6.contains(Dr6Flags::STEP) {
			SingleThreadStopReason::DoneStep
		} else {
			let n = (0..4)
				.find(|&n| {
					let n = DebugAddressRegisterNumber::new(n).unwrap();
					dr6.contains(Dr6Flags::trap(n))
				})
				.unwrap();
			let breakpoint = self.0[usize::from(n)].unwrap();

			match breakpoint.condition {
				BreakpointCondition::InstructionExecution => SingleThreadStopReason::HwBreak(()),
				BreakpointCondition::DataWrites => SingleThreadStopReason::Watch {
					tid: (),
					kind: WatchKind::Write,
					addr: breakpoint.addr.as_u64(),
				},
				BreakpointCondition::DataReadsWrites => SingleThreadStopReason::Watch {
					tid: (),
					kind: WatchKind::ReadWrite,
					addr: breakpoint.addr.as_u64(),
				},
				BreakpointCondition::IoReadsWrites => unreachable!(),
			}
		}
	}
}

impl Default for HwBreakpoints {
	fn default() -> Self {
		Self::new()
	}
}
