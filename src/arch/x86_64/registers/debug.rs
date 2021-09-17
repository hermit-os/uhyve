//! Functions to read and write debug registers.

use std::convert::{TryFrom, TryInto};

use gdbstub::target::ext::breakpoints::WatchKind;
use x86_64::{
	registers::debug::{
		DebugAddressRegisterNumber, Dr7Flags, Dr7Value, HwBreakpointCondition, HwBreakpointSize,
		TryFromIntError,
	},
	VirtAddr,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HwBreakpoint {
	addr: VirtAddr,
	size: HwBreakpointSize,
	condition: HwBreakpointCondition,
}

impl HwBreakpoint {
	pub fn new_breakpoint(addr: u64, kind: usize) -> Result<Self, TryFromIntError> {
		Ok(Self {
			addr: VirtAddr::new(addr),
			size: kind.try_into()?,
			condition: HwBreakpointCondition::InstructionExecution,
		})
	}

	pub fn new_watchpoint(addr: u64, len: u64, kind: WatchKind) -> Option<Self> {
		let condition = match kind {
			WatchKind::Write => Some(HwBreakpointCondition::DataWrites),
			WatchKind::Read => None,
			WatchKind::ReadWrite => Some(HwBreakpointCondition::DataReadsWrites),
		}?;

		let ret = Self {
			addr: VirtAddr::new(addr),
			size: usize::try_from(len).ok()?.try_into().ok()?,
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

			dr7_value
				.flags_mut()
				.insert(Dr7Flags::global_breakpoint_enable(n));
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
}

impl Default for HwBreakpoints {
	fn default() -> Self {
		Self::new()
	}
}
