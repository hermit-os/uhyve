use std::collections::{HashMap, hash_map::Entry};

use gdbstub::target::{self, TargetResult, ext::breakpoints::WatchKind};
use uhyve_interface::GuestVirtAddr;

use super::Freewheel;
use crate::arch::x86_64::{
	registers::{self, debug::HwBreakpoints},
	virt_to_phys,
};

#[derive(Clone, Debug, Default)]
pub struct AllBreakpoints {
	pub hard: HwBreakpoints,
	pub soft: SwBreakpoints,
}

impl AllBreakpoints {
	pub fn new() -> Self {
		Default::default()
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SwBreakpoint {
	addr: u64,
	kind: usize,
}

impl SwBreakpoint {
	const OPCODE: u8 = 0xcc;

	pub fn new(addr: u64, kind: usize) -> Self {
		Self { addr, kind }
	}
}

pub type SwBreakpoints = HashMap<SwBreakpoint, Vec<u8>>;

impl target::ext::breakpoints::Breakpoints for Freewheel {
	#[inline(always)]
	fn support_sw_breakpoint(
		&mut self,
	) -> Option<target::ext::breakpoints::SwBreakpointOps<'_, Self>> {
		Some(self)
	}

	#[inline(always)]
	fn support_hw_breakpoint(
		&mut self,
	) -> Option<target::ext::breakpoints::HwBreakpointOps<'_, Self>> {
		Some(self)
	}

	#[inline(always)]
	fn support_hw_watchpoint(
		&mut self,
	) -> Option<target::ext::breakpoints::HwWatchpointOps<'_, Self>> {
		Some(self)
	}
}

impl target::ext::breakpoints::SwBreakpoint for Freewheel {
	fn add_sw_breakpoint(&mut self, addr: u64, kind: usize) -> TargetResult<bool, Self> {
		let sw_breakpoint = SwBreakpoint::new(addr, kind);

		if let Entry::Vacant(entry) = self.breakpoints.write().unwrap().soft.entry(sw_breakpoint) {
			// Safety: mem is not altered during the lifetime of `instructions`
			let instructions = unsafe {
				self.peripherals.mem.slice_at_mut(
					virt_to_phys(
						GuestVirtAddr::new(addr),
						&self.peripherals.mem,
						self.vcpus[0]
							.shared
							.vcpu
							.read()
							.unwrap()
							.get_root_pagetable(),
					)
					.map_err(|_err| ())?,
					kind,
				)
			}
			.unwrap();
			entry.insert(instructions.into());
			instructions.fill(SwBreakpoint::OPCODE);
			Ok(true)
		} else {
			Ok(false)
		}
	}

	fn remove_sw_breakpoint(&mut self, addr: u64, kind: usize) -> TargetResult<bool, Self> {
		let sw_breakpoint = SwBreakpoint::new(addr, kind);

		Ok(
			if let Some(bp) = self
				.breakpoints
				.write()
				.unwrap()
				.soft
				.remove(&sw_breakpoint)
			{
				// Safety: mem is not altered during the lifetime of `instructions`
				let instructions = unsafe {
					self.peripherals.mem.slice_at_mut(
						virt_to_phys(
							GuestVirtAddr::new(addr),
							&self.peripherals.mem,
							self.vcpus[0]
								.shared
								.vcpu
								.read()
								.unwrap()
								.get_root_pagetable(),
						)
						.map_err(|_err| ())?,
						kind,
					)
				}
				.unwrap();
				instructions.copy_from_slice(&bp);
				true
			} else {
				false
			},
		)
	}
}

impl target::ext::breakpoints::HwBreakpoint for Freewheel {
	fn add_hw_breakpoint(&mut self, addr: u64, kind: usize) -> TargetResult<bool, Self> {
		let hw_breakpoint = match registers::debug::HwBreakpoint::new_breakpoint(addr, kind) {
			Some(hw_breakpoint) => hw_breakpoint,
			None => return Ok(false),
		};

		let success = self
			.breakpoints
			.write()
			.unwrap()
			.hard
			.try_insert(hw_breakpoint)
			.is_ok();
		Ok(success)
	}

	fn remove_hw_breakpoint(&mut self, addr: u64, kind: usize) -> TargetResult<bool, Self> {
		let hw_breakpoint = match registers::debug::HwBreakpoint::new_breakpoint(addr, kind) {
			Some(hw_breakpoint) => hw_breakpoint,
			None => return Ok(false),
		};

		let success = self
			.breakpoints
			.write()
			.unwrap()
			.hard
			.take(&hw_breakpoint)
			.is_some();
		Ok(success)
	}
}

impl target::ext::breakpoints::HwWatchpoint for Freewheel {
	fn add_hw_watchpoint(
		&mut self,
		addr: u64,
		len: u64,
		kind: WatchKind,
	) -> TargetResult<bool, Self> {
		let hw_breakpoint = match registers::debug::HwBreakpoint::new_watchpoint(addr, len, kind) {
			Some(hw_breakpoint) => hw_breakpoint,
			None => return Ok(false),
		};

		let success = self
			.breakpoints
			.write()
			.unwrap()
			.hard
			.try_insert(hw_breakpoint)
			.is_ok();
		Ok(success)
	}

	fn remove_hw_watchpoint(
		&mut self,
		addr: u64,
		len: u64,
		kind: WatchKind,
	) -> TargetResult<bool, Self> {
		let hw_breakpoint = match registers::debug::HwBreakpoint::new_watchpoint(addr, len, kind) {
			Some(hw_breakpoint) => hw_breakpoint,
			None => return Ok(false),
		};

		let success = self
			.breakpoints
			.write()
			.unwrap()
			.hard
			.take(&hw_breakpoint)
			.is_some();
		Ok(success)
	}
}
