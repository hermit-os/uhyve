use std::collections::{hash_map::Entry, HashMap};

use gdbstub::target::{self, ext::breakpoints::WatchKind, TargetResult};
use uhyve_interface::GuestVirtAddr;

use super::GdbUhyve;
use crate::arch::x86_64::{registers, virt_to_phys};
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

impl target::ext::breakpoints::Breakpoints for GdbUhyve {
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

impl target::ext::breakpoints::SwBreakpoint for GdbUhyve {
	fn add_sw_breakpoint(&mut self, addr: u64, kind: usize) -> TargetResult<bool, Self> {
		let sw_breakpoint = SwBreakpoint::new(addr, kind);

		if let Entry::Vacant(entry) = self.sw_breakpoints.entry(sw_breakpoint) {
			// Safety: mem is not altered during the lifetime of `instructions`
			let instructions = unsafe {
				self.vm.mem.slice_at_mut(
					virt_to_phys(GuestVirtAddr::new(addr), &self.vm.mem).map_err(|_err| ())?,
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

		if let Entry::Occupied(entry) = self.sw_breakpoints.entry(sw_breakpoint) {
			// Safety: mem is not altered during the lifetime of `instructions`
			let instructions = unsafe {
				self.vm.mem.slice_at_mut(
					virt_to_phys(GuestVirtAddr::new(addr), &self.vm.mem).map_err(|_err| ())?,
					kind,
				)
			}
			.unwrap();
			instructions.copy_from_slice(&entry.remove());
			Ok(true)
		} else {
			Ok(false)
		}
	}
}

impl target::ext::breakpoints::HwBreakpoint for GdbUhyve {
	fn add_hw_breakpoint(&mut self, addr: u64, kind: usize) -> TargetResult<bool, Self> {
		let hw_breakpoint = match registers::debug::HwBreakpoint::new_breakpoint(addr, kind) {
			Some(hw_breakpoint) => hw_breakpoint,
			None => return Ok(false),
		};

		let success = self.hw_breakpoints.try_insert(hw_breakpoint).is_ok();
		Ok(success)
	}

	fn remove_hw_breakpoint(&mut self, addr: u64, kind: usize) -> TargetResult<bool, Self> {
		let hw_breakpoint = match registers::debug::HwBreakpoint::new_breakpoint(addr, kind) {
			Some(hw_breakpoint) => hw_breakpoint,
			None => return Ok(false),
		};

		let success = self.hw_breakpoints.take(&hw_breakpoint).is_some();
		Ok(success)
	}
}

impl target::ext::breakpoints::HwWatchpoint for GdbUhyve {
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

		let success = self.hw_breakpoints.try_insert(hw_breakpoint).is_ok();
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

		let success = self.hw_breakpoints.take(&hw_breakpoint).is_some();
		Ok(success)
	}
}
