// Copyright (c) 2017 Colin Finck, RWTH Aachen University
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// This is a heavily stripped down and slightly modified version of the libhermit-rs x86-64 paging code written by Colin Finck

#![allow(dead_code)]

/// Number of Offset bits of a virtual address for a 4 KiB page, which are shifted away to get its Page Frame Number (PFN).
pub const PAGE_BITS: usize = 12;

/// Number of bits of the index in each table (PML4, PDPT, PDT, PGT).
pub const PAGE_MAP_BITS: usize = 9;

use bitflags::bitflags;

bitflags! {
	/// Possible flags for an entry in either table (PML4, PDPT, PDT, PGT)
	///
	/// See Intel Vol. 3A, Tables 4-14 through 4-19
	pub struct PageTableEntryFlags: usize {
		/// Set if this entry is valid and points to a page or table.
		const PRESENT = 1;

		/// Set if memory referenced by this entry shall be writable.
		const WRITABLE = 1 << 1;

		/// Set if memory referenced by this entry shall be accessible from user-mode (Ring 3).
		const USER_ACCESSIBLE = 1 << 2;

		/// Set if Write-Through caching shall be enabled for memory referenced by this entry.
		/// Otherwise, Write-Back caching is used.
		const WRITE_THROUGH = 1 << 3;

		/// Set if caching shall be disabled for memory referenced by this entry.
		const CACHE_DISABLE = 1 << 4;

		/// Set if software has accessed this entry (for memory access or address translation).
		const ACCESSED = 1 << 5;

		/// Only for page entries: Set if software has written to the memory referenced by this entry.
		const DIRTY = 1 << 6;

		/// Only for page entries in PDPT or PDT: Set if this entry references a 1 GiB (PDPT) or 2 MiB (PDT) page.
		const HUGE_PAGE = 1 << 7;

		/// Only for page entries: Set if this address translation is global for all tasks and does not need to
		/// be flushed from the TLB when CR3 is reset.
		const GLOBAL = 1 << 8;

		/// Set if code execution shall be disabled for memory referenced by this entry.
		const EXECUTE_DISABLE = 1 << 63;
	}
}

impl PageTableEntryFlags {
	/// An empty set of flags for unused/zeroed table entries.
	/// Needed as long as empty() is no const function.
	const BLANK: PageTableEntryFlags = PageTableEntryFlags { bits: 0 };
}

/// An entry in either table (PML4, PDPT, PDT, PGT)
#[derive(Clone)]
#[repr(C)]
pub struct PageTableEntry {
	/// Physical memory address this entry refers, combined with flags from PageTableEntryFlags.
	physical_address_and_flags: usize,
}

impl PageTableEntry {
	/// Return the stored physical address.
	pub fn address(&self) -> usize {
		let mask = if self.is_hugepage() {
			LargePageSize::SIZE - 1
		} else {
			BasePageSize::SIZE - 1
		};
		self.physical_address_and_flags & !mask & !(PageTableEntryFlags::EXECUTE_DISABLE).bits()
	}

	pub fn check_flags(&self, flags: PageTableEntryFlags) -> bool {
		(self.physical_address_and_flags & flags.bits()) == flags.bits()
	}

	/// Returns whether this entry is valid (present).
	pub fn is_present(&self) -> bool {
		self.check_flags(PageTableEntryFlags::PRESENT)
	}

	pub fn is_hugepage(&self) -> bool {
		self.check_flags(PageTableEntryFlags::HUGE_PAGE)
	}

	/// Mark this as a valid (present) entry and set address translation and flags.
	///
	/// # Arguments
	///
	/// * `physical_address` - The physical memory address this entry shall translate to
	/// * `flags` - Flags from PageTableEntryFlags (note that the PRESENT and ACCESSED flags are set automatically)
	pub fn set(&mut self, physical_address: usize, flags: PageTableEntryFlags) {
		if flags.contains(PageTableEntryFlags::HUGE_PAGE) {
			// HUGE_PAGE may indicate a 2 MiB or 1 GiB page.
			// We don't know this here, so we can only verify that at least the offset bits for a 2 MiB page are zero.
			assert!(
				physical_address % LargePageSize::SIZE == 0,
				"Physical address is not on a 2 MiB page boundary (physical_address = {:#X})",
				physical_address
			);
		} else {
			// Verify that the offset bits for a 4 KiB page are zero.
			assert!(
				physical_address % BasePageSize::SIZE == 0,
				"Physical address is not on a 4 KiB page boundary (physical_address = {:#X})",
				physical_address
			);
		}

		self.physical_address_and_flags =
			physical_address | (PageTableEntryFlags::PRESENT | flags).bits();
	}

	pub fn set_flags(&mut self, flags: usize) {
		let flags_mask = (BasePageSize::SIZE - 1) | (PageTableEntryFlags::EXECUTE_DISABLE).bits();
		self.physical_address_and_flags &= !flags_mask;
		self.physical_address_and_flags |= flags & flags_mask;
	}

	pub fn flags(&self) -> usize {
		let flags_mask = (BasePageSize::SIZE - 1) | (PageTableEntryFlags::EXECUTE_DISABLE).bits();
		self.physical_address_and_flags & flags_mask
	}
}

/// A generic interface to support all possible page sizes.
///
/// This is defined as a subtrait of Copy to enable #[derive(Clone, Copy)] for Page.
/// Currently, deriving implementations for these traits only works if all dependent types implement it as well.
pub trait PageSize {
	/// The page size in bytes.
	const SIZE: usize;

	/// The page table level at which a page of this size is mapped (from 0 for PGT through 3 for PML4).
	/// Implemented as a numeric value to enable numeric comparisons.
	const MAP_LEVEL: usize;

	/// Any extra flag that needs to be set to map a page of this size.
	/// For example: PageTableEntryFlags::HUGE_PAGE
	const MAP_EXTRA_FLAG: PageTableEntryFlags;
}

/// A 4 KiB page mapped in the PGT.
pub enum BasePageSize {}
impl PageSize for BasePageSize {
	const SIZE: usize = 4096;
	const MAP_LEVEL: usize = 0;
	const MAP_EXTRA_FLAG: PageTableEntryFlags = PageTableEntryFlags::BLANK;
}

/// A 2 MiB page mapped in the PDT.
pub enum LargePageSize {}
impl PageSize for LargePageSize {
	const SIZE: usize = 2 * 1024 * 1024;
	const MAP_LEVEL: usize = 1;
	const MAP_EXTRA_FLAG: PageTableEntryFlags = PageTableEntryFlags::HUGE_PAGE;
}

/// Representation of any page table (PML4, PDPT, PD, PT) in memory.
#[repr(C)]
pub struct PageTable {
	/// Each page table has 512 entries (can be calculated using PAGE_MAP_BITS).
	pub entries: [PageTableEntry; 1 << PAGE_MAP_BITS],
}
