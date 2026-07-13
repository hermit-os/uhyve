pub(crate) mod breakpoints;
pub(crate) mod paging;

use std::fmt::Display;

use hermit_entry::{UhyveIfVersion, elf::KernelObject};
pub(crate) use paging::BOOT_GDT_MAX;
use uhyve_interface::{GuestPhysAddr, GuestVirtAddr};
use x86_64::structures::paging::{
	PageSize, PageTable, PageTableIndex, Size4KiB,
	page_table::{FrameError, PageTableEntry},
};

use crate::{
	mem::MmapMemory,
	mem_layout::{
		BootInfoSection, FdtSection, KernelSection, MemoryLayout, PagetableSection, Section,
		StackSection, generate_guest_start_address,
	},
	os::x86_64::kvm_cpu::KVM_32BIT_GAP_START,
	paging::PagetableError,
	params::Params,
};

pub const PAGE_SIZE: usize = Size4KiB::SIZE as usize;
pub const GUEST_PAGE_SIZE: u64 = 0x200000; /* 2 MB pages in guest */

pub(crate) const RAM_START: GuestPhysAddr = GuestPhysAddr::new(0x0);
// Right below 3 GiB, aka. 0xBFFF_FFFF
// Only relevant to x86_64 Linux for now, but that's our only x86_64 target.
pub(crate) const V1_MAX_ADDR: u64 = KVM_32BIT_GAP_START as u64 - 1;
pub(crate) const V1_ADDR_RANGE: (u64, u64) = (RAM_START.as_u64(), V1_MAX_ADDR);
// Upper value taken from previous V1_MAX_ADDR of macOS.
pub(crate) const V2_ADDR_RANGE: (u64, u64) = (0x0001_0000_0000u64, 0x0010_0000_0000u64);

/// Converts a virtual address in the guest to a physical address in the guest
pub(crate) fn virt_to_phys(
	addr: GuestVirtAddr,
	mem: &MmapMemory,
	pml4: GuestPhysAddr,
) -> Result<GuestPhysAddr, PagetableError> {
	/// Number of Offset bits of a virtual address for a 4 KiB page, which are shifted away to get its Page Frame Number (PFN).
	pub const PAGE_BITS: u64 = 12;

	/// Number of bits of the index in each table (PML4, PDPT, PDT, PGT).
	pub const PAGE_MAP_BITS: usize = 9;

	let mut page_table =
		unsafe { (mem.host_address(pml4).unwrap() as *mut PageTable).as_mut() }.unwrap();
	let mut page_bits = 39;
	let mut entry = PageTableEntry::new();

	for _i in 0..4 {
		let index =
			PageTableIndex::new(((addr.as_u64() >> page_bits) & ((1 << PAGE_MAP_BITS) - 1)) as u16);
		entry = page_table[index].clone();

		match entry.frame() {
			Ok(frame) => {
				page_table = unsafe {
					(mem.host_address(frame.start_address().into()).unwrap() as *mut PageTable)
						.as_mut()
				}
				.unwrap();
				page_bits -= PAGE_MAP_BITS;
			}
			Err(FrameError::FrameNotPresent) => return Err(PagetableError::InvalidAddress),
			Err(FrameError::HugeFrame) => {
				return Ok((entry.addr() + (addr.as_u64() & !((!0_u64) << page_bits))).into());
			}
		}
	}

	Ok((entry.addr() + (addr.as_u64() & !((!0u64) << PAGE_BITS))).into())
}

/// x86_64 Memory Layout.
///
/// It looks as follows:
///
/// ```txt
///     0x0000_0000 ┌──────────────────────────┐
///                 │ Hypercalls               │
///                 ├──────────────────────────┤
///                 │ not present              │
///                 │                          │
///    guest_address├──────────────────────────┤ ▲ ▲ ▲ ▲
///                 │ GDT                      │ │ │ │ │ FDT_OFFSET
///                 ├──────────────────────────┤ │ │ │ ▼
///                 │ Device Tree (FDT) (4KiB) │ │ │ │ BOOT_INFO_OFFSET
///                 ├──────────────────────────┤ │ │ ▼
///                 │ Boot Info         (1KiB) │ │ │
///                 ├──────────────────────────┤ │ │
///                 │                          │ │ │PAGETABLES_OFFSET
///                 ├──────────────────────────┤ │ ▼
///                 │                          │ │
///                 │ Pagetables               │ │
///                 │                          │ │
///    stack_address├──────────────────────────┤ │
///                 │ Stack                    │ │KERNEL_OFFSET
///   kernel_address├──────────────────────────┤ ▼
///                 │ Kernel                   │
///   entry_point──►│                          │
///                 │                          │
///                 ├──────────────────────────┤
///                 │ Kernel Memory            │
///                 │                          │
///                 └──────────────────────────┘
/// ```
#[derive(Debug, Copy, Clone)]
pub(crate) struct X86_64MemoryLayout {
	guest_address: GuestPhysAddr,
	kernel_address: GuestPhysAddr,
	kernel_len: usize,
}
impl X86_64MemoryLayout {
	const FDT_OFFSET: u64 = 0x1000;
	const FDT_SIZE: usize = 4 * PAGE_SIZE;
	const BOOT_INFO_OFFSET: u64 = Self::FDT_OFFSET + Self::FDT_SIZE as u64;

	const PAGETABLES_OFFSET: u64 = 0x11000;
	const PAGETABLES_END: u64 = Self::KERNEL_OFFSET - Self::KERNEL_STACK_SIZE;
	const KERNEL_STACK_SIZE: u64 = 0x8000;
	pub(crate) const KERNEL_OFFSET: u64 = 0x40000;

	const GDT_OFFSET: u64 = 0x0;
	const PML4_OFFSET: u64 = 0x10000;
	#[cfg(test)]
	const MIN_PHYSMEM_SIZE: usize = 0x43000;

	#[cfg(test)]
	fn simple_layout(guest_addr: GuestPhysAddr) -> Self {
		Self {
			guest_address: guest_addr,
			kernel_address: guest_addr + Self::KERNEL_OFFSET,
			kernel_len: 0x1000,
		}
	}

	pub fn pml4_address(&self) -> GuestPhysAddr {
		self.guest_address() + Self::PML4_OFFSET
	}

	pub fn gdt_address(&self) -> GuestPhysAddr {
		self.guest_address() + Self::GDT_OFFSET
	}
}
impl MemoryLayout for X86_64MemoryLayout {
	fn new(params: &Params, object: &KernelObject<'_>) -> Self {
		let uhyve_interface_version = object
			.uhyve_interface_version()
			.unwrap_or(UhyveIfVersion(1));

		let memory_size = params.memory_size.get();

		let (guest_address, kernel_address) = generate_guest_start_address(
			uhyve_interface_version,
			params.aslr,
			object.mem_size(),
			object.start_addr(),
			memory_size,
			Self::KERNEL_OFFSET,
		);

		assert!(
			kernel_address.as_u64() > Self::KERNEL_STACK_SIZE,
			"there should be enough space for the boot stack before the kernel start address",
		);

		Self {
			guest_address,
			kernel_address,
			kernel_len: object.mem_size(),
		}
	}

	fn guest_address(&self) -> GuestPhysAddr {
		self.guest_address
	}

	fn stack(&self) -> StackSection {
		StackSection(Section {
			addr: self.kernel_address - Self::KERNEL_STACK_SIZE,
			length: Self::KERNEL_STACK_SIZE as usize,
		})
	}

	fn fdt(&self) -> FdtSection {
		FdtSection(Section {
			addr: self.guest_address + Self::FDT_OFFSET,
			length: Self::FDT_SIZE,
		})
	}

	fn boot_info(&self) -> BootInfoSection {
		BootInfoSection(Section {
			addr: self.guest_address + Self::BOOT_INFO_OFFSET,
			length: PAGE_SIZE,
		})
	}

	fn kernel(&self) -> KernelSection {
		KernelSection(Section {
			addr: self.kernel_address,
			length: self.kernel_len,
		})
	}

	fn pagetables(&self) -> crate::mem_layout::PagetableSection {
		PagetableSection(Section {
			addr: self.guest_address + Self::PAGETABLES_OFFSET,
			length: (Self::PAGETABLES_END - Self::PAGETABLES_OFFSET) as usize,
		})
	}
}
impl Display for X86_64MemoryLayout {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		writeln!(f, "Memory Layout:")?;
		writeln!(f, "guest_address:     {:12x}", self.guest_address())?;
		writeln!(f, "boot_info_address: {:12x}", self.boot_info().0.addr)?;
		writeln!(f, "fdt_address:       {:12x}", self.fdt().0.addr)?;
		writeln!(f, "stack_address:     {:12x}", self.stack().0.addr)?;
		writeln!(f, "kernel_address:    {:12x}", self.kernel().0.addr)?;
		writeln!(
			f,
			"guest_heap:        {:12x}",
			self.kernel().0.addr + self.kernel_len
		)
	}
}

#[cfg(test)]
mod tests {
	use x86_64::structures::paging::PageTableFlags;

	use super::*;

	#[cfg(target_arch = "x86_64")]
	#[test]
	fn test_virt_to_phys() {
		let _ = env_logger::builder()
			.filter(None, log::LevelFilter::Trace)
			.is_test(true)
			.try_init();

		let guest_address = GuestPhysAddr::new(0x11111000);

		let mut mem = MmapMemory::new(
			X86_64MemoryLayout::MIN_PHYSMEM_SIZE * 2,
			guest_address,
			true,
			true,
		);
		log::debug!("mmap memory created {mem:x?}");

		let layout = X86_64MemoryLayout::simple_layout(guest_address);
		crate::arch::x86_64::paging::initialize_pagetables(
			&mut mem,
			&layout,
			X86_64MemoryLayout::MIN_PHYSMEM_SIZE as u64 * 2,
			false,
		);

		// Get the address of the first entry in PML4 (the address of the PML4 itself)
		let virt_addr = GuestVirtAddr::new(0xFFFFFFFFFFFFF000);
		let p_addr = virt_to_phys(virt_addr, &mem, layout.pml4_address()).unwrap();
		assert_eq!(p_addr, layout.pml4_address());

		// The last entry on the PML4 is the address of the PML4 with flags
		let virt_addr = GuestVirtAddr::new(0xFFFFFFFFFFFFF000 | (4096 - 8));
		let p_addr = virt_to_phys(virt_addr, &mem, layout.pml4_address()).unwrap();
		assert_eq!(
			mem.read::<u64>(p_addr).unwrap(),
			layout.pml4_address().as_u64()
				| (PageTableFlags::PRESENT | PageTableFlags::WRITABLE).bits()
		);

		// the first entry on the 3rd level entry in the pagetables is the address of the boot pdpte
		let virt_addr = GuestVirtAddr::new(0xFFFFFFFFFFE00000);
		let p_addr = virt_to_phys(virt_addr, &mem, layout.pml4_address()).unwrap();
		assert!(p_addr >= layout.pagetables().0.start());
		assert!(p_addr <= layout.pagetables().0.end());

		// the idx2 entry on the 2rd level entry in the pagetables is the address of the boot pde
		let idx2 = GuestVirtAddr::new(guest_address.as_u64()).p2_index();
		let virt_addr = GuestVirtAddr::new(0xFFFFFFFFC0000000)
			+ u64::from(idx2) * size_of::<PageTableEntry>() as u64;
		let p_addr = virt_to_phys(virt_addr, &mem, layout.pml4_address()).unwrap();
		assert!(p_addr >= layout.pagetables().0.start());
		assert!(p_addr <= layout.pagetables().0.end());
		// That address points to a huge page
		assert!(
			PageTableFlags::from_bits_truncate(mem.read::<u64>(p_addr).unwrap()).contains(
				PageTableFlags::HUGE_PAGE | PageTableFlags::PRESENT | PageTableFlags::WRITABLE
			)
		);
	}
}
