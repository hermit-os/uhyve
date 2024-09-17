pub mod registers;

use core::arch::x86_64::_rdtsc as rdtsc;
use std::{
	convert::TryInto,
	time::{Duration, Instant},
};

use log::{debug, warn};
use raw_cpuid::{CpuId, CpuIdReaderNative};
use uhyve_interface::{GuestPhysAddr, GuestVirtAddr};
use x86_64::{
	structures::paging::{
		page_table::{FrameError, PageTableEntry},
		Page, PageTable, PageTableFlags, PageTableIndex, Size2MiB,
	},
	PhysAddr,
};

use crate::{consts::*, mem::MmapMemory, paging::PagetableError};

pub const RAM_START: GuestPhysAddr = GuestPhysAddr::new(0x00);
const MHZ_TO_HZ: u64 = 1000000;
const KHZ_TO_HZ: u64 = 1000;

use crate::arch::FrequencyDetectionFailed;

pub fn detect_freq_from_cpuid(
	cpuid: &CpuId<CpuIdReaderNative>,
) -> std::result::Result<u32, FrequencyDetectionFailed> {
	debug!("Trying to detect CPU frequency by tsc info");

	let has_invariant_tsc = cpuid
		.get_advanced_power_mgmt_info()
		.map_or(false, |apm_info| apm_info.has_invariant_tsc());
	if !has_invariant_tsc {
		warn!("TSC frequency varies with speed-stepping")
	}

	let tsc_frequency_hz = cpuid.get_tsc_info().map(|tinfo| {
		if tinfo.tsc_frequency().is_some() {
			tinfo.tsc_frequency()
		} else {
			// Skylake and Kabylake don't report the crystal clock, approximate with base frequency:
			cpuid
				.get_processor_frequency_info()
				.map(|pinfo| pinfo.processor_base_frequency() as u64 * MHZ_TO_HZ)
				.map(|cpu_base_freq_hz| {
					let crystal_hz =
						cpu_base_freq_hz * tinfo.denominator() as u64 / tinfo.numerator() as u64;
					crystal_hz * tinfo.numerator() as u64 / tinfo.denominator() as u64
				})
		}
	});

	let hz = match tsc_frequency_hz {
		Some(x) => x.unwrap_or(0),
		None => {
			return Err(FrequencyDetectionFailed);
		}
	};

	if hz > 0 {
		Ok((hz / MHZ_TO_HZ).try_into().unwrap())
	} else {
		Err(FrequencyDetectionFailed)
	}
}

pub fn detect_freq_from_cpuid_hypervisor_info(
	cpuid: &CpuId<CpuIdReaderNative>,
) -> std::result::Result<u32, FrequencyDetectionFailed> {
	debug!("Trying to detect CPU frequency by hypervisor info");
	let hypervisor_info = cpuid
		.get_hypervisor_info()
		.ok_or(FrequencyDetectionFailed)?;
	debug!(
		"cpuid detected hypervisor: {:?}",
		hypervisor_info.identify()
	);
	let hz = hypervisor_info
		.tsc_frequency()
		.ok_or(FrequencyDetectionFailed)? as u64
		* KHZ_TO_HZ;
	let mhz: u32 = (hz / MHZ_TO_HZ).try_into().unwrap();
	if mhz > 0 {
		Ok(mhz)
	} else {
		Err(FrequencyDetectionFailed)
	}
}

pub fn get_cpu_frequency_from_os() -> std::result::Result<u32, FrequencyDetectionFailed> {
	// Determine TSC frequency by measuring it (loop for a second, record ticks)
	let duration = Duration::from_millis(10);
	let now = Instant::now();
	let start = unsafe { crate::x86_64::rdtsc() };
	if start > 0 {
		loop {
			if now.elapsed() >= duration {
				break;
			}
		}
		let end = unsafe { rdtsc() };
		Ok((((end - start) * 100) / MHZ_TO_HZ).try_into().unwrap())
	} else {
		Err(FrequencyDetectionFailed)
	}
}

// Constructor for a conventional segment GDT (or LDT) entry
pub fn create_gdt_entry(flags: u64, base: u64, limit: u64) -> u64 {
	((base & 0xff000000u64) << (56 - 24))
		| ((flags & 0x0000f0ffu64) << 40)
		| ((limit & 0x000f0000u64) << (48 - 16))
		| ((base & 0x00ffffffu64) << 16)
		| (limit & 0x0000ffffu64)
}

pub const MIN_PHYSMEM_SIZE: usize = BOOT_PDE.as_u64() as usize + 0x1000;

/// Creates the pagetables and the GDT in the guest memory space.
///
/// The memory slice must be larger than [`MIN_PHYSMEM_SIZE`].
/// Also, the memory `mem` needs to be zeroed for [`PAGE_SIZE`] bytes at the
/// offsets [`BOOT_PML4`] and [`BOOT_PDPTE`], otherwise the integrity of the
/// pagetables and thus the integrity of the guest's memory is not ensured
pub fn initialize_pagetables(mem: &mut [u8]) {
	assert!(mem.len() >= MIN_PHYSMEM_SIZE);
	let mem_addr = std::ptr::addr_of_mut!(mem[0]);

	let (gdt_entry, pml4, pdpte, pde);
	// Safety:
	// We only operate in `mem`, which is plain bytes and we have ownership of
	// these and it is asserted to be large enough.
	unsafe {
		gdt_entry = mem_addr
			.add(BOOT_GDT.as_u64() as usize)
			.cast::<[u64; 3]>()
			.as_mut()
			.unwrap();

		pml4 = mem_addr
			.add(BOOT_PML4.as_u64() as usize)
			.cast::<PageTable>()
			.as_mut()
			.unwrap();
		pdpte = mem_addr
			.add(BOOT_PDPTE.as_u64() as usize)
			.cast::<PageTable>()
			.as_mut()
			.unwrap();
		pde = mem_addr
			.add(BOOT_PDE.as_u64() as usize)
			.cast::<PageTable>()
			.as_mut()
			.unwrap();

		/* For simplicity we currently use 2MB pages and only a single
		PML4/PDPTE/PDE. */

		// per default is the memory zeroed, which we allocate by the system
		// call mmap, so the following is not necessary:
		/*libc::memset(pml4 as *mut _ as *mut libc::c_void, 0x00, PAGE_SIZE);
		libc::memset(pdpte as *mut _ as *mut libc::c_void, 0x00, PAGE_SIZE);
		libc::memset(pde as *mut _ as *mut libc::c_void, 0x00, PAGE_SIZE);*/
	}
	// initialize GDT
	gdt_entry[BOOT_GDT_NULL] = 0;
	gdt_entry[BOOT_GDT_CODE] = create_gdt_entry(0xA09B, 0, 0xFFFFF);
	gdt_entry[BOOT_GDT_DATA] = create_gdt_entry(0xC093, 0, 0xFFFFF);

	pml4[0].set_addr(
		BOOT_PDPTE,
		PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
	);
	pml4[511].set_addr(
		BOOT_PML4,
		PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
	);
	pdpte[0].set_addr(BOOT_PDE, PageTableFlags::PRESENT | PageTableFlags::WRITABLE);

	for i in 0..512 {
		let addr = PhysAddr::new(i as u64 * Page::<Size2MiB>::SIZE);
		pde[i].set_addr(
			addr,
			PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::HUGE_PAGE,
		);
	}
}

/// Converts a virtual address in the guest to a physical address in the guest
pub fn virt_to_phys(
	addr: GuestVirtAddr,
	mem: &MmapMemory,
	pagetable_l0: GuestPhysAddr,
) -> Result<GuestPhysAddr, PagetableError> {
	/// Number of Offset bits of a virtual address for a 4 KiB page, which are shifted away to get its Page Frame Number (PFN).
	pub const PAGE_BITS: u64 = 12;

	/// Number of bits of the index in each table (PML4, PDPT, PDT, PGT).
	pub const PAGE_MAP_BITS: usize = 9;

	let mut page_table =
		unsafe { (mem.host_address(pagetable_l0).unwrap() as *mut PageTable).as_mut() }.unwrap();
	let mut page_bits = 39;
	let mut entry = PageTableEntry::new();

	for _i in 0..4 {
		let index =
			PageTableIndex::new(((addr.as_u64() >> page_bits) & ((1 << PAGE_MAP_BITS) - 1)) as u16);
		entry = page_table[index].clone();

		match entry.frame() {
			Ok(frame) => {
				page_table = unsafe {
					(mem.host_address(frame.start_address()).unwrap() as *mut PageTable).as_mut()
				}
				.unwrap();
				page_bits -= PAGE_MAP_BITS;
			}
			Err(FrameError::FrameNotPresent) => return Err(PagetableError::InvalidAddress),
			Err(FrameError::HugeFrame) => {
				return Ok(entry.addr() + (addr.as_u64() & !((!0_u64) << page_bits)));
			}
		}
	}

	Ok(entry.addr() + (addr.as_u64() & !((!0u64) << PAGE_BITS)))
}

pub fn init_guest_mem(mem: &mut [u8]) {
	// TODO: we should maybe return an error on failure (e.g., the memory is too small)
	initialize_pagetables(mem);
}

#[cfg(test)]
mod tests {
	use super::*;
	// test is derived from
	// https://github.com/gz/rust-cpuid/blob/master/examples/tsc_frequency.rs
	#[test]
	fn test_detect_freq_from_cpuid() {
		let cpuid = raw_cpuid::CpuId::new();
		let has_tsc = cpuid
			.get_feature_info()
			.map_or(false, |finfo| finfo.has_tsc());

		let has_invariant_tsc = cpuid
			.get_advanced_power_mgmt_info()
			.map_or(false, |apm_info| apm_info.has_invariant_tsc());

		let tsc_frequency_hz = cpuid.get_tsc_info().map(|tinfo| {
			if tinfo.tsc_frequency().is_some() {
				tinfo.tsc_frequency()
			} else {
				// Skylake and Kabylake don't report the crystal clock, approximate with base frequency:
				cpuid
					.get_processor_frequency_info()
					.map(|pinfo| pinfo.processor_base_frequency() as u64 * crate::x86_64::MHZ_TO_HZ)
					.map(|cpu_base_freq_hz| {
						let crystal_hz = cpu_base_freq_hz * tinfo.denominator() as u64
							/ tinfo.numerator() as u64;
						crystal_hz * tinfo.numerator() as u64 / tinfo.denominator() as u64
					})
			}
		});

		assert!(has_tsc, "System does not have a TSC.");

		// Try to figure out TSC frequency with CPUID
		println!(
			"TSC Frequency is: {} ({})",
			match tsc_frequency_hz {
				Some(x) => format!("{} Hz", x.unwrap_or(0)),
				None => String::from("unknown"),
			},
			if has_invariant_tsc {
				"invariant"
			} else {
				"TSC frequency varies with speed-stepping"
			}
		);

		// Check if we run in a VM and the hypervisor can give us the TSC frequency
		cpuid.get_hypervisor_info().map(|hv| {
			hv.tsc_frequency().map(|tsc_khz| {
				let virtual_tsc_frequency_hz = tsc_khz as u64 * crate::x86_64::KHZ_TO_HZ;
				println!("Hypervisor reports TSC Frequency at: {virtual_tsc_frequency_hz} Hz");
			})
		});

		// Determine TSC frequency by measuring it (loop for a second, record ticks)
		let one_second = crate::x86_64::Duration::from_secs(1);
		let now = crate::x86_64::Instant::now();
		let start = unsafe { crate::x86_64::rdtsc() };
		assert!(start > 0, "Don't have rdtsc on stable!");
		loop {
			if now.elapsed() >= one_second {
				break;
			}
		}
		let end = unsafe { crate::x86_64::rdtsc() };
		println!(
			"Empirical measurement of TSC frequency was: {} Hz",
			(end - start)
		);
	}

	#[test]
	fn test_get_cpu_frequency_from_os() {
		let freq_res = crate::x86_64::get_cpu_frequency_from_os();
		assert!(freq_res.is_ok());
		let freq = freq_res.unwrap();
		// The unit of the value for the first core must be in MHz.
		// We presume that more than 10 GHz is incorrect.
		assert!(freq > 0);
		assert!(freq < 10000);
	}

	#[test]
	fn test_pagetable_initialization() {
		let mut mem: Vec<u8> = vec![0; MIN_PHYSMEM_SIZE];
		initialize_pagetables((&mut mem[0..MIN_PHYSMEM_SIZE]).try_into().unwrap());

		// Test pagetable setup
		let addr_pdpte = u64::from_le_bytes(
			mem[(BOOT_PML4.as_u64() as usize)..(BOOT_PML4.as_u64() as usize + 8)]
				.try_into()
				.unwrap(),
		);
		assert_eq!(
			addr_pdpte,
			BOOT_PDPTE.as_u64() | (PageTableFlags::PRESENT | PageTableFlags::WRITABLE).bits()
		);
		let addr_pde = u64::from_le_bytes(
			mem[(BOOT_PDPTE.as_u64() as usize)..(BOOT_PDPTE.as_u64() as usize + 8)]
				.try_into()
				.unwrap(),
		);
		assert_eq!(
			addr_pde,
			BOOT_PDE.as_u64() | (PageTableFlags::PRESENT | PageTableFlags::WRITABLE).bits()
		);

		for i in (0..4096).step_by(8) {
			let addr = BOOT_PDE.as_u64() as usize + i;
			let entry = u64::from_le_bytes(mem[addr..(addr + 8)].try_into().unwrap());
			assert!(
				PageTableFlags::from_bits_truncate(entry)
					.difference(
						PageTableFlags::PRESENT
							| PageTableFlags::WRITABLE | PageTableFlags::HUGE_PAGE
					)
					.is_empty(),
				"Pagetable bits at {addr:#x} are incorrect"
			)
		}

		// Test GDT
		let gdt_results = [0x0, 0xAF9B000000FFFF, 0xCF93000000FFFF];
		for (i, res) in gdt_results.iter().enumerate() {
			let gdt_addr = BOOT_GDT.as_u64() as usize + i * 8;
			let gdt_entry = u64::from_le_bytes(mem[gdt_addr..gdt_addr + 8].try_into().unwrap());
			assert_eq!(*res, gdt_entry);
		}
	}

	#[test]
	fn test_virt_to_phys() {
		let mem = MmapMemory::new(0, MIN_PHYSMEM_SIZE * 2, GuestPhysAddr::new(0), true, true);
		initialize_pagetables(unsafe { mem.as_slice_mut() }.try_into().unwrap());

		// Get the address of the first entry in PML4 (the address of the PML4 itself)
		let virt_addr = GuestVirtAddr::new(0xFFFFFFFFFFFFF000);
		let p_addr = virt_to_phys(virt_addr, &mem, BOOT_PML4).unwrap();
		assert_eq!(p_addr, BOOT_PML4);

		// The last entry on the PML4 is the address of the PML4 with flags
		let virt_addr = GuestVirtAddr::new(0xFFFFFFFFFFFFF000 | (4096 - 8));
		let p_addr = virt_to_phys(virt_addr, &mem, BOOT_PML4).unwrap();
		assert_eq!(
			mem.read::<u64>(p_addr).unwrap(),
			BOOT_PML4.as_u64() | (PageTableFlags::PRESENT | PageTableFlags::WRITABLE).bits()
		);

		// the first entry on the 3rd level entry in the pagetables is the address of the boot pdpte
		let virt_addr = GuestVirtAddr::new(0xFFFFFFFFFFE00000);
		let p_addr = virt_to_phys(virt_addr, &mem, BOOT_PML4).unwrap();
		assert_eq!(p_addr, BOOT_PDPTE);

		// the first entry on the 2rd level entry in the pagetables is the address of the boot pde
		let virt_addr = GuestVirtAddr::new(0xFFFFFFFFC0000000);
		let p_addr = virt_to_phys(virt_addr, &mem, BOOT_PML4).unwrap();
		assert_eq!(p_addr, BOOT_PDE);
		// That address points to a huge page
		assert!(
			PageTableFlags::from_bits_truncate(mem.read::<u64>(p_addr).unwrap()).contains(
				PageTableFlags::HUGE_PAGE | PageTableFlags::PRESENT | PageTableFlags::WRITABLE
			)
		);
	}
}
