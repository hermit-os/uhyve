pub mod paging;
pub mod registers;

use core::arch::x86_64::_rdtsc as rdtsc;
use std::{
	convert::TryInto,
	time::{Duration, Instant},
};

use log::{debug, warn};
use raw_cpuid::{CpuId, CpuIdReaderNative};
use uhyve_interface::{GuestPhysAddr, GuestVirtAddr};
use x86_64::structures::paging::{
	page_table::{FrameError, PageTableEntry},
	PageTable, PageTableIndex,
};

use crate::{arch::paging::initialize_pagetables, mem::MmapMemory, paging::PagetableError};

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
		.is_some_and(|apm_info| apm_info.has_invariant_tsc());
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

pub fn init_guest_mem(mem: &mut [u8]) {
	// TODO: we should maybe return an error on failure (e.g., the memory is too small)
	initialize_pagetables(mem);
}

#[cfg(test)]
mod tests {
	use x86_64::structures::paging::PageTableFlags;

	use super::*;
	use crate::{
		arch::paging::MIN_PHYSMEM_SIZE,
		consts::{BOOT_PDE, BOOT_PDPTE, BOOT_PML4},
	};

	// test is derived from
	// https://github.com/gz/rust-cpuid/blob/master/examples/tsc_frequency.rs
	#[test]
	fn test_detect_freq_from_cpuid() {
		let cpuid = raw_cpuid::CpuId::new();
		let has_tsc = cpuid
			.get_feature_info()
			.is_some_and(|finfo| finfo.has_tsc());

		let has_invariant_tsc = cpuid
			.get_advanced_power_mgmt_info()
			.is_some_and(|apm_info| apm_info.has_invariant_tsc());

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
	fn test_virt_to_phys() {
		let _ = env_logger::builder()
			.filter(None, log::LevelFilter::Trace)
			.is_test(true)
			.try_init();

		let mem = MmapMemory::new(
			0,
			align_up!(MIN_PHYSMEM_SIZE * 2, 0x20_0000),
			GuestPhysAddr::zero(),
			true,
			true,
		);
		println!("mmap memory created {mem:?}");
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
