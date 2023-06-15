pub mod registers;

use core::arch::x86_64::_rdtsc as rdtsc;
use std::{
	convert::TryInto,
	time::{Duration, Instant},
};

use log::{debug, warn};
use raw_cpuid::{CpuId, CpuIdReaderNative};
use thiserror::Error;
use x86_64::{
	structures::paging::{Page, PageTable, PageTableFlags, Size2MiB},
	PhysAddr,
};

use crate::consts::*;

pub const RAM_START: u64 = 0x00;
const MHZ_TO_HZ: u64 = 1000000;
const KHZ_TO_HZ: u64 = 1000;

#[derive(Error, Debug)]
#[error("Frequency detection failed")]
pub struct FrequencyDetectionFailed;

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

pub const MIN_PAGING_MEM_SIZE: usize = BOOT_PDE.as_u64() as usize + 0x1000;

/// Creates the pagetables and the GDT in the guest memory space.
///
/// The memory slice must be larger than [`MIN_PAGING_MEM_SIZE`].
/// Also, the memory `mem` needs to be zeroed for [`PAGE_SIZE`] bytes at the
/// offsets [`BOOT_PML4`] and [`BOOT_PDPTE`], otherwise the integrity of the
/// pagetables and thus the integrity of the guest's memory is not ensured
pub fn initialize_pagetables(mem: &mut [u8]) {
	assert!(mem.len() >= MIN_PAGING_MEM_SIZE);
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
		assert!(freq > 0);
		assert!(freq < 10000); //More than 10Ghz is probably wrong
	}

	#[test]
	fn test_pagetable_initialization() {
		let mut mem: Vec<u8> = vec![0; MIN_PAGING_MEM_SIZE];
		initialize_pagetables((&mut mem[0..MIN_PAGING_MEM_SIZE]).try_into().unwrap());

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
}
