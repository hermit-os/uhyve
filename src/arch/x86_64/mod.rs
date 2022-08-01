pub mod registers;

use core::arch::x86_64::_rdtsc as rdtsc;
use log::{debug, warn};
use raw_cpuid::CpuId;
use std::convert::TryInto;
use std::time::{Duration, Instant};

pub const RAM_START: u64 = 0x00;
const MHZ_TO_HZ: u64 = 1000000;
const KHZ_TO_HZ: u64 = 1000;

#[derive(Debug)]
pub struct FrequencyDetectionFailed;

impl std::fmt::Display for FrequencyDetectionFailed {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "Frequency detection failed")
	}
}

impl std::error::Error for FrequencyDetectionFailed {}

pub fn detect_freq_from_cpuid(cpuid: &CpuId) -> std::result::Result<u32, FrequencyDetectionFailed> {
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
	cpuid: &CpuId,
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

mod tests {
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
				println!(
					"Hypervisor reports TSC Frequency at: {} Hz",
					virtual_tsc_frequency_hz
				);
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
}

// Constructor for a conventional segment GDT (or LDT) entry
pub fn create_gdt_entry(flags: u64, base: u64, limit: u64) -> u64 {
	((base & 0xff000000u64) << (56 - 24))
		| ((flags & 0x0000f0ffu64) << 40)
		| ((limit & 0x000f0000u64) << (48 - 16))
		| ((base & 0x00ffffffu64) << 16)
		| (limit & 0x0000ffffu64)
}
