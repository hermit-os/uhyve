use std::{
	collections::HashMap,
	fmt::Display,
	time::{Duration, Instant},
};

use uhyve_interface::{
	v1::{self, HypercallAddress as AddressV1},
	v2::{self, HypercallAddress as AddressV2},
};

/// Possible hypercalls that can cause an exit.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[repr(u64)]
pub enum HypercallAddresses {
	V1(AddressV1),
	V2(AddressV2),
}

/// Possible causes a VM exit (guest -> host transition)
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum VmExit {
	MMIORead,
	MMIOWrite,
	PCIRead,
	PCIWrite,
	Debug,
	Hypercall(HypercallAddresses),
}

impl From<v1::HypercallAddress> for VmExit {
	fn from(item: v1::HypercallAddress) -> Self {
		VmExit::Hypercall(HypercallAddresses::V1(item))
	}
}

impl<'a> From<&v1::Hypercall<'a>> for VmExit {
	fn from(item: &v1::Hypercall<'a>) -> Self {
		v1::HypercallAddress::from(item).into()
	}
}

impl From<v2::HypercallAddress> for VmExit {
	fn from(item: v2::HypercallAddress) -> Self {
		VmExit::Hypercall(HypercallAddresses::V2(item))
	}
}

impl<'a> From<&v2::Hypercall<'a>> for VmExit {
	fn from(item: &v2::Hypercall<'a>) -> Self {
		v2::HypercallAddress::from(item).into()
	}
}

#[derive(Debug, Clone)]
pub(crate) struct CpuStats {
	id: usize,
	vm_exits: HashMap<VmExit, usize>,
	runtime: Option<Duration>,
	start_time: Option<Instant>,
}
impl CpuStats {
	pub(crate) fn new(id: usize) -> Self {
		Self {
			id,
			vm_exits: HashMap::new(),
			runtime: None,
			start_time: None,
		}
	}

	#[inline]
	pub(crate) fn increment_val(&mut self, val: VmExit) {
		*self.vm_exits.entry(val).or_insert(0) += 1;
	}

	pub(crate) fn start_time_measurement(&mut self) {
		let _ = self.start_time.insert(Instant::now());
	}

	pub(crate) fn stop_time_measurement(&mut self) {
		if let Some(start_time) = self.start_time {
			self.runtime = Some(start_time.elapsed());
		}
	}
}

#[derive(Debug, Clone)]
pub struct VmStats {
	/// Number of Vm exits per CPU
	pub vm_exits: HashMap<VmExit, HashMap<usize, usize>>,
	/// total runtime per cpu (`(cpu_id, runtime)`)
	pub cpu_runtimes: Vec<(usize, Duration)>,
}
impl VmStats {
	pub(crate) fn new(cpu_stats: &[CpuStats]) -> Self {
		let mut stats = Self {
			vm_exits: HashMap::new(),
			cpu_runtimes: Vec::new(),
		};
		for cpu in cpu_stats.iter() {
			for (exit, count) in cpu.vm_exits.iter() {
				stats
					.vm_exits
					.entry(*exit)
					.or_default()
					.insert(cpu.id, *count);
			}
			if let Some(runtime) = cpu.runtime {
				stats.cpu_runtimes.push((cpu.id, runtime));
			}
		}
		stats
			.cpu_runtimes
			.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

		stats
	}
}
impl Display for VmStats {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let cpu_id_start = self
			.vm_exits
			.values()
			.map(|counts| *counts.keys().min().unwrap())
			.min()
			.unwrap_or(0);

		let cpu_id_end = self
			.vm_exits
			.values()
			.map(|counts| *counts.keys().max().unwrap())
			.max()
			.unwrap_or(0);
		write!(f, "VM exits:                       total  ")?;
		for i in cpu_id_start..=cpu_id_end {
			write!(f, " {:>6.} ", format!("cpu{i}"))?;
		}
		writeln!(f)?;
		for (exit, counts) in self.vm_exits.iter() {
			let total: usize = counts.values().sum();
			write!(f, "  {:<28} {total:>6.}  ", format!("{exit:?}:"))?;
			for i in cpu_id_start..=cpu_id_end {
				if let Some(cnt) = counts.get(&i) {
					write!(f, " {cnt:>6.} ")?;
				} else {
					write!(f, "        ")?;
				}
			}
			writeln!(f)?;
		}
		writeln!(f, "CPU runtimes:")?;
		self.cpu_runtimes
			.iter()
			.for_each(|(id, rt)| writeln!(f, "  cpu {id}: {rt:?}").unwrap());
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_stats() {
		let mut s1 = CpuStats::new(1);
		s1.start_time_measurement();
		s1.increment_val(VmExit::PCIRead);
		s1.increment_val(VmExit::PCIRead);
		s1.increment_val(AddressV1::Uart.into());
		s1.increment_val(AddressV1::Uart.into());
		s1.increment_val(AddressV1::FileOpen.into());
		s1.stop_time_measurement();
		println!("{s1:?}");

		let mut s2 = CpuStats::new(2);
		s2.start_time_measurement();
		s2.increment_val(VmExit::PCIRead);
		s2.increment_val(VmExit::MMIOWrite);
		s2.increment_val(AddressV1::Uart.into());
		s2.increment_val(AddressV1::FileWrite.into());
		// Technically, having a v2 FileClose is not necessarily possible in some real-world
		// scenarios (specifically when assuming Linux x86_64 here), but we are testing the
		// data structure here.
		s2.increment_val(AddressV2::FileClose.into());
		s2.increment_val(AddressV2::SerialWriteBuffer.into());
		s2.increment_val(AddressV2::SerialWriteBuffer.into());
		s2.stop_time_measurement();
		println!("{s2:?}");

		let vm_stats = VmStats::new(&[s1, s2]);
		println!("{vm_stats}");

		assert_eq!(vm_stats.vm_exits.get(&VmExit::PCIRead).unwrap().len(), 2);
		assert_eq!(
			vm_stats
				.vm_exits
				.get(&VmExit::PCIRead)
				.unwrap()
				.values()
				.sum::<usize>(),
			3
		);
		assert_eq!(
			vm_stats
				.vm_exits
				.get(&VmExit::MMIOWrite)
				.unwrap()
				.values()
				.sum::<usize>(),
			1
		);
		assert_eq!(
			vm_stats
				.vm_exits
				.get(&AddressV2::FileClose.into())
				.unwrap()
				.values()
				.sum::<usize>(),
			1
		);
		assert_eq!(
			vm_stats
				.vm_exits
				.get(&AddressV2::SerialWriteBuffer.into())
				.unwrap()
				.values()
				.sum::<usize>(),
			2
		);
		assert_eq!(vm_stats.cpu_runtimes.len(), 2);
	}
}
