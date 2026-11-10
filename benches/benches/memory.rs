use std::{path::PathBuf, time::Duration};

use byte_unit::{Byte, Unit};
use criterion::{Criterion, criterion_group};
use regex::Regex;
#[cfg(target_os = "linux")]
use uhyvelib::params::FileSandboxMode;
use uhyvelib::{
	UhyveVm,
	params::{Output, Params},
};

use crate::common::{BuildMode, build_hermit_bin};

const MEMORY_MIB: u64 = 768;

/// Runs `scenario` of the `memory` kernel and returns the time measured by the guest.
fn memory_bench(kernel_path: PathBuf, scenario: &str, cpus: u32, threads: u32) -> Duration {
	let params = Params {
		cpu_count: cpus.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(MEMORY_MIB, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		output: Output::Buffer,
		aslr: false,
		#[cfg(target_os = "linux")]
		file_isolation: FileSandboxMode::None,
		kernel_args: vec![
			"--".to_owned(),
			format!("testname={scenario}"),
			format!("ram_mib={MEMORY_MIB}"),
			format!("threads={threads}"),
		],
		..Default::default()
	};

	let res = UhyveVm::new(kernel_path, params).unwrap().run();
	let output = res.output.unwrap();
	assert_eq!(res.code, 0, "Kernel failed. Output:\n{output}");

	let re = Regex::new(r"(?m)^Elapsed: ([0-9]+) ns").unwrap();
	let caps = re.captures(&output).unwrap();
	Duration::from_nanos(caps[1].parse().expect("invalid number"))
}

pub fn memory_allocation(c: &mut Criterion) {
	env_logger::try_init().ok();
	let kernel_path = build_hermit_bin("memory", BuildMode::Release);

	let mut group = c.benchmark_group("memory");
	for (scenario, cpus, threads) in [
		("random_alloc_bench", 1, 1),
		("random_alloc_bench", 2, 2),
		("random_alloc_bench", 4, 4),
		("random_alloc_bench", 1, 4),
		("random_walk_bench", 1, 1),
		("random_walk_bench", 2, 2),
		("random_walk_bench", 4, 4),
		("random_walk_bench", 1, 4),
		("page_alloc_bench", 1, 1),
	] {
		let name = if cpus == threads {
			format!("{scenario} {cpus} cpus")
		} else {
			format!("{scenario} {cpus} cpus {threads} threads")
		};
		group.bench_function(name, |b| {
			b.iter_custom(|iters| {
				(0..iters)
					.map(|_| memory_bench(kernel_path.clone(), scenario, cpus, threads))
					.sum()
			});
		});
	}
}

criterion_group!(
	name = memory_benchmark_group;
	config = Criterion::default().sample_size(10);
	targets = memory_allocation
);
