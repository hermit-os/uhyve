mod common;

use byte_unit::{Byte, Unit};
use common::{build_hermit_bin, check_result};
use regex::Regex;
use uhyvelib::{
	params::{Output, Params},
	vm::UhyveVm,
};

#[test]
fn multicore_test() {
	env_logger::try_init().ok();
	let bin_path = build_hermit_bin("multi-thread");

	let re = Regex::new(r"Speedup: [\d]+us / \d+us =\s*([\d.]+)").unwrap();

	for nr_cpus in [2, 4] {
		println!("Launching kernel {}", bin_path.display());
		let params = Params {
			cpu_count: nr_cpus.try_into().unwrap(),
			memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
				.unwrap()
				.try_into()
				.unwrap(),
			output: Output::Buffer,
			..Default::default()
		};
		let vm = UhyveVm::new(bin_path.clone(), params).unwrap();
		let res = vm.run(None);
		check_result(&res);

		let outp = res.output.unwrap();
		let caps = re
			.captures(outp.as_str())
			.expect("Speedup not present in test output");
		dbg!(&caps);
		let speedup = caps.get(1).unwrap().as_str().parse::<f64>().unwrap();
		dbg!(&speedup);
		if speedup < nr_cpus as f64 * 0.66 {
			panic!("Speedup of {speedup} is not enough for a CPU count of {nr_cpus}");
		}
	}
}
