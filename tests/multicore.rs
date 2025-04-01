mod common;

use byte_unit::{Byte, Unit};
use common::{build_hermit_bin, check_result, get_fs_fixture_path};
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

	/*
	 * Workaround so as to avoid the multicore test from freaking out
	 * because of Landlock on Linux platforms. Given that UhyveVm::new creates
	 * new temporary files and enforces a process-wide Landlock restriction,
	 * we avoid an error from being raised by adding the directory in which
	 * the temporary directories are generated as a "mapping", from which a R/W
	 * ruleset is generated.
	 */

	let fixture_path = get_fs_fixture_path();
	let uhyvefilemap_params = [format!("{}:{}", fixture_path.to_str().unwrap(), "/root/")];

	for nr_cpus in [2, 4] {
		println!("Launching kernel {}", bin_path.display());
		let params = Params {
			cpu_count: nr_cpus.try_into().unwrap(),
			memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
				.unwrap()
				.try_into()
				.unwrap(),
			output: Output::Buffer,
			file_mapping: uhyvefilemap_params.to_vec(),
			tempdir: get_fs_fixture_path().to_str().map(String::from),
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
