mod common;

use byte_unit::{Byte, Unit};
use common::{BuildMode, build_hermit_bin, check_result};
use regex::Regex;
#[cfg(target_os = "linux")]
use uhyvelib::params::FileSandboxMode;
use uhyvelib::{
	params::{Output, Params},
	vm::UhyveVm,
};

#[test]
fn multicore_test() {
	env_logger::try_init().ok();
	let bin_path = build_hermit_bin("multi-thread", BuildMode::Debug);

	let re = Regex::new(r"Speedup: [\d]+us / \d+us =\s*([\d.]+)").unwrap();

	// The expected speedup values are rather conservative, so that CI doesn't fail easily on
	// overloaded runners
	for (nr_cpus, expected_min_speedup) in [(2, 1.25), (3, 1.5), (4, 2.0)] {
		println!("Launching kernel {}", bin_path.display());
		let params = Params {
			cpu_count: nr_cpus.try_into().unwrap(),
			memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
				.unwrap()
				.try_into()
				.unwrap(),
			output: Output::Buffer,
			#[cfg(target_os = "linux")]
			// We are not testing for Landlock here, and running UhyveVm::new
			// repeatedly causes the creation of a new temporary directory,
			// which will fail on the second iteration.
			file_isolation: FileSandboxMode::None,
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
		assert!(
			speedup >= expected_min_speedup,
			"Speedup of {speedup} is not enough for a CPU count of {nr_cpus}"
		);
	}
}
