mod common;

use std::collections::HashMap;

use byte_unit::{Byte, Unit};
use common::{BuildMode, build_hermit_bin, check_result_and_print_output, env_logger_build};
use uhyvelib::{
	params::{EnvVars, Output, Params},
	vm::UhyveVm,
};

#[test]
fn selective_env_test() {
	env_logger_build();
	let bin_path = build_hermit_bin("env", BuildMode::Debug);

	let env_vars = [
		("ASDF".to_string(), "ASDF".to_string()),
		("a0978gbsdf".to_string(), ";3254jgnsadfg".to_string()),
		("EMOJI".to_string(), "🙂".to_string()),
	];

	println!("Launching kernel {}", bin_path.display());
	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		output: Output::Buffer,
		env: EnvVars::Set(HashMap::from(env_vars.clone())),
		..Default::default()
	};
	let vm = UhyveVm::new(bin_path, params).unwrap();
	let res = vm.run(None);
	check_result_and_print_output(&res, 0);
	for (key, value) in env_vars.iter() {
		assert!(
			res.output
				.as_ref()
				.unwrap()
				.contains(&format!("ENVIRONMENT: {key}: {value}"))
		);
	}
}

#[test]
fn host_env_test() {
	env_logger_build();
	let bin_path = build_hermit_bin("env", BuildMode::Debug);

	println!("Launching kernel {}", bin_path.display());
	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		output: Output::Buffer,
		env: EnvVars::Host,
		..Default::default()
	};
	let vm = UhyveVm::new(bin_path, params).unwrap();
	let res = vm.run(None);
	check_result_and_print_output(&res, 0);

	let common_env_vars = ["PWD", "CARGO_MANIFEST_DIR"];
	for env in common_env_vars.iter() {
		assert!(
			res.output
				.as_ref()
				.unwrap()
				.contains(&format!("ENVIRONMENT: {env}:"))
		);
	}
}
