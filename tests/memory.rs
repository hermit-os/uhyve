mod common;

use std::{sync::mpsc, thread, time::Duration};

use byte_unit::{Byte, Unit};
use common::{
	BuildMode, build_hermit_bin, check_result_and_print_output, env_logger_build,
	run_vm_with_custom_memory,
};
#[cfg(target_os = "linux")]
use uhyvelib::params::FileSandboxMode;
use uhyvelib::{
	UhyveVm,
	params::{Output, Params},
};

const TIMEOUT: Duration = Duration::from_secs(60);

/// Tries to start Uhyve VMs with different memory sizes.
#[test]
fn vm_physmem_size() {
	env_logger_build();
	let bin_path = build_hermit_bin("hello_world", BuildMode::Debug);
	for mem_size in [
		128,
		256,
		512,
		1024,
		1 * 1024,
		2 * 1024,
		3 * 1024,
		4 * 1024,
		5 * 1024,
		6 * 1024,
	] {
		println!("Starting VM with {mem_size} MiB physmem");
		let res = run_vm_with_custom_memory(bin_path.clone(), mem_size);
		check_result_and_print_output(&res, 0);
	}
}

/// Runs `scenario` of the `memory` kernel and returns the kernel output.
/// Panics on timeout, non-zero exit code, kernel panic or a missing completion marker.
fn run_memory_kernel(
	scenario: &str,
	memory_mib: u64,
	cpu_count: u32,
	threads: u32,
	log_level: Option<&str>,
) -> String {
	env_logger_build();
	let bin_path = build_hermit_bin("memory", BuildMode::Debug);

	let mut kernel_args: Vec<String> = log_level
		.map(|level| vec![format!("env=HERMIT_LOG_LEVEL_FILTER={level}")])
		.unwrap_or_default();
	kernel_args.extend([
		"--".to_owned(),
		format!("testname={scenario}"),
		format!("ram_mib={memory_mib}"),
		format!("threads={threads}"),
	]);
	let params = Params {
		kernel_args,
		cpu_count: cpu_count.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(memory_mib, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		output: Output::Buffer,
		#[cfg(target_os = "linux")]
		file_isolation: FileSandboxMode::None,
		..Default::default()
	};

	println!("Launching kernel {} ({scenario})", bin_path.display());
	let (tx, rx) = mpsc::channel();
	thread::spawn(move || {
		let res = UhyveVm::new(bin_path, params).unwrap().run();
		let _ = tx.send(res);
	});
	let res = rx
		.recv_timeout(TIMEOUT)
		.expect("VM did not finish in time (deadlock?)");
	check_result_and_print_output(&res, 0);

	let output = res.output.unwrap();
	assert!(
		output.contains(&format!("memory: {scenario} done")),
		"Scenario '{scenario}' did not complete"
	);
	assert!(!output.contains("panic"), "Kernel panicked");
	assert!(!output.contains("Unable to map the initial heap"));
	output
}

#[test]
fn memory_heap_then_stacks() {
	run_memory_kernel("heap_then_stacks", 64, 1, 32, None);
}

#[test]
fn memory_stacks_then_heap() {
	run_memory_kernel("stacks_then_heap", 64, 1, 32, None);
}

#[test]
fn memory_realloc_growth() {
	run_memory_kernel("realloc_growth", 128, 1, 1, None);
}

#[test]
fn memory_concurrent_growth() {
	let output = run_memory_kernel("concurrent_growth", 128, 4, 4, Some("trace"));
	assert!(
		output.contains("Mapping"),
		"No trace output from paging::map"
	);
}

#[test]
fn memory_fill_verify() {
	run_memory_kernel("fill_verify", 512, 2, 1, None);
}

#[test]
fn memory_mixed_sizes() {
	run_memory_kernel("mixed_sizes", 128, 1, 1, None);
}

#[test]
fn memory_random_free() {
	run_memory_kernel("random_free", 128, 1, 1, None);
}

#[test]
fn memory_oom() {
	run_memory_kernel("oom", 64, 1, 1, None);
}
