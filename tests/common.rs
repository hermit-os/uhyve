use std::{path::PathBuf, process::Command};
use uhyvelib::{uhyve_run, vm::Parameter};

/// Uses Cargo to build a kernel in the `tests/test-kernels/` directory.
/// Returns a path to the build binary.
pub fn build_hermit_bin(kernel: &str) -> PathBuf {
	println!("Building Kernel {}", kernel);
	let kernel_src_path = PathBuf::from("tests/test-kernels");
	let cmd = Command::new("cargo")
		.args(&["build"])
		.args(&["--bin", kernel])
		.env_remove("RUSTUP_TOOLCHAIN") // Otherwise uhyve's toolchain would be used instead of the one from the rust-toolchain.toml of the kernels
		.current_dir(&kernel_src_path)
		.status()
		.expect("failed to execute `cargo build`");
	assert!(cmd.success(), "Test binaries could not be build");
	let mut bin_path = kernel_src_path;
	bin_path.push("target/x86_64-unknown-hermit/debug/");
	bin_path.push(kernel);
	bin_path
}

/// Small wrapper around ['uhyve_run'] with default parameters for a small and
/// simple uhyve vm
pub fn run_simple_vm(kernel_path: PathBuf) {
	let params = Parameter {
		mem_size: 32 * 1024 * 1024,
		num_cpus: 2,
		verbose: false,
		hugepage: true,
		mergeable: false,
		ip: None,
		gateway: None,
		mask: None,
		nic: None,
		gdbport: None,
	};
	uhyve_run(kernel_path, &params, None);
}
