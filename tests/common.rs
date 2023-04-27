use std::{
	env,
	path::{Path, PathBuf},
	process::Command,
};

use byte_unit::Byte;
use uhyvelib::{params::Params, Uhyve};

/// Uses Cargo to build a kernel in the `tests/test-kernels` directory.
/// Returns a path to the build binary.
pub fn build_hermit_bin(kernel: impl AsRef<Path>) -> PathBuf {
	let kernel = kernel.as_ref();
	println!("Building Kernel {}", kernel.display());
	let kernel_src_path = Path::new("tests/test-kernels");
	let cmd = Command::new("cargo")
		.arg("build")
		.arg("-Zbuild-std=std,panic_abort")
		.arg("--target=x86_64-unknown-hermit")
		.arg("--bin")
		.arg(kernel)
		// Remove environment variables related to the current cargo instance (toolchain version, coverage flags)
		.env_clear()
		// Retain PATH since it is used to find cargo and cc
		.env("PATH", env::var_os("PATH").unwrap())
		.current_dir(kernel_src_path)
		.status()
		.expect("failed to execute `cargo build`");
	assert!(cmd.success(), "Test binaries could not be build");
	[
		kernel_src_path,
		Path::new("target/x86_64-unknown-hermit/debug"),
		Path::new(kernel),
	]
	.iter()
	.collect()
}

/// Small wrapper around [`Uhyve::run`] with default parameters for a small and
/// simple uhyve vm
pub fn run_simple_vm(kernel_path: PathBuf) {
	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_bytes(32 * 1024 * 1024).try_into().unwrap(),
		..Default::default()
	};
	let code = Uhyve::new(kernel_path, params).unwrap().run(None);
	assert_eq!(0, code);
}
