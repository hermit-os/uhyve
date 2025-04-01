use std::{
	env,
	fs::remove_file,
	path::{Path, PathBuf},
	process::Command,
};

use byte_unit::{Byte, Unit};
use log::info;
#[cfg(target_os = "linux")]
use uhyvelib::params::FileSandboxMode;
use uhyvelib::{
	params::{Output, Params},
	vm::{UhyveVm, VmResult},
};

/// Uses Cargo to build a kernel in the `tests/test-kernels` directory.
/// Returns a path to the build binary.
pub fn build_hermit_bin(kernel: impl AsRef<Path> + std::fmt::Display) -> PathBuf {
	info!("Building kernel {kernel}");
	let kernel = kernel.as_ref();
	let kernel_src_path = Path::new("tests/test-kernels");
	println!("Building test kernel: {}", kernel.display());

	let cmd = cargo()
		.arg("build")
		.arg("-Zbuild-std=std,panic_abort")
		.arg("--target=x86_64-unknown-hermit")
		.arg("--bin")
		.arg(kernel)
		.env("HERMIT_LOG_LEVEL_FILTER", "Debug")
		.current_dir(kernel_src_path)
		.status()
		.expect("failed to execute `cargo build`");

	assert!(cmd.success(), "Test binaries could not be built.");
	[
		kernel_src_path,
		Path::new("target/x86_64-unknown-hermit/debug"),
		Path::new(kernel),
	]
	.iter()
	.collect()
}

/// Small wrapper around [`Uhyve::run`] with default parameters for a small and
/// simple Uhyve vm
#[allow(dead_code)]
pub fn run_simple_vm(kernel_path: PathBuf) -> VmResult {
	env_logger::try_init().ok();
	println!("Launching kernel {}", kernel_path.display());
	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(128, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		output: Output::Buffer,
		stats: true,
		#[cfg(target_os = "linux")]
		file_isolation: strict_sandbox(),
		..Default::default()
	};

	UhyveVm::new(kernel_path, params).unwrap().run(None)
}

#[allow(dead_code)]
pub fn remove_file_if_exists(path: &PathBuf) {
	if path.exists() {
		println!("Removing existing directory {}", path.display());
		remove_file(path).unwrap_or_else(|_| panic!("Can't remove {}", path.display()));
	}
}

/// Panics if the result's status code is not 0 and prints the serial output of the kernel
#[allow(dead_code)]
pub fn check_result(res: &VmResult) {
	if res.code != 0 {
		println!("Kernel Output:\n{}", res.output.as_ref().unwrap());
		panic!();
	}
}

#[allow(dead_code)]
pub fn get_fs_fixture_path() -> PathBuf {
	let mut fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	fixture_path.push("tests/data/fixtures/fs");
	assert!(fixture_path.is_dir());
	fixture_path
}

/// If UHYVE_TEST_STRICT_SANDBOX == 1, enable strict sandboxing mode (for the CI).
///
/// Currently unused for fs-test.rs because of mysterious cargo test shenanigans.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub fn strict_sandbox() -> FileSandboxMode {
	if env::var("UHYVE_TEST_STRICT_SANDBOX").is_ok() {
		FileSandboxMode::Strict
	} else {
		FileSandboxMode::Normal
	}
}

pub fn cargo() -> Command {
	sanitize("cargo")
}

#[allow(dead_code)] // This is only used by the gdb test.
pub fn rust_gdb() -> Command {
	sanitize("rust-gdb")
}

fn sanitize(cmd: &str) -> Command {
	let cmd = {
		let exe = format!("{cmd}{}", env::consts::EXE_SUFFIX);
		// On windows, the userspace toolchain ends up in front of the rustup proxy in $PATH.
		// To reach the rustup proxy nonetheless, we explicitly query $CARGO_HOME.
		let mut cargo_home = home::cargo_home().unwrap();
		cargo_home.push("bin");
		cargo_home.push(&exe);
		if cargo_home.exists() {
			cargo_home
		} else {
			// Custom `$CARGO_HOME` values do not necessarily reflect in the environment.
			// For these cases, our best bet is using `$PATH` for resolution.
			PathBuf::from(exe)
		}
	};

	let mut cmd = Command::new(cmd);

	// Remove rust-toolchain-specific environment variables from kernel cargo
	cmd.env_remove("LD_LIBRARY_PATH");
	env::vars()
		.filter(|(key, _value)| {
			key.starts_with("CARGO") && !key.starts_with("CARGO_HOME")
				|| key.starts_with("RUST") && !key.starts_with("RUSTUP_HOME")
		})
		.for_each(|(key, _value)| {
			cmd.env_remove(&key);
		});

	cmd
}
