#![allow(
	dead_code,
	reason = "Many helper functions are not used in every test."
)]

use std::{
	collections::HashMap,
	env,
	fs::remove_file,
	path::{Path, PathBuf},
	process::Command,
	sync::{Mutex, OnceLock},
	thread,
};

use byte_unit::{Byte, Unit};
#[cfg(target_os = "linux")]
use uhyvelib::params::FileSandboxMode;
use uhyvelib::{
	params::{Output, Params},
	vm::VmResult,
};

#[derive(PartialEq, Eq)]
pub enum BuildMode {
	Debug,
	Release,
}

pub const HERMIT_GATEWAY: &str = "10.0.5.2";
pub const HERMIT_IP: &str = "10.0.5.3";

/// Uses Cargo to build a kernel in the `tests/test-kernels` directory.
/// Returns a path to the build binary.
pub fn build_hermit_bin(kernel: impl AsRef<Path>, mode: BuildMode) -> PathBuf {
	// Build hermit binaries sequentially
	// and avoid invoking cargo twice for the same kernel
	// if we already know it is up-to-date.
	static BUILT_HERMIT_BINS: OnceLock<Mutex<HashMap<PathBuf, ()>>> = OnceLock::new();

	let kernel = kernel.as_ref();
	let kernel_src_path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests/test-kernels"]
		.iter()
		.collect();

	BUILT_HERMIT_BINS
		.get_or_init(|| Mutex::new(HashMap::new()))
		.lock()
		.unwrap()
		.entry(kernel.to_path_buf())
		.or_insert_with(|| {
			println!("Building kernel {kernel:?}");
			let mut cmd = cargo();
			let mut cmd = cmd
				.arg("build")
				.arg("-Zbuild-std=std,panic_abort")
				.arg("--target=x86_64-unknown-hermit")
				.arg("--bin")
				.arg(kernel)
				.env("HERMIT_IP", HERMIT_IP)
				.env("HERMIT_GATEWAY", HERMIT_GATEWAY)
				.current_dir(&kernel_src_path);

			cmd = if mode == BuildMode::Release {
				cmd.arg("--release").env("HERMIT_LOG_LEVEL_FILTER", "Error")
			} else {
				cmd.env("HERMIT_LOG_LEVEL_FILTER", "Debug")
			};

			let cmd = cmd.status().expect("failed to execute `cargo build`");

			assert!(cmd.success(), "Test binaries could not be built.");
		});

	let p = if mode == BuildMode::Release {
		Path::new("target/x86_64-unknown-hermit/release")
	} else {
		Path::new("target/x86_64-unknown-hermit/debug")
	};
	[&kernel_src_path, p, Path::new(kernel)].iter().collect()
}

/// Internal function for running VMs using a specific Params object.
/// Useful e.g. when we only need to modify one parameter but do not
/// want to avoid boilerplate in the actual integration test definitions.
///
/// This also checks whether a logger has been configured.
fn run_vm(kernel_path: PathBuf, params: Params) -> VmResult {
	use uhyvelib::vm::UhyveVm;
	// This helps us ensure consistency across integration tests.
	env_logger::try_init().expect_err("Caller has not initialized a logger yet.");
	println!("Launching kernel {}", kernel_path.display());
	UhyveVm::new(kernel_path, params).unwrap().run(None)
}

/// Small wrapper around [`Uhyve::run`] with default parameters for a small and
/// simple Uhyve vm
pub fn run_simple_vm(kernel_path: PathBuf) -> VmResult {
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

	run_vm(kernel_path, params)
}

/// Small wrapper around [`Uhyve::run`] with default parameters, but the
/// memory size used is modifiable.
///
/// Used in memory tests. Landlock is disabled because that is covered by tests
/// utilizing other functions.
pub fn run_vm_with_custom_memory(kernel_path: PathBuf, memory_size: u64) -> VmResult {
	let params = Params {
		cpu_count: 2.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(memory_size, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		output: Output::Buffer,
		stats: true,
		#[cfg(target_os = "linux")]
		file_isolation: FileSandboxMode::None,
		..Default::default()
	};

	run_vm(kernel_path, params)
}

pub fn remove_file_if_exists(path: &PathBuf) {
	if path.exists() {
		println!("Removing existing directory {}", path.display());
		remove_file(path).unwrap_or_else(|_| panic!("Can't remove {}", path.display()));
	}
}

/// Panics if the result's status code is not 0 and prints the serial output of
/// the kernel.
///
/// - `res`: VmResult returned by vm.run().
/// - `expected`: Expected return code of `res.code`.
pub fn check_result_and_print_output(res: &VmResult, expected: i32) {
	if let Some(output) = &res.output {
		println!("Kernel output:\n{}", output);
	}
	let actual = res.code;
	assert_eq!(
		actual, expected,
		"Kernel return code ({actual}) differs from expected ({expected})"
	);
}

pub fn get_fs_fixture_path() -> PathBuf {
	let mut fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	fixture_path.push("tests/data/fixtures/fs");
	assert!(fixture_path.is_dir());
	fixture_path
}

/// Wrapper that builds test kernels and runs the VM in a new thread.
/// Useful for testing Landlock.
///
/// * `bin_path` - Path of kernel to be run.
/// * `params` - Params to run the VM with.
pub fn run_vm_in_thread(bin_path: PathBuf, params: Params) -> VmResult {
	thread::spawn(move || run_vm(bin_path, params))
		.join()
		.expect("Uhyve thread panicked.")
}

/// If UHYVE_TEST_STRICT_SANDBOX == 1, enable strict sandboxing mode (for the CI).
///
/// Currently unused for fs-test.rs because of mysterious cargo test shenanigans.
#[cfg(target_os = "linux")]
pub fn strict_sandbox() -> FileSandboxMode {
	if env::var("UHYVE_TEST_STRICT_SANDBOX").is_ok() {
		FileSandboxMode::Strict
	} else {
		FileSandboxMode::Normal
	}
}

/// This constructs an env_logger that should be called at the beginning of
/// every integration test.
pub fn env_logger_build() {
	let _ = env_logger::builder().is_test(true).try_init();
}

pub fn cargo() -> Command {
	sanitize("cargo")
}

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
