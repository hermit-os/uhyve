extern crate criterion;

use std::{
	env, fs,
	path::{Path, PathBuf},
	process::{Command, Stdio},
	time::Duration,
};

use criterion::{criterion_group, Criterion};

// based on https://stackoverflow.com/questions/35045996/check-if-a-command-is-in-path-executable-as-process#35046243
fn is_program_in_path(program: &str) -> bool {
	if let Ok(path) = env::var("PATH") {
		for p in path.split(':') {
			let p_str = format!("{p}/{program}");
			if fs::metadata(p_str).is_ok() {
				return true;
			}
		}
	}
	false
}

pub fn run_hello_world(c: &mut Criterion) {
	let uhyve_path = [env!("CARGO_MANIFEST_DIR"), "target/release/uhyve"]
		.iter()
		.collect::<PathBuf>();
	assert!(
		uhyve_path.exists(),
		"uhyve release build is required to run this benchmark"
	);

	let hello_world_path = [env!("CARGO_MANIFEST_DIR"), "data/x86_64/hello_world"]
		.iter()
		.collect::<PathBuf>();
	assert!(
		hello_world_path.exists(),
		"hello_world executable missing from bench_data"
	);

	let mut group = c.benchmark_group("hello_world");
	group.sample_size(30);

	group.bench_function("uhyve data/x86_64/hello_world", |b| {
		b.iter(|| {
			let status = Command::new(&uhyve_path)
				.arg(&hello_world_path)
				.arg("-m")
				.arg("64MiB")
				.stdout(Stdio::null())
				.status()
				.expect("failed to execute process");
			assert!(status.success());
		})
	});

	let qemu_available = is_program_in_path("qemu-system-x86_64");

	if !qemu_available {
		println!("qemu-system-x86_64 not found in path, skipping QEMU benchmark");
		return;
	}

	let rusty_loader_path = [
		env!("CARGO_MANIFEST_DIR"),
		"data/x86_64/hermit-loader-x86_64",
	]
	.iter()
	.collect::<PathBuf>();
	assert!(
		rusty_loader_path.exists(),
		"rusty-loader is missing from bench_data"
	);

	group.bench_function("qemu data/x86_64/hello_world", |b| {
		b.iter(|| {
			let status = Command::new("qemu-system-x86_64")
				.arg("-smp")
				.arg("1")
				.arg("-m")
				.arg("64M")
				.arg("-kernel")
				.arg(&rusty_loader_path)
				.arg("-initrd")
				.arg(&hello_world_path)
				.arg("-display")
				.arg("none")
				.arg("-serial")
				.arg("stdio")
				.arg("-enable-kvm")
				.arg("-cpu")
				.arg("host")
				.stdout(Stdio::null())
				.status()
				.expect("failed to execute process");
			assert!(status.success());
		})
	});
}

pub fn run_rusty_demo(c: &mut Criterion) {
	let uhyve_path = [env!("CARGO_MANIFEST_DIR"), "target/release/uhyve"]
		.iter()
		.collect::<PathBuf>();
	assert!(
		uhyve_path.exists(),
		"uhyve release build is required to run this benchmark"
	);

	let rusty_demo_path = [env!("CARGO_MANIFEST_DIR"), "data/x86_64/rusty_demo"]
		.iter()
		.collect::<PathBuf>();
	assert!(
		Path::new(&rusty_demo_path).exists(),
		"rusty_demo executable missing from bench_data"
	);

	let mut group = c.benchmark_group("rusty_demo");
	group.measurement_time(Duration::from_secs(60));

	group.bench_function("uhyve data/x86_64/rusty_demo", |b| {
		b.iter(|| {
			let status = Command::new(&uhyve_path)
				.arg(&rusty_demo_path)
				.stdout(Stdio::null())
				.status()
				.expect("failed to execute process");
			assert!(status.success());
		})
	});

	let qemu_available = is_program_in_path("qemu-system-x86_64");

	if !qemu_available {
		println!("qemu-system-x86_64 not found in path, skipping QEMU benchmark");
		return;
	}

	let rusty_loader_path = [
		env!("CARGO_MANIFEST_DIR"),
		"data/x86_64/hermit-loader-x86_64",
	]
	.iter()
	.collect::<PathBuf>();
	assert!(
		rusty_loader_path.exists(),
		"rusty-loader is missing from bench_data"
	);

	group.bench_function("qemu data/x86_64/rusty_demo", |b| {
		b.iter(|| {
			let status = Command::new("qemu-system-x86_64")
				.arg("-smp")
				.arg("1")
				.arg("-m")
				.arg("64M")
				.arg("-kernel")
				.arg(&rusty_loader_path)
				.arg("-initrd")
				.arg(&rusty_demo_path)
				.arg("-display")
				.arg("none")
				.arg("-serial")
				.arg("stdio")
				.arg("-enable-kvm")
				.arg("-cpu")
				.arg("host")
				.stdout(Stdio::null())
				.status()
				.expect("failed to execute process");
			assert!(status.success());
		})
	});
}

criterion_group!(run_complete_binaries_group, run_hello_world, run_rusty_demo);
