extern crate criterion;

use criterion::{criterion_group, Criterion};

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

pub fn run_hello_world(c: &mut Criterion) {
	let uhyve_path = env!("CARGO_MANIFEST_DIR").to_string() + &"/target/release/uhyve".to_string();
	assert!(
		Path::new(&uhyve_path).exists(),
		"uhyve release build is required to run this benchmark"
	);

	let hello_world_path =
		env!("CARGO_MANIFEST_DIR").to_string() + &"/benches_data/hello_world".to_string();
	assert!(
		Path::new(&hello_world_path).exists(),
		"hello_world executable missing from bench_data"
	);

	let mut group = c.benchmark_group("uhyve complete run");
	group.sample_size(30);

	group.bench_function("uhyve benches_data/hello_world", |b| {
		b.iter(|| {
			let status = Command::new(&uhyve_path)
				.arg(&hello_world_path)
				.stdout(Stdio::null())
				.status()
				.expect("failed to execute process");
			assert!(status.success());
		})
	});
}

criterion_group!(run_hello_world_group, run_hello_world);
