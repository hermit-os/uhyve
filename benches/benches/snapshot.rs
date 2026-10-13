use std::{path::PathBuf, sync::Arc, thread};

use byte_unit::{Byte, Unit};
use criterion::Criterion;
use uhyvelib::{
	params::{FileSandboxMode, Output, Params},
	snapshot::{GuestSnapshotStore, RestoreOptions, Snapshot},
	vm::{DefaultBackend, UhyveVm},
};

use crate::common::{BuildMode, build_hermit_bin};

fn bench_params() -> Params {
	Params {
		cpu_count: 1.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		output: Output::Buffer,
		stats: false,
		aslr: false,
		file_isolation: FileSandboxMode::None,
		kernel_args: vec![],
		..Default::default()
	}
}

fn capture_shared_snapshot(kernel_path: PathBuf) -> Arc<Snapshot<DefaultBackend>> {
	let store = GuestSnapshotStore::default();
	let mut params = bench_params();
	params.snapshot_store = Some(store.clone());
	let res = UhyveVm::<DefaultBackend>::new(kernel_path, params)
		.expect("snapshot capture VM")
		.run();
	assert_eq!(res.code, 0, "{:?}", res.output);
	Arc::new(
		store
			.take_snapshot::<DefaultBackend>()
			.expect("guest should have produced a snapshot"),
	)
}

fn run_parallel_cold(n: usize, kernel_path: PathBuf) {
	let params = bench_params();
	let handles: Vec<_> = (0..n)
		.map(|_| {
			let kp = kernel_path.clone();
			let p = params.clone();
			thread::spawn(move || {
				let res = UhyveVm::<DefaultBackend>::new(kp, p)
					.expect("UhyveVm::new")
					.run();
				assert_eq!(res.code, 0, "{:?}", res.output);
			})
		})
		.collect();
	for h in handles {
		h.join().expect("cold-boot thread panicked");
	}
}

fn run_parallel_restore(n: usize, snap: &Arc<Snapshot<DefaultBackend>>) {
	let handles: Vec<_> = (0..n)
		.map(|_| {
			let s = Arc::clone(snap);
			thread::spawn(move || {
				let vm =
					UhyveVm::<DefaultBackend>::from_snapshot(s.as_ref(), RestoreOptions::default())
						.expect("from_snapshot");
				let res = vm.run();
				assert_eq!(res.code, 0, "{:?}", res.output);
			})
		})
		.collect();
	for h in handles {
		h.join().expect("restore thread panicked");
	}
}

fn run_parallel_restore_with_snapshot(n: usize, kernel_path: PathBuf) {
	let store = GuestSnapshotStore::default();

	let capture_store = store.clone();
	let capture = thread::spawn(move || {
		let mut params = bench_params();
		params.snapshot_store = Some(capture_store);
		let res = UhyveVm::<DefaultBackend>::new(kernel_path, params)
			.expect("snapshot capture VM")
			.run();
		assert_eq!(res.code, 0, "{:?}", res.output);
	});

	while !store.snapshot_ready() {
		thread::yield_now();
	}
	let snap = Arc::new(
		store
			.take_snapshot::<DefaultBackend>()
			.expect("guest should have produced a snapshot"),
	);

	let restore_handles: Vec<_> = (0..(n - 1))
		.map(|_| {
			let s = Arc::clone(&snap);
			thread::spawn(move || {
				let vm =
					UhyveVm::<DefaultBackend>::from_snapshot(s.as_ref(), RestoreOptions::default())
						.expect("from_snapshot");
				let res = vm.run();
				assert_eq!(res.code, 0, "{:?}", res.output);
			})
		})
		.collect();

	capture.join().expect("capture thread panicked");
	for h in restore_handles {
		h.join().expect("restore thread panicked");
	}
}

pub fn total_vm_runtime_excl_snapshot(c: &mut Criterion) {
	env_logger::try_init().ok();

	let kernel_cold = build_hermit_bin("hello_world", BuildMode::Release);
	let kernel_snap = build_hermit_bin("snapshot_hello", BuildMode::Release);

	let arc_snapshot = capture_shared_snapshot(kernel_snap.clone());

	// for n in [10, 100, 1000] {
	for n in [1, 10, 100, 1000] {
		c.bench_function(format!("vm_parallel_{n}_classic").as_str(), |b| {
			b.iter(|| {
				run_parallel_cold(n, kernel_cold.clone());
			});
		});

		c.bench_function(format!("vm_parallel_{n}_from_snapshot").as_str(), |b| {
			b.iter(|| {
				run_parallel_restore(n, &arc_snapshot);
			});
		});

		c.bench_function(
			format!("vm_parallel_{n}_from_snapshot_incl_snapshot").as_str(),
			|b| {
				b.iter(|| {
					run_parallel_restore_with_snapshot(n, kernel_snap.clone());
				});
			},
		);
	}
}

criterion::criterion_group!(
	name = snapshot_parallel_vm_group;
	config = criterion::Criterion::default();
		// .sample_size(10)
		// .measurement_time(std::time::Duration::from_secs(10));
	targets = total_vm_runtime_excl_snapshot
);
