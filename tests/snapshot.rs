#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

mod common;

use std::{ffi::CString, hint::black_box};

use byte_unit::{Byte, Unit};
use common::{BuildMode, build_hermit_bin, check_result_and_print_output, env_logger_build};
use uhyvelib::{
	params::{FileSandboxMode, Output, Params},
	snapshot::{GuestSnapshotStore, RestoreOptions, SnapshotOptions},
	vm::{DefaultBackend, UhyveVm},
};

#[test]
fn snapshot_serialize_deserialize_restore() {
	env_logger_build();

	let kernel_path = build_hermit_bin("snapshot_restore", BuildMode::Debug);
	let store = GuestSnapshotStore::default();

	let params = Params {
		cpu_count: 1.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		output: Output::Buffer,
		stats: true,
		aslr: false,
		file_isolation: FileSandboxMode::None,
		snapshot: Some(SnapshotOptions {
			store: store.clone(),
			resume_after_snapshot: false,
		}),
		..Default::default()
	};

	let res_capture = UhyveVm::<DefaultBackend>::new(kernel_path, params)
		.unwrap()
		.run();
	check_result_and_print_output(&res_capture, 0);

	println!(">> Snapshot captured <<");

	let snapshot = store
		.take_snapshot::<DefaultBackend>()
		.expect("guest should have produced a snapshot");

	let bytes = black_box(bitcode::serialize(&snapshot).expect("snapshot serialize"));
	let snapshot_deser =
		black_box(UhyveVm::<DefaultBackend>::deserialize_snapshot(&bytes).unwrap());

	let restore_string = "-- restored_args_from_test";

	let restore_options = RestoreOptions {
		new_args: Some(CString::new(restore_string).unwrap()),
		..Default::default()
	};
	println!(">> Restoring snapshot <<");
	let vm = UhyveVm::<DefaultBackend>::from_snapshot(&snapshot_deser, restore_options).unwrap();
	let res_restore = vm.run();
	check_result_and_print_output(&res_restore, 0);

	assert!(
		res_restore
			.output
			.as_ref()
			.unwrap()
			.contains("hello-snapshot: restored execution continued")
	);
	assert!(
		res_restore
			.output
			.as_ref()
			.unwrap()
			.contains(restore_string)
	);
}
