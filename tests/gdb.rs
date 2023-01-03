#![cfg(target_os = "linux")]

#[allow(dead_code)]
mod common;

use std::{
	fs::File,
	io::{self, Write},
	process::Command,
	thread,
};

use assert_fs::{assert::PathAssert, fixture::PathChild, TempDir};
use common::build_hermit_bin;
use uhyvelib::{params::Params, Uhyve};

#[test]
fn gdb() -> io::Result<()> {
	let port = 1234;
	let bin_path = build_hermit_bin("gdb");

	let bin_path_clone = bin_path.clone();
	let vm = thread::spawn(move || {
		let bin_path = bin_path_clone;
		let vm = Uhyve::new(
			bin_path,
			Params {
				gdb_port: Some(port),
				..Default::default()
			},
		)
		.unwrap();
		let code = vm.run(None);
		assert_eq!(0, code);
	});

	let temp = TempDir::new().unwrap();
	let output_path = temp.child("output");
	let command_path = temp.child("commands");
	let mut command_file = File::create(&command_path)?;

	write!(
		&mut command_file,
		"target remote :{port}
symbol-file {bin_path} -o 0x400000
break gdb::main
continue

next
pipe print _x|cat >> {output_path}
set var _x=6
pipe print _x|cat >> {output_path}

next
pipe print _x|cat >> {output_path}
set var _x=4.5
pipe print _x|cat >> {output_path}

hbreak gdb::main::break1
continue

next
set $rcx = 5
next
pipe print $rax|cat >> {output_path}
pipe print _x|cat >> {output_path}

next
watch WATCH
pipe print WATCH|cat >> {output_path}
pipe print _x|cat >> {output_path}
continue
pipe print WATCH|cat >> {output_path}
pipe print _x|cat >> {output_path}

next
awatch WATCH
continue
next
pipe print _x|cat >> {output_path}

continue
",
		port = port,
		bin_path = bin_path.display(),
		output_path = output_path.display()
	)?;

	let status = Command::new("rust-gdb")
		.arg("-batch-silent")
		.arg(format!("-command={}", command_path.display()))
		.arg(&bin_path)
		.status()?;
	assert!(status.success());

	output_path.assert(
		"$1 = 5
$2 = 6
$3 = 3.5
$4 = 4.5
$5 = 5
$6 = 5
$7 = 2
$8 = 0
$9 = 3
$10 = 0
$11 = 3
",
	);

	temp.close().unwrap();
	vm.join().unwrap();
	Ok(())
}
