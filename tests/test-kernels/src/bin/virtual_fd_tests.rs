use std::{env, fs::File, io::prelude::*, os::fd::FromRawFd};

#[cfg(target_os = "hermit")]
use hermit as _;

/// Read from a file descriptor and make sure the content matches
fn read_expect(fd: i32, data: &str) {
	let mut file = unsafe { File::from_raw_fd(fd) };
	let mut buf = Vec::with_capacity(data.len());
	match file.read_exact(&mut buf[..]) {
		Ok(_) => {
			assert_eq!(buf, data.as_bytes());
		}
		Err(e) => {
			eprintln!("Got Error: {:?}", e.raw_os_error());
			panic!("{:?}", e);
		}
	}
}

fn main() {
	let args: Vec<String> = env::args().collect();
	let testname = &args[1].split('=').collect::<Vec<_>>()[1];
	let fd = args[2].split('=').collect::<Vec<_>>()[1]
		.parse::<i32>()
		.expect("unable to parse fd");
	let data = &args[3];

	println!("Hello from fs_tests (test: {testname}, fd: {fd})!");

	match *testname {
		"read_expect" => read_expect(fd, data),
		_ => panic!("test not found"),
	}
}
