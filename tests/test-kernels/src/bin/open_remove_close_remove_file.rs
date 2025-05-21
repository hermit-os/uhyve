// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::{
	fs::{File, remove_file},
	io::prelude::*,
};

#[cfg(target_os = "hermit")]
use hermit as _;

fn main() {
	println!("Hello from open_remove_close_remove_file!");

	{
		let mut file = File::create("/root/foo.txt").unwrap();
		file.write_all(b"Hello, world!").unwrap();
		remove_file("/root/foo.txt").unwrap();
	}

	// This is expected to panic.
	remove_file("/root/foo.txt").unwrap();
}
