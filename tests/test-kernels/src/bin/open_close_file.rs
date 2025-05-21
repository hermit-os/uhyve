// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::{
	fs::{File, read_to_string},
	io::prelude::*,
};

#[cfg(target_os = "hermit")]
use hermit as _;

fn main() {
	println!("Hello from open_close_file!");

	{
		let mut file = File::create("/root/foo.txt").unwrap();
		file.write_all(b"Hello, world!").unwrap();
	}
	{
		let file_content = read_to_string("/root/foo.txt").unwrap();
		assert_eq!(file_content, "Hello, world!".to_string());
	}
}
