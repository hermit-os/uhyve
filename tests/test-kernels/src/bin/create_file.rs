use std::{fs::File, io::prelude::*};

#[cfg(target_os = "hermit")]
use hermit as _;

fn main() {
	let mut file = File::create("/root/foo.txt").unwrap();
	file.write_all(b"Hello, world!").unwrap();
}
