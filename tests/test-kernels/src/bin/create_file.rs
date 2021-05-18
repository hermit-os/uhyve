#![allow(dead_code)]
#![allow(unused_imports)]

use std::fs::File;
use std::io::prelude::*;

#[cfg(target_os = "hermit")]
extern crate hermit_sys;

fn main() {
	let mut file = File::create("foo.txt").unwrap();
	file.write_all(b"Hello, world!").unwrap();
}
