use std::fs;

#[cfg(target_os = "hermit")]
use hermit as _;

fn main() {
	println!("Hello from remove_file!");

	fs::remove_file("/root/file_to_remove.txt").unwrap();
}
