use std::{
	fs::{self, File, read_to_string},
    os::fd::AsRawFd,
	io::Write,
};

#[cfg(target_os = "hermit")]
use hermit as _;

fn main() {
	println!("Hello from write_to_same_file!");

	{
		println!("Creating file in first block...");
		let mut created_file = File::create_new("/root/foo.txt").unwrap();
		created_file.write_all(b"Good morning!\n\n").unwrap();
		println!("Removing file in first block (fd: {})...", created_file.as_raw_fd());
		fs::remove_file("/root/foo.txt").unwrap();
	}

	{
		println!("Creating file in second block...");
		let mut created_file = File::create_new("/root/foo.txt").unwrap();
        println!("Writing to object in second block (fd: {})...", created_file.as_raw_fd());
		created_file.write_all(b"Good morning!\n\n").unwrap();
	}

	// For good measure: Testing whether the file definitely exists.
	File::create_new("/root/foo.txt").expect_err("File already exists.");

	let mut file1 = File::create("/root/foo.txt").unwrap();
	println!("Writing to first object (fd: {})...", file1.as_raw_fd());
	file1.write_all(b"Hello, ").unwrap();

	let mut file2 = File::create("/root/foo.txt").unwrap();
	println!("Writing to second object (fd: {})...", file2.as_raw_fd());
	file2.write_all(b"Hello, world!").unwrap();

	println!("Reading using read_to_string...");
    let file_content = read_to_string("/root/foo.txt").unwrap();
    assert_eq!(file_content, "Hello, world!".to_string());

	let mut file3 = File::create("/root/foo.txt").unwrap();

	println!("Removing /root/foo.txt...");
	// fs::remove_file("/root/foo.txt").unwrap();

	println!("Writing to third object (fd: {}))...", file3.as_raw_fd());
	file3.write_all(b"world!").unwrap();
}
