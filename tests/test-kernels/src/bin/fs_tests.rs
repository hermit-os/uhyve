use std::{
	env,
	fs::{File, OpenOptions, read_to_string, remove_file},
	io::{SeekFrom, prelude::*},
};

#[cfg(target_os = "hermit")]
use hermit as _;

/// Create (+ open), write, close, read, close, remove.
fn create_rw_remove_file(filename: &str) {
	println!("Running create_rw_remove_file with filename {filename}.");

	{
		let mut file = File::create(filename).unwrap();
		file.write_all(b"Hello, world!").unwrap();
	}
	{
		let file_content = read_to_string(filename).unwrap();
		assert_eq!(file_content, "Hello, world!".to_string());
	}

	remove_file(filename).unwrap();
}

/// Create (+ open), write, close, read, close.
///
/// The file is not deleted, so that its contents can be analyzed by the host.
fn create_rw_file(filename: &str) {
	println!("Running create_rw_file with filename {filename}.");

	{
		let mut file = File::create(filename).unwrap();
		file.write_all(b"Hello, world!").unwrap();
	}
	{
		let file_content = read_to_string(filename).unwrap();
		assert_eq!(file_content, "Hello, world!".to_string());
	}
}

/// Simply removes a file presumed to have been created by the host.
fn simple_remove_file(filename: &str) {
	println!("Running simple_remove_file with filename {filename}.");

	remove_file(filename).unwrap();
}

/// Opens a file and unlinks it before the file is closed.
fn open_remove_before_closing(filename: &str) {
	println!("Running open_remove_before_closing with filename {filename}.");

	{
		let mut file = File::create(filename).unwrap();
		file.write_all(b"Hello, world!").unwrap();
		remove_file(filename).unwrap();
	}
}

/// Opens a file and unlinks it before and after the file is closed.
fn open_remove_before_and_after_closing(filename: &str) {
	println!("Running open_remove_before_closing with filename {filename}.");

	{
		let mut file = File::create(filename).unwrap();
		file.write_all(b"Hello, world!").unwrap();
		remove_file(filename).unwrap();
	}

	// This is expected to crash.
	remove_file(filename).unwrap();
}

/// Opens a file and unlinks it twice before closing it.
fn remove_twice_before_closing(filename: &str) {
	println!("Running remove_twice_before_closing with filename {filename}.",);

	{
		let mut file = File::create(filename).unwrap();
		file.write_all(b"Hello, world!").unwrap();
		remove_file(filename).unwrap();

		// This is expected to panic.
		remove_file(filename).unwrap();
	}
}

fn open_read_only_write(filename: &str) {
	{
		let mut file = File::create(filename).unwrap();
		file.write_all(b"Hello, world!").unwrap();
		file.flush().unwrap();
	}

	{
		let mut file = File::open(filename).unwrap();
		// This is expected to crash.
		let _ = file.write_all(b"No more.");
	}
}

fn lseek_file(filename: &str) {
	let mut buf: [u8; 10] = [0; 10];
	println!("Initial Buffer: {buf:?}");
	let mut f = OpenOptions::new()
		.read(true)
		.write(true)
		.create(true)
		.truncate(true)
		.open(filename)
		.unwrap();
	f.write_all(&[
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
	])
	.unwrap();

	// file position is at the end of the file after writing
	assert_eq!(f.read(&mut buf).unwrap(), 0);

	f.seek(SeekFrom::Start(0)).unwrap();
	f.read_exact(&mut buf).unwrap();
	assert_eq!(buf, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
	println!("file at pos 0: {buf:?}");

	f.seek(SeekFrom::Start(5)).unwrap();
	f.read_exact(&mut buf).unwrap();
	println!("file at pos 5: {buf:?}");
	assert_eq!(buf, [5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
}

fn mount_test() {
	println!("Mounts Test");
	let mut f = File::open("/testdir1/testfile_a.txt").unwrap();
	let mut contents = String::new();
	f.read_to_string(&mut contents).unwrap();
	assert_eq!(contents, "12345");

	let mut f = File::open("/testdir2/testfile_b.txt").unwrap();
	let mut contents = String::new();
	f.read_to_string(&mut contents).unwrap();
	assert_eq!(contents, "abcde");

	let mut f = File::open("/testdir3/subdir1/subdir2/subdir3/testfile_c.txt").unwrap();
	let mut contents = String::new();
	f.read_to_string(&mut contents).unwrap();
	assert_eq!(contents, "a1b2c3");

	let mut f = File::open("/testdir4/testfile_b.txt").unwrap();
	let mut contents = String::new();
	f.read_to_string(&mut contents).unwrap();
	assert_eq!(contents, "abcde");

	let mut f = File::open("/anothermountpoint/test_a.txt").unwrap();
	let mut contents = String::new();
	f.read_to_string(&mut contents).unwrap();
	assert_eq!(contents, "12345");
}

fn main() {
	let args: Vec<String> = env::args().collect();
	let testname = &args[1].split('=').collect::<Vec<_>>()[1];
	let filename = &args[2].split('=').collect::<Vec<_>>()[1];

	println!("Hello from fs_tests (test: {testname})!");

	match *testname {
		"create_mapped_parent_nonpresent_file" => create_rw_remove_file(filename),
		"create_write_unmapped_nonpresent_file" => create_rw_remove_file(filename),
		"create_write_mapped_nonpresent_file" => create_rw_file(filename),
		"remove_mapped_present_file" => simple_remove_file(filename),
		"remove_mapped_parent_present_file" => simple_remove_file(filename),
		"remove_nonpresent_file_test" => simple_remove_file(filename),
		"fd_open_remove_close" => open_remove_before_closing(filename),
		"fd_open_remove_before_and_after_closing" => open_remove_before_and_after_closing(filename),
		"fd_remove_twice_before_closing" => remove_twice_before_closing(filename),
		"open_read_only_write" => open_read_only_write(filename),
		"lseek_file" => lseek_file(filename),
		"mounts_test" => mount_test(),
		_ => panic!("test not found"),
	}
}
