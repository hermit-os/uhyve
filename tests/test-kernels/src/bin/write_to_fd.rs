use std::{
	fs::File,
	io::Write,
	mem::forget,
	os::fd::{AsRawFd, FromRawFd},
};

#[cfg(target_os = "hermit")]
use hermit as _;

fn main() {
	println!("Hello from write_to_fd!");

	let mut stdout = unsafe { File::from_raw_fd(1) };
	stdout.write_all(b"Wrote to stdout manually!\n").unwrap();
	let mut stderr = unsafe { File::from_raw_fd(2) };
	stderr.write_all(b"Wrote to stderr manually!\n").unwrap();

	// File descriptors above 2 that were not obtained using an open/create hypercall
	// should not be able to write.
	let mut file_from_arbitrary_fd = unsafe { File::from_raw_fd(42) };
	file_from_arbitrary_fd
		.write_all(b"What?!?!!\n")
		.expect_err("Could not write to fd 42.");

	{
		let mut file = File::create("/root/foo.txt").unwrap();
		file.write_all(b"No! ").unwrap();
		// Store file descriptor of file before leaking.
		let fd_leaked = file.as_raw_fd();
		println!("File descriptor: {fd_leaked}");
		// Leak the file descriptor.
		forget(file);

		// Create a new file out of the leaked file descriptor.
		let mut fd_right = unsafe { File::from_raw_fd(fd_leaked) };
		fd_right.write_all(b"Nothing is impossible!\n").unwrap();
	}
}
