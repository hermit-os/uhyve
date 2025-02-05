use std::{
	fs::OpenOptions,
	io::{prelude::*, SeekFrom},
};

#[cfg(target_os = "hermit")]
use hermit as _;

fn main() {
	let mut buf: [u8; 10] = [0; 10];
	println!("Initial Buffer: {buf:?}");
	let mut f = OpenOptions::new()
		.read(true)
		.write(true)
		.create(true)
		.open("/root/foo.txt")
		.unwrap();
	f.write(&[
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
	])
	.unwrap();
	f.read(&mut buf).unwrap();
	assert_eq!(buf, [0; 10]);
	println!("file pre-seek: {buf:?}");

	f.seek(SeekFrom::Start(5)).unwrap();
	f.read(&mut buf).unwrap();
	println!("file post-seek: {buf:?}");
	assert_eq!(buf, [5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
}
