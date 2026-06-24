use std::{
	env,
	ffi::CString,
	fs::{File, OpenOptions, read_to_string, remove_file},
	io::{SeekFrom, prelude::*},
	os::fd::{AsRawFd, FromRawFd, IntoRawFd},
	ptr,
};

#[cfg(target_os = "hermit")]
use hermit as _;
use uhyve_interface::{
	GuestVirtAddr,
	v2::{
		Hypercall,
		parameters::{
			Dirent64, FileAttr, FileType, FstatParams, GetdentParams, GetdentResult, MkdirParams,
			MkdirResult, O_DIRECTORY, O_RDONLY, OpenParams, StatKind, StatParams, StatResult,
			Timespec,
		},
	},
};
use uhyve_test_kernels::hypercall::{uhyve_hypercall, virtual_to_physical};

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

fn write_to_fd_test() {
	println!("Running write_to_fd_test.");
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
		// Store file descriptor of file (and leak it).
		let fd_leaked = file.into_raw_fd();
		println!("File descriptor: {fd_leaked}");

		// Create a new file out of the leaked file descriptor.
		let mut fd_right = unsafe { File::from_raw_fd(fd_leaked) };
		fd_right.write_all(b"Nothing is impossible!\n").unwrap();
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

fn open_read(filename: &str) {
	let mut file = File::open(filename).unwrap();
	let mut buf = Vec::new();
	file.read_to_end(&mut buf).unwrap();
	assert_eq!(buf, b"Hello, world!\n");
}

/// Opens a mapped directory and reads its entries via the Getdents hypercall directly.
fn hypercall_getdents(dirname: &str) {
	println!("Running hypercall_getdents with dirname {dirname}.");

	let path = CString::new(dirname).unwrap();
	let name_phys = virtual_to_physical(GuestVirtAddr::from_ptr(path.as_ptr())).unwrap();
	let mut open_params = OpenParams {
		name: name_phys,
		flags: O_RDONLY | O_DIRECTORY,
		mode: 0,
		ret: -1,
	};
	uhyve_hypercall(Hypercall::FileOpen(&mut open_params));
	let fd = open_params.ret; // copy out of packed struct before use
	assert!(fd >= 0, "FileOpen for directory failed: {fd}");
	// Wrap in File so the fd is closed on drop.
	let dir = unsafe { File::from_raw_fd(fd) };

	let buf = [0u8; 1024];
	let buf_phys = virtual_to_physical(GuestVirtAddr::from_ptr(buf.as_ptr())).unwrap();
	let mut getdent_params = GetdentParams {
		fd: dir.as_raw_fd(),
		buf: buf_phys,
		len: buf.len() as u64,
		ret: GetdentResult::None,
	};
	uhyve_hypercall(Hypercall::Getdents(&mut getdent_params));

	let GetdentResult::Success(buflen) = getdent_params.ret else {
		panic!(
			"Getdents hypercall not successful: {:?}",
			getdent_params.ret
		);
	};

	// Reads a dirent from the returned buffer.
	let read_dirent = |offset: usize| -> (&Dirent64, &str) {
		let ptr = buf[offset..].as_ptr();
		let dirent = unsafe { &*ptr.cast::<Dirent64>() };
		let name_ptr = unsafe { ptr.add(core::mem::offset_of!(Dirent64, d_name)) };
		let name_len = (0usize..)
			.take_while(|&i| unsafe { *name_ptr.add(i) } != 0)
			.count();
		let name = std::str::from_utf8(unsafe { core::slice::from_raw_parts(name_ptr, name_len) })
			.expect("dirent name is not valid UTF-8");
		(dirent, name)
	};

	let mut dirents = Vec::new();
	let (first, first_name) = read_dirent(0);
	dirents.push((first_name, first));
	let (second, second_name) = read_dirent(first.d_reclen as usize);
	dirents.push((second_name, second));
	let (third, third_name) = read_dirent((first.d_reclen + second.d_reclen) as usize);
	dirents.push((third_name, third));
	assert_eq!(
		first.d_reclen + second.d_reclen + third.d_reclen,
		buflen as u16
	);
	for (entry_name, dirent) in dirents {
		println!("Directory contains {entry_name}");
		if entry_name == "." || entry_name == ".." {
			assert_eq!(dirent.d_type, FileType::Directory);
		}
	}
}

/// Creates a directory via the Mkdir hypercall directly, then populates it with a few files.
fn hypercall_mkdir(dirname: &str) {
	println!("Running hypercall_mkdir with dirname {dirname}.");

	let path = CString::new(dirname).unwrap();
	let path_phys = virtual_to_physical(GuestVirtAddr::from_ptr(path.as_ptr())).unwrap();
	let mut mkdir_params = MkdirParams {
		path: path_phys,
		len: dirname.len() as u64 + 1,
		ret: MkdirResult::None,
	};
	uhyve_hypercall(Hypercall::Mkdir(&mut mkdir_params));

	let MkdirResult::Success = mkdir_params.ret else {
		panic!("Mkdir hypercall not successful: {:?}", mkdir_params.ret);
	};

	// Create a few files inside the newly created directory.
	for i in 0..3 {
		let file_path = format!("{dirname}/file_{i}.txt");
		let mut file = File::create(&file_path).unwrap();
		write!(file, "contents of file {i}").unwrap();
	}
}

enum StatMode {
	Stat,
	Fstat,
}

fn hypercall_stat(filename: &str, mode: StatMode) {
	println!("Running hypercall_stat with filename {filename}.");
	let attr = FileAttr::default();
	let attr_phys = virtual_to_physical(GuestVirtAddr::from_ptr(ptr::addr_of!(attr))).unwrap();

	let ret = match mode {
		StatMode::Stat => {
			let path = CString::new(filename).unwrap();
			let name_phys = virtual_to_physical(GuestVirtAddr::from_ptr(path.as_ptr())).unwrap();

			let mut stat_params = StatParams {
				name: name_phys,
				kind: StatKind::Stat,
				attr: attr_phys,
				ret: StatResult::None,
			};
			uhyve_hypercall(Hypercall::FileStat(&mut stat_params));
			stat_params.ret
		}
		StatMode::Fstat => {
			let file = File::open(filename).unwrap();

			let mut stat_params = FstatParams {
				fd: file.as_raw_fd(),
				attr: attr_phys,
				ret: StatResult::None,
			};
			uhyve_hypercall(Hypercall::FileFstat(&mut stat_params));
			stat_params.ret
		}
	};
	assert_eq!(ret, StatResult::Success);
	dbg!(&attr);
	assert_ne!(attr, FileAttr::default());
	assert_ne!(attr.st_blocks, 0);
	assert_ne!(attr.st_atim, Timespec::default());
	assert_ne!(attr.st_size, 0);
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
		"write_to_fd" => write_to_fd_test(),
		"lseek_file" => lseek_file(filename),
		"mounts_test" => mount_test(),
		"open_read" => open_read(filename),
		"hypercall_getdents" => hypercall_getdents(filename),
		"hypercall_stat" => hypercall_stat(filename, StatMode::Stat),
		"hypercall_fstat" => hypercall_stat(filename, StatMode::Fstat),
		"hypercall_mkdir" => hypercall_mkdir(filename),
		_ => panic!("test not found"),
	}
}
