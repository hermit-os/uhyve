mod common;

use std::{
	io::Write,
	net::TcpStream,
	thread::{self, sleep},
	time::Duration,
};

use byte_unit::{Byte, Unit};
use common::{HERMIT_IP, build_hermit_bin};
use uhyvelib::{
	params::{Output, Params},
	vm::UhyveVm,
};

#[test]
fn network_test() {
	let mut builder = env_logger::Builder::from_default_env();
	// The precise timestampe can be important when debugging networking,
	builder.format_timestamp_nanos().init();

	let bin_path = build_hermit_bin("network_test");
	let params = Params {
		cpu_count: 1.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		output: Output::Buffer,
		stats: true,
		aslr: false,
		..Default::default()
	};

	let t = thread::spawn(move || {
		sleep(Duration::from_secs(2));

		let mut hermit_ip = String::from(HERMIT_IP);
		hermit_ip.push_str(":9975");
		let mut stream = TcpStream::connect(hermit_ip).unwrap();
		for i in 0..10_u8 {
			let mut v = Vec::with_capacity(i as usize);
			for _ in 0..=i {
				v.push(b'a' + i);
			}
			println!("Sending {v:?}");
			stream.write(&v).unwrap();
			// TODO: Currently this test fails without the delay. Remove once fixed.
			sleep(Duration::from_millis(100));
		}
		stream.write(b"exit").unwrap();
	});

	let res = UhyveVm::new(bin_path, params).unwrap().run(None);

	t.join().unwrap();

	for t in ["a\n", "bb\n", "ccc\n", "dddd\n", "eeeee\n"] {
		assert!(res.output.as_ref().unwrap().contains(t));
	}
}
