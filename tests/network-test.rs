mod common;

use std::{
	io::{Read, Write},
	net::{TcpListener, TcpStream},
	sync::Mutex,
	thread,
};

use byte_unit::{Byte, Unit};
use common::{BuildMode, HERMIT_GATEWAY, HERMIT_IP, build_hermit_bin, check_result};
use uhyvelib::{
	params::{NetworkMode, Output, Params},
	vm::UhyveVm,
};

static NETWORK_TEST_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn network_guest_receive_test() {
	let mut builder = env_logger::Builder::from_default_env();
	// The precise timestampe can be important when debugging networking,
	builder.format_timestamp_nanos().try_init().ok();

	let bin_path = build_hermit_bin("network_test", BuildMode::Debug);
	let params = Params {
		cpu_count: 1.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		output: Output::Buffer,
		stats: true,
		aslr: false,
		network: Some(NetworkMode::Tap {
			name: "tap10".to_string(),
		}),
		kernel_args: vec![
			"--".to_owned(),
			"testname=simple_receive_test".to_owned(),
			"test_argument=".to_owned(),
		],
		..Default::default()
	};

	let _guard = NETWORK_TEST_MUTEX.lock();

	let t = thread::spawn(move || {
		let mut hermit_ip = String::from(HERMIT_IP);
		hermit_ip.push_str(":9975");
		let mut stream = TcpStream::connect(hermit_ip).unwrap();
		for i in 0..10_u8 {
			let mut v = Vec::with_capacity(i as usize);
			for _ in 0..=i {
				v.push(b'a' + i);
			}
			println!("Sending {v:?}");
			stream.write_all(&v).unwrap();
		}
		stream.write_all(b"exit").unwrap();
	});

	let res = UhyveVm::new(bin_path, params).unwrap().run(None);
	check_result(&res);

	t.join().unwrap();

	for t in ["a", "bb", "ccc", "dddd", "eeeee"] {
		assert!(res.output.as_ref().unwrap().contains(t));
	}
}

#[test]
fn network_guest_send_test() {
	let mut builder = env_logger::Builder::from_default_env();
	// The precise timestampe can be important when debugging networking,
	builder.format_timestamp_nanos().try_init().ok();

	let bin_path = build_hermit_bin("network_test", BuildMode::Debug);
	let params = Params {
		cpu_count: 1.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		output: Output::Buffer,
		stats: true,
		aslr: false,
		network: Some(NetworkMode::Tap {
			name: "tap10".to_string(),
		}),
		kernel_args: vec![
			"--".to_owned(),
			"testname=simple_send_test".to_owned(),
			"test_argument=".to_owned() + HERMIT_GATEWAY + ":9975",
		],
		..Default::default()
	};

	let _guard = NETWORK_TEST_MUTEX.lock();
	let t = thread::spawn(move || {
		let listener = TcpListener::bind(HERMIT_GATEWAY.to_string() + ":9975").unwrap();
		println!("socket bound");
		let (mut socket, _) = listener.accept().unwrap();
		println!("connection established");
		let mut received_bytes = Vec::new();
		loop {
			let mut buf = [0u8; 1500];
			match socket.read(&mut buf) {
				Err(e) => {
					println!("read err {e:?}");
				}
				Ok(received) => {
					println!("read {}", std::str::from_utf8(&buf[..received]).unwrap());
					received_bytes.extend_from_slice(&buf[..received]);
					if buf.windows(4).any(|window| window == b"exit") {
						break;
					}
				}
			}
		}
		println!("received bytes: {received_bytes:?}");
		for t in ["a", "bb", "ccc", "dddd", "eeeee"] {
			assert!(
				received_bytes
					.windows(t.len())
					.any(|window| window == t.as_bytes())
			);
		}
	});

	let res = UhyveVm::new(bin_path, params).unwrap().run(None);
	check_result(&res);

	t.join().unwrap();
}
