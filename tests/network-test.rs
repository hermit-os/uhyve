mod common;

use std::{
	io::{Read, Write},
	net::{Shutdown, TcpListener, TcpStream},
	sync::Mutex,
	thread,
	time::Instant,
};

use byte_unit::{Byte, Unit};
use common::{BuildMode, HERMIT_GATEWAY, HERMIT_IP, build_hermit_bin, check_result};
use regex::Regex;
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

const TOTAL_BYTES: u64 = 128 * 1024 * 1024; // 128 MiB

#[test]
fn network_receive_large() {
	env_logger::try_init().ok();
	let kernel_path = build_hermit_bin("network_test", BuildMode::Debug);

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
			"testname=receive_bench".to_owned(),
			"test_argument=".to_owned(),
		],
		..Default::default()
	};

	let t = thread::spawn(move || {
		let mut hermit_ip = String::from(HERMIT_IP);
		hermit_ip.push_str(":9975");
		let mut stream = TcpStream::connect(hermit_ip).unwrap();

		let buf = vec![123u8; 64 * 1024]; // Bytes without meaning
		let mut sent: u64 = 0;

		let start = Instant::now();

		while sent < TOTAL_BYTES {
			let remaining = (TOTAL_BYTES - sent) as usize;
			let to_send = remaining.min(buf.len());
			stream.write_all(&buf[..to_send]).unwrap();
			sent += to_send as u64;
		}

		stream.shutdown(Shutdown::Write).unwrap();
		let elapsed = start.elapsed();
		let secs = elapsed.as_secs_f64();

		println!("Sent {sent} bytes in {secs:.3} s");
		let mbit = (sent as f64 * 8.0) / (secs * 1_000_000.0);
		println!("Throughput (sending): {mbit:.2} Mbit/s");
	});

	let res = UhyveVm::new(kernel_path.clone(), params).unwrap().run(None);

	check_result(&res);
	println!("Kernel Output:\n{}", res.output.as_ref().unwrap());

	let re = Regex::new(r"(?m)^Received\s*([0-9]+)\s+Bytes").unwrap();

	let caps = re
		.captures(res.output.as_ref().unwrap())
		.expect("kernel output doesn't container received bytes");
	let bytes_received: u64 = caps[1].parse().expect("invalid number");

	assert_eq!(TOTAL_BYTES, bytes_received);

	t.join().unwrap();
}

#[test]
fn network_send_large() {
	env_logger::try_init().ok();
	let kernel_path = build_hermit_bin("network_test", BuildMode::Debug);

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
			"testname=send_bench".to_owned(),
			format!("test_argument={HERMIT_GATEWAY}:9975/{TOTAL_BYTES}").to_owned(),
		],
		..Default::default()
	};

	let t = thread::spawn(move || {
		let listener = TcpListener::bind(HERMIT_GATEWAY.to_string() + ":9975").unwrap();
		println!("socket bound");
		let (mut stream, peer) = listener.accept().unwrap();
		println!("Got connection from {}", peer);

		stream.set_nodelay(true).unwrap();

		let mut buf = vec![0u8; 8192];
		let mut received: u64 = 0;

		let start = Instant::now();
		loop {
			let n = stream.read(&mut buf).unwrap();
			if n == 0 {
				// connection terminated
				break;
			}
			received += n as u64;
		}

		let elapsed = start.elapsed();
		let secs = elapsed.as_secs_f64();

		println!("Received {received} bytes in {secs:.3} s");
		let mbit = (received as f64 * 8.0) / (secs * 1_000_000.0);
		println!("Throughput (receiving): {mbit:.2} Mbit/s");
		received
	});

	let res = UhyveVm::new(kernel_path.clone(), params).unwrap().run(None);

	let received = t.join().unwrap();

	check_result(&res);
	println!("Kernel Output:\n{}", res.output.as_ref().unwrap());

	assert_eq!(TOTAL_BYTES, received);
}
