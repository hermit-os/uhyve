use std::{
	io::{Read, Write},
	net::{Shutdown, TcpListener, TcpStream},
	thread,
	time::Instant,
};

use byte_unit::{Byte, Unit};
use criterion::{Criterion, criterion_group, measurement::Measurement};
use log::debug;
use regex::Regex;
use uhyvelib::{
	params::{FileSandboxMode, NetworkMode, Output, Params},
	vm::UhyveVm,
};

#[path = "../tests/common.rs"]
mod common;
use common::{BuildMode, HERMIT_GATEWAY, HERMIT_IP, build_hermit_bin, check_result};

const TOTAL_BYTES: u64 = 1 * 1024 * 1024 * 1024;

/// Custom struct for throughput measurements in criterion. Must be used in connection with `iter_custom`
pub struct ThroughputMeasurement;

impl Measurement for ThroughputMeasurement {
	type Intermediate = ();
	type Value = u64;

	fn start(&self) -> Self::Intermediate {
		()
	}

	fn end(&self, _i: Self::Intermediate) -> Self::Value {
		unreachable!("This measurement uses iter_custom")
	}

	fn add(&self, v1: &Self::Value, v2: &Self::Value) -> Self::Value {
		*v1 + *v2
	}

	fn zero(&self) -> Self::Value {
		0
	}

	fn to_f64(&self, value: &Self::Value) -> f64 {
		*value as f64
	}

	fn formatter(&self) -> &dyn criterion::measurement::ValueFormatter {
		&ThroughputFormatter
	}
}

struct ThroughputFormatter;

impl criterion::measurement::ValueFormatter for ThroughputFormatter {
	fn scale_values(&self, typical_value: f64, values: &mut [f64]) -> &'static str {
		let (factor, unitstr) = match typical_value {
			0.0..1000.0 => (1.0, "bits/s"),
			1000.0..1000000.0 => (1000.0, "Kbits/s"),
			1000000.0..1000000000.0 => (1000000.0, "Mbits/s"),
			1000000000.0.. => (1000000000.0, "Gbits/s"),
			_ => unreachable!("Negative Throughput???"),
		};
		values.iter_mut().for_each(|v| *v /= factor);
		unitstr
	}

	fn scale_throughputs(
		&self,
		_typical_value: f64,
		_throughput: &criterion::Throughput,
		_throughputs: &mut [f64],
	) -> &'static str {
		"bits/s"
	}

	fn scale_for_machines(&self, _values: &mut [f64]) -> &'static str {
		"bits/s"
	}
}

fn network_receive_bench() -> u64 {
	env_logger::try_init().ok();
	let kernel_path = build_hermit_bin("network_test", BuildMode::Release);

	let params = Params {
		cpu_count: 1.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		output: Output::Buffer,
		stats: true,
		aslr: false,
		file_isolation: FileSandboxMode::None,
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

		debug!("Sent {sent} bytes in {secs:.3} s");
		let mbit = (sent as f64 * 8.0) / (secs * 1_000_000.0);
		debug!("Throughput (sending): {mbit:.2} Mbit/s");
	});

	let res = UhyveVm::new(kernel_path.clone(), params).unwrap().run(None);

	check_result(&res);

	let re =
		Regex::new(r"(?m)^Throughput \(receiving\):\s*([0-9]+(?:\.[0-9]+)?)\s+Mbit/s").unwrap();

	let caps = re.captures(res.output.as_ref().unwrap()).unwrap();
	let throughput: f64 = caps[1].parse().expect("invalid number");

	t.join().unwrap();
	(throughput * 1000000.0) as u64
}

fn network_send_bench() -> u64 {
	env_logger::try_init().ok();
	let kernel_path = build_hermit_bin("network_test", BuildMode::Release);

	let params = Params {
		cpu_count: 1.try_into().unwrap(),
		memory_size: Byte::from_u64_with_unit(64, Unit::MiB)
			.unwrap()
			.try_into()
			.unwrap(),
		output: Output::Buffer,
		stats: true,
		aslr: false,
		file_isolation: FileSandboxMode::None,
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
		debug!("socket bound");
		let (mut stream, peer) = listener.accept().unwrap();
		debug!("Got connection from {}", peer);

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

		debug!("Received {received} bytes in {secs:.3} s");
		let mbit = (received as f64 * 8.0) / (secs * 1_000_000.0);
		debug!("Throughput (receiving): {mbit:.2} Mbit/s");
	});

	let res = UhyveVm::new(kernel_path.clone(), params).unwrap().run(None);

	check_result(&res);

	let re = Regex::new(r"(?m)^Throughput \(sending\):\s*([0-9]+(?:\.[0-9]+)?)\s+Mbit/s").unwrap();

	let caps = re.captures(res.output.as_ref().unwrap()).unwrap();
	let throughput: f64 = caps[1].parse().expect("invalid number");

	t.join().unwrap();
	(throughput * 1000000.0) as u64
}

pub fn network_receive_throughput(c: &mut Criterion<ThroughputMeasurement>) {
	c.bench_function("network_receive_throughput", |b| {
		b.iter_custom(|iters| {
			let mut total: u64 = 0;
			for _ in 0..iters {
				total += network_receive_bench();
			}
			total / iters
		});
	});
}

pub fn network_send_throughput(c: &mut Criterion<ThroughputMeasurement>) {
	c.bench_function("network_send_throughput", |b| {
		b.iter_custom(|iters| {
			let mut total: u64 = 0;
			for _ in 0..iters {
				total += network_send_bench();
			}
			total / iters
		});
	});
}

criterion_group!(
	name = network_benchmark_group;
	config = Criterion::default().with_measurement(ThroughputMeasurement).sample_size(15);
	targets = network_receive_throughput, network_send_throughput
);
