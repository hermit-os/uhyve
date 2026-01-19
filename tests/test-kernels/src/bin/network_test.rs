#![allow(dead_code)]
#![allow(unused_imports)]

use std::{
	env,
	fs::File,
	io::{Error, Read, Write},
	net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream},
	time::Instant,
};

#[cfg(target_os = "hermit")]
use hermit as _;

fn simple_receive_test() -> Result<(), Error> {
	let listener = TcpListener::bind("127.0.0.1:9975").unwrap();
	println!("socket bound");
	let (mut socket, _) = listener.accept().unwrap();
	println!("connection established");
	loop {
		let mut buf = [0u8; 1500];
		match socket.read(&mut buf) {
			Err(e) => {
				println!("read err {e:?}");
			}
			Ok(received) => {
				println!("read {}", std::str::from_utf8(&buf[..received]).unwrap());
				if buf.windows(4).any(|window| window == b"exit") {
					break;
				}
			}
		}
	}
	Ok(())
}

fn simple_send_test(host_ip_port: &str) -> Result<(), Error> {
	let mut stream = TcpStream::connect(host_ip_port).expect("Can't connect to host");
	for i in 0..10_u8 {
		let mut v = Vec::with_capacity(i as usize);
		for _ in 0..=i {
			v.push(b'a' + i);
		}
		println!("Sending {v:?}");
		stream.write_all(&v)?;
	}
	stream.write_all(b"exit")?;
	Ok(())
}

fn send_bench(host_ip_send_cnt: &str) -> Result<(), Error> {
	let v = host_ip_send_cnt.split("/").collect::<Vec<_>>();

	let total_bytes: u64 = v[1].parse().unwrap();

	let mut stream = TcpStream::connect(v[0]).expect("Can't connect to host");

	let buf = vec![123u8; 64 * 1024]; // Bytes without meaning
	let mut sent: u64 = 0;

	let start = Instant::now();

	while sent < total_bytes {
		let remaining = (total_bytes - sent) as usize;
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

	Ok(())
}

fn receive_bench() -> Result<(), Error> {
	let listener = TcpListener::bind("127.0.0.1:9975").unwrap();
	println!("Waiting for connection...");

	let (mut stream, peer) = listener.accept()?;
	println!("Got connection from {}", peer);

	stream.set_nodelay(true)?;

	let mut buf = vec![0u8; 8192];
	let mut received: u64 = 0;

	let start = Instant::now();

	loop {
		let n = stream.read(&mut buf)?;
		if n == 0 {
			// connection terminated
			break;
		}
		received += n as u64;
	}

	let elapsed = start.elapsed();
	let secs = elapsed.as_secs_f64();

	println!("Received {} Bytes in {:.3} s", received, secs);
	let mbit = (received as f64 * 8.0) / (secs * 1_000_000.0);
	println!("Throughput (receiving): {:.2} Mbit/s", mbit);

	Ok(())
}

fn main() -> Result<(), Error> {
	let args: Vec<String> = env::args().collect();
	let testname = &args[1].split('=').collect::<Vec<_>>()[1];
	let test_argument = &args[2].split('=').collect::<Vec<_>>()[1];

	println!("Network Test - {testname}");

	match *testname {
		"simple_receive_test" => simple_receive_test(),
		"simple_send_test" => simple_send_test(test_argument),
		"receive_bench" => receive_bench(),
		"send_bench" => send_bench(test_argument),
		_ => panic!("test {testname} not found"),
	}
}
