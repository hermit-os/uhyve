#![allow(dead_code)]
#![allow(unused_imports)]

use std::{
	env,
	fs::File,
	io::{Error, Read, Write},
	net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream},
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

fn main() -> Result<(), Error> {
	let args: Vec<String> = env::args().collect();
	let testname = &args[1].split('=').collect::<Vec<_>>()[1];
	let test_argument = &args[2].split('=').collect::<Vec<_>>()[1];

	println!("Network Test - {testname}");

	match *testname {
		"simple_receive_test" => simple_receive_test(),
		"simple_send_test" => simple_send_test(test_argument),
		_ => panic!("test {testname} not found"),
	}
}
