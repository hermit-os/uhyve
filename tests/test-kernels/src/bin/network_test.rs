#![allow(dead_code)]
#![allow(unused_imports)]

use std::{
	fs::File,
	io::{Error, Read},
	net::{Ipv4Addr, SocketAddrV4, TcpListener},
};

#[cfg(target_os = "hermit")]
use hermit as _;

fn main() -> Result<(), Error> {
	println!("Network Test - ");
	// let loopback = Ipv4Addr::new(10, 8, 8, 11);
	// println!("1");
	// let socket = SocketAddrV4::new(loopback, 0);
	// println!("2");
	// let listener = TcpListener::bind(socket)?;
	// println!("3");

	let listener = TcpListener::bind("127.0.0.1:9975").unwrap();
	let (mut socket, _) = listener.accept().unwrap();
	let mut buf = [0u8; 1000];
	println!("about to read");
	match socket.read(&mut buf) {
		Err(e) => {
			println!("read err {e:?}");
		}
		Ok(received) => {
			print!("read {}", std::str::from_utf8(&buf[..received]).unwrap());
		}
	}
	Ok(())
}
