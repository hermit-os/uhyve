#![allow(dead_code)]
#![allow(unused_imports)]

use std::{
	fs::File,
	io::{Error, Read, Write},
	net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream},
};

#[cfg(target_os = "hermit")]
use hermit as _;

fn main() -> Result<(), Error> {
	println!("Network Test");
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
				if &buf[0..4] == b"exit" {
					break;
				}
				println!("read {}", std::str::from_utf8(&buf[..received]).unwrap());
			}
		}
	}
	Ok(())
}
