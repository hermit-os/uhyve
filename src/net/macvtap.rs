//! Tap device wrapper for uhyve.

use std::{
	io::{self, Read, Write},
	os::fd::AsRawFd,
	str::FromStr,
	sync::Mutex,
};

use macvtap::{Iface, Mode};
use nix::{ifaddrs::InterfaceAddress, net::if_::InterfaceFlags, sys::socket::LinkAddr};

use crate::net::{NetworkInterface, UHYVE_NET_MTU};

/// Wrapper for a tap device, containing the descriptor and mac address.
pub struct MacVTap {
	tap: Iface,
	interface_address: InterfaceAddress,
}

impl MacVTap {
	/// Create a Layer 2 Linux/*BSD tap device, named "tap[0-9]+".
	pub fn new() -> io::Result<Self> {
		let iface_name = std::env::var("TAP").unwrap_or("tap10".to_owned());

		Self::from_str(&iface_name)
	}

	/// Return the tap device name
	pub fn name(&self) -> &str {
		&self.interface_address.interface_name
	}

	fn mac_addr(&self) -> LinkAddr {
		*self
			.interface_address
			.address
			.unwrap()
			.as_link_addr()
			.unwrap()
	}
}

impl NetworkInterface for Mutex<MacVTap> {
	fn mac_address_as_bytes(&self) -> [u8; 6] {
		self.lock().unwrap().mac_addr().addr().unwrap()
	}

	fn send(&self, buf: &[u8]) -> io::Result<usize> {
		let mut guard = self.lock().unwrap();
		trace!("sending {} bytes on MacVTap {}", buf.len(), guard.name());
		guard.tap.write(buf)
	}

	fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
		let mut guard = self.lock().unwrap();
		let res = guard.tap.read(buf);
		trace!("receiving {res:?} bytes on MacVTap {}", guard.name());
		res
	}
}

impl Drop for MacVTap {
	fn drop(&mut self) {
		self.tap.close();
	}
}

impl AsRawFd for MacVTap {
	fn as_raw_fd(&self) -> i32 {
		self.tap.as_raw_fd()
	}
}

impl Default for MacVTap {
	fn default() -> Self {
		Self::new().unwrap()
	}
}

impl FromStr for MacVTap {
	type Err = std::io::Error;

	fn from_str(name: &str) -> std::result::Result<Self, Self::Err> {
		// TODO: MacVTap mode
		let tap = Iface::new(name, Mode::Tap, UHYVE_NET_MTU.try_into().unwrap()).expect(
			"Failed to create tap device (Device busy, or you may need to enable CAP_NET_ADMIN capability).",
		);

		let interface_address = nix::ifaddrs::getifaddrs()
			.unwrap()
			.find(|dev| dev.interface_name == name)
			.expect("Could not find TAP interface.");

		// TODO: ensure the tap device is header-less

		assert!(
			interface_address.flags.contains(InterfaceFlags::IFF_TAP),
			"Interface is not a valid TAP device."
		);

		assert!(
			interface_address.flags.contains(InterfaceFlags::IFF_UP),
			"Interface is not up and running."
		);

		Ok(MacVTap {
			tap,
			interface_address,
		})
	}
}
