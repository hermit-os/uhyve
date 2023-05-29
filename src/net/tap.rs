//! Tap device wrapper for uhyve.

use std::{
	io::{self, Read, Write},
	os::fd::AsRawFd,
	str::FromStr,
};

use macvtap::{Iface, Mode};
use nix::{ifaddrs::InterfaceAddress, net::if_::InterfaceFlags, sys::socket::LinkAddr};

use crate::net::consts::UHYVE_NET_MTU;

/// Wrapper for a tap device, containing the descriptor and mac address.
pub struct Tap {
	tap: Iface,
	interface_address: InterfaceAddress,
}

impl Tap {
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

	/// Return the MAC address as a byte array
	pub fn mac_address_as_bytes(&self) -> [u8; 6] {
		self.mac_addr().addr().unwrap()
	}

	/// Get the tap interface struct
	pub fn get_iface(&self) -> &Iface {
		&self.tap
	}

	/// Sends a packet to the interface.
	///
	/// **NOTE**: ensure the packet has the appropriate format and header.
	/// Incorrect packets will be dropped without warning.
	pub fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
		self.tap.write(buf)
	}

	/// Receives a packet from the interface.
	///
	/// Blocks until a packet is sent into the virtual interface. At that point, the content of the
	/// packet is copied into the provided buffer.
	///
	/// Returns the size of the received packet
	pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		self.tap.read(buf)
	}
}

impl Drop for Tap {
	fn drop(&mut self) {
		self.tap.close();
	}
}

impl AsRawFd for Tap {
	fn as_raw_fd(&self) -> i32 {
		self.tap.as_raw_fd()
	}
}

impl Default for Tap {
	fn default() -> Self {
		Self::new().unwrap()
	}
}

impl FromStr for Tap {
	type Err = std::io::Error;

	fn from_str(name: &str) -> std::result::Result<Self, Self::Err> {
		// TODO: MacVTap mode
		let tap = Iface::new(name, Mode::Tap, UHYVE_NET_MTU.try_into().unwrap())
		.expect("Failed to create tap device (Device busy, or you may need to enable CAP_NET_ADMIN capability).");

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

		Ok(Tap {
			tap,
			interface_address,
		})
	}
}
