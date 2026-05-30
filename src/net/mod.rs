#![cfg_attr(not(target_os = "linux"), expect(unused))]

use std::{fmt::Debug, io};

#[cfg(target_os = "linux")]
use crate::net::tap::{Tap, TapRX, TapTX};
use crate::params::NetworkMode;

pub const PCI_ETHERNET_CLASS_CODE: u8 = 0x2;
pub const PCI_ETHERNET_SUBCLASS: u8 = 0x0;
pub const PCI_ETHERNET_PROG_IF: u8 = 0;
pub const PCI_ETHERNET_REVISION_ID: u8 = 0;
pub const UHYVE_QUEUE_SIZE: u16 = 256;

pub const UHYVE_PCI_CLASS_INFO: [u8; 3] = [
	PCI_ETHERNET_REVISION_ID,
	PCI_ETHERNET_PROG_IF,
	PCI_ETHERNET_SUBCLASS,
];

pub const UHYVE_NET_MTU: usize = 1500;
pub trait NetworkBackend: Sized + Debug {}

// tap devices on macOS don't seem to be supported directly by Apple
// TODO: Let mac users investigate if this is possible.
// #[cfg(target_os = "linux")]
pub(crate) mod tap;

/// Host network attachment opened during virtio-net device construction.
#[derive(Default)]
pub(crate) enum Interface {
	#[default]
	None,
	#[cfg(target_os = "linux")]
	Tap(Tap),
}
impl Interface {
	pub(crate) fn from_network_mode(mode: NetworkMode) -> Self {
		match mode {
			NetworkMode::Tap { name } => {
				#[cfg(target_os = "linux")]
				{
					Self::Tap(Tap::new(&name).expect("Could not create Tap device"))
				}
				#[cfg(not(target_os = "linux"))]
				Self::None
			}
		}
	}

	pub(crate) fn mtu(&self) -> u16 {
		match self {
			Self::None => 1500,
			#[cfg(target_os = "linux")]
			Self::Tap(tap) => tap.mtu(),
		}
	}

	pub(crate) fn mac_address(&self) -> [u8; 6] {
		match self {
			Self::None => [0; 6],
			#[cfg(target_os = "linux")]
			Self::Tap(tap) => tap.mac_address_as_bytes(),
		}
	}

	#[cfg(target_os = "linux")]
	pub(crate) fn split(self) -> (TapRX, TapTX) {
		match self {
			#[cfg(target_os = "linux")]
			Self::Tap(tap) => tap.split(),
			Self::None => panic!("cannot split absent network interface"),
		}
	}
}

pub(crate) trait NetworkInterface {
	type RX: NetworkInterfaceRX;
	type TX: NetworkInterfaceTX;

	/// Return the MAC address as a byte array
	fn mac_address_as_bytes(&self) -> [u8; 6];

	/// Split off a tx and rx object.
	fn split(self) -> (Self::RX, Self::TX);
}

pub(crate) trait NetworkInterfaceTX: Send {
	/// Sends a packet to the interface.
	///
	/// **NOTE**: ensure the packet has the appropriate format and header.
	/// Incorrect packets will be dropped without warning.
	fn send(&mut self, buf: &[u8]) -> io::Result<usize>;
}

pub(crate) trait NetworkInterfaceRX: Send {
	/// Receives a packet from the interface.
	///
	/// Blocks until a packet is sent into the virtual interface. At that point, the content of the
	/// packet is copied into the provided buffer.
	///
	/// Returns the size of the received packet
	fn recv(&mut self, buf: &mut [u8], timeout: u16) -> io::Result<usize>;
}
