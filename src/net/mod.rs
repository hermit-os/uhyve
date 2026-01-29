use std::io;

pub use crate::consts::{UHYVE_NET_MTU, UHYVE_QUEUE_SIZE};

pub const BROADCAST_MAC_ADDR: [u8; 6] = [0xff; 6];
pub const PCI_ETHERNET_CLASS_CODE: u8 = 0x2;
pub const PCI_ETHERNET_SUBCLASS: u8 = 0x0;
pub const PCI_ETHERNET_PROG_IF: u8 = 0;
pub const PCI_ETHERNET_REVISION_ID: u8 = 0;

pub const UHYVE_PCI_CLASS_INFO: [u8; 3] = [
	PCI_ETHERNET_REVISION_ID,
	PCI_ETHERNET_PROG_IF,
	PCI_ETHERNET_SUBCLASS,
];

pub(crate) mod tap;

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
