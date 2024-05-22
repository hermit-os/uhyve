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

pub mod tap;

pub mod virtio;
