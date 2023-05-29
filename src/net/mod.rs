pub mod consts {
	pub use crate::{
		consts::{UHYVE_NET_MTU, UHYVE_QUEUE_SIZE},
		linux::virtqueue::QUEUE_LIMIT,
	};

	pub const BROADCAST_MAC_ADDR: [u8; 6] = [0xff; 6];
	pub const PCI_ETHERNET_CLASS_CODE: u8 = 0x2;
	pub const PCI_ETHERNET_SUBCLASS: u8 = 0x0;
	pub const PCI_ETHERNET_PROG_IF: u8 = 0;
	pub const PCI_ETHERNET_REVISION_ID: u8 = 0;

	pub const UHYVE_PCI_CLASS_INFO: u32 = ((PCI_ETHERNET_CLASS_CODE as u32) << 24)
		| ((PCI_ETHERNET_SUBCLASS as u32) << 16)
		| ((PCI_ETHERNET_PROG_IF as u32) << 8)
		| (PCI_ETHERNET_REVISION_ID as u32);
}

pub mod tap;

pub mod virtio;
