pub mod capabilities;
pub mod pci;

pub use virtio_bindings::{
	bindings::virtio_net::{VIRTIO_NET_F_MAC, VIRTIO_NET_F_MTU, VIRTIO_NET_F_STATUS},
	virtio_config::{VIRTIO_F_RING_RESET, VIRTIO_F_VERSION_1},
};

pub mod features {
	use virtio_bindings::{
		bindings::virtio_net::{VIRTIO_NET_F_MAC, VIRTIO_NET_F_MTU, VIRTIO_NET_F_STATUS},
		virtio_config::VIRTIO_F_VERSION_1,
	};

	pub const UHYVE_NET_FEATURES_LOW: u32 =
		1 << VIRTIO_NET_F_MAC | 1 << VIRTIO_NET_F_STATUS | 1 << VIRTIO_NET_F_MTU;
	pub const UHYVE_NET_FEATURES_HIGH: u32 = ((1_usize << VIRTIO_F_VERSION_1) >> 32) as u32;
}

use bitflags::bitflags;
pub use virtio_bindings::bindings::virtio_net::{VIRTIO_NET_HDR_GSO_NONE, VIRTIO_NET_S_LINK_UP};
use zerocopy::AsBytes;

/// Virtio device status field. See section 2.1 virtio v1.2
#[derive(Copy, Clone, Debug, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct DeviceStatus(u16);
bitflags! {
	impl DeviceStatus : u16 {
		/// Despite not being a valid virtio Flag, 0 represents an uninitialized or reset device.
		const UNINITIALIZED = 0;
		/// Indicates the guest has found the device and recognises it as valid.
		const ACKNOWLEDGE = 1;

		/// Indicates the guest knows how to drive the device.
		const DRIVER = 2;

		/// Indicates the driver is set up and ready to drive the device.
		const DRIVER_OK = 4;

		/// indicates the driver has acknowledged the features it understands and negotiation is
		/// complete.
		const FEATURES_OK = 8;

		/// Indicates that the device has experienced an error from which it can’t recover.
		const DEVICE_NEEDS_RESET = 64;

		/// Indicates that the PCI capabilities pointer points to a linked list at register address
		/// 0x34.
		///
		/// See: PCI-to-PCI bridge architechture, section 3.2.4.4
		const PCI_CAPABILITIES_LIST_ENABLE = 16;

		/// Failed to initialize.
		const FAILED = 128;
	}
}

pub mod config {

	/// Virtio Device IDs.
	///
	/// The device is calculated by adding 0x1040 to the virtio device ID as in section 5, or have a
	/// transitional device ID.
	///
	/// See sections 4.1.2.1 and 5 virtio v1.2
	pub mod device_id {
		const ROOT_DEVICE_ID: u16 = 0x1040;
		pub const NET_DEVICE: u16 = ROOT_DEVICE_ID + 1;
		const _BLOCK_DEVICE: u16 = ROOT_DEVICE_ID + 2;
		const _CONSOLE_DEVICE: u16 = ROOT_DEVICE_ID + 3;
		const _SOCKET_DEVICE: u16 = ROOT_DEVICE_ID + 19;
		// const TRANSITIONAL_NETWORK_CARD: u32 = 0x1000;
	}


}

/// Virtio PCI vendor ID, section 4.1.2 v1.2
pub const VIRTIO_VENDOR_ID: u16 = 0x1AF4;

/// For now, use an address large enough to be outside of kvm_userspace,
/// as IO/MMIO writes are otherwise dismissed.
pub const IOBASE: u32 = 0xFE000000;
const VIRTIO_MSI_NO_VECTOR: u16 = 0xffff;
