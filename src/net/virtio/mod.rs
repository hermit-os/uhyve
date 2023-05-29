pub mod capabilities;

use std::ops::Add;

pub use virtio_bindings::{
	bindings::virtio_net::{VIRTIO_NET_F_MAC, VIRTIO_NET_F_MTU, VIRTIO_NET_F_STATUS},
	virtio_config::VIRTIO_F_VERSION_1,
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

pub use virtio_bindings::bindings::virtio_net::{VIRTIO_NET_HDR_GSO_NONE, VIRTIO_NET_S_LINK_UP};

pub mod config {
	/// Virtio device status field. See section 2.1 virtio v1.2
	pub mod status {
		/// Despite not being a valid virtio Flag, 0 represents an uninitialized or reset device.
		pub const UNINITIALIZED: u8 = 0;
		/// Indicates the guest has found the device and recognises it as valid.
		pub const ACKNOWLEDGE: u8 = 1;

		/// Indicates the guest knows how to drive the device.
		pub const DRIVER: u8 = 2;

		/// Indicates the driver is set up and ready to drive the device.
		pub const DRIVER_OK: u8 = 4;

		/// indicates the driver has acknowledged the features it understands and negotiation is
		/// complete.
		pub const FEATURES_OK: u8 = 8;

		/// Indicates that the device has experienced an error from which it can’t recover.
		pub const DEVICE_NEEDS_RESET: u8 = 64;

		/// Indicates that the PCI capabilities pointer points to a linked list at register address
		/// 0x34.
		///
		/// See: PCI-to-PCI bridge architechture, section 3.2.4.4
		pub const PCI_CAPABILITIES_LIST_ENABLE: u8 = 16;

		/// Failed to initialize.
		pub const FAILED: u8 = 128;
	}

	/// Virtio ISR status flags. See section 4.1.4.5 virtio v1.2
	pub mod interrupt {
		/// Notify that the buffers/Virtqueues have been changed
		pub const NOTIFY_USED_BUFFER: u8 = 1 << 0;
		/// Notify that the device configuration has been changed.
		///
		/// *Note: libhermit-rs does not support configuration changes at this time.*
		pub const NOTIFY_CONFIGURUTION_CHANGED: u8 = 1 << 1;
	}
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

	/// Virtio capability type IDs. See section 4.1.4 virtio v1.2
	pub mod cfg_type {
		pub const INVALID_CFG: u8 = 0x00;
		/// Common configuration
		pub const COMMON_CFG: u8 = 0x01;
		/// Notifications
		pub const NOTIFY_CFG: u8 = 0x02;
		/// ISR status
		pub const ISR_CFG: u8 = 0x03;
		/// Device-specific configuration
		pub const DEVICE_CFG: u8 = 0x04;
		/// PCI configuration access
		pub const PCI_CFG: u8 = 0x05;
		/// Shared memory region
		const _SHARED_MEMORY_CFG: u8 = 0x08;
		/// Vendor-specific data
		pub const VENDOR_CFG: u8 = 0x09;
	}
}

/// Stores an address in the PCI configuration space.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct ConfigAddress(pub(crate) u32);

impl const Add<usize> for ConfigAddress {
	type Output = Self;

	fn add(self, rhs: usize) -> Self::Output {
		ConfigAddress(self.0 + rhs as u32)
	}
}

impl ConfigAddress {
	/// Returns offset from the PCI **Configuration** space start.
	/// Panics if the address is before PCI_CAP_PTR_START (configuration header)
	pub const fn capability_space_start(&self) -> usize {
		if self.0 < crate::net::virtio::PCI_CAP_PTR_START {
			panic!("Address is in PCI configuration header!")
		}
		(self.0 - crate::net::virtio::PCI_CAP_PTR_START) as usize
	}

	pub const fn from_configuration_address(address: u32) -> Self {
		Self(address)
	}

	pub fn from_guest_address(address: u64) -> Self {
		if address < IOBASE.into() || address >= CONFIG_SPACE_END {
			panic!("Address provided is not within IOSPACE")
		}
		Self(u32::try_from(address).unwrap() - IOBASE)
	}

	pub fn guest_address(&self) -> u64 {
		(self.0 + IOBASE).try_into().unwrap()
	}
}

macro_rules! get_offset {
	($offset:expr, $ty:ty, $field:ident) => {
		unsafe {
			let base_ptr: *const _ = std::mem::MaybeUninit::<$ty>::uninit().as_ptr();
			let f: *const _ = std::ptr::addr_of!((*base_ptr).$field);
			ConfigAddress::from_configuration_address(
				(f as *const u8).offset_from(base_ptr as *const u8) as u32 + $offset as u32,
			)
		}
	};
}

/// Contains immutable offsets of uhyve's virtio configuration.
pub mod offsets {
	use super::capabilities::{
		offsets::{COMMON_CFG_OFFSET, DEVICE_CFG_OFFSET, ISR_CFG_OFFSET, NOTIFY_CFG},
		ComCfg, IsrStatus, NetDevCfg,
	};
	use crate::net::virtio::ConfigAddress;

	// Common configuration.
	pub const DEVICE_FEATURE_SELECT: ConfigAddress =
		get_offset!(COMMON_CFG_OFFSET, ComCfg, device_feature_select);

	pub const DEVICE_FEATURE: ConfigAddress =
		get_offset!(COMMON_CFG_OFFSET, ComCfg, device_feature);

	pub const DRIVER_FEATURE_SELECT: ConfigAddress =
		get_offset!(COMMON_CFG_OFFSET, ComCfg, driver_feature_select);

	pub const DRIVER_FEATURE: ConfigAddress =
		get_offset!(COMMON_CFG_OFFSET, ComCfg, driver_feature);

	pub const CONFIG_MSIX_VECTOR: ConfigAddress =
		get_offset!(COMMON_CFG_OFFSET, ComCfg, config_msix_vector);

	pub const DEVICE_STATUS: ConfigAddress = get_offset!(COMMON_CFG_OFFSET, ComCfg, device_status);

	pub const QUEUE_SELECT: ConfigAddress = get_offset!(COMMON_CFG_OFFSET, ComCfg, queue_select);

	pub const QUEUE_SIZE: ConfigAddress = get_offset!(COMMON_CFG_OFFSET, ComCfg, queue_size);

	pub const QUEUE_MSIX_VECTOR: ConfigAddress =
		get_offset!(COMMON_CFG_OFFSET, ComCfg, queue_msix_vector);

	pub const QUEUE_ENABLE: ConfigAddress = get_offset!(COMMON_CFG_OFFSET, ComCfg, queue_enable);

	pub const QUEUE_NOTIFY_OFFSET: ConfigAddress =
		get_offset!(COMMON_CFG_OFFSET, ComCfg, queue_notify_off);

	pub const QUEUE_DESC: ConfigAddress = get_offset!(COMMON_CFG_OFFSET, ComCfg, queue_desc);

	pub const QUEUE_DRIVER: ConfigAddress = get_offset!(COMMON_CFG_OFFSET, ComCfg, queue_driver);

	pub const QUEUE_DEVICE: ConfigAddress = get_offset!(COMMON_CFG_OFFSET, ComCfg, queue_device);

	/// Notify structure in case config changes take place
	pub const ISR_NOTIFY: ConfigAddress = get_offset!(ISR_CFG_OFFSET, IsrStatus, flags);

	// TODO: should this really be a seperate address?
	// or can we use seperate notify addresses for seperate things?
	pub const MEM_NOTIFY: ConfigAddress = NOTIFY_CFG;
	pub const MEM_NOTIFY_1: ConfigAddress = MEM_NOTIFY + 1;

	// Device configuration.
	pub const MAC_ADDRESS: ConfigAddress = get_offset!(DEVICE_CFG_OFFSET, NetDevCfg, mac);
	pub const MAC_ADDRESS_1: ConfigAddress = MAC_ADDRESS + 4;
	pub const NET_STATUS: ConfigAddress = get_offset!(DEVICE_CFG_OFFSET, NetDevCfg, status);
	pub const MTU: ConfigAddress = get_offset!(DEVICE_CFG_OFFSET, NetDevCfg, mtu);
}

/// Virtio PCI vendor ID, section 4.1.2 v1.2
pub const VIRTIO_VENDOR_ID: u16 = 0x1AF4;

/// For now, use an address large enough to be outside of kvm_userspace,
/// as IO/MMIO writes are otherwise dismissed.
pub const IOBASE: u32 = 0xFE000000;
pub const PCI_CAP_PTR_START: u32 = 0x40;
pub const CONFIG_SPACE_START: u64 = (IOBASE + PCI_CAP_PTR_START) as u64;

pub const CONFIG_SPACE_SIZE: usize = 0x200;

const VIRTIO_MSI_NO_VECTOR: u16 = 0xffff;
const CONFIG_SPACE_END: u64 = CONFIG_SPACE_START + CONFIG_SPACE_SIZE as u64;
