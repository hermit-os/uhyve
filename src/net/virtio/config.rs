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
