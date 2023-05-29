//! VirtIO capability structures.

use std::mem::size_of;

use zerocopy::AsBytes;

use crate::net::{
	consts::{BROADCAST_MAC_ADDR, UHYVE_NET_MTU, UHYVE_QUEUE_SIZE},
	virtio::config::cfg_type,
};

/// Collection of all VirtIO Capabilities
#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct VirtioCapColl {
	pub common: ComCfg,
	pub isr: IsrStatus,
	pub notif: NotifCfg,
	pub dev: NetDevCfg,
}

/// Vendor-specific PCI capability.
/// Section 4.1.4 virtio v1.2
#[derive(AsBytes, Clone, Copy, Debug)]
#[repr(C)]
pub struct PciCap {
	/// Generic PCI field: PCI_CAP_ID_VNDR
	cap_vndr: u8,

	/// Generic PCI field: next ptr
	pub cap_next: u8,

	/// Generic PCI field: capability length
	pub cap_len: u8,

	/// Identifies the structure. See [`crate::net::virtio::config::cfg_type`]
	pub cfg_type: u8,

	/// Index of the device BAR register
	bar_index: u8,

	/// Identify multiple capabilities of the same type.
	id: u8,

	_padding: [u8; 2],

	/// Offset of address relative to the base address within the BAR.
	pub offset: u32,

	/// Length of the structure, in bytes.
	///
	/// The length **MAY** include padding padding, or fields unused by the driver, etc.
	pub length: u32,
}

impl Default for PciCap {
	fn default() -> Self {
		Self {
			cap_vndr: cfg_type::VENDOR_CFG,
			cap_next: 0,
			cap_len: std::mem::size_of::<PciCap>() as u8,
			cfg_type: cfg_type::INVALID_CFG,
			bar_index: 0,
			id: 0,
			_padding: [0u8; 2],
			offset: 0,
			length: 0,
		}
	}
}

/// Virtio device configuration layout.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct NetDevCfg {
	/// **read-only**: macaddress, always exists.
	pub mac: [u8; 6],

	/// **read-write** Status field: VIRTIO_NET_S_LINK_UP and VIRTIO_NET_S_ANNOUNCE.
	pub status: u16,

	/// **read-only**: only exists if VIRTIO_F_MQ or VIRTIO_NET_F_RSS are negotiated, however
	/// implements and does not use it. TODO
	_max_virtqueue_pairs: u16,
	/// Exists only if VIRTIO_NET_F_MTU is negotiated. Must be at least 1280 (5.1.4.1 v1.2).
	/// must not modify once set.
	pub mtu: u16,
	_speed: u32,
	_duplex: u8,
	_rss_max_key_size: u8,
	_rss_max_indirection_table_length: u16,
	_supported_hash_types: u32,
}

impl Default for NetDevCfg {
	fn default() -> Self {
		Self {
			mac: BROADCAST_MAC_ADDR,
			status: 0,
			_max_virtqueue_pairs: 0,
			mtu: UHYVE_NET_MTU as u16,
			_speed: 0u32,
			_duplex: 0u8,
			_rss_max_key_size: 0u8,
			_rss_max_indirection_table_length: 0u16,
			_supported_hash_types: 0u32,
		}
	}
}

/// ISR capability, refers to at a single byte which ocntains an 8-bit ISR status field to be used
/// for INT#x interrupt handling. The offset has no alignmen requirements.
///
/// See section 4.1.5.3 and 4.1.5.4 on usage.
#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct IsrStatus {
	/// Bit 0 of `flags` refers to a queue interrupt, bit ` to a configuration interrupt. Reading
	/// this register resets it to 0.
	pub flags: u8,
}

/// Notification location. This is a standard PciCap, followed by an offset multiplier.
///
/// ## Important
///
/// `cap.offset` must be 2-byte aligned, `notify_off_multiplier` must be an even power of 2 or 0.
/// `cap.length` must be at least 2 and larg enough to support queue notification offset.
///
/// See section 4.1.4.4.1 virtio v1.2
#[derive(Clone, Debug)]
#[repr(C)]
pub struct NotifCfg {
	pub cap: PciCap,
	/// Combind with queue_notify_off to derive the Queue Notify address
	/// within a BAR for a virtqueue.
	///
	/// For example: if notify_off_multiplier is 0, the same Queue Notify address
	/// is used for all queues. (section 4.1.4.4 virtio v1.2)
	pub notify_off_multiplier: u32,
}

impl Default for NotifCfg {
	fn default() -> Self {
		Self {
			cap: PciCap {
				cap_len: std::mem::size_of::<NotifCfg>() as u8,
				cfg_type: cfg_type::NOTIFY_CFG,
				offset: offsets::NOTIFY_CAP.0,
				length: (std::mem::size_of::<NotifCfg>() * 8) as u32,
				..Default::default()
			},
			notify_off_multiplier: Default::default(),
		}
	}
}

/// Common configuration, section 4.1.4.3 virtio v1.2
///
/// All data should be treated as little-endian.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct ComCfg {
	/// **read-write**: The driver uses this to select device_feature.
	///
	/// Values may only be 0 for feature bits 0-31, or one for feature bits 32-63.
	pub device_feature_select: u32,

	/// **read-only**: The driver reads the currently activated feature bits.
	///
	/// See: [`crate::virtio-bindings`] for `VIRTIO_NET_F_*` feature flags
	pub device_feature: u32,

	/// **read-write**: The driver uses this to report which feature bits it is offering.
	pub driver_feature_select: u32,

	/// **read-write**: Driver reads activated feature bits
	///
	/// See: [`crate::virtio-bindings`] for `VIRTIO_NET_F_*` feature flags
	pub driver_feature: u32,

	/// **read-write**: The driver sets the Configuration Vector for MSI-X.
	pub config_msix_vector: u16,

	/// **read-only**: The device specifies the maximum number of virtqueues supported here.
	pub num_queues: u16,

	/// **read-write**:
	/// The driver writes the device status here (section 2.1 virtio v1.2).
	/// Writing 0 into this field resets the device.
	pub device_status: u8,

	/// **read-only**: Configuration atomicity value. The device changes this every time the
	/// configuration noticeably changes.
	pub config_generation: u8, // read-only for driver

	// About a specific virtqueue
	/// **read-write**: The driver selects which virtqueue the following fields refer to.
	pub queue_select: u16,

	/// **read-write**: On reset, specifies the maximum queue size supported by the device.
	///
	/// This can be modified by the driver to reduce memory requirements. A 0 means the queue is
	/// unavailable.
	pub queue_size: u16,

	/// **read-write**: The driver uses this to specify the queue vector for MSI-Xw.
	pub queue_msix_vector: u16,

	/// **read-write**: The driver uses this to selectively prevent the device from executing
	/// requests from this virtqueue.
	///
	/// 1 - enabled; 0 - disabled.
	pub queue_enable: u16,

	/// **read-only**: Offset of the notification area.
	///
	/// **NOTE**: This is not an offset in bytes. Section 4.1.4.4 virtio v1.2
	pub queue_notify_off: u16,

	/// **read-write**: The driver writes the physical address of Descriptor Area here. See section
	/// 2.6 virtio v1.2
	pub queue_desc: u64,

	/// **read-write**: The driver writes the physical address of Driver Area here. See section 2.6
	/// virtio v1.2
	pub queue_driver: u64,

	/// **read-write**: The driver writes the physical address of Device Area here. See section 2.6
	/// virtio v1.2
	pub queue_device: u64,
}

impl Default for ComCfg {
	fn default() -> Self {
		Self {
			device_feature_select: 0,
			device_feature: 0,
			driver_feature_select: 0,
			driver_feature: 0,
			config_msix_vector: super::VIRTIO_MSI_NO_VECTOR,
			num_queues: 0,
			device_status: 0,
			config_generation: 0,
			queue_select: 0,
			queue_size: UHYVE_QUEUE_SIZE as u16,
			queue_msix_vector: 0,
			queue_enable: 0,
			// we will use the same address for all queues, since we only have 2. TODO
			queue_notify_off: 0,
			queue_desc: 0,
			queue_driver: 0,
			queue_device: 0,
		}
	}
}

pub mod offsets {
	use crate::net::virtio::{ConfigAddress, PCI_CAP_PTR_START};

	pub const CFG_START: ConfigAddress =
		ConfigAddress::from_configuration_address(PCI_CAP_PTR_START);

	pub const COMMON_CFG_OFFSET: u32 = 0x40;
	pub const COMMON_CFG: ConfigAddress =
		ConfigAddress::from_configuration_address(COMMON_CFG_OFFSET);

	pub const NOTIFY_CAP_OFFSET: u32 = 0x60;
	pub const NOTIFY_CAP: ConfigAddress =
		ConfigAddress::from_configuration_address(NOTIFY_CAP_OFFSET);

	pub const ISR_CFG_OFFSET: u32 = 0x80;
	pub const ISR_CFG: ConfigAddress = ConfigAddress::from_configuration_address(ISR_CFG_OFFSET);

	const NOTIFY_CFG_OFFSET: u32 = 0x100;
	pub const NOTIFY_CFG: ConfigAddress =
		ConfigAddress::from_configuration_address(NOTIFY_CFG_OFFSET);

	pub const DEVICE_CFG_OFFSET: u32 = 0x180;
	pub const DEVICE_CFG: ConfigAddress =
		ConfigAddress::from_configuration_address(DEVICE_CFG_OFFSET);
}

// TODO: use appropriate constants and offsets
pub const PCICAP_COM: PciCap = PciCap {
	cap_vndr: cfg_type::VENDOR_CFG,
	cap_next: 0x50,
	cap_len: size_of::<PciCap>() as u8,
	cfg_type: cfg_type::COMMON_CFG,
	bar_index: 0,
	id: 0,
	_padding: [0u8; 2],
	offset: offsets::COMMON_CFG.0,
	length: (size_of::<ComCfg>() * 8) as u32,
};

pub const PCICAP_ISR: PciCap = PciCap {
	cap_vndr: cfg_type::VENDOR_CFG,
	cap_next: 0x60,
	cap_len: size_of::<PciCap>() as u8,
	cfg_type: cfg_type::ISR_CFG,
	bar_index: 0,
	id: 0,
	_padding: [0; 2],
	offset: offsets::ISR_CFG.0,
	length: (size_of::<IsrStatus>() * 8) as u32,
};

pub const PCICAP_NOTIF: PciCap = PciCap {
	cap_vndr: cfg_type::VENDOR_CFG,
	cap_next: 0x80,
	cap_len: size_of::<NotifCfg>() as u8,
	cfg_type: cfg_type::NOTIFY_CFG,
	bar_index: 0,
	id: 0,
	_padding: [0; 2],
	offset: offsets::NOTIFY_CFG.0,
	length: (size_of::<NotifCfg>() * 8) as u32,
};

pub const PCICAP_DEV: PciCap = PciCap {
	cap_vndr: cfg_type::VENDOR_CFG,
	cap_next: 0,
	cap_len: size_of::<PciCap>() as u8,
	cfg_type: cfg_type::DEVICE_CFG,
	bar_index: 0,
	id: 0,
	_padding: [0; 2],
	offset: offsets::DEVICE_CFG.0,
	length: (size_of::<PciCap>() * 8) as u32,
};
