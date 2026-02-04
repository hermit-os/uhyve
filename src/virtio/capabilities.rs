//! VirtIO capability structures.

use bitflags::bitflags;
use zerocopy::{Immutable, IntoBytes};

use crate::{
	net::{BROADCAST_MAC_ADDR, UHYVE_NET_MTU},
	pci::PciConfigurationOffset,
	virtio::{
		VirtqueueNotification,
		pci::{HeaderConf, get_offset},
	},
};

/// Virtio capability type IDs. See section 4.1.4 virtio v1.2
#[derive(Debug, Clone, Copy, IntoBytes, PartialEq, Eq, Immutable)]
#[repr(u8)]
#[allow(non_camel_case_types, dead_code)]
pub enum CfgType {
	INVALID_CFG = 0x00,
	/// Common configuration
	COMMON_CFG = 0x01,
	/// Notifications
	NOTIFY_CFG = 0x02,
	/// ISR status
	ISR_CFG = 0x03,
	/// Device-specific configuration
	DEVICE_CFG = 0x04,
	/// PCI configuration access
	PCI_CFG = 0x05,
	/// Shared memory region
	_SHARED_MEMORY_CFG = 0x08,
	/// Vendor-specific data
	VENDOR_CFG = 0x09,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, IntoBytes, Immutable)]
pub enum FeatureSelector {
	Low = 0,
	High = 1,
}

impl From<u32> for FeatureSelector {
	fn from(value: u32) -> Self {
		match value {
			0 => Self::Low,
			1 => Self::High,
			_ => Self::Low, // TODO, should this panic, or should we set to an invalid value?
		}
	}
}

/// Vendor-specific PCI capability.
/// Section 4.1.4 virtio v1.2
#[derive(IntoBytes, Clone, Copy, Debug, Immutable)]
#[repr(C)]
pub struct PciCap {
	/// Generic PCI field: PCI_CAP_ID_VNDR
	cap_vndr: u8,

	/// Generic PCI field: next ptr
	pub cap_next: u8,

	/// Generic PCI field: capability length
	pub cap_len: u8,

	/// Identifies the structure. See [`crate::net::virtio::config::cfg_type`]
	pub cfg_type: CfgType,

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
			cap_vndr: 0x09, // Virtio v1.2 Sec. 4.1.4
			cap_next: 0,
			cap_len: std::mem::size_of::<PciCap>() as u8,
			cfg_type: CfgType::INVALID_CFG,
			bar_index: 0,
			id: 0,
			_padding: [0u8; 2],
			offset: 0,
			length: 0,
		}
	}
}

#[derive(Copy, Clone, Debug, IntoBytes, PartialEq, Eq, Immutable)]
#[repr(C)]
pub struct NetDevStatus(u16);
bitflags! {
	impl NetDevStatus: u16 {
		const UNINITIALIZED = 0;
		const VIRTIO_NET_S_LINK_UP = 1;
		const VIRTIO_NET_S_ANNOUNCE = 2;
	}
}

// TODO: Replace with virtio_bindings::Virtio_net_config?
/// Virtio device configuration layout. Virtio v1.2 Section 5.1.4
#[derive(IntoBytes, Clone, Debug, Immutable)]
#[repr(C)]
pub struct NetDevCfg {
	/// **read-only**: macaddress, always exists.
	pub mac: [u8; 6],

	/// **read-write** Status field: VIRTIO_NET_S_LINK_UP and VIRTIO_NET_S_ANNOUNCE.
	pub status: NetDevStatus,

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
impl NetDevCfg {
	pub const MAC_ADDRESS: u8 = get_offset!(HeaderConf::DEVICE_CFG_START, NetDevCfg, mac).0;
	pub const MAC_ADDRESS_END: u8 = get_offset!(HeaderConf::DEVICE_CFG_START, NetDevCfg, mac).0 + 6;
	pub const NET_STATUS: u8 = get_offset!(HeaderConf::DEVICE_CFG_START, NetDevCfg, status).0;
	pub const MTU: u8 = get_offset!(HeaderConf::DEVICE_CFG_START, NetDevCfg, mtu).0;
}

impl Default for NetDevCfg {
	fn default() -> Self {
		Self {
			mac: BROADCAST_MAC_ADDR,
			status: NetDevStatus::UNINITIALIZED,
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
/// for INT#x interrupt handling. The offset has no alignment requirements. See Virtio v1.2 Sec. 4.1.4.5.
///
/// See section 4.1.5.3 and 4.1.5.4 on usage.
#[derive(Copy, Clone, Debug, IntoBytes, PartialEq, Eq, Default, Immutable)]
#[repr(C)]
pub struct IsrStatus(u8);
bitflags! {
	impl IsrStatus: u8 {
		/// Notify that the buffers/Virtqueues have been changed
		const NOTIFY_USED_BUFFER = 0b01;
		/// Notify that the device configuration has been changed.
		const NOTIFY_CONFIGURUTION_CHANGED = 0b10;
	}
}
impl IsrStatus {
	pub const ISR_FLAGS: u8 = PciConfigurationOffset(HeaderConf::ISR_CFG_START).0;
}

/// Notification location. This is a standard PciCap, followed by an offset multiplier.
///
/// ## Important
///
/// `cap.offset` must be 2-byte aligned, `notify_off_multiplier` must be an even power of 2 or 0.
/// `cap.length` must be at least 2 and larg enough to support queue notification offset.
///
/// See section 4.1.4.4.1 virtio v1.2
#[derive(IntoBytes, Clone, Debug, Immutable)]
#[repr(C)]
pub struct NotifyCap {
	pub cap: PciCap,
	/// Combind with queue_notify_off to derive the Queue Notify address
	/// within a BAR for a virtqueue.
	///
	/// For example: if notify_off_multiplier is 0, the same Queue Notify address
	/// is used for all queues. (section 4.1.4.4 virtio v1.2)
	pub notify_off_multiplier: u32,
}

impl Default for NotifyCap {
	fn default() -> Self {
		Self {
			cap: PciCap {
				cap_len: std::mem::size_of::<NotifyCap>() as u8,
				cfg_type: CfgType::NOTIFY_CFG,
				offset: 0,
				// We have two notification addresses. TODO: We prob. only need one
				length: std::mem::size_of::<VirtqueueNotification>() as u32 * 2,
				..Default::default()
			},
			notify_off_multiplier: 0,
		}
	}
}

/// Common configuration, section 4.1.4.3 virtio v1.2
///
/// All data should be treated as little-endian.
#[derive(IntoBytes, Clone, Copy, Debug, Immutable)]
#[repr(C)]
#[allow(dead_code)]
pub struct ComCfg {
	/// **read-write**: The driver uses this to select device_feature.
	///
	/// Values may only be 0 for feature bits 0-31, or one for feature bits 32-63.
	pub device_feature_select: FeatureSelector,

	/// **read-only**: The driver reads the currently activated feature bits.
	///
	/// See: [`crate::virtio-bindings`] for `VIRTIO_NET_F_*` feature flags
	pub device_feature: u32,

	/// **read-write**: The driver uses this to report which feature bits it is offering.
	pub driver_feature_select: FeatureSelector,

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

	/// **read-only** for driver: The driver will use this value to put it in the ’virtqueue number’ field
	/// in the available buffer notification structure.
	///  This field exists only if VIRTIO_F_NOTIF_CONFIG_DATA has been negotiated.
	pub queue_notify_data: u16,

	/// ***read-write**: The driver uses this to selectively reset the queue.
	/// This field exists only if VIRTIO_F_RING_RESET has been negotiated.
	pub queue_reset: u16,

	_padding: [u8; 4],
}
#[allow(dead_code)]
impl ComCfg {
	pub const DEVICE_FEATURE_SELECT: u8 =
		get_offset!(HeaderConf::COMMON_CFG_START, Self, device_feature_select).0;

	pub const DEVICE_FEATURE: u8 =
		get_offset!(HeaderConf::COMMON_CFG_START, Self, device_feature).0;

	pub const DRIVER_FEATURE_SELECT: u8 =
		get_offset!(HeaderConf::COMMON_CFG_START, Self, driver_feature_select).0;

	pub const DRIVER_FEATURE: u8 =
		get_offset!(HeaderConf::COMMON_CFG_START, Self, driver_feature).0;

	pub const NUM_QUEUES: u8 = get_offset!(HeaderConf::COMMON_CFG_START, Self, num_queues).0;

	pub const CONFIG_MSIX_VECTOR: u8 =
		get_offset!(HeaderConf::COMMON_CFG_START, Self, config_msix_vector).0;

	pub const DEVICE_STATUS: u8 = get_offset!(HeaderConf::COMMON_CFG_START, Self, device_status).0;

	pub const CONFIG_GENERATION: u8 =
		get_offset!(HeaderConf::COMMON_CFG_START, Self, config_generation).0;

	pub const QUEUE_SELECT: u8 = get_offset!(HeaderConf::COMMON_CFG_START, Self, queue_select).0;

	pub const QUEUE_SIZE: u8 = get_offset!(HeaderConf::COMMON_CFG_START, Self, queue_size).0;

	pub const QUEUE_MSIX_VECTOR: u8 =
		get_offset!(HeaderConf::COMMON_CFG_START, Self, queue_msix_vector).0;

	pub const QUEUE_ENABLE: u8 = get_offset!(HeaderConf::COMMON_CFG_START, Self, queue_enable).0;

	pub const QUEUE_NOTIFY_OFFSET: u8 =
		get_offset!(HeaderConf::COMMON_CFG_START, Self, queue_notify_off).0;

	pub const QUEUE_DESC_LOW: u8 = get_offset!(HeaderConf::COMMON_CFG_START, Self, queue_desc).0;
	pub const QUEUE_DESC_HIGH: u8 =
		get_offset!(HeaderConf::COMMON_CFG_START, Self, queue_desc).0 + 4;

	pub const QUEUE_DRIVER_LOW: u8 =
		get_offset!(HeaderConf::COMMON_CFG_START, Self, queue_driver).0;
	pub const QUEUE_DRIVER_HIGH: u8 =
		get_offset!(HeaderConf::COMMON_CFG_START, Self, queue_driver).0 + 4;

	pub const QUEUE_DEVICE_LOW: u8 =
		get_offset!(HeaderConf::COMMON_CFG_START, Self, queue_device).0;
	pub const QUEUE_DEVICE_HIGH: u8 =
		get_offset!(HeaderConf::COMMON_CFG_START, Self, queue_device).0 + 4;

	pub const QUEUE_NOTIFY_DATA: u8 =
		get_offset!(HeaderConf::COMMON_CFG_START, Self, queue_notify_data).0;

	pub const QUEUE_RESET: u8 = get_offset!(HeaderConf::COMMON_CFG_START, Self, queue_reset).0;
}

impl Default for ComCfg {
	fn default() -> Self {
		Self {
			device_feature_select: FeatureSelector::Low,
			device_feature: 0,
			driver_feature_select: FeatureSelector::Low,
			driver_feature: 0,
			config_msix_vector: super::VIRTIO_MSI_NO_VECTOR,
			num_queues: 0,
			device_status: 0,
			config_generation: 0,
			queue_select: 0,
			queue_size: 0,
			queue_msix_vector: 0,
			queue_enable: 0,
			// we will use the same address for all queues, since we only have 2. TODO
			queue_notify_off: 0,
			queue_desc: 0,
			queue_driver: 0,
			queue_device: 0,
			queue_notify_data: 0,
			queue_reset: 0,
			_padding: Default::default(),
		}
	}
}
