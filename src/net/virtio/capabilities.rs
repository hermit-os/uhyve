//! VirtIO capability structures.

use bitflags::bitflags;
use zerocopy::AsBytes;

use super::pci::ConfigAddress;
use crate::{
	net::{
		BROADCAST_MAC_ADDR, UHYVE_NET_MTU, UHYVE_QUEUE_SIZE,
		virtio::{
			config::cfg_type,
			pci::{COMMON_CFG_START, DEVICE_CFG_START, ISR_CFG_START, get_offset},
		},
	},
	pci::PciError,
	virtqueue::VirtqueueNotification,
};

#[repr(u32)]
#[derive(Clone, Copy, Debug, AsBytes)]
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
impl PciCap {
	pub fn read(&self, address: u8, dest: &mut [u8]) -> Result<(), PciError> {
		if address + dest.len() as u8 > std::mem::size_of::<Self>() as u8 {
			return Err(PciError::InvalidAddress(address as u32));
		}
		match address {
			0..=0x3f => {
				dest.copy_from_slice(
					&self.as_bytes()[address as usize..address as usize + dest.len()],
				);
				Ok(())
			}
			_ => Err(PciError::InvalidAddress(address as u32)),
		}
	}
	pub fn write(&mut self, address: u8, _data: &[u8]) -> Result<(), PciError> {
		Err(PciError::ReadOnlyAccess(address as u32))
	}
}

#[derive(Copy, Clone, Debug, AsBytes, PartialEq, Eq)]
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
/// Virtio device configuration layout.
#[derive(Clone, Debug)]
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
	pub const MAC_ADDRESS: ConfigAddress = get_offset!(DEVICE_CFG_START, NetDevCfg, mac);
	// pub const MAC_ADDRESS_1: ConfigAddress = ConfigAddress(MAC_ADDRESS.0 + 4);
	pub const NET_STATUS: ConfigAddress = get_offset!(DEVICE_CFG_START, NetDevCfg, status);
	pub const MTU: ConfigAddress = get_offset!(DEVICE_CFG_START, NetDevCfg, mtu);
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
impl IsrStatus {
	pub const ISR_FLAGS: ConfigAddress = get_offset!(ISR_CFG_START, IsrStatus, flags);
}

/// Notification location. This is a standard PciCap, followed by an offset multiplier.
///
/// ## Important
///
/// `cap.offset` must be 2-byte aligned, `notify_off_multiplier` must be an even power of 2 or 0.
/// `cap.length` must be at least 2 and larg enough to support queue notification offset.
///
/// See section 4.1.4.4.1 virtio v1.2
#[derive(AsBytes, Clone, Debug)]
#[repr(C)]
// TODO: Rename Notif -> Notify
pub struct NotifyCap {
	pub cap: PciCap,
	/// Combind with queue_notify_off to derive the Queue Notify address
	/// within a BAR for a virtqueue.
	///
	/// For example: if notify_off_multiplier is 0, the same Queue Notify address
	/// is used for all queues. (section 4.1.4.4 virtio v1.2)
	pub notify_off_multiplier: u32,
}
impl NotifyCap {
	pub fn read(&self, address: u8, dest: &mut [u8]) -> Result<(), PciError> {
		if address + dest.len() as u8 > std::mem::size_of::<Self>() as u8 {
			return Err(PciError::InvalidAddress(address as u32));
		}
		match address {
			0..=0x3f => {
				dest.copy_from_slice(
					&self.as_bytes()[address as usize..address as usize + dest.len()],
				);
				Ok(())
			}
			_ => Err(PciError::InvalidAddress(address as u32)),
		}
	}
	pub fn write(&mut self, address: u8, _data: &[u8]) -> Result<(), PciError> {
		Err(PciError::ReadOnlyAccess(address as u32))
	}
}
impl Default for NotifyCap {
	fn default() -> Self {
		Self {
			cap: PciCap {
				cap_len: std::mem::size_of::<NotifyCap>() as u8,
				cfg_type: cfg_type::NOTIFY_CFG,
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
#[derive(AsBytes, Clone, Copy, Debug)]
#[repr(C)]
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
impl ComCfg {
	pub const DEVICE_FEATURE_SELECT: ConfigAddress =
		get_offset!(COMMON_CFG_START, Self, device_feature_select);

	pub const DEVICE_FEATURE: ConfigAddress = get_offset!(COMMON_CFG_START, Self, device_feature);

	pub const DRIVER_FEATURE_SELECT: ConfigAddress =
		get_offset!(COMMON_CFG_START, ComCfg, driver_feature_select);

	pub const DRIVER_FEATURE: ConfigAddress = get_offset!(COMMON_CFG_START, ComCfg, driver_feature);

	pub const CONFIG_MSIX_VECTOR: ConfigAddress =
		get_offset!(COMMON_CFG_START, ComCfg, config_msix_vector);

	pub const DEVICE_STATUS: ConfigAddress = get_offset!(COMMON_CFG_START, ComCfg, device_status);

	pub const QUEUE_SELECT: ConfigAddress = get_offset!(COMMON_CFG_START, ComCfg, queue_select);

	pub const QUEUE_SIZE: ConfigAddress = get_offset!(COMMON_CFG_START, ComCfg, queue_size);

	pub const QUEUE_MSIX_VECTOR: ConfigAddress =
		get_offset!(COMMON_CFG_START, ComCfg, queue_msix_vector);

	pub const QUEUE_ENABLE: ConfigAddress = get_offset!(COMMON_CFG_START, ComCfg, queue_enable);

	pub const QUEUE_NOTIFY_OFFSET: ConfigAddress =
		get_offset!(COMMON_CFG_START, ComCfg, queue_notify_off);

	pub const QUEUE_DESC: ConfigAddress = get_offset!(COMMON_CFG_START, ComCfg, queue_desc);

	pub const QUEUE_DRIVER: ConfigAddress = get_offset!(COMMON_CFG_START, ComCfg, queue_driver);

	pub const QUEUE_DEVICE: ConfigAddress = get_offset!(COMMON_CFG_START, ComCfg, queue_device);

	pub const QUEUE_NOTIFY_DATA: ConfigAddress =
		get_offset!(COMMON_CFG_START, ComCfg, queue_notify_data);

	pub const QUEUE_RESET: ConfigAddress = get_offset!(COMMON_CFG_START, ComCfg, queue_reset);

	pub fn read(&self, address: u8, dest: &mut [u8]) -> Result<(), PciError> {
		if address + dest.len() as u8 > std::mem::size_of::<Self>() as u8 {
			return Err(PciError::InvalidAddress(address as u32));
		}
		const SELF_SIZE: u8 = std::mem::size_of::<ComCfg>() as u8;
		match address {
			SELF_SIZE..=u8::MAX => Err(PciError::InvalidAddress(address as u32)),
			_ => {
				dest.copy_from_slice(
					&self.as_bytes()[address as usize..address as usize + dest.len()],
				);
				Ok(())
			}
		}
	}
	pub fn write(&mut self, address: u8, _data: &[u8]) -> Result<(), PciError> {
		Err(PciError::ReadOnlyAccess(address as u32))
	}
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
			queue_size: UHYVE_QUEUE_SIZE as u16,
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
