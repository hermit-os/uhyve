//! Configuration Structures for Virtio PCI devices

use std::mem::size_of;

use zerocopy::{Immutable, IntoBytes};

use crate::{
	pci::{PciConfigurationOffset, PciError, PciType0ConfigSpaceHeader},
	virtio::{VirtqueueNotification, capabilities::*},
};

/// Helper macro to calculate the byte offset of a field in a struct.
/// offset is a base offset of the struct that is added to the calculation,
/// ty is the struct and field is ty's field to calculate the offset from.
macro_rules! get_offset {
	($offset:expr, $ty:ty, $field:ident) => {
		unsafe {
			let base_ptr: *const _ = std::mem::MaybeUninit::<$ty>::uninit().as_ptr();
			let f: *const _ = std::ptr::addr_of!((*base_ptr).$field);
			crate::pci::PciConfigurationOffset(
				(f as *const u8).offset_from(base_ptr as *const u8) as u8 + $offset as u8,
			)
		}
	};
}
// Make macro visible for uhyve
pub(crate) use get_offset;

/// The default memory layout of the PCI header and the capabilities looks as follows:
/// ```text
///  0x00 ┌─────────────────────────┐
///       │  PCI Header             │────┐
///  0x40 ├─────────────────────────┤◄───┘
///       │  Common Capability      ├────────┐
///  0x50 ├─────────────────────────┤        │
///       │  ISR Capability         ├──────┐ │
///  0x60 ├─────────────────────────┤      │ │
///       │  Notify Capability      ├────┐ │ │
///  0x78 ├─────────────────────────┤    │ │ │
///       │  Device Capability      ├──┐ │ │ │
///  0x88 ├─────────────────────────┤◄─┼─┼─┼─┘
///       │  Common Configuration   │  │ │ │
///  0xC8 ├─────────────────────────┤◄─┼─┼─┘
///       │  ISR Configuration      │  │ │
///  0xD0 ├─────────────────────────┤◄─┼─┘
///       │  Notification Region    │  │
///  0xD8 ├─────────────────────────┤◄─┘
///       │  Device Configuration   │
///  0xF0 └─────────────────────────┘
/// ```
#[derive(Default, Debug, IntoBytes, Immutable)]
#[repr(C)]
pub(crate) struct HeaderConf {
	pub pci_config_hdr: PciType0ConfigSpaceHeader,
	pub common_cap: PciCap,
	pub isr_cap: PciCap,
	pub notify_cap: NotifyCap,
	_padding0: u32,
	pub device_cap: PciCap,
	pub common_cfg: ComCfg,
	pub _isr: IsrStatus,
	_padding1: [u8; 7],
	pub _notif: [VirtqueueNotification; 2],
	pub dev: NetDevCfg,
}
impl HeaderConf {
	pub const HDR_START: u8 = get_offset!(0, HeaderConf, pci_config_hdr).0;
	pub const HDR_END: u8 = Self::COMMON_CAP_START - 1;
	pub const COMMON_CAP_START: u8 = get_offset!(0, HeaderConf, common_cap).0;
	pub const ISR_CAP_START: u8 = get_offset!(0, HeaderConf, isr_cap).0;
	pub const NOTIFY_CAP_START: u8 = get_offset!(0, HeaderConf, notify_cap).0;
	pub const DEVICE_CAP_START: u8 = get_offset!(0, HeaderConf, device_cap).0;
	pub const COMMON_CFG_START: u8 = get_offset!(0, HeaderConf, common_cfg).0;
	pub const ISR_CFG_START: u8 = get_offset!(0, HeaderConf, _isr).0;
	pub const ISR_CFG_END: u8 = Self::NOTIFY_REGION_START - 1;
	pub const NOTIFY_REGION_START: u8 = get_offset!(0, HeaderConf, _notif).0;
	pub const NOTIFY_0: u8 = Self::NOTIFY_REGION_START;
	pub const NOTIFY_1: u8 = Self::NOTIFY_REGION_START + size_of::<VirtqueueNotification>() as u8;
	pub const NOTIFY_REGION_END: u8 = Self::DEVICE_CFG_START - 1;
	pub const DEVICE_CFG_START: u8 = get_offset!(0, HeaderConf, dev).0;
	pub const DEVICE_CFG_END: u8 = Self::DEVICE_CFG_START + size_of::<NetDevCfg>() as u8 - 1;

	/// Provides the empty but linked datastructures for VirtioPCI. See module level description for the internal memory layout.
	pub fn new() -> Self {
		let mut h: Self = Default::default();
		h.pci_config_hdr.capabilities_ptr = Self::COMMON_CAP_START;
		h.common_cap.cap_next = Self::ISR_CAP_START;
		h.common_cap.offset = Self::COMMON_CFG_START as u32;
		h.common_cap.cfg_type = CfgType::COMMON_CFG;
		h.common_cap.length = size_of::<ComCfg>() as u32;

		h.isr_cap.cap_next = Self::NOTIFY_CAP_START;
		h.isr_cap.offset = Self::ISR_CFG_START as u32;
		h.isr_cap.cfg_type = CfgType::ISR_CFG;
		h.isr_cap.length = size_of::<IsrStatus>() as u32;

		h.notify_cap.cap.cap_next = Self::DEVICE_CAP_START;
		h.notify_cap.cap.offset = Self::NOTIFY_REGION_START as u32;
		h.notify_cap.cap.cfg_type = CfgType::NOTIFY_CFG;

		h.device_cap.cap_next = 0;
		h.device_cap.offset = Self::DEVICE_CFG_START as u32;
		h.device_cap.cfg_type = CfgType::DEVICE_CFG;
		h.device_cap.length = size_of::<NetDevCfg>() as u32;

		h
	}

	pub fn read(&self, address: PciConfigurationOffset, dest: &mut [u8]) -> Result<(), PciError> {
		let a = address.0;
		match a {
			Self::ISR_CFG_START..=Self::ISR_CFG_END => unreachable!(),
			Self::NOTIFY_REGION_START..=Self::NOTIFY_REGION_END => unreachable!(),
			0..Self::DEVICE_CFG_END => {
				dest.copy_from_slice(
					&self.as_bytes()[address.0 as usize..address.0 as usize + dest.len()],
				);
				Ok(())
			}

			_ => Err(PciError::InvalidOffset(address)),
		}
	}
	pub fn write(&mut self, address: PciConfigurationOffset, data: &[u8]) -> Result<(), PciError> {
		let a = address.0;
		match a {
			ComCfg::DEVICE_FEATURE_SELECT
			| ComCfg::NUM_QUEUES
			| ComCfg::CONFIG_GENERATION
			| ComCfg::QUEUE_NOTIFY_OFFSET
			| ComCfg::QUEUE_NOTIFY_DATA => Err(PciError::ReadOnlyOffset(address)),
			Self::HDR_START..=Self::HDR_END => self.pci_config_hdr.write(address, data),
			Self::COMMON_CAP_START..=Self::DEVICE_CFG_END => Err(PciError::ReadOnlyOffset(address)),
			_ => Err(PciError::InvalidOffset(address)),
		}
	}
}
