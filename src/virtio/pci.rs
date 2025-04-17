//! Configuration Structures for Virtio PCI devices

use std::{mem::size_of, ops::Add};

use align_address::u8_align_up;

use crate::{
	pci::{IOBASE, PciError, PciType0ConfigSpaceHeader},
	virtio::{capabilities::*, virtqueue::VirtqueueNotification},
};

pub const HDR_END: u8 = size_of::<PciType0ConfigSpaceHeader>() as u8 - 1;

pub const COMMON_CAP_START: u8 = size_of::<PciType0ConfigSpaceHeader>() as u8;
pub const COMMON_CAP_END: u8 = ISR_CAP_START - 1;

pub const ISR_CAP_START: u8 = COMMON_CAP_START + size_of::<PciCap>() as u8;
pub const ISR_CAP_END: u8 = NOTIFY_CAP_START - 1;

pub const NOTIFY_CAP_START: u8 = ISR_CAP_START + size_of::<PciCap>() as u8;
pub const NOTIFY_CAP_END: u8 = DEVICE_CAP_START - 1;

pub const DEVICE_CAP_START: u8 = NOTIFY_CAP_START + size_of::<NotifyCap>() as u8;
pub const DEVICE_CAP_END: u8 = COMMON_CFG_START - 1;

pub const COMMON_CFG_START: u8 = DEVICE_CAP_START + size_of::<PciCap>() as u8;
pub const COMMON_CFG_END: u8 = ISR_CFG_START - 1;

pub const ISR_CFG_START: u8 = COMMON_CFG_START + size_of::<ComCfg>() as u8;
pub const ISR_CFG_END: u8 = NOTIFY_REGION_START - 1;

// The notification capabilite refers to the notification region directly
pub const NOTIFY_REGION_START: u8 = u8_align_up(
	ISR_CFG_START + size_of::<IsrStatus>() as u8,
	size_of::<u32>() as u8,
);
pub const MEM_NOTIFY: ConfigAddress =
	ConfigAddress::from_configuration_address(NOTIFY_REGION_START as u32);
pub const MEM_NOTIFY_1: ConfigAddress = ConfigAddress::from_configuration_address(
	NOTIFY_REGION_START as u32 + size_of::<VirtqueueNotification>() as u32,
);
pub const NOTIFY_REGION_END: u8 =
	NOTIFY_REGION_START + 2 * size_of::<VirtqueueNotification>() as u8 - 1;

pub const DEVICE_CFG_START: u8 = u8_align_up(NOTIFY_REGION_END + 1, size_of::<u32>() as u8);
pub const DEVICE_CFG_END: u8 = DEVICE_CFG_START + size_of::<NetDevCfg>() as u8 - 1;

/// An address in the PCI configuration space.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct ConfigAddress(pub(crate) u32);

impl Add<usize> for ConfigAddress {
	type Output = Self;

	fn add(self, rhs: usize) -> Self::Output {
		ConfigAddress(self.0 + rhs as u32)
	}
}

impl ConfigAddress {
	pub const fn from_configuration_address(address: u32) -> Self {
		Self(address)
	}

	pub fn from_guest_address(address: u64) -> Option<Self> {
		if address < IOBASE as u64 {
			return None;
		}
		let a = address as u32 - IOBASE;
		if a >= DEVICE_CFG_END as u32 {
			None
		} else {
			Some(Self(a))
		}
	}

	pub fn guest_address(&self) -> u64 {
		(self.0 + IOBASE).into()
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
// Make macro visible for uhyve
pub(crate) use get_offset;

/// The default memory layout of the PCI header and the capabilities looks as follows:
/// ```
///  0x00 ┌─────────────────────────┐
///       │  PCI Header             │────┐
///  0x40 ├─────────────────────────┤◄───┘
///       │  Common Capability      ├────────┐
///  0x50 ├─────────────────────────┤        │
///       │  ISR Capability         ├──────┐ │
///  0x60 ├─────────────────────────┤      │ │
///       │  Notify Capability      ├────┐ │ │
///  0x74 ├─────────────────────────┤    │ │ │
///       │  Device Capability      ├──┐ │ │ │
///  0x84 ├─────────────────────────┤◄─┼─┼─┼─┘
///       │  Common Configuration   │  │ │ │
///  0xC4 ├─────────────────────────┤◄─┼─┼─┘
///       │  ISR Configuration      │  │ │
///  0xC8 ├─────────────────────────┤◄─┼─┘
///       │  Notification Region    │  │
///  0xD0 ├─────────────────────────┤◄─┘
///       │  Device Configuration   │
///  0xE8 └─────────────────────────┘
/// ```
#[derive(Default, Debug)]
#[repr(C)]
pub(crate) struct HeaderConf {
	pub pci_config_hdr: PciType0ConfigSpaceHeader,
	pub common_cap: PciCap,
	pub isr_cap: PciCap,
	pub notify_cap: NotifyCap,
	pub device_cap: PciCap,
	pub common_cfg: ComCfg,
	pub _isr: IsrStatus,
	pub _notif: [VirtqueueNotification; 2],
	pub dev: NetDevCfg,
}
impl HeaderConf {
	/// Provides the empty but linked datastructures for VirtioPCI. See module level description for the internal memory layout.
	pub fn new() -> Self {
		let mut h: Self = Default::default();
		h.pci_config_hdr.capabilities_ptr = COMMON_CAP_START;
		h.common_cap.cap_next = ISR_CAP_START;
		h.common_cap.offset = COMMON_CFG_START as u32;
		h.common_cap.cfg_type = CfgType::COMMON_CFG;
		h.common_cap.length = size_of::<ComCfg>() as u32;

		h.isr_cap.cap_next = NOTIFY_CAP_START;
		h.isr_cap.offset = ISR_CFG_START as u32;
		h.isr_cap.cfg_type = CfgType::ISR_CFG;
		h.isr_cap.length = size_of::<IsrStatus>() as u32;

		h.notify_cap.cap.cap_next = DEVICE_CAP_START;
		h.notify_cap.cap.offset = NOTIFY_REGION_START as u32;
		h.notify_cap.cap.cfg_type = CfgType::NOTIFY_CFG;

		h.device_cap.cap_next = 0;
		h.device_cap.offset = DEVICE_CFG_START as u32;
		h.device_cap.cfg_type = CfgType::DEVICE_CFG;
		h.device_cap.length = size_of::<NetDevCfg>() as u32;

		h
	}

	pub fn read(&self, address: u32, dest: &mut [u8]) -> Result<(), PciError> {
		if address > u8::MAX as u32 {
			return Err(PciError::InvalidAddress(address));
		}
		let a = address as u8;
		match a {
			0..=HDR_END => self.pci_config_hdr.read(a, dest),
			COMMON_CAP_START..=COMMON_CAP_END => self.common_cap.read(a - COMMON_CAP_START, dest),
			ISR_CAP_START..=ISR_CAP_END => self.isr_cap.read(a - ISR_CAP_START, dest),
			NOTIFY_CAP_START..=NOTIFY_CAP_END => self.notify_cap.read(a - NOTIFY_CAP_START, dest),
			DEVICE_CAP_START..=DEVICE_CAP_END => self.device_cap.read(a - DEVICE_CAP_START, dest),
			COMMON_CFG_START..=COMMON_CFG_END => self.common_cfg.read(a - COMMON_CFG_START, dest),
			ISR_CFG_START..=ISR_CFG_END => unreachable!(),
			NOTIFY_REGION_START..=NOTIFY_REGION_END => unreachable!(),
			DEVICE_CFG_START..=DEVICE_CFG_END => self.common_cap.read(a - DEVICE_CFG_START, dest),

			_ => Err(PciError::InvalidAddress(address)),
		}
	}
	pub fn write(&mut self, address: u32, data: &[u8]) -> Result<(), PciError> {
		if address > u8::MAX as u32 {
			return Err(PciError::InvalidAddress(address));
		}
		let a = address as u8;
		match a {
			0..=HDR_END => self.pci_config_hdr.write(a, data),
			COMMON_CAP_START..=COMMON_CAP_END => self.common_cap.write(a - COMMON_CAP_START, data),
			ISR_CAP_START..=ISR_CAP_END => self.common_cap.write(a - ISR_CAP_START, data),
			NOTIFY_CAP_START..=NOTIFY_CAP_END => self.common_cap.write(a - NOTIFY_CAP_START, data),
			DEVICE_CAP_START..=DEVICE_CAP_END => self.common_cap.write(a - DEVICE_CAP_START, data),
			COMMON_CFG_START..=COMMON_CFG_END => self.common_cap.write(a - COMMON_CFG_START, data),
			ISR_CFG_START..=ISR_CFG_END => self.common_cap.write(a - ISR_CFG_START, data),
			NOTIFY_REGION_START..=NOTIFY_REGION_END => {
				self.common_cap.write(a - NOTIFY_REGION_START, data)
			}
			DEVICE_CFG_START..=DEVICE_CFG_END => self.common_cap.write(a - DEVICE_CFG_START, data),
			_ => Err(PciError::InvalidAddress(address)),
		}
	}
}
