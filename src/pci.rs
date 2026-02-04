use std::ops::Add;

use thiserror::Error;
use uhyve_interface::GuestPhysAddr;
use zerocopy::{Immutable, IntoBytes};

use crate::{
	consts::GUEST_PAGE_SIZE,
	net::{PCI_ETHERNET_REVISION_ID, UHYVE_PCI_CLASS_INFO},
	virtio::{DeviceStatus, VIRTIO_VENDOR_ID},
};

/// For now, use an address large enough to be outside of kvm_userspace,
/// as IO/MMIO writes are otherwise dismissed.
// pub const IOBASE: u64 = 0xFE000000;
pub const IOBASE_U64: u64 = 0xFE000000;
pub const IOBASE: GuestPhysAddr = GuestPhysAddr::new(IOBASE_U64);
pub const IOEND_U64: u64 = IOBASE.as_u64() + (1_u64 << 24); // Configuration space address length is 24 (PCI Bus Local Spec 3.2.2.3.2)
pub const IOEND: GuestPhysAddr = GuestPhysAddr::new(IOEND_U64);

/// An address in the PCI configuration space.
/// (PCI Bus Local Specification 3.2.2.3)
/// These addresses are 24-bit long, and the last two bytes specify the transaction type.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct PciConfigurationAddress(pub(crate) u32);
impl Add<usize> for PciConfigurationAddress {
	type Output = Self;

	fn add(self, rhs: usize) -> Self::Output {
		PciConfigurationAddress(self.0 + rhs as u32)
	}
}
impl PciConfigurationAddress {
	pub const fn new(address: u32) -> Self {
		Self(address)
	}

	pub fn from_guest_address(address: GuestPhysAddr) -> Option<Self> {
		if address & 0b11 != 0 {
			warn!("PciConfigurationAddress not at word boundary");
		}

		if address < IOBASE || address >= IOEND {
			return None;
		}
		Some(Self((address - IOBASE) as u32))
	}

	pub fn guest_address(&self) -> GuestPhysAddr {
		IOBASE + self.0 as u64
	}

	pub fn offset(&self) -> PciConfigurationOffset {
		PciConfigurationOffset((self.0 & 0b1111_1111) as u8)
	}
}

/// The offset is the effective addressing within a PCI function
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct PciConfigurationOffset(pub(crate) u8);

pub trait PciDevice {
	fn handle_read(&mut self, address: PciConfigurationAddress, dest: &mut [u8]);
	fn handle_write(&mut self, address: PciConfigurationAddress, src: &[u8]);
}

#[derive(Error, Debug)]
pub enum PciError {
	#[error("Trying to write to function's read_only field ({:#x})", .0.0)]
	ReadOnlyOffset(PciConfigurationOffset),
	#[error("Trying to access function at invalid offset ({:#x})", .0.0)]
	InvalidOffset(PciConfigurationOffset),
	#[error("Unaligned Access to a PCI struct ({:#x})", .0.0)]
	UnalignedAccess(PciConfigurationOffset),
	#[error("Read/Write data is not a power of two")]
	InvalidAccessSize,
}

#[derive(IntoBytes, Clone, Copy, Debug, Default, Immutable)]
#[repr(C)]
pub struct MemoryBar64 {
	address: u64,
}
impl MemoryBar64 {
	pub fn new(address: u64) -> Self {
		// BAR size is 0x200000
		assert_eq!(address, address & -(GUEST_PAGE_SIZE as i64) as u64);
		Self {
			address: address | 0b1100,
		}
	}
	// pub fn read(&self) -> u64 {
	// 	self.address
	// }
	// pub fn read_upper(&self) -> u32 {
	// 	(self.address >> 32) as u32
	// }
	// pub fn read_lower(&self) -> u32 {
	// 	self.address as u32
	// }

	pub fn write(&mut self, data: &[u8]) -> Result<(), PciError> {
		// BAR0 -> BAR detection writes something to this register and reads it back. We protect the lowest bits to ensure it stays a 64-Bit address field

		let addr_lower = self.address & (GUEST_PAGE_SIZE - 1);
		let d = match data.len() {
			1 | 2 => return Ok(()), // This is smaller than GUEST_PAGE_SIZE -> Ignore it
			4 => u64::from_le_bytes([data[0], data[1], data[2], data[3], 0, 0, 0, 0]),
			8 => u64::from_le_bytes([
				data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
			]),
			_ => return Err(PciError::InvalidAccessSize),
		};
		self.address = (d & -(GUEST_PAGE_SIZE as i64) as u64) + addr_lower;
		Ok(())
	}

	pub fn write_upper(&mut self, data: &[u8]) -> Result<(), PciError> {
		let mut addr_bytes = self.address.to_le_bytes();
		for (d, c) in data.iter().zip(addr_bytes.iter_mut().skip(4)) {
			*c = *d;
		}
		self.address = u64::from_le_bytes(addr_bytes);
		Ok(())
	}
}

/// Type 0 Configuration Space Header.
/// PCIe Base Specification Section 7.5.2
#[derive(IntoBytes, Clone, Copy, Debug, Immutable)]
#[repr(C)]
pub struct PciType0ConfigSpaceHeader {
	pub vendor_id: u16,
	pub device_id: u16,
	pub command: u16,
	pub status: DeviceStatus,
	pub revision: u8,
	pub class_code: [u8; 3],
	pub cache_line_size: u8,
	pub master_latency_timr: u8,
	pub header_type: u8,
	pub bist: u8,
	pub base_address_registers: [MemoryBar64; 3],
	pub cardbus_cis_pointer: u32,
	pub subsystem_vendor_id: u16,
	pub subsystem_id: u16,
	pub expansion_rom_base_address: u32,
	pub capabilities_ptr: u8,
	pub _reserved: [u8; 7],
	pub interrupt_line: u8,
	pub interrupt_pin: u8,
	pub min_gnt: u8,
	pub max_lat: u8,
}
impl Default for PciType0ConfigSpaceHeader {
	fn default() -> Self {
		Self {
			vendor_id: VIRTIO_VENDOR_ID,
			device_id: 0,
			command: 0,
			status: DeviceStatus::UNINITIALIZED,
			revision: PCI_ETHERNET_REVISION_ID,
			class_code: UHYVE_PCI_CLASS_INFO,
			cache_line_size: 0,
			master_latency_timr: 0,
			header_type: 0,
			bist: 0,
			base_address_registers: [MemoryBar64::new(0); 3],
			cardbus_cis_pointer: 0,
			subsystem_vendor_id: 0,
			subsystem_id: 0,
			expansion_rom_base_address: 0,
			capabilities_ptr: 0,
			_reserved: [0; 7],
			interrupt_line: 0,
			interrupt_pin: 0,
			min_gnt: 0,
			max_lat: 0,
		}
	}
}
impl PciType0ConfigSpaceHeader {
	pub fn write(&mut self, offset: PciConfigurationOffset, data: &[u8]) -> Result<(), PciError> {
		if offset.0 + data.len() as u8 > 0x40 {
			return Err(PciError::InvalidOffset(offset));
		}
		match offset.0 {
			0..=0x03 | 0x06..=0x0F | 0x28..=0x33 | 0x35..=0x3B => {
				Err(PciError::InvalidOffset(offset))
			}
			0x04 => {
				// Command register
				self.command = u16::from_le_bytes([data[0], data[1]]);
				Ok(())
			}
			0x10 | 0x18 | 0x20 => {
				self.base_address_registers[((offset.0 - 0x10) / 8) as usize].write(data)
			}
			0x14 | 0x1c | 0x24 => {
				self.base_address_registers[((offset.0 - 0x14) / 8) as usize].write_upper(data)
			}
			0x05
			| 0x11..=0x13
			| 0x15..=0x17
			| 0x19..=0x1B
			| 0x1d..=0x1f
			| 0x21..=0x23
			| 0x25..=0x27 => {
				warn!("Unaligned PCI BAR access");
				Err(PciError::UnalignedAccess(offset))
			}
			0x34 => {
				self.capabilities_ptr = data[0];
				Ok(())
			}
			_ => Err(PciError::InvalidOffset(offset)),
		}
	}
}
