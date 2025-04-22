use thiserror::Error;
use zerocopy::AsBytes;

use crate::{
	consts::GUEST_PAGE_SIZE,
	net::{PCI_ETHERNET_REVISION_ID, UHYVE_PCI_CLASS_INFO},
	virtio::{DeviceStatus, VIRTIO_VENDOR_ID},
};

/// For now, use an address large enough to be outside of kvm_userspace,
/// as IO/MMIO writes are otherwise dismissed.
pub const IOBASE: u32 = 0xFE000000;

pub trait PciDevice {
	fn handle_read(&self, address: u32, dest: &mut [u8]);
	fn handle_write(&mut self, address: u32, src: &[u8]);
}

#[derive(Error, Debug)]
pub enum PciError {
	#[error("Trying to write to read_only memory (PCI space address: {0:#x})")]
	ReadOnlyAccess(u32),
	#[error("Trying to access invalid address ({0:#x})")]
	InvalidAddress(u32),
	#[error("Unaligned Access to a PCI struct ({0:#x})")]
	UnalignedAccess(u32),
	#[error("Read/Write data is not a power of two")]
	InvalidAccessSize,
}

#[derive(AsBytes, Clone, Copy, Debug, Default)]
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
#[derive(AsBytes, Clone, Copy, Debug)]
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
	pub fn read(&self, address: u8, dest: &mut [u8]) -> Result<(), PciError> {
		if address + dest.len() as u8 > 0x40 {
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

	pub fn write(&mut self, address: u8, data: &[u8]) -> Result<(), PciError> {
		if address + data.len() as u8 > 0x40 {
			return Err(PciError::InvalidAddress(address as u32));
		}
		match address {
			0..=0x03 | 0x06..=0x0F | 0x28..=0x33 | 0x35..=0x3B => {
				Err(PciError::InvalidAddress(address as u32))
			}
			0x04 => {
				// Command register
				self.command = u16::from_le_bytes([data[0], data[1]]);
				Ok(())
			}
			0x10 | 0x18 | 0x20 => {
				self.base_address_registers[((address - 0x10) / 8) as usize].write(data)
			}
			0x14 | 0x1c | 0x24 => {
				self.base_address_registers[((address - 0x14) / 8) as usize].write_upper(data)
			}
			0x05
			| 0x11..=0x13
			| 0x15..=0x17
			| 0x19..=0x1B
			| 0x1d..=0x1f
			| 0x21..=0x23
			| 0x25..=0x27 => {
				warn!("Unaligned PCI BAR access");
				Err(PciError::UnalignedAccess(address as u32))
			}
			0x34 => {
				self.capabilities_ptr = data[0];
				Ok(())
			}
			_ => Err(PciError::InvalidAddress(address as u32)),
		}
	}
}
