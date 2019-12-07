use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

const VENDOR_ID_REGISTER: usize = 0x0;
const DEVICE_ID_REGISTER: usize = 0x2;
const _COMMAND_REGISTER: usize = 0x4;
const STATUS_REGISTER: u32 = 0x6;
const CLASS_REGISTER: usize = 0x8;
const _BAR0_REGISTER: usize = 0x10;
const _SUBSYSTEM_VENDOR_ID_REGISTER: usize = 0x2C;
const _SUBSYSTEM_ID_REGISTER: usize = 0x2E;
const _INTERRUPT_REGISTER: usize = 0x3C;
const IOBASE: u16 = 0xC000;
const VIRTIO_PCI_HOST_FEATURES: u16 = 0;
const VIRTIO_PCI_GUEST_FEATURES: u16 = 4;
const VIRTIO_PCI_QUEUE_PFN: u16 = IOBASE + 8;
const VIRTIO_PCI_QUEUE_NUM: u16 = IOBASE + 12;
const VIRTIO_PCI_QUEUE_SEL: u16 = IOBASE + 14;
const VIRTIO_PCI_QUEUE_NOTIFY: u16 = IOBASE + 16;
const VIRTIO_PCI_STATUS: u16 = IOBASE + 18;
const VIRTIO_PCI_ISR: u16 = 19;

pub trait PciDevice {
	fn handle_read(&self, address: u32, dest: &mut [u8]) -> ();
	fn handle_write(&mut self, address: u32, src: &[u8]) -> ();
}

type PciRegisters = [u8; 0x40];

pub struct VirtioNetPciDevice {
	registers: PciRegisters, //Add more
	requested_features: Option<u32>,
	selected_queue_num: Option<u16>,
}

impl fmt::Debug for VirtioNetPciDevice {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "Useless")
	}
}

macro_rules! read_u16 {
	($registers:expr, $address:expr) => {
		($registers[$address] as u16) | ($registers[$address + 1] as u16) << 8
	};
}

macro_rules! write_u16 {
	($registers:expr, $address:expr, $value:expr) => {
		$registers[$address] = ($value & 0xFF) as u8;
		$registers[$address + 1] = (($value >> 8) & 0xFF) as u8;
			()
	};
}

#[macro_export]
macro_rules! read_u32 {
	($registers:expr, $address:expr) => {
		($registers[$address] as u32)
			| (($registers[$address + 1] as u32) << 8)
			| (($registers[$address + 2] as u32) << 16)
			| (($registers[$address + 3] as u32) << 24)
	};
}

macro_rules! write_u32 {
	($registers:expr, $address:expr, $value:expr) => {
		$registers[$address] = ($value & 0xFF) as u8;
		$registers[$address + 1] = (($value >> 8) & 0xFF) as u8;
		$registers[$address + 2] = (($value >> 16) & 0xFF) as u8;
		$registers[$address + 3] = (($value >> 24) & 0xFF) as u8;
			()
	};
}

impl VirtioNetPciDevice {
	pub const fn new() -> VirtioNetPciDevice {
		let mut registers: PciRegisters = [0; 0x40];
		write_u16!(registers, VENDOR_ID_REGISTER, 0x1AF4 as u16);
		write_u16!(registers, DEVICE_ID_REGISTER, 0x1000 as u16);
		write_u16!(registers, CLASS_REGISTER + 2, 0x0200 as u16);
		VirtioNetPciDevice {
			registers,
			requested_features: None,
			selected_queue_num: None,
		}
	}

	pub fn handle_notify_output(&mut self, dest: &mut [u8]) {
		// TODO: Validate state and send packets, etc.
	}

	pub fn read_status(&self, dest: &mut [u8]) {
		self.handle_read(STATUS_REGISTER & 0x3FFF, dest);
	}

	pub fn write_status(&mut self, dest: &[u8]) {
		// TODO: Status transition logic.
		self.handle_write(STATUS_REGISTER & 0x3FFF, dest)
	}

	pub fn write_selected_queue(&mut self, dest: &[u8]) {
		self.selected_queue_num = Some(unsafe { *(dest.as_ptr() as *const u16) })
	}

	pub fn write_pfn(&mut self, dest: &[u8]) {
		match self.selected_queue_num {
			Some(value) => {
				// TODO: Verify that creating a queue at selection is legal.
				// TODO: Create the queue using the given physical address.
			}
			None => error!("virtio write_pfn: Attempted to register before selecting a queue.");
		}
	}

	pub fn write_requested_features(&self, dest: &mut [u8]) {
		// TODO: And requested and host features, store in requested_features
	}

	pub fn read_requested_features(&self, dest: &mut [u8]) {
		// TODO: Write requested_features to dest if they exist. Error if not requested?
	}

	pub fn read_host_features(&self, dest: &mut [u8]) {
		// TODO: Write features supported by device to dest.
	}

	pub fn reset_interrupt(&self) {
		// TODO
	}
}

impl PciDevice for VirtioNetPciDevice {
	fn handle_read(&self, address: u32, dest: &mut [u8]) -> () {
		for i in 0..dest.len() {
			dest[i] = self.registers[(address as usize) + i];
		}
		()
	}

	fn handle_write(&mut self, address: u32, dest: &[u8]) -> () {
		for (i, var) in dest.iter().enumerate() {
			self.registers[(address as usize) + i] = *var;
		}

		//Case statement to determine what was updated
		()
	}
}
