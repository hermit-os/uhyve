use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::vec::Vec;
use linux::virtqueue::Virtqueue;
extern crate tun_tap;
use self::tun_tap::*;
extern crate virtio_bindings;
use self::virtio_bindings::bindings::virtio_net::*;

#[repr(u8)]
enum Status {
    ACKNOWLEDGE = 1,
    DRIVE = 2,
    FAILED = 128,
    FEATURES_OK = 8,
    DRIVER_OK = 4,
    DRIVE_NEEDS_RESET = 64,
}


const VENDOR_ID_REGISTER: usize = 0x0;
const DEVICE_ID_REGISTER: usize = 0x2;
const _COMMAND_REGISTER: usize = 0x4;
const STATUS_REGISTER: u32 = 0x6;
const CLASS_REGISTER: usize = 0x8;
const BAR0_REGISTER: usize = 0x10;
const _SUBSYSTEM_VENDOR_ID_REGISTER: usize = 0x2C;
const _SUBSYSTEM_ID_REGISTER: usize = 0x2E;
const _INTERRUPT_REGISTER: usize = 0x3C;
const RX_QUEUE: usize = 0;
const TX_QUEUE: usize = 1;
const IOBASE: u16 = 0xc000;
const VIRTIO_PCI_HOST_FEATURES: u16 = IOBASE;
const VIRTIO_PCI_GUEST_FEATURES: u16 = IOBASE + 4;
const VIRTIO_PCI_QUEUE_PFN: u16 = IOBASE + 8;
const VIRTIO_PCI_QUEUE_NUM: u16 = IOBASE + 12;
const VIRTIO_PCI_QUEUE_SEL: u16 = IOBASE + 14;
const VIRTIO_PCI_QUEUE_NOTIFY: u16 = IOBASE + 16;
const VIRTIO_PCI_STATUS: u16 = IOBASE + 18;
const VIRTIO_PCI_ISR: u16 = IOBASE + 19;
const TAP_DEVICE_NAME : &str = "uhyve-tap";

const HOST_FEATURES: u32 = (1 << VIRTIO_NET_F_STATUS) | (1 << VIRTIO_NET_F_MAC);

pub trait PciDevice {
	fn handle_read(&self, address: u32, dest: &mut [u8]) -> ();
	fn handle_write(&mut self, address: u32, src: &[u8]) -> ();
}

type PciRegisters = [u8; 0x40];

pub struct VirtioNetPciDevice<'a> {
	registers: PciRegisters, //Add more
	requested_features: u32,
	selected_queue_num: u16,
    virt_queues: Vec<Virtqueue<'a>>,
    iface : Option<Iface>,
}

impl fmt::Debug for VirtioNetPciDevice<'_> {
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

impl VirtioNetPciDevice<'_> {
	pub const fn new<'a>() -> VirtioNetPciDevice<'a> {
		let mut registers: PciRegisters = [0; 0x40];
		write_u16!(registers, VENDOR_ID_REGISTER, 0x1AF4 as u16);
		write_u16!(registers, DEVICE_ID_REGISTER, 0x1000 as u16);
		write_u16!(registers, CLASS_REGISTER + 2, 0x0200 as u16);
		write_u16!(registers, BAR0_REGISTER, IOBASE as u16);
        let mut virt_queues: Vec<Virtqueue> = Vec::new();
		VirtioNetPciDevice {
			registers,
			requested_features: 0,
			selected_queue_num: 0,
            virt_queues,
            iface: None,
		}
	}

	pub fn handle_notify_output(&mut self, dest: &[u8]) {
		// TODO: Validate state and send packets, etc.
	}

	pub fn read_status(&self, dest: &mut [u8]) {
		self.handle_read(STATUS_REGISTER & 0x3FFF, dest);
	}

	pub fn write_status(&mut self, dest: &[u8]) {
		// TODO: Status transition logic.
		self.handle_write(STATUS_REGISTER & 0x3FFF, dest);
	}

    fn write_status_enum(&mut self, status : Status) {
        let byte_status = status as u8;
        self.write_status(&[byte_status]);
    }

	pub fn write_selected_queue(&mut self, dest: &[u8]) {
		self.selected_queue_num = unsafe { *(dest.as_ptr() as *const u16) }
	}

	pub fn write_pfn(&mut self, dest: &[u8]) {
        if self.selected_queue_num as usize != self.virt_queues.len() { 
        } else {
            //TODO: whats going on
            self.write_status(dest)
        }
	}

	pub fn write_requested_features(&mut self, dest: &[u8]) {
		// TODO: And requested and host features, store in requested_features
		let requested_features = unsafe { *(dest.as_ptr() as *const u32) };
		self.requested_features = (self.requested_features | requested_features) & HOST_FEATURES;
	}

	pub fn read_requested_features(&self, dest: &mut [u8]) {
		// TODO: Write requested_features to dest if they exist. Error if not requested?
		let bytes = self.requested_features.to_ne_bytes();
		for i in 0..bytes.len() {
			dest[i] = bytes[i];
		}
	}

	pub fn read_host_features(&self, dest: &mut [u8]) {
		// TODO: Write features supported by device to dest.
		let bytes = HOST_FEATURES.to_ne_bytes();
		for i in 0..bytes.len() {
			dest[i] = bytes[i];
		}
	}

	pub fn reset_interrupt(&mut self) {
		// TODO
        //let iface = Iface::new(TAP_DEVICE_NAME, Mode::Tap).expect("Failed to create a TAP device");
        self.iface = None;
	}
}

impl PciDevice for VirtioNetPciDevice<'_> {
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
