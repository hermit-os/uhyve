use linux::virtqueue::*;
use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::thread;
use std::vec::Vec;
use vm::VirtualCPU;
extern crate tun_tap;
use self::tun_tap::*;
extern crate virtio_bindings;
use self::virtio_bindings::bindings::virtio_net::*;

const STATUS_ACKNOWLEDGE: u8 = 0b00000001;
const STATUS_DRIVER: u8 = 0b00000010;
const STATUS_DRIVER_OK: u8 = 0b00000100;
const STATUS_FEATURES_OK: u8 = 0b00001000;
const STATUS_DRIVER_NEEDS_RESET: u8 = 0b01000000;
const STATUS_FAILED: u8 = 0b10000000;

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
const TAP_DEVICE_NAME_BASE: &str = "uhyve-tap";

const HOST_FEATURES: u32 = (1 << VIRTIO_NET_F_STATUS) | (1 << VIRTIO_NET_F_MAC);

pub trait PciDevice {
	fn handle_read(&self, address: u32, dest: &mut [u8]) -> ();
	fn handle_write(&mut self, address: u32, src: &[u8]) -> ();
}

type PciRegisters = [u8; 0x40];

pub struct VirtioNetPciDevice {
	registers: PciRegisters, //Add more
	requested_features: u32,
	selected_queue_num: u16,
	virt_queues: Vec<Virtqueue>,
	iface: Option<Mutex<Iface>>,
}

impl fmt::Debug for VirtioNetPciDevice {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(
			f,
			"Status: {}\n IRQ: ",
			self.registers[STATUS_REGISTER as usize]
		)
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
		write_u16!(registers, BAR0_REGISTER, IOBASE as u16);
		registers[STATUS_REGISTER as usize] = STATUS_DRIVER_NEEDS_RESET;
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
        // strip off virtio header
        // lock around tap dev
        // put on net?
	}

	pub fn read_status(&self, dest: &mut [u8]) {
		self.handle_read(STATUS_REGISTER & 0x3FFF, dest);
	}

	pub fn write_status(&mut self, dest: &[u8]) {
		let status = self.read_status_reg();
		if dest[0] == 0 {
			self.write_status_reg(0);
			self.requested_features = 0;
			self.selected_queue_num = 0;
			self.virt_queues.clear();
		} else if status == STATUS_DRIVER_NEEDS_RESET || status == 0 {
			self.write_status_reset(dest);
		} else if status == STATUS_ACKNOWLEDGE {
			self.write_status_acknowledge(dest);
		} else if status == STATUS_ACKNOWLEDGE | STATUS_DRIVER {
			self.write_status_features(dest);
		} else if status == STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK {
			self.write_status_ok(dest);
		}
	}

	fn write_status_reset(&mut self, dest: &[u8]) {
		if dest[0] == STATUS_ACKNOWLEDGE {
			self.write_status_reg(dest[0]);
		}
	}

	fn write_status_acknowledge(&mut self, dest: &[u8]) {
		if dest[0] == STATUS_ACKNOWLEDGE | STATUS_DRIVER {
			self.write_status_reg(dest[0]);
		}
	}

	fn write_status_features(&mut self, dest: &[u8]) {
		if dest[0] == STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK {
			self.write_status_reg(STATUS_FEATURES_OK);
		}
	}

	fn write_status_ok(&mut self, dest: &[u8]) {
		if dest[0] == STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK {
			self.write_status_reg(dest[0]);
            //TODO: activate tap_tun device, spawn polling thread
            self.iface = match Iface::new("",Mode::Tap) {
                Ok(tap) => Some(Mutex::new(tap)),
                Err(err) => {
                    info!("Error creating TAP device: {}", err);
                    self.registers[STATUS_REGISTER as usize] |= STATUS_DRIVER_NEEDS_RESET;
                    None
                },
            };
            let rcv_thread = thread::spawn(|| {
            });
		}
	}

	fn write_status_reg(&mut self, status: u8) {
		self.registers[STATUS_REGISTER as usize] = status;
	}

	fn read_status_reg(&self) -> u8 {
		(self.registers[STATUS_REGISTER as usize])
	}

	pub fn write_selected_queue(&mut self, dest: &[u8]) {
		self.selected_queue_num = unsafe { *(dest.as_ptr() as *const u16) }
	}

	pub fn write_pfn(&mut self, dest: &[u8], uhyve: &dyn VirtualCPU) {
		let status = self.read_status_reg();
		if status & STATUS_FEATURES_OK != 0
			&& status & STATUS_DRIVER_OK == 0
			&& self.selected_queue_num as usize != self.virt_queues.len()
		{
			let gpa = unsafe { *(dest.as_ptr() as *const usize) };
			let hva = (*uhyve).host_address(gpa) as *mut u8;
			let queue = Virtqueue::new(hva, QUEUE_LIMIT);
			self.virt_queues.push(queue);
		}
	}

	pub fn write_requested_features(&mut self, dest: &[u8]) {
		if self.read_status_reg() == STATUS_ACKNOWLEDGE | STATUS_DRIVER {
			let requested_features = unsafe { *(dest.as_ptr() as *const u32) };
			self.requested_features =
				(self.requested_features | requested_features) & HOST_FEATURES;
		}
	}

	pub fn read_requested_features(&mut self, dest: &mut [u8]) {
		if self.read_status_reg() == STATUS_ACKNOWLEDGE | STATUS_DRIVER {
			let bytes = self.requested_features.to_ne_bytes();
			for i in 0..bytes.len() {
				dest[i] = bytes[i];
			}
		}
	}

	pub fn read_host_features(&self, dest: &mut [u8]) {
		let bytes = HOST_FEATURES.to_ne_bytes();
		for i in 0..bytes.len() {
			dest[i] = bytes[i];
		}
	}

	pub fn reset_interrupt(&mut self) {
		// TODO: what are IRQ
		//let iface = Iface::new(TAP_DEVICE_NAME, Mode::Tap).expect("Failed to create a TAP device");
		self.iface = None;
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
		()
	}
}
