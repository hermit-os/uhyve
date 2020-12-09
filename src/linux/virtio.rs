use crate::linux::virtqueue::*;
use crate::vm::VirtualCPU;
use log::info;
use std::fmt;
use std::mem::size_of;
use std::ptr::copy_nonoverlapping;
use std::sync::Mutex;
use std::vec::Vec;
use tun_tap::*;
extern crate virtio_bindings;
use self::virtio_bindings::bindings::virtio_net::*;
extern crate mac_address;
use self::mac_address::*;

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
const _RX_QUEUE: usize = 0;
const TX_QUEUE: usize = 1;
const IOBASE: u16 = 0xc000;
const ETHARP_HWADDR_LEN: u16 = 6;

pub const VIRTIO_PCI_HOST_FEATURES: u16 = IOBASE;
pub const VIRTIO_PCI_GUEST_FEATURES: u16 = IOBASE + 4;
pub const VIRTIO_PCI_QUEUE_PFN: u16 = IOBASE + 8;
pub const _VIRTIO_PCI_QUEUE_NUM: u16 = IOBASE + 12;
pub const VIRTIO_PCI_QUEUE_SEL: u16 = IOBASE + 14;
pub const VIRTIO_PCI_QUEUE_NOTIFY: u16 = IOBASE + 16;
pub const VIRTIO_PCI_STATUS: u16 = IOBASE + 18;
pub const VIRTIO_PCI_ISR: u16 = IOBASE + 19;
pub const VIRTIO_PCI_CONFIG_OFF_MSIX_OFF: u16 = 20;
pub const VIRTIO_PCI_CONFIG_OFF_MSIX_OFF_MAX: u16 = VIRTIO_PCI_CONFIG_OFF_MSIX_OFF + 5;
pub const VIRTIO_PCI_LINK_STATUS_MSIX_OFF: u16 = ETHARP_HWADDR_LEN + VIRTIO_PCI_CONFIG_OFF_MSIX_OFF;

const HOST_FEATURES: u32 = (1 << VIRTIO_NET_F_STATUS) | (1 << VIRTIO_NET_F_MAC);

pub trait PciDevice {
	fn handle_read(&self, address: u32, dest: &mut [u8]);
	fn handle_write(&mut self, address: u32, src: &[u8]);
}

type PciRegisters = [u8; 0x40];

pub struct VirtioNetPciDevice {
	registers: PciRegisters, //Add more
	requested_features: u32,
	selected_queue_num: u16,
	virt_queues: Vec<Virtqueue>,
	iface: Option<Mutex<Iface>>,
	mac_addr: [u8; 6],
}

impl fmt::Debug for VirtioNetPciDevice {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "Status: {}", self.registers[STATUS_REGISTER as usize])
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
		let virt_queues: Vec<Virtqueue> = Vec::new();
		VirtioNetPciDevice {
			registers,
			requested_features: 0,
			selected_queue_num: 0,
			virt_queues,
			iface: None,
			mac_addr: [0; 6],
		}
	}

	pub fn _poll_rx(_device: &mut VirtioNetPciDevice) {
		//TODO: how to read packets without synchronization issues
	}

	pub fn handle_notify_output(&mut self, dest: &[u8], cpu: &dyn VirtualCPU) {
		let tx_num = read_u16!(dest, 0);
		if tx_num == 1 && self.read_status_reg() & STATUS_DRIVER_OK == STATUS_DRIVER_OK {
			self.send_available_packets(cpu);
		}
	}

	// Sends packets using the tun_tap crate, subject to change
	fn send_available_packets(&mut self, cpu: &dyn VirtualCPU) {
		let tx_queue = &mut self.virt_queues[TX_QUEUE];
		let mut send_indices = Vec::new();
		for index in tx_queue.avail_iter() {
			send_indices.push(index);
		}
		for index in send_indices {
			let desc = unsafe { tx_queue.get_descriptor(index) };
			let gpa = unsafe { *(desc.addr as *const usize) };
			let hva = (*cpu).host_address(gpa) as *mut u8;
			match &self.iface {
				Some(tap) => unsafe {
					let vec = vec![0; (desc.len as usize) - size_of::<virtio_net_hdr>()];
					let slice: &[u8] = &vec;
					copy_nonoverlapping(
						hva as *const u8,
						slice.as_ptr() as *mut u8,
						(desc.len as usize) - size_of::<virtio_net_hdr>(),
					);
					let unlocked_tap = tap.lock().unwrap();
					//Actually send packet
					unlocked_tap.send(slice).unwrap_or(0);
				},
				None => self.registers[STATUS_REGISTER as usize] |= STATUS_DRIVER_NEEDS_RESET,
			}
			tx_queue.add_used(index as u32, 1)
		}
	}

	pub fn read_status(&self, dest: &mut [u8]) {
		self.handle_read(STATUS_REGISTER & 0x3FFF, dest);
	}

	// Virtio handshake
	pub fn write_status(&mut self, dest: &[u8]) {
		let status = self.read_status_reg();
		if dest[0] == 0 {
			self.write_status_reg(0);
			self.requested_features = 0;
			self.selected_queue_num = 0;
			self.virt_queues.clear();
			self.iface = None;
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

	pub fn read_mac_byte(&self, dest: &mut [u8], index: u16) {
		dest[0] = self.mac_addr[index as usize];
	}

	// This function is reliant on tap devices as the underlying packet sending mechanism
	// Gets the tap device by name then gets its mac address
	fn get_mac_addr(&mut self) {
		match &self.iface {
			Some(tap) => {
				let locked_dev = tap.lock().unwrap();
				match mac_address_by_name(locked_dev.name()) {
					Ok(Some(ma)) => self.mac_addr = ma.bytes(),
					Ok(None) => {
						info!("No MAC address found.");
						self.registers[STATUS_REGISTER as usize] |= STATUS_DRIVER_NEEDS_RESET;
					}
					Err(e) => {
						info!("{:?}", e);
						self.registers[STATUS_REGISTER as usize] |= STATUS_DRIVER_NEEDS_RESET;
					}
				}
			}
			None => {}
		}
	}

	// Driver acknowledges device
	fn write_status_reset(&mut self, dest: &[u8]) {
		if dest[0] == STATUS_ACKNOWLEDGE {
			self.write_status_reg(dest[0]);
		}
	}

	// Driver recognizes the device
	fn write_status_acknowledge(&mut self, dest: &[u8]) {
		if dest[0] == STATUS_ACKNOWLEDGE | STATUS_DRIVER {
			self.write_status_reg(dest[0]);
		}
	}

	// finish negotiating features
	fn write_status_features(&mut self, dest: &[u8]) {
		if dest[0] == STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK {
			self.write_status_reg(dest[0]);
		}
	}

	// Complete handshake
	fn write_status_ok(&mut self, dest: &[u8]) {
		if dest[0] == STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK {
			self.write_status_reg(dest[0]);
			self.iface = match Iface::new("", Mode::Tap) {
				Ok(tap) => Some(Mutex::new(tap)),
				Err(err) => {
					info!("Error creating TAP device: {}", err);
					self.registers[STATUS_REGISTER as usize] |= STATUS_DRIVER_NEEDS_RESET;
					None
				}
			};
			self.get_mac_addr();
		}
	}

	fn write_status_reg(&mut self, status: u8) {
		self.registers[STATUS_REGISTER as usize] = status;
	}

	fn read_status_reg(&self) -> u8 {
		self.registers[STATUS_REGISTER as usize]
	}

	pub fn write_selected_queue(&mut self, dest: &[u8]) {
		self.selected_queue_num = unsafe {
			#[allow(clippy::cast_ptr_alignment)]
			*(dest.as_ptr() as *const u16)
		};
	}

	// Register virtqueue
	pub fn write_pfn(&mut self, dest: &[u8], vcpu: &dyn VirtualCPU) {
		let status = self.read_status_reg();
		if status & STATUS_FEATURES_OK != 0
			&& status & STATUS_DRIVER_OK == 0
			&& self.selected_queue_num as usize == self.virt_queues.len()
		{
			let gpa = unsafe {
				#[allow(clippy::cast_ptr_alignment)]
				*(dest.as_ptr() as *const usize)
			};
			let hva = (*vcpu).host_address(gpa) as *mut u8;
			let queue = Virtqueue::new(hva, QUEUE_LIMIT);
			self.virt_queues.push(queue);
		}
	}

	pub fn write_requested_features(&mut self, dest: &[u8]) {
		if self.read_status_reg() == STATUS_ACKNOWLEDGE | STATUS_DRIVER {
			let requested_features = unsafe {
				#[allow(clippy::cast_ptr_alignment)]
				*(dest.as_ptr() as *const u32)
			};
			self.requested_features =
				(self.requested_features | requested_features) & HOST_FEATURES;
		}
	}

	pub fn read_requested_features(&mut self, dest: &mut [u8]) {
		if self.read_status_reg() == STATUS_ACKNOWLEDGE | STATUS_DRIVER {
			let bytes = self.requested_features.to_ne_bytes();
			dest[0..(bytes.len())].clone_from_slice(&bytes[..]);
		}
	}

	pub fn read_link_status(&self, dest: &mut [u8]) {
		let status = self.read_status_reg();
		if status & STATUS_FAILED != 0 || status & STATUS_DRIVER_NEEDS_RESET != 0 {
			dest[0] = 0;
		} else {
			match &self.iface {
				Some(_) => dest[0] = 1,
				None => dest[0] = 0,
			}
		}
	}

	pub fn read_host_features(&self, dest: &mut [u8]) {
		let bytes = HOST_FEATURES.to_ne_bytes();
		dest[0..(bytes.len())].clone_from_slice(&bytes[..]);
	}

	pub fn reset_interrupt(&mut self) {
		// TODO: IRQ
	}
}

impl PciDevice for VirtioNetPciDevice {
	fn handle_read(&self, address: u32, dest: &mut [u8]) {
		for i in 0..dest.len() {
			dest[i] = self.registers[(address as usize) + i];
		}
	}

	fn handle_write(&mut self, address: u32, dest: &[u8]) {
		for (i, var) in dest.iter().enumerate() {
			self.registers[(address as usize) + i] = *var;
		}
	}
}
