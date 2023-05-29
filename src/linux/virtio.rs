use std::{
	fmt,
	io::{Read, Write},
	mem,
	ops::{Index, IndexMut, RangeFrom},
	ptr,
	sync::{
		atomic::{AtomicBool, Ordering},
		Arc,
	},
	thread, time,
	vec::Vec,
};

use kvm_ioctls::{IoEventAddress, NoDatamatch, VmFd};
use spin::Mutex;
use virtio_bindings::bindings::virtio_net::virtio_net_hdr_v1;
use vmm_sys_util::eventfd::EventFd;
use zerocopy::AsBytes;

use crate::{
	consts::{UHYVE_IRQ_NET, UHYVE_NET_MTU},
	linux::virtqueue::*,
	net::{
		tap::Tap,
		virtio::{
			capabilities::*,
			config::{
				device_id,
				interrupt::{NOTIFY_CONFIGURUTION_CHANGED, NOTIFY_USED_BUFFER},
				status,
			},
			features::{UHYVE_NET_FEATURES_HIGH, UHYVE_NET_FEATURES_LOW},
			offsets, ConfigAddress, IOBASE, PCI_CAP_PTR_START, VIRTIO_NET_S_LINK_UP,
			VIRTIO_VENDOR_ID,
		},
	},
	vm::VirtualCPU,
};

const VIRTIO_NET_HEADER_SZ: usize = mem::size_of::<virtio_net_hdr_v1>();

// PCI Spec 2.0 - 7.5.1
const VENDOR_ID_REGISTER: usize = 0x0;
const DEVICE_ID_REGISTER: usize = 0x2;
// const COMMAND_REGISTER: usize = 0x4;
const STATUS_REGISTER: usize = 0x6;
const CLASS_REGISTER: usize = 0x8;
const BAR0_REGISTER: usize = 0x10;
const BASE_ADDRESS_SIZE: usize = 0x100;
const PCI_CAPABILITY_LIST_POINTER: usize = 0x34;
const PCI_INTERRUPT_REGISTER: usize = 0x3C;
const RX_QUEUE: u16 = 0;
const TX_QUEUE: u16 = 1;
const PCI_MEM_BASE_ADDRESS_64BIT: u16 = 1 << 2;
pub const VIRTIO_PCI_MEM_BAR_PFN: u16 = 1 << 3;

pub trait PciDevice {
	fn handle_read(&self, address: u32, dest: &mut [u8]);
	fn handle_write(&mut self, address: u32, src: &[u8]);
}

#[derive(Debug)]
struct PciConfigSpace {
	pub slice: [u8; BASE_ADDRESS_SIZE],
}

impl PciConfigSpace {
	pub fn new() -> Self {
		Self {
			slice: [0u8; BASE_ADDRESS_SIZE],
		}
	}

	pub fn write_slice<T>(&mut self, data: T, offset: u8)
	where
		T: AsBytes,
	{
		let slice = data.as_bytes();
		self.slice[(offset as usize)..][..slice.len()].copy_from_slice(slice)
	}
}

impl Index<usize> for PciConfigSpace {
	type Output = u8;

	fn index(&self, index: usize) -> &Self::Output {
		&self.slice[index]
	}
}

impl IndexMut<usize> for PciConfigSpace {
	fn index_mut(&mut self, index: usize) -> &mut Self::Output {
		&mut self.slice[index]
	}
}

impl Index<RangeFrom<usize>> for PciConfigSpace {
	type Output = [u8];

	fn index(&self, index: RangeFrom<usize>) -> &Self::Output {
		&self.slice[..][index]
	}
}

/// Struct to manage uhyve's network device.
pub struct VirtioNetPciDevice {
	/// PCI configuration space
	config_space: PciConfigSpace,
	/// VirtIO capabilities.
	capabilities: VirtioCapColl,
	/// records if ISR status must be alerted. This is set by the thread and
	/// read by read_isr_notify
	isr_changed: Arc<AtomicBool>,
	/// received virtqueue
	rx_queue: Arc<Mutex<Virtqueue>>,
	/// transmitted virtqueue
	tx_queue: Arc<Mutex<Virtqueue>>,
	/// virtual network interface
	iface: Option<Arc<Tap>>,
	/// File Descriptor for IRQ event signalling to guest
	irq_evtfd: Option<EventFd>,
	/// File Descriptor for polling guest (MMIO) IOEventFD signals
	notify_evtfd: Option<EventFd>,
}

impl fmt::Debug for VirtioNetPciDevice {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("VirtioNetPciDevice")
			.field("status", &self.capabilities.common.device_status)
			.finish()
	}
}

impl VirtioNetPciDevice {
	pub fn new() -> VirtioNetPciDevice {
		let mut config_space: PciConfigSpace = PciConfigSpace::new();

		write_data!(config_space, VENDOR_ID_REGISTER, VIRTIO_VENDOR_ID);
		write_data!(config_space, DEVICE_ID_REGISTER, device_id::NET_DEVICE);
		write_data!(
			config_space,
			CLASS_REGISTER,
			crate::net::consts::UHYVE_PCI_CLASS_INFO
		);

		// write the correct feature flags to BAR0
		write_data!(
			config_space,
			BAR0_REGISTER,
			IOBASE | (PCI_MEM_BASE_ADDRESS_64BIT | VIRTIO_PCI_MEM_BAR_PFN) as u32
		);
		// Set the IRQ line
		write_data!(config_space, PCI_INTERRUPT_REGISTER, UHYVE_IRQ_NET);
		// nullify the status register.
		write_data!(config_space, STATUS_REGISTER, 0);

		// Create invalid virtqueues. Improper, unsafe and poor practice!
		// Ideally, we would mark and watch the queues as ready.
		let rx_queue = unsafe { Arc::new(Mutex::new(Virtqueue::blank())) };
		let tx_queue = unsafe { Arc::new(Mutex::new(Virtqueue::blank())) };

		let capabilities = VirtioCapColl::default();

		VirtioNetPciDevice {
			config_space,
			capabilities,
			isr_changed: Arc::new(AtomicBool::new(false)),
			rx_queue,
			tx_queue,
			iface: None,
			irq_evtfd: None,
			notify_evtfd: None,
		}
	}

	/// Write the capabilities to the config_space and register eventFDs to the VM
	pub fn setup(&mut self, vm: &VmFd) {
		self.config_space
			.write_slice(PCICAP_COM, PCI_CAP_PTR_START as u8);

		self.config_space
			.write_slice(PCICAP_ISR, PCICAP_COM.cap_next);

		self.config_space
			.write_slice(PCICAP_NOTIF, PCICAP_ISR.cap_next);

		self.config_space
			.write_slice(PCICAP_DEV, PCICAP_NOTIF.cap_next);

		self.capabilities.common.num_queues = 2;
		self.capabilities.common.device_feature = UHYVE_NET_FEATURES_LOW;

		// Set capabilities pointer address, device as available
		write_data!(
			self.config_space,
			STATUS_REGISTER,
			status::DEVICE_NEEDS_RESET | status::PCI_CAPABILITIES_LIST_ENABLE
		);
		write_data!(
			self.config_space,
			PCI_CAPABILITY_LIST_POINTER,
			PCI_CAP_PTR_START
		);

		let notifd = self.notify_evtfd.insert(EventFd::new(0).unwrap());

		vm.register_ioevent(
			notifd,
			&IoEventAddress::Mmio(offsets::MEM_NOTIFY.guest_address()),
			NoDatamatch,
		)
		.unwrap();

		// TODO: Possibly remove 2nd MEM_NOTIFY address?
		vm.register_ioevent(
			notifd,
			&IoEventAddress::Mmio(offsets::MEM_NOTIFY_1.guest_address()),
			NoDatamatch,
		)
		.unwrap();

		vm.register_irqfd(
			self.irq_evtfd.insert(EventFd::new(0).unwrap()),
			UHYVE_IRQ_NET,
		)
		.unwrap();
	}

	#[inline]
	pub fn read_isr_notify(&self, data: &mut [u8]) {
		// We must be alerted from the thread somehow, hence fetching an AtomicBool
		if self.isr_changed.swap(false, Ordering::AcqRel) {
			data[0] = NOTIFY_USED_BUFFER;
		}
	}

	#[allow(dead_code)]
	pub fn configuration_changed_notify(&mut self, data: &mut [u8]) {
		// Warning: HermitCore does not handle configuration changes!
		data[0] = NOTIFY_CONFIGURUTION_CHANGED;
		// ISR may be used as fallback notification
		// self.capabilities.isr.flags = NOTIFY_CONFIGURUTION_CHANGED
	}

	// Virtio handshake: chapter 3 virtio v1.2
	pub fn write_status(&mut self, dest: &[u8], vm_start: usize) {
		let status = self.read_status_reg();
		if dest[0] == status::UNINITIALIZED {
			// reset the device.
			self.write_status_reg(status::UNINITIALIZED);
			self.capabilities.common.driver_feature = 0;
			self.capabilities.common.queue_select = 0;

			unsafe {
				*self.rx_queue.as_ref().lock() = Virtqueue::blank();
				*self.tx_queue.as_ref().lock() = Virtqueue::blank();
			}
		} else if status == status::DEVICE_NEEDS_RESET || status == status::UNINITIALIZED {
			self.write_status_reset(dest);
		} else if status == status::ACKNOWLEDGE {
			// guest OS acknowledges device
			self.write_status_acknowledge(dest);
		} else if status == status::ACKNOWLEDGE | status::DRIVER {
			// guest OS knows how to drive device, reads features
			self.write_status_features(dest);
		} else if status == status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK {
			// guest OS is ready, we'll set ourselves as ready and start the networking interface.
			self.write_status_ok(dest, vm_start);
		}
	}

	/// Gets the mac address from the TAP device.
	/// This function is reliant on tap devices as the underlying packet sending mechanism
	fn get_mac_addr(&mut self) {
		self.capabilities.dev.mac = self.iface.as_ref().unwrap().mac_address_as_bytes();
	}

	/// Write the MAC address to the input slice. Since reads are not [u8; 6],
	/// but may be 2, 4, or 8 bytes, we'll need to calculate the slice.
	pub fn read_mac_address(&self, addr: u64, data: &mut [u8]) {
		let start = ConfigAddress::from_guest_address(addr).capability_space_start()
			- offsets::MAC_ADDRESS.capability_space_start();

		data.copy_from_slice(&self.capabilities.dev.mac[start..(start + data.len())])
	}

	/// Driver acknowledges device
	#[inline]
	fn write_status_reset(&mut self, dest: &[u8]) {
		if dest[0] == status::ACKNOWLEDGE {
			self.write_status_reg(dest[0]);
		}
	}

	/// Driver recognizes the device
	fn write_status_acknowledge(&mut self, dest: &[u8]) {
		if dest[0] == status::ACKNOWLEDGE | status::DRIVER {
			self.write_status_reg(dest[0]);
		}
	}

	/// finish negotiating features
	fn write_status_features(&mut self, dest: &[u8]) {
		if dest[0] == status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK {
			self.write_status_reg(dest[0]);
		}
	}

	/// Complete handshake: set device as ready.
	fn write_status_ok(&mut self, dest: &[u8], vm_start: usize) {
		if dest[0] == status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK
		{
			self.write_status_reg(dest[0]);

			// Create a TAP device without packet info headers.
			let iface = self
				.iface
				.insert(Arc::new(Tap::new().expect("Could not create TAP device")));
			let sink = iface.clone();

			let notify_evtfd = self.notify_evtfd.take().unwrap();

			let poll_tx_queue = self.tx_queue.clone();

			// Start the ioeventfd watcher
			thread::spawn(move || {
				debug!("Starting notification watcher.");
				loop {
					if notify_evtfd.read().is_ok() {
						send_available_packets(&sink, &poll_tx_queue, vm_start);
					} else {
						panic!("Could not read eventfd. Is the file nonblocking?");
					}
				}
			});

			let poll_rx_queue = self.rx_queue.clone();
			let stream = self.iface.as_mut().unwrap().clone();
			let alert = Arc::clone(&self.isr_changed);
			let mut frame_queue: Vec<([u8; 1500], usize)> = Vec::with_capacity(QUEUE_LIMIT / 2);

			let irq_evtfd = self.irq_evtfd.take().unwrap();

			// Start the rx thread.
			thread::spawn(move || loop {
				let mut _delay = time::Instant::now();

				let mut buf = [0u8; UHYVE_NET_MTU];
				let len = stream.get_iface().read(&mut buf).unwrap();
				frame_queue.push((buf, len));

				// Not ideal to wait random values or queue lengths.
				if _delay
					.elapsed()
					.cmp(&time::Duration::from_micros(300))
					.is_le() && frame_queue.len() < 5
				{
					continue;
				}

				assert!(
					len <= UHYVE_NET_MTU,
					"Frame larger than MTU, was the device reconfigured?"
				);

				if write_packet(&poll_rx_queue, vm_start, &mut frame_queue) {
					_delay = time::Instant::now();
					alert.store(true, Ordering::Release);
					irq_evtfd.write(1).unwrap();
				}
			});

			// "should've would've panicked by now, if no mac existed!" BAD!
			self.get_mac_addr();
			self.capabilities.dev.status |= VIRTIO_NET_S_LINK_UP as u16;
		}
	}

	fn write_status_reg(&mut self, status: u8) {
		self.capabilities.dev.status = status as u16;
	}

	pub fn read_status_reg(&self) -> u8 {
		self.capabilities.dev.status as u8
	}

	#[inline]
	pub fn read_net_status(&self, data: &mut [u8]) {
		data.copy_from_slice(&self.capabilities.dev.status.to_le_bytes())
	}

	#[inline]
	pub fn read_mtu(&self, data: &mut [u8]) {
		data.copy_from_slice(&self.capabilities.dev.mtu.to_le_bytes())
	}

	#[inline]
	pub fn read_queue_size(&self, data: &mut [u8]) {
		data.copy_from_slice(&self.capabilities.common.queue_size.to_le_bytes())
	}

	#[inline]
	pub fn read_queue_notify_offset(&self, data: &mut [u8]) {
		data.copy_from_slice(&self.capabilities.common.queue_notify_off.to_le_bytes());
	}

	pub fn write_selected_queue(&mut self, data: &[u8]) {
		// let val = u16::from_le_bytes(dest.try_into().unwrap());
		let val = data[0] as u16;

		// VirtIO 4.1.4.3.1: Set queue_size to 0 if current queue is 'unavailable'.
		// We only support 2, so handling like this for now.
		if val != RX_QUEUE && val != TX_QUEUE {
			self.capabilities.common.queue_size = 0;
		}
		// trace!("Select queue: {val}");
		self.capabilities.common.queue_select = val;
	}

	pub fn write_queue_device(&mut self, data: &[u8]) {
		self.capabilities.common.queue_device = u64::from_le_bytes(data.try_into().unwrap())
	}

	pub fn write_queue_driver(&mut self, data: &[u8]) {
		self.capabilities.common.queue_driver = u64::from_le_bytes(data.try_into().unwrap())
	}

	/// Enable or disable the currently selected queue.
	#[inline]
	pub fn queue_enable(&mut self, data: &[u8]) {
		let val = data[0] as u16;
		// let val = u16::from_le_bytes(data.try_into().unwrap());

		assert!(val == 1 || val == 0, "Invalid queue enable value provided!");
		// trace!(
		// 	"{} current queue..",
		// 	if val == 1 { "enabling" } else { "disabling" }
		// );
		self.capabilities.common.queue_enable = val;
	}

	pub fn reset_device(&mut self) {
		warn!("RustyHermit does not support device reset!");
		self.write_status_reg(status::DEVICE_NEEDS_RESET);
		self.capabilities.common.driver_feature = 0;
		self.capabilities.common.queue_select = 0;
		self.capabilities.common.queue_size = 0;
		// TODO: A virtioqueue must check validity!
		unsafe {
			*self.rx_queue.as_ref().lock() = Virtqueue::blank();
			*self.tx_queue.as_ref().lock() = Virtqueue::blank();
		}
		// self.cap_space[ISR_STATUS] = NOTIFY_CONFIGURUTION_CHANGED;
	}

	/// Register virtqueue and grab the host-address pointer
	pub fn write_pfn(&mut self, dest: &[u8], vcpu: &impl VirtualCPU) {
		let status = self.read_status_reg();
		if status & status::FEATURES_OK != 0 && status & status::DRIVER_OK == 0 {
			let gpa = unsafe { ptr::read_unaligned(dest.as_ptr() as *const usize) };
			assert!(gpa != 0, "Received a null pointer as an address!");

			let hva = (*vcpu).host_address(gpa) as *mut u8;

			match self.capabilities.common.queue_select {
				RX_QUEUE => {
					*self.rx_queue.as_ref().lock() = unsafe { Virtqueue::new(hva, QUEUE_LIMIT) };
				}
				TX_QUEUE => {
					*self.tx_queue.as_ref().lock() = unsafe { Virtqueue::new(hva, QUEUE_LIMIT) };
				}
				_ => error!("Invalid queue selected"),
			}
		}
	}

	pub fn write_requested_features(&mut self, data: &[u8]) {
		if self.read_status_reg() == status::ACKNOWLEDGE | status::DRIVER {
			let requested_features: u32 = u32::from_le_bytes(data.try_into().unwrap());

			self.capabilities.common.driver_feature =
				match self.capabilities.common.driver_feature_select {
					0 => {
						(self.capabilities.common.driver_feature | requested_features)
							& UHYVE_NET_FEATURES_LOW
					}
					1 => {
						(self.capabilities.common.driver_feature | requested_features)
							& UHYVE_NET_FEATURES_HIGH
					}
					_ => panic!("Driver feature selector is invalid"),
				}
		}
	}

	pub fn write_device_feature_select(&mut self, data: &[u8]) {
		self.capabilities.common.device_feature_select =
			u32::from_le_bytes(data.try_into().unwrap())
	}

	pub fn write_driver_feature_select(&mut self, data: &[u8]) {
		self.capabilities.common.driver_feature_select =
			u32::from_le_bytes(data.try_into().unwrap())
	}

	pub fn read_host_features(&self, data: &mut [u8]) {
		match self.capabilities.common.device_feature_select {
			0 => data.copy_from_slice(&UHYVE_NET_FEATURES_LOW.to_le_bytes()),
			1 => data.copy_from_slice(&UHYVE_NET_FEATURES_HIGH.to_le_bytes()),
			_ => data.fill(0), // VirtIO 4.1.4.3.1: present zero for any invalid select
		}
	}

	#[allow(dead_code)]
	fn reset_interrupt(&mut self) {
		todo!()
	}
}

impl Default for VirtioNetPciDevice {
	fn default() -> Self {
		Self::new()
	}
}

impl PciDevice for VirtioNetPciDevice {
	fn handle_read(&self, address: u32, dest: &mut [u8]) {
		dest.copy_from_slice(&self.config_space[address as usize..][..dest.len()]);
	}

	fn handle_write(&mut self, address: u32, dest: &[u8]) {
		// TODO: we are temporarily stepping over this to allow us to have a register size
		// larger than 0x10. Hacky solution!
		for (i, var) in dest.iter().enumerate() {
			if i == 1 && address == BAR0_REGISTER as u32 {
				self.config_space[(address as usize) + i] = *var & !(0x10);
			} else {
				self.config_space[(address as usize) + i] = *var;
			}
		}
	}
}

/// Returns true if notification must occur
fn write_packet(
	rx_queue: &Arc<Mutex<Virtqueue>>,
	guest_start_addr: usize,
	frame_queue: &mut Vec<([u8; UHYVE_NET_MTU], usize)>,
) -> bool {
	frame_queue.retain(|(frame, len)| {
		let mut queue = rx_queue.lock();
		// TODO: better handling of notification suppression.
		// queue.used_ring.disable_notification();

		// This may not be correct, what if it was changed?
		let index = queue.last_seen_available;

		if let Some(desc) = unsafe { queue.get_descriptor(index) } {
			if !desc.is_writable() {
				return true;
			}
			if desc.flags as u32 & VRING_DESC_F_NEXT != 0 {
				error!("Chained descriptors are unhandled!");
				return true;
			}

			let hva = (guest_start_addr + desc.addr as usize) as *mut u8;

			// Write virtio header and frame
			unsafe {
				ptr::write(
					hva as *mut virtio_net_hdr_v1,
					virtio_net_hdr_v1 {
						num_buffers: 1,
						..Default::default()
					},
				);

				ptr::copy_nonoverlapping(frame.as_ptr(), hva.add(VIRTIO_NET_HEADER_SZ), *len);
			}
			let len = desc.len;
			queue.add_used(index as u32, len);
			return false;
		}
		true
	});

	// TODO
	// queue.used_ring.enable_notification();
	true
}

fn send_available_packets(
	sink: &Arc<Tap>,
	tx_queue_locked: &Arc<Mutex<Virtqueue>>,
	guest_start_address: usize,
) {
	let tx_queue = &mut tx_queue_locked.try_lock().unwrap();

	let send_indices: Vec<u16> = tx_queue.avail_iter().collect();

	for index in send_indices {
		//	TODO: improper behavior? find a better solution
		// tl;dr - disable notifications and skip this part if the queue doesn't report as ready
		if let Some(desc) = unsafe { tx_queue.get_descriptor(index) } {
			if !desc.is_readable() {
				error!("Descriptor is not readable {}", desc.flags);
				continue;
			}

			assert!(
				desc.len as usize <= UHYVE_NET_MTU + VIRTIO_NET_HEADER_SZ,
				"VirtIO buffer is larger than permitted"
			);
			let len = desc.len as usize - VIRTIO_NET_HEADER_SZ;
			let buf = vec![0u8; len];

			// TODO: not the nicest solution
			let hva =
				(guest_start_address + desc.addr as usize + VIRTIO_NET_HEADER_SZ) as *const u8;

			unsafe { ptr::copy_nonoverlapping(hva, buf.as_ptr() as *mut u8, len) };
			// transmission failure is not necessarily grounds for a device reset
			match sink.get_iface().write(&buf) {
				Ok(_) => {}
				Err(e) => {
					error!("could not send frame: {e:?}");
					// trace!("frame slice: {buf:x?}");
				}
			}

			tx_queue.add_used(index as u32, 1);
		}
	}
}
