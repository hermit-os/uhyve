use std::{
	collections::VecDeque as Vec,
	fmt,
	io::{Read, Write},
	mem,
	sync::{
		self,
		atomic::{AtomicBool, Ordering},
		Arc,
	},
	thread, time,
};

use kvm_ioctls::{IoEventAddress, NoDatamatch, VmFd};
use spin::Mutex;
use virtio_bindings::{
	bindings::virtio_net::virtio_net_hdr_v1, virtio_config::VIRTIO_F_RING_RESET,
};
use virtio_queue::{Descriptor, DescriptorChain, Error as VirtIOError, Queue, QueueOwnedT, QueueT};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
use vmm_sys_util::eventfd::EventFd;

use crate::{
	consts::{UHYVE_IRQ_NET, UHYVE_NET_MTU},
	net::{macvtap::MacVTap, NetworkInterface},
	pci::{MemoryBar64, PciDevice},
	virtio::{
		capabilities::IsrStatus,
		features::{UHYVE_NET_FEATURES_HIGH, UHYVE_NET_FEATURES_LOW},
		pci::{HeaderConf, MEM_NOTIFY, MEM_NOTIFY_1},
		virtqueue::{self, QUEUE_LIMIT},
		DeviceStatus, IOBASE, NET_DEVICE_ID,
	},
};

const VIRTIO_NET_HEADER_SZ: usize = mem::size_of::<virtio_net_hdr_v1>();

const RX_QUEUE: u16 = 0;
const TX_QUEUE: u16 = 1;

use crate::virtio::capabilities::{FeatureSelector, NetDevStatus};

/// Struct to manage uhyve's network device.
pub struct VirtioNetPciDevice {
	/// PCI configuration space & VirtIO capabilities.
	header_caps: HeaderConf,
	/// records if ISR status must be alerted. This is set by the thread and
	/// read by read_isr_notify
	isr_changed: Arc<AtomicBool>,
	/// received virtqueue
	rx_queue: Arc<Mutex<Queue>>,
	/// transmitted virtqueue
	tx_queue: Arc<Mutex<Queue>>,
	/// virtual network interface
	iface: Option<Arc<dyn NetworkInterface>>,
	/// File Descriptor for IRQ event signalling to guest
	irq_evtfd: Option<EventFd>,
	/// File Descriptor for polling guest (MMIO) IOEventFD signals
	notify_evtfd: Option<EventFd>,
	guest_mmap: Arc<GuestMemoryMmap>,
	/// Store all negotiated feature sets. Chapter 2.2 virtio v1.2
	feature_set: u64,
}
impl fmt::Debug for VirtioNetPciDevice {
	// TODO: More exhaustive debug print
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("VirtioNetPciDevice")
			.field("status", &self.header_caps.common_cfg.device_status)
			.finish()
	}
}

impl VirtioNetPciDevice {
	pub fn new(guest_mmap: vm_memory::GuestMemoryMmap) -> VirtioNetPciDevice {
		let mut header_caps = HeaderConf::new();
		header_caps.pci_config_hdr.device_id = NET_DEVICE_ID;
		header_caps.pci_config_hdr.base_address_registers[0] = MemoryBar64::new(IOBASE as u64);
		header_caps.pci_config_hdr.interrupt_line = UHYVE_IRQ_NET;
		header_caps.common_cfg.num_queues = 2;
		header_caps.common_cfg.device_feature_select = FeatureSelector::Low;
		header_caps.common_cfg.device_feature = UHYVE_NET_FEATURES_LOW;

		// Create invalid virtqueues. Improper, unsafe and poor practice!
		// Ideally, we would mark and watch the queues as ready.
		let rx_queue = Arc::new(Mutex::new(Queue::new(QUEUE_LIMIT as u16).unwrap()));
		let tx_queue = Arc::new(Mutex::new(Queue::new(QUEUE_LIMIT as u16).unwrap()));

		let guest_mmap = Arc::new(guest_mmap);
		VirtioNetPciDevice {
			header_caps,
			isr_changed: Arc::new(AtomicBool::new(false)),
			rx_queue,
			tx_queue,
			iface: None,
			irq_evtfd: None,
			notify_evtfd: None,
			guest_mmap,
			feature_set: (UHYVE_NET_FEATURES_LOW as u64) & ((UHYVE_NET_FEATURES_HIGH as u64) << 32),
		}
	}

	/// Write the capabilities to the config_space and register eventFDs to the VM
	pub fn setup(&mut self, vm: &VmFd) {
		self.header_caps.pci_config_hdr.status =
			DeviceStatus::DEVICE_NEEDS_RESET | DeviceStatus::PCI_CAPABILITIES_LIST_ENABLE;

		let notifd = self.notify_evtfd.insert(EventFd::new(0).unwrap());

		vm.register_ioevent(
			notifd,
			&IoEventAddress::Mmio(MEM_NOTIFY.guest_address()),
			NoDatamatch,
		)
		.unwrap();

		// TODO: Possibly remove 2nd MEM_NOTIFY address?
		vm.register_ioevent(
			notifd,
			&IoEventAddress::Mmio(MEM_NOTIFY_1.guest_address()),
			NoDatamatch,
		)
		.unwrap();

		vm.register_irqfd(
			self.irq_evtfd.insert(EventFd::new(0).unwrap()),
			UHYVE_IRQ_NET as u32,
		)
		.unwrap();
	}

	#[inline]
	pub fn read_isr_notify(&self, data: &mut [u8]) {
		// We must be alerted from the thread somehow, hence fetching an AtomicBool
		if self.isr_changed.swap(false, Ordering::AcqRel) {
			data[0] = IsrStatus::NOTIFY_USED_BUFFER.bits();
		}
	}

	/// Reset queue in common capability structure when VIRTIO_F_RING_RESET is negotiated.
	/// This is currently disabled, but only called in vcpu.rs
	/// Virtqueue Reset: chapter 2.6.1 virtio v1.2
	pub fn write_reset_queue(&mut self) {
		if self.feature_set & (1 << VIRTIO_F_RING_RESET) != 0 {
			// reset only selected queue
			let mut queue = match self.header_caps.common_cfg.queue_select {
				RX_QUEUE => self.rx_queue.lock(),
				TX_QUEUE => self.tx_queue.lock(),
				_ => panic!("invalid queue selected!"),
			};
			queue.reset();
		}
		self.header_caps.common_cfg.queue_reset = 0;
	}

	/// Read queue_reset from common capability structure when VIRTIO_F_RING_RESET is negotiated.
	/// Virtqueue Reset: chapter 2.6.1 virtio v1.2
	pub fn read_queue_reset(&self, data: &mut [u8]) {
		data[0] = self.header_caps.common_cfg.queue_reset as u8;
	}

	// Virtio handshake: chapter 3 virtio v1.2
	pub fn write_status(&mut self, data: &[u8]) {
		let status_reg = &mut self.header_caps.pci_config_hdr.status;

		// A state machine might be a nicer way to structure the code here.

		// Device initialization procedure: See Virtio V1.2 Sec. 4.2.2
		// Step 1: reset the device
		if data[0] == DeviceStatus::UNINITIALIZED.bits() as u8 {
			*status_reg = DeviceStatus::UNINITIALIZED;
			self.header_caps.common_cfg.driver_feature = 0;
			self.header_caps.common_cfg.queue_select = 0;
			self.rx_queue.as_ref().lock().reset();
			self.tx_queue.as_ref().lock().reset();
			return;
		}

		if status_reg.contains(DeviceStatus::DEVICE_NEEDS_RESET) {
			error!("Virtio PCI device needs reset but is written to anyway");
			return;
		}

		if *status_reg == DeviceStatus::UNINITIALIZED
			&& data[0] == DeviceStatus::ACKNOWLEDGE.bits() as u8
		{
			// Step 2: Guest has noted device
			status_reg.insert(DeviceStatus::ACKNOWLEDGE)
		} else if *status_reg == DeviceStatus::ACKNOWLEDGE
			&& data[0] == (*status_reg | DeviceStatus::DRIVER).bits() as u8
		{
			// Step 3: Guest knows how to drive device
			status_reg.insert(DeviceStatus::DRIVER)
		} else if *status_reg == DeviceStatus::ACKNOWLEDGE | DeviceStatus::DRIVER
			&& data[0] == (*status_reg | DeviceStatus::FEATURES_OK).bits() as u8
		{
			// Step 5: Fix features
			status_reg.insert(DeviceStatus::FEATURES_OK)
		} else if *status_reg
			== DeviceStatus::ACKNOWLEDGE | DeviceStatus::DRIVER | DeviceStatus::FEATURES_OK
			&& data[0] == (*status_reg | DeviceStatus::DRIVER_OK).bits() as u8
		{
			// Step 8: guest OS is ready
			status_reg.insert(DeviceStatus::DRIVER_OK);
			self.start_network_interface();
		} else {
			error!(
				"Invalid status register operation (Status register: {:?}, operation: {:b})",
				status_reg, data[0]
			);
			*status_reg = DeviceStatus::DEVICE_NEEDS_RESET;
		}
	}

	pub fn read_status_reg(&self) -> u8 {
		self.header_caps.pci_config_hdr.status.bits() as u8
	}

	/// Gets the mac address from the TAP device.
	/// This function is reliant on tap devices as the underlying packet sending mechanism
	fn get_mac_addr(&mut self) {
		self.header_caps.dev.mac = self.iface.as_ref().unwrap().mac_address_as_bytes();
	}

	/// Write the MAC address to the input slice.
	pub fn read_mac_address(&self, data: &mut [u8]) {
		for (d, m) in data.iter_mut().zip(self.header_caps.dev.mac.iter()).take(6) {
			*d = *m;
		}
	}

	fn start_network_interface(&mut self) {
		// Create a TAP device without packet info headers.
		let iface = self.iface.insert(Arc::new(sync::Mutex::new(
			// Tap::new().expect("Could not create TAP device"),
			MacVTap::new().expect("Could not create TAP device"),
		)));
		let sink = iface.clone();

		let notify_evtfd = self.notify_evtfd.take().unwrap();

		let poll_tx_queue = self.tx_queue.clone();
		let guest_mmap = Arc::clone(&self.guest_mmap);
		let mmap = guest_mmap.clone();

		// Start the ioeventfd watcher
		thread::spawn(move || {
			debug!("Starting notification watcher.");
			loop {
				if notify_evtfd.read().is_ok() {
					match send_available_packets(&(*sink), &poll_tx_queue, &mmap) {
						Ok(_) => {}
						Err(VirtIOError::QueueNotReady) => {
							error!("Sending before queue is ready!")
						}
						Err(e) => error!("Error sending frames: {e:?}"),
					}
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
		let mmap = Arc::clone(&guest_mmap);
		// Start the rx thread.
		thread::spawn(move || loop {
			let mut _delay = time::Instant::now();

			let mut buf = [0u8; UHYVE_NET_MTU];
			let len = stream.recv(&mut buf).unwrap();
			let mmap = mmap.as_ref().clone();
			frame_queue.push_back((buf, len));

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

			match write_packet(&poll_rx_queue, &mut frame_queue, &mmap) {
				Ok(data_sent) => {
					if data_sent && poll_rx_queue.lock().needs_notification(&mmap).unwrap() {
						_delay = time::Instant::now();
						alert.store(true, Ordering::Release);
						irq_evtfd.write(1).unwrap();
					}
				}
				Err(VirtIOError::QueueNotReady) => error!("Sending before queue is ready!"),
				Err(e) => error!("Could not write frames to guest: {e:?}"),
			}
		});

		// "should've would've panicked by now, if no mac existed!" BAD!
		self.get_mac_addr();
		self.header_caps.dev.status = NetDevStatus::VIRTIO_NET_S_LINK_UP;
	}

	#[inline]
	pub fn read_net_status(&self, data: &mut [u8]) {
		data.copy_from_slice(&self.header_caps.dev.status.bits().to_le_bytes())
	}

	#[inline]
	pub fn read_mtu(&self, data: &mut [u8]) {
		data.copy_from_slice(&self.header_caps.dev.mtu.to_le_bytes())
	}

	#[inline]
	pub fn read_queue_size(&self, data: &mut [u8]) {
		data.copy_from_slice(&self.header_caps.common_cfg.queue_size.to_le_bytes())
	}

	#[inline]
	pub fn read_queue_notify_offset(&self, data: &mut [u8]) {
		data.copy_from_slice(&self.header_caps.common_cfg.queue_notify_off.to_le_bytes());
	}

	pub fn write_selected_queue(&mut self, data: &[u8]) {
		// let val = u16::from_le_bytes(dest.try_into().unwrap());
		let val = data[0] as u16;

		// VirtIO 4.1.4.3.1: Set queue_size to 0 if current queue is 'unavailable'.
		// We only support 2, so handling like this for now.
		if val != RX_QUEUE && val != TX_QUEUE {
			self.header_caps.common_cfg.queue_size = 0;
		}
		// trace!("Select queue: {val}");
		self.header_caps.common_cfg.queue_select = val;
	}

	pub fn write_queue_device(&mut self, data: &[u8]) {
		let data_u64 = match data.len() {
			1 => [data[0], 0, 0, 0, 0, 0, 0, 0],
			2 => [data[0], data[1], 0, 0, 0, 0, 0, 0],
			4 => [data[0], data[1], data[2], data[3], 0, 0, 0, 0],
			8 => [
				data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
			],
			_ => panic!("Invalid write length"),
		};
		self.header_caps.common_cfg.queue_device = u64::from_le_bytes(data_u64)
	}

	pub fn write_queue_driver(&mut self, data: &[u8]) {
		let data_u64 = match data.len() {
			1 => [data[0], 0, 0, 0, 0, 0, 0, 0],
			2 => [data[0], data[1], 0, 0, 0, 0, 0, 0],
			4 => [data[0], data[1], data[2], data[3], 0, 0, 0, 0],
			8 => [
				data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
			],
			_ => panic!("Invalid write length"),
		};
		self.header_caps.common_cfg.queue_driver = u64::from_le_bytes(data_u64)
	}

	/// Enable or disable the currently selected queue.
	#[inline]
	pub fn queue_enable(&mut self, data: &[u8]) {
		let val = data[0] as u16;
		// let val = u16::from_le_bytes(data.try_into().unwrap());

		assert!(val == 1 || val == 0, "Invalid queue enable value provided!");

		let stat = val == 1;

		let mut queue = match self.header_caps.common_cfg.queue_select {
			RX_QUEUE => self.rx_queue.lock(),
			TX_QUEUE => self.tx_queue.lock(),
			_ => {
				panic!("Cannot enable invalid queue!")
			}
		};
		queue.set_ready(stat);
		// we'll need to set if we're enabling, as queue is_valid will return false
		// the queue is disabled
		if stat && !queue.is_valid(self.guest_mmap.as_ref()) {
			error!("tried to set queue as ready, but is not valid")
		}
		self.header_caps.common_cfg.queue_enable = val;
	}

	pub fn reset_device(&mut self) {
		warn!("RustyHermit does not support device reset!");
		self.header_caps
			.pci_config_hdr
			.status
			.insert(DeviceStatus::DEVICE_NEEDS_RESET);
		self.header_caps.common_cfg.driver_feature = 0;
		self.header_caps.common_cfg.queue_select = 0;
		self.header_caps.common_cfg.queue_size = 0;
		self.rx_queue.as_ref().lock().reset();
		self.tx_queue.as_ref().lock().reset();
	}

	/// Register virtqueue and grab the host-address pointer
	pub fn write_pfn(&mut self, dest: &[u8]) {
		let status = self.header_caps.pci_config_hdr.status;
		if status.contains(DeviceStatus::FEATURES_OK) && !status.contains(DeviceStatus::DRIVER_OK) {
			let gpa = unsafe { *(dest.as_ptr() as *const usize) };
			assert!(gpa != 0, "Received a null pointer as an address!");

			let guest_addr = GuestAddress(gpa as u64);
			let availaddr = GuestAddress(
				(mem::size_of::<Descriptor>() * QUEUE_LIMIT + guest_addr.0 as usize) as u64,
			);

			let usedaddr = GuestAddress(virtqueue::align(
				availaddr.0 as usize + (mem::size_of::<u16>() * (QUEUE_LIMIT + 3)),
				crate::consts::PAGE_SIZE,
			) as u64);

			let mut queue = match self.header_caps.common_cfg.queue_select {
				RX_QUEUE => self.rx_queue.as_ref().lock(),
				TX_QUEUE => self.tx_queue.as_ref().lock(),
				_ => panic!("Invalid queue selected!"),
			};

			queue.set_size(QUEUE_LIMIT as u16);
			queue.set_desc_table_address(
				Some(guest_addr.0 as u32),
				Some((guest_addr.0 >> 32) as u32),
			);
			queue.set_avail_ring_address(Some(availaddr.0 as u32), None);
			queue.set_used_ring_address(Some(usedaddr.0 as u32), None)
		}
	}

	pub fn write_requested_features(&mut self, data: &[u8]) {
		if self
			.header_caps
			.pci_config_hdr
			.status
			.contains(DeviceStatus::ACKNOWLEDGE | DeviceStatus::DRIVER)
		{
			let requested_features: u32 = u32::from_le_bytes(data.try_into().unwrap());

			self.header_caps.common_cfg.driver_feature =
				match self.header_caps.common_cfg.driver_feature_select {
					FeatureSelector::Low => {
						(self.header_caps.common_cfg.driver_feature | requested_features)
							& UHYVE_NET_FEATURES_LOW
					}
					FeatureSelector::High => {
						(self.header_caps.common_cfg.driver_feature | requested_features)
							& UHYVE_NET_FEATURES_HIGH
					}
				}
		}
	}

	pub fn write_device_feature_select(&mut self, data: &[u8]) {
		self.header_caps.common_cfg.device_feature_select =
			FeatureSelector::from(u32::from_le_bytes(data.try_into().unwrap()))
	}

	pub fn write_driver_feature_select(&mut self, data: &[u8]) {
		self.header_caps.common_cfg.driver_feature_select =
			FeatureSelector::from(u32::from_le_bytes(data.try_into().unwrap()))
	}

	pub fn read_host_features(&self, data: &mut [u8]) {
		match self.header_caps.common_cfg.device_feature_select {
			FeatureSelector::Low => data.copy_from_slice(&UHYVE_NET_FEATURES_LOW.to_le_bytes()),
			FeatureSelector::High => data.copy_from_slice(&UHYVE_NET_FEATURES_HIGH.to_le_bytes()),
			// _ => data.fill(0), // VirtIO 4.1.4.3.1: present zero for any invalid select
		}
	}

	#[allow(dead_code)]
	fn reset_interrupt(&mut self) {
		todo!()
	}
}

impl PciDevice for VirtioNetPciDevice {
	fn handle_read(&self, address: u32, dest: &mut [u8]) {
		if let Err(e) = self.header_caps.read(address, dest) {
			error!("PCI Read error: {e:?}");
		}
	}

	fn handle_write(&mut self, address: u32, data: &[u8]) {
		if let Err(e) = self.header_caps.write(address, data) {
			error!("PCI Write error: {e:?}");
		}
	}
}

/// Returns true if notification must occur
fn write_packet(
	rx_queue: &Arc<Mutex<Queue>>,
	frame_queue: &mut Vec<([u8; UHYVE_NET_MTU], usize)>,
	mmap: &GuestMemoryMmap,
) -> Result<bool, VirtIOError> {
	let mut queue = rx_queue.lock();

	if !queue.is_valid(mmap) {
		error!("Queue is not valid!");
		return Err(VirtIOError::InvalidSize);
	}

	if !queue.ready() {
		error!("QueueTx not ready!");
		return Err(VirtIOError::QueueNotReady);
	}

	queue.disable_notification(mmap)?;

	let l = frame_queue.len();

	frame_queue.retain(|(frame, len)| {
		while let Some(chain) = queue.iter(mmap).unwrap().next() {
			let c: DescriptorChain<&GuestMemoryMmap> = chain.clone();
			for desc in chain.into_iter() {
				if desc.refers_to_indirect_table() {
					error!("Unhandled indirect descriptor");
					return true;
				}
				if desc.has_next() {
					error!("Buffer continues in another field!");
					return true;
				}

				let mut buf = vec![0u8; len + VIRTIO_NET_HEADER_SZ];
				let p: *mut u8 = (&virtio_net_hdr_v1 {
					num_buffers: 1,
					..Default::default()
				} as *const _ as *const u8)
					.cast_mut();

				// Write virtio header
				buf[0..VIRTIO_NET_HEADER_SZ].copy_from_slice(unsafe {
					std::slice::from_raw_parts_mut(p, VIRTIO_NET_HEADER_SZ)
				});
				// write packet content
				buf[VIRTIO_NET_HEADER_SZ..].copy_from_slice(&frame[0..*len]);

				mmap.write_slice(&buf, desc.addr()).unwrap();

				queue.add_used(mmap, c.head_index(), desc.len()).unwrap();
			}
		}
		false
	});
	queue.enable_notification(mmap)?;

	Ok(l - frame_queue.len() > 0)
}

fn send_available_packets(
	sink: &dyn NetworkInterface,
	tx_queue_locked: &Arc<Mutex<Queue>>,
	mem: &GuestMemoryMmap,
) -> std::result::Result<bool, VirtIOError> {
	let queue = &mut tx_queue_locked.try_lock().unwrap();
	if !queue.is_valid(mem) {
		error!("Queue is not valid!");
		return Err(VirtIOError::InvalidSize);
	}

	if !queue.ready() {
		error!("QueueTx not ready!");
		return Err(VirtIOError::QueueNotReady);
	}

	queue.disable_notification(mem)?;

	while let Some(chain) = queue.iter(mem).unwrap().next() {
		let c = chain.clone();

		for desc in chain {
			let len = desc.len();

			assert!(
				len as usize <= UHYVE_NET_MTU + VIRTIO_NET_HEADER_SZ,
				"VirtIO buffer is larger than permitted"
			);

			let mut buf = vec![0; len as usize];
			mem.read_slice(&mut buf, desc.addr()).unwrap();

			match (*sink).send(&buf[VIRTIO_NET_HEADER_SZ..]) {
				Ok(sent_len) => {
					if sent_len != len as usize - VIRTIO_NET_HEADER_SZ {
						error!("Could not send all data provided! sent {sent_len}, vs {len}");
					}
				}
				Err(e) => {
					error!("could not send frame: {e}");
					error!(
						"frame slice: {:x?}",
						&buf[VIRTIO_NET_HEADER_SZ..(len as usize)]
					);
				}
			}

			queue.add_used(mem, c.head_index(), desc.len())?;
		}
	}
	queue.enable_notification(mem)?;

	Ok(true)
}
