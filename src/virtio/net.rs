// #![cfg_attr(target_os = "macos", allow(dead_code))] // no virtio implementation for macos
use std::{
	collections::VecDeque,
	fmt,
	io::{Read, Write},
	mem,
	sync::{
		Arc, Mutex,
		atomic::{AtomicBool, Ordering},
		mpsc::{Receiver, Sender, channel},
	},
	thread::{self, JoinHandle},
};

use virtio_bindings::{
	bindings::virtio_net::virtio_net_hdr_v1, virtio_config::VIRTIO_F_RING_RESET,
};
use virtio_queue::{Error as VirtIOError, Queue, QueueOwnedT, QueueT};

use crate::{
	consts::{UHYVE_IRQ_NET_LINE, UHYVE_IRQ_NET_PIN, UHYVE_NET_MTU, UHYVE_NET_READ_TIMEOUT},
	mem::MmapMemory,
	net::{NetworkInterface, NetworkInterfaceRX, NetworkInterfaceTX, UHYVE_QUEUE_SIZE, tap::Tap},
	params::NetworkMode,
	pci::{MemoryBar64, PciConfigurationAddress, PciDevice},
	virtio::{
		DeviceStatus, IOBASE, NET_DEVICE_ID, QUEUE_LIMIT,
		capabilities::{ComCfg, FeatureSelector, IsrStatus, NetDevCfg, NetDevStatus},
		features::{UHYVE_NET_FEATURES_HIGH, UHYVE_NET_FEATURES_LOW},
		pci::HeaderConf,
	},
};

const VIRTIO_NET_HEADER_SZ: usize = mem::size_of::<virtio_net_hdr_v1>();

/// Network -> Uhyve -> VM
const RX_QUEUE: u16 = 0;
/// VM -> Uhyve -> Network
const TX_QUEUE: u16 = 1;

pub(crate) trait VirtQueueNotificationWaiter: Send {
	/// Wait until the virtqueue sends a notify
	fn wait_for_notify(&self);

	/// Wait until the virtqueue sends a notify with `timeout` in milliseconds.
	/// Returns `true` if notification happened, `false` on timeout.
	fn wait_with_timeout(&self, timeout: u16) -> bool;
}

pub(crate) trait VirtQueueInterrupter: Send {
	fn send_interrupt(&self);
}

/// Write access to u64 fields in virtio is done in two separate accesses. This is a helper struct to support this pattern.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum Area {
	DescHigh,
	DescLow,
	DriverHigh,
	DriverLow,
	DeviceHigh,
	DeviceLow,
}

enum ThreadStartMsg {
	Start,
	Abort,
}

/// Struct to manage uhyve's network device.
pub(crate) struct VirtioNetPciDevice {
	/// PCI configuration space & VirtIO capabilities.
	pub header_caps: HeaderConf,
	/// records if ISR status must be alerted. This is set by the thread and
	/// read by read_isr_notify
	isr_changed: Arc<AtomicBool>,
	/// received virtqueue
	rx_queue: Arc<Mutex<Queue>>,
	/// transmitted virtqueue
	tx_queue: Arc<Mutex<Queue>>,
	guest_mmap: Arc<MmapMemory>,
	/// Store all negotiated feature sets. Chapter 2.2 virtio v1.2
	feature_set: u64,
	config_generation: (bool, u8), // changed & counter
	interface_cfg: NetworkMode,
	rx_thread: Option<JoinHandle<()>>,
	tx_thread: Option<JoinHandle<()>>,
	thread_start_channels: (Sender<ThreadStartMsg>, Sender<ThreadStartMsg>),
	rx_thread_start_channel_receiver: Option<Receiver<ThreadStartMsg>>,
	tx_thread_start_channel_receiver: Option<Receiver<ThreadStartMsg>>,
	stop_threads: Arc<AtomicBool>,
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
	pub fn new(interface_cfg: NetworkMode, guest_mmap: Arc<MmapMemory>) -> VirtioNetPciDevice {
		let mut header_caps = HeaderConf::new();
		header_caps.pci_config_hdr.device_id = NET_DEVICE_ID;
		header_caps.pci_config_hdr.base_address_registers[0] = MemoryBar64::new(IOBASE as u64);
		header_caps.pci_config_hdr.interrupt_pin = UHYVE_IRQ_NET_PIN;
		header_caps.pci_config_hdr.interrupt_line = UHYVE_IRQ_NET_LINE;
		header_caps.common_cfg.num_queues = 2;
		header_caps.common_cfg.device_feature_select = FeatureSelector::Low;
		header_caps.common_cfg.device_feature = UHYVE_NET_FEATURES_LOW;
		header_caps.common_cfg.queue_size = UHYVE_QUEUE_SIZE;
		header_caps.notify_cap.notify_off_multiplier = 4;

		// Create invalid virtqueues. Improper, unsafe and poor practice!
		// Ideally, we would mark and watch the queues as ready.
		let rx_queue = Arc::new(Mutex::new(
			Queue::new(header_caps.common_cfg.queue_size).unwrap(),
		));
		let tx_queue = Arc::new(Mutex::new(
			Queue::new(header_caps.common_cfg.queue_size).unwrap(),
		));

		let (tx_sender, tx_receiver) = channel();
		let (rx_sender, rx_receiver) = channel();

		VirtioNetPciDevice {
			header_caps,
			isr_changed: Arc::new(AtomicBool::new(false)),
			rx_queue,
			tx_queue,
			guest_mmap,
			feature_set: (UHYVE_NET_FEATURES_LOW as u64) & ((UHYVE_NET_FEATURES_HIGH as u64) << 32),
			config_generation: (false, 0),
			rx_thread: None,
			tx_thread: None,
			thread_start_channels: (tx_sender, rx_sender),
			rx_thread_start_channel_receiver: Some(rx_receiver),
			tx_thread_start_channel_receiver: Some(tx_receiver),
			interface_cfg,
			stop_threads: Arc::new(AtomicBool::new(false)),
		}
	}

	/// VirtIO v1.2 - 4.1.4.3.1 requires that "The device MUST present a changed config_generation
	/// after the driver has read a device-specific configuration value which has changed since any
	/// part of the device-specific configuration was last read."
	pub fn update_config_generation(&mut self) {
		if !self.config_generation.0 {
			self.config_generation.1 += 1;
			self.config_generation.0 = true;
		}
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
				RX_QUEUE => self.rx_queue.lock().unwrap(),
				TX_QUEUE => self.tx_queue.lock().unwrap(),
				_ => panic!("invalid queue selected!"),
			};
			queue.reset();
		}
		self.header_caps.common_cfg.queue_reset = 0;
		self.update_config_generation();
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
			self.rx_queue.as_ref().lock().unwrap().reset();
			self.tx_queue.as_ref().lock().unwrap().reset();
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
			debug!("Starting RX & TX Threads");
			self.thread_start_channels
				.0
				.send(ThreadStartMsg::Start)
				.unwrap();
			self.thread_start_channels
				.1
				.send(ThreadStartMsg::Start)
				.unwrap();
		} else {
			error!(
				"Invalid status register operation (Status register: {:?}, operation: {:b})",
				status_reg, data[0]
			);
			*status_reg = DeviceStatus::DEVICE_NEEDS_RESET;
		}
		self.update_config_generation();
	}

	pub fn read_status_reg(&self) -> u8 {
		self.header_caps.pci_config_hdr.status.bits() as u8
	}

	pub fn read_mac_address_bytes(&self, offset: usize, data: &mut [u8]) {
		for (d, m) in data
			.iter_mut()
			.zip(self.header_caps.dev.mac.iter())
			.take(6)
			.skip(offset)
		{
			*d = *m;
		}
	}

	pub(crate) fn start_network_threads<
		TXNOTIFIER: VirtQueueNotificationWaiter + 'static,
		RXNOTIFIER: VirtQueueNotificationWaiter + 'static,
		INTERRUPTER: VirtQueueInterrupter + 'static,
	>(
		&mut self,
		tx_notifier: TXNOTIFIER,
		rx_notifier: RXNOTIFIER,
		interrupter: INTERRUPTER,
	) {
		let iface = match &self.interface_cfg {
			NetworkMode::Tap { name } => {
				Box::new(Tap::new(name).expect("Could not create Tap device"))
			}
		};

		// store the interfaces MAC address
		self.header_caps.dev.mac = iface.mac_address_as_bytes();

		let (mut rx, mut tx) = iface.split();

		self.tx_thread = Some({
			let tx_queue = self.tx_queue.clone();
			let mmap = Arc::clone(&self.guest_mmap);
			let tx_start_channel_receiver = self.tx_thread_start_channel_receiver.take().unwrap();
			let stop_threads = self.stop_threads.clone();
			thread::spawn(move || {
				match tx_start_channel_receiver.recv().unwrap() {
					ThreadStartMsg::Abort => return,
					ThreadStartMsg::Start => {}
				}
				debug!("Starting TX thread.");
				while !stop_threads.load(Ordering::Relaxed) {
					if tx_notifier.wait_with_timeout(UHYVE_NET_READ_TIMEOUT) {
						match send_available_packets(&mut tx, &tx_queue, &mmap) {
							Ok(_) => {}
							Err(VirtIOError::QueueNotReady) => {
								error!("Sending before queue is ready!")
							}
							Err(e) => error!("Error sending frames: {e:?}"),
						}
					}
				}
			})
		});

		self.rx_thread = Some({
			let rx_queue = self.rx_queue.clone();
			let alert = Arc::clone(&self.isr_changed);
			let mut frame_queue: VecDeque<([u8; 1500], usize)> =
				VecDeque::with_capacity(QUEUE_LIMIT / 2);
			let rx_start_channel_receiver = self.rx_thread_start_channel_receiver.take().unwrap();
			let mmap = Arc::clone(&self.guest_mmap);
			let stop_threads = self.stop_threads.clone();

			// reads frames from the frame queue and puts them in the virtio queue. Notifies the driver if necessary.
			thread::spawn(move || {
				match rx_start_channel_receiver.recv().unwrap() {
					ThreadStartMsg::Abort => return,
					ThreadStartMsg::Start => {}
				}
				debug!("Starting RX thread.");
				while !stop_threads.load(Ordering::Relaxed) {
					let mut buf = [0u8; UHYVE_NET_MTU];
					let len = rx.recv(&mut buf, UHYVE_NET_READ_TIMEOUT).unwrap();
					let mmap = mmap.as_ref();
					frame_queue.push_back((buf, len));

					assert!(
						len <= UHYVE_NET_MTU,
						"Frame larger than MTU, was the device reconfigured?"
					);

					match write_packet(&rx_queue, &mut frame_queue, mmap, &rx_notifier) {
						Ok(data_sent) => {
							if data_sent
								&& rx_queue
									.lock()
									.unwrap()
									.needs_notification(&mmap.mem)
									.unwrap()
							{
								alert.store(true, Ordering::Release);
								interrupter.send_interrupt();
							}
						}
						Err(VirtIOError::QueueNotReady) => error!("Sending before queue is ready!"),
						Err(e) => error!("Could not write frames to guest: {e:?}"),
					}
				}
			})
		});

		self.header_caps.dev.status = NetDevStatus::VIRTIO_NET_S_LINK_UP;
		self.update_config_generation();
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
		let offs = match self.header_caps.common_cfg.queue_select {
			RX_QUEUE => 0,
			TX_QUEUE => 1,
			_ => {
				warn!("driver reads invalid queue");
				0
			}
		};
		data.copy_from_slice(&[offs, 0]);
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
		self.update_config_generation();
	}

	/// Enable or disable the currently selected queue.
	#[inline]
	pub fn queue_enable(&mut self, data: &[u8]) {
		let val = data[0] as u16;
		// let val = u16::from_le_bytes(data.try_into().unwrap());

		assert!(val == 1 || val == 0, "Invalid queue enable value provided!");

		let stat = val == 1;

		{
			let mut queue = match self.header_caps.common_cfg.queue_select {
				RX_QUEUE => self.rx_queue.lock().unwrap(),
				TX_QUEUE => self.tx_queue.lock().unwrap(),
				_ => {
					panic!("Cannot enable invalid queue!")
				}
			};
			queue.set_ready(stat);
			// we'll need to set if we're enabling, as queue is_valid will return false
			// the queue is disabled
			if stat && !queue.is_valid(&self.guest_mmap.mem) {
				error!("tried to set queue as ready, but is not valid")
			}
		}
		self.header_caps.common_cfg.queue_enable = val;
		self.update_config_generation();
	}

	/// The driver tells us the addresses of the queues used for communication
	pub fn update_queue_addr(&mut self, area: Area, bytes: &[u8]) {
		debug!("updating queue address {area:?} to {bytes:x?}");
		let status = self.header_caps.pci_config_hdr.status;
		assert!(
			status.contains(DeviceStatus::FEATURES_OK),
			"Driver tries to set queue addresses before feature negotiation"
		);
		assert!(
			!status.contains(DeviceStatus::DRIVER_OK),
			"Driver tries to set queue addresses after driver initialization"
		);

		{
			let mut queue = match self.header_caps.common_cfg.queue_select {
				RX_QUEUE => self.rx_queue.as_ref().lock().unwrap(),
				TX_QUEUE => self.tx_queue.as_ref().lock().unwrap(),
				_ => panic!("Invalid queue selected!"),
			};

			match bytes.len() {
				4 => {
					let addr_part = u32::from_le_bytes(bytes.try_into().unwrap());
					match area {
						Area::DescHigh => queue.set_desc_table_address(None, Some(addr_part)),
						Area::DescLow => queue.set_desc_table_address(Some(addr_part), None),
						Area::DriverHigh => queue.set_avail_ring_address(None, Some(addr_part)),
						Area::DriverLow => queue.set_avail_ring_address(Some(addr_part), None),
						Area::DeviceHigh => queue.set_used_ring_address(None, Some(addr_part)),
						Area::DeviceLow => queue.set_used_ring_address(Some(addr_part), None),
					}
				}
				8 => {
					let addr_low = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
					let addr_high = u32::from_le_bytes(bytes[4..7].try_into().unwrap());
					match area {
						Area::DescLow => {
							queue.set_desc_table_address(Some(addr_low), Some(addr_high))
						}
						Area::DriverLow => {
							queue.set_avail_ring_address(Some(addr_low), Some(addr_high))
						}
						Area::DeviceLow => {
							queue.set_used_ring_address(Some(addr_low), Some(addr_high))
						}
						_ => panic!("Unaligned virtqueue area address"),
					}
				}
				_ => unreachable!("Not a 4 or 8 byte access to the virtqueue configuration"),
			}
		}
		self.update_config_generation();
	}

	pub fn read_config_generation(&mut self, data: &mut [u8; 1]) {
		data[0] = self.config_generation.1;
		self.config_generation.0 = false;
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
		self.update_config_generation();
	}

	pub fn write_device_feature_select(&mut self, data: &[u8]) {
		self.header_caps.common_cfg.device_feature_select =
			FeatureSelector::from(u32::from_le_bytes(data.try_into().unwrap()));
		self.update_config_generation();
	}

	pub fn write_driver_feature_select(&mut self, data: &[u8]) {
		self.header_caps.common_cfg.driver_feature_select =
			FeatureSelector::from(u32::from_le_bytes(data.try_into().unwrap()));
		self.update_config_generation();
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
impl Drop for VirtioNetPciDevice {
	fn drop(&mut self) {
		self.thread_start_channels
			.0
			.send(ThreadStartMsg::Abort)
			.unwrap();
		self.thread_start_channels
			.1
			.send(ThreadStartMsg::Abort)
			.unwrap();
		self.stop_threads.store(true, Ordering::Relaxed);
		if let Some(rx_thread) = self.rx_thread.take() {
			rx_thread.join().unwrap()
		}
		if let Some(tx_thread) = self.tx_thread.take() {
			tx_thread.join().unwrap()
		}
	}
}

impl PciDevice for VirtioNetPciDevice {
	fn handle_read(&mut self, address: PciConfigurationAddress, dest: &mut [u8]) {
		match address.offset().0 {
			IsrStatus::ISR_FLAGS => self.read_isr_notify(dest),
			ComCfg::DEVICE_STATUS => dest[0] = self.read_status_reg(),
			ComCfg::DEVICE_FEATURE => self.read_host_features(dest),
			ComCfg::CONFIG_GENERATION => self.read_config_generation(dest.try_into().unwrap()),
			ComCfg::QUEUE_SIZE => self.read_queue_size(dest),
			ComCfg::QUEUE_NOTIFY_OFFSET => self.read_queue_notify_offset(dest),
			NetDevCfg::MAC_ADDRESS..NetDevCfg::MAC_ADDRESS_END => {
				let offs = address.offset().0 - NetDevCfg::MAC_ADDRESS;
				self.read_mac_address_bytes(offs as usize, dest);
			}
			NetDevCfg::NET_STATUS => self.read_net_status(dest),
			NetDevCfg::MTU => self.read_mtu(dest),
			ComCfg::QUEUE_RESET => self.read_queue_reset(dest),
			_ => {
				if let Err(e) = self.header_caps.read(address.offset(), dest) {
					error!("PCI Read error: {e}");
				}
			}
		}
	}

	fn handle_write(&mut self, address: PciConfigurationAddress, data: &[u8]) {
		match address.offset().0 {
			ComCfg::DEVICE_STATUS => self.write_status(data),
			ComCfg::DRIVER_FEATURE_SELECT => self.write_driver_feature_select(data),
			ComCfg::DEVICE_FEATURE_SELECT => self.write_device_feature_select(data),
			ComCfg::DRIVER_FEATURE => self.write_requested_features(data),
			ComCfg::QUEUE_SELECT => self.write_selected_queue(data),
			ComCfg::QUEUE_DESC_LOW => self.update_queue_addr(Area::DescLow, data),
			ComCfg::QUEUE_DESC_HIGH => self.update_queue_addr(Area::DescHigh, data),
			ComCfg::QUEUE_ENABLE => self.queue_enable(data),
			ComCfg::QUEUE_DRIVER_LOW => self.update_queue_addr(Area::DriverLow, data),
			ComCfg::QUEUE_DRIVER_HIGH => self.update_queue_addr(Area::DriverHigh, data),
			ComCfg::QUEUE_DEVICE_LOW => self.update_queue_addr(Area::DeviceLow, data),
			ComCfg::QUEUE_DEVICE_HIGH => self.update_queue_addr(Area::DeviceHigh, data),
			ComCfg::QUEUE_RESET => self.write_reset_queue(),
			IsrStatus::ISR_FLAGS => {
				panic!("Guest should not write to ISR!")
			}
			HeaderConf::NOTIFY_REGION_START..HeaderConf::NOTIFY_REGION_END => {
				panic!("Writing to MemNotify address! Is IOEventFD correctly configured?")
			}
			_ => {
				if let Err(e) = self.header_caps.write(address.offset(), data) {
					error!("PCI Write error: {e}");
				}
			}
		}
	}
}

/// Write host-received packets to the virtio-queue.
/// Returns true if notification must occur
pub fn write_packet<NOTIFIER: VirtQueueNotificationWaiter>(
	rx_queue: &Arc<Mutex<Queue>>,
	frame_queue: &mut VecDeque<([u8; UHYVE_NET_MTU], usize)>,
	mmap: &MmapMemory,
	notifier: &NOTIFIER,
) -> Result<bool, VirtIOError> {
	let mut queue = rx_queue.lock().unwrap();

	if !queue.is_valid(&mmap.mem) {
		error!("Queue is not valid!");
		return Err(VirtIOError::InvalidSize);
	}

	if !queue.ready() {
		error!("QueueTx not ready!");
		return Err(VirtIOError::QueueNotReady);
	}

	queue.disable_notification(&mmap.mem)?;

	for &(frame, len) in frame_queue.iter() {
		debug!("Transmitting: writing host-received frame of length {len} into virtqueue");

		let header = virtio_net_hdr_v1 {
			num_buffers: 1,
			..Default::default()
		};

		let desc_chain;
		loop {
			if let Some(d) = queue.pop_descriptor_chain(&mmap.mem) {
				desc_chain = d;
				break;
			}
			queue.enable_notification(&mmap.mem)?;
			notifier.wait_for_notify();
			queue.disable_notification(&mmap.mem)?;
		}

		let mut writer = desc_chain.clone().writer(&mmap.mem).unwrap();
		writer
			.write_all(unsafe {
				std::slice::from_raw_parts(
					&header as *const _ as *const u8,
					size_of::<virtio_net_hdr_v1>(),
				)
			})
			.unwrap();
		writer.write_all(frame.as_slice()).unwrap();
		trace!(
			"Transmitting: Putting index {} to used ring (next used: {}, size: {})",
			desc_chain.head_index(),
			queue.next_used(),
			queue.size()
		);
		queue
			.add_used(
				&mmap.mem,
				desc_chain.head_index(),
				(len + VIRTIO_NET_HEADER_SZ) as u32,
			)
			.unwrap();
	}
	frame_queue.clear();

	queue.enable_notification(&mmap.mem)?;

	Ok(true)
}

/// Sends the packets received from the guest to the network interface
pub fn send_available_packets(
	sink: &mut dyn NetworkInterfaceTX,
	tx_queue_locked: &Arc<Mutex<Queue>>,
	mem: &MmapMemory,
) -> std::result::Result<bool, VirtIOError> {
	trace!("reading frames from VM");
	let queue = &mut tx_queue_locked.try_lock().unwrap();
	if !queue.is_valid(&mem.mem) {
		error!("Queue is not valid!");
		return Err(VirtIOError::InvalidSize);
	}

	if !queue.ready() {
		error!("QueueTx not ready!");
		return Err(VirtIOError::QueueNotReady);
	}

	queue.disable_notification(&mem.mem)?;

	while let Some(chain) = queue.iter(&mem.mem).unwrap().next() {
		let mut buff = Vec::<u8>::with_capacity(1512);
		let mut reader = chain.clone().reader(&mem.mem).unwrap();
		let mut packet_reader = reader.split_at(VIRTIO_NET_HEADER_SZ).unwrap();

		let header_bytes_read = reader.read_to_end(&mut buff).unwrap();
		let packet_bytes_read = packet_reader.read_to_end(&mut buff).unwrap();
		trace!("received frame of length {packet_bytes_read} from VM");

		match (*sink).send(&buff[VIRTIO_NET_HEADER_SZ..]) {
			Ok(sent_len) => {
				if sent_len != packet_bytes_read {
					error!(
						"Could not send all data provided! sent {sent_len}, vs {packet_bytes_read}"
					);
				}
			}
			Err(e) => {
				error!("could not send frame: {e}");
				error!("frame slice: {:x?}", &buff[VIRTIO_NET_HEADER_SZ..]);
			}
		}

		queue.add_used(
			&mem.mem,
			chain.head_index(),
			(header_bytes_read + packet_bytes_read) as u32,
		)?;
	}
	queue.enable_notification(&mem.mem)?;

	Ok(true)
}
