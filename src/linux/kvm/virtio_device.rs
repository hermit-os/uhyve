use std::{
	io,
	os::fd::{AsRawFd, BorrowedFd},
};

use kvm_ioctls::{IoEventAddress, NoDatamatch, VmFd};
use uhyve_interface::GuestPhysAddr;
use vmm_sys_util::eventfd::EventFd;

use crate::{
	arch::kvm as arch,
	net::NetworkBackend,
	pci::PciConfigurationAddress,
	virtio::{
		DeviceStatus,
		net::{VirtQueueInterrupter, VirtQueueNotificationWaiter, VirtioNetPciDevice},
		pci::HeaderConf,
	},
};

/// Thin Wrapper around `EventFd` to implement `VirtQueueNotificationWaiter`
struct EventFdNotifier(EventFd);
impl VirtQueueNotificationWaiter for EventFdNotifier {
	fn wait_for_notify(&self) {
		self.0.read().unwrap();
	}

	fn wait_with_timeout(&self, timeout: u16) -> bool {
		match wait_eventfd_with_timeout(&self.0, timeout) {
			Ok(()) => {
				self.wait_for_notify();
				true
			}
			Err(e) => {
				if e.kind() == io::ErrorKind::TimedOut {
					return false;
				}
				panic!("Could not read eventfd. Is the file nonblocking?");
			}
		}
	}
}

/// Thin Wrapper around `EventFd` to implement `VirtQueueInterrupter`
struct EventFdInterrupter(EventFd);
impl VirtQueueInterrupter for EventFdInterrupter {
	fn send_interrupt(&self) {
		self.0.write(1).unwrap();
	}
}

/// Wrapper around `VirtioNetPciDevice` containing the architecture specific functionality.
#[derive(Debug)]
pub struct KvmVirtioNetDevice {
	pub virtio: VirtioNetPciDevice,
}
impl NetworkBackend for KvmVirtioNetDevice {}
impl KvmVirtioNetDevice {
	pub const fn new(virtio: VirtioNetPciDevice) -> Self {
		Self { virtio }
	}

	/// Write the capabilities to the config_space and register eventFDs to the VM
	pub fn setup(&mut self, vm: &VmFd) {
		self.virtio.header_caps.pci_config_hdr.status =
			DeviceStatus::DEVICE_NEEDS_RESET | DeviceStatus::PCI_CAPABILITIES_LIST_ENABLE;

		let (irqfd, interrupt_line) = arch::setup_virtio_interrupt(vm);
		// Inform the kernel on which line the PCI interrupt will appear.
		self.virtio.header_caps.pci_config_hdr.interrupt_line = interrupt_line;

		let notify_evtfd_rx = initialize_mmio_notify(
			PciConfigurationAddress::new(HeaderConf::NOTIFY_0 as u32).guest_address(),
			vm,
		);
		let notify_evtfd_tx = initialize_mmio_notify(
			PciConfigurationAddress::new(HeaderConf::NOTIFY_1 as u32).guest_address(),
			vm,
		);

		self.virtio.update_config_generation();

		self.virtio.start_network_threads(
			EventFdNotifier(notify_evtfd_tx),
			EventFdNotifier(notify_evtfd_rx),
			EventFdInterrupter(irqfd),
		);
	}
}

fn initialize_mmio_notify(addr: GuestPhysAddr, vm: &VmFd) -> EventFd {
	let notifyfd = EventFd::new(0).unwrap();
	vm.register_ioevent(&notifyfd, &IoEventAddress::Mmio(addr.as_u64()), NoDatamatch)
		.unwrap();
	notifyfd
}

/// Waits for any activity on `fd`. Returns `1` on success, `0` on timeout and `-1` on error.
pub(crate) fn wait_eventfd_with_timeout(fd: &EventFd, timeout: u16) -> io::Result<()> {
	use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
	let mut pollfds = [PollFd::new(
		// Safety: no ownership is leaked
		unsafe { BorrowedFd::borrow_raw(fd.as_raw_fd()) },
		PollFlags::POLLIN,
	)];
	match poll::<PollTimeout>(&mut pollfds, timeout.into())? {
		-1 => Err(io::Error::last_os_error()),
		0 => Err(io::Error::new(
			io::ErrorKind::TimedOut,
			"eventfd wait timed out",
		)),
		1 => Ok(()),
		i => unreachable!("Poll returned {i}"),
	}
}
