#![expect(dead_code, reason = "Unimplemented")]
use crate::{net::NetworkBackend, virtio::net::VirtioNetPciDevice};

/// Wrapper around `VirtioNetPciDevice` containing the architecture specific functionality.
#[derive(Debug)]
pub struct XHyveVirtioNetDevice {
	pub virtio: VirtioNetPciDevice,
}
impl XHyveVirtioNetDevice {
	pub const fn new(virtio: VirtioNetPciDevice) -> Self {
		Self { virtio }
	}

	/// Write the capabilities to the config_space and register eventFDs to the VM
	pub fn setup(&mut self) {
		// we need to setup interrupts and notification infrastructure for the virtqueues here. See linux::x86_64::virtio_device for an example
		unimplemented!()
	}
}

impl NetworkBackend for XHyveVirtioNetDevice {
	fn lock_for_snapshot(&mut self) -> crate::virtio::net::VirtioNetSnapshotLock<'_> {
		unimplemented!();
	}

	fn setup_from_snapshot(
		&mut self,
		snapshot: &crate::virtio::net::VirtioNetPciDeviceSnapshot,
	) -> crate::HypervisorResult<()> {
		unimplemented!();
	}
}
