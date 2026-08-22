#![expect(dead_code, reason = "Unimplemented")]
use crate::{net::NetworkBackend, virtio::net::VirtioNetPciDevice};

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
	pub fn setup(&mut self, _vm: &kvm_ioctls::VmFd) {
		// This requires wiring the virtqueue notifications and interrupts up to
		// the GIC. See linux::x86_64::virtio_device for the x86 equivalent.
		unimplemented!()
	}
}
