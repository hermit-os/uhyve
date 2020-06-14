pub mod gdb;
pub mod uhyve;
pub mod vcpu;
pub mod virtio;
pub mod virtqueue;

use kvm_ioctls::Kvm;
use lazy_static::lazy_static;

lazy_static! {
	static ref KVM: Kvm = Kvm::new().unwrap();
}

trait MemoryRegion {
	fn flags(&self) -> u32;
	fn memory_size(&self) -> usize;
	fn guest_address(&self) -> usize;
	fn host_address(&self) -> usize;
}

#[cfg(test)]
pub mod tests {
	use super::*;

	lazy_static! {
		static ref KVM_TEST: bool = Kvm::new().is_ok();
	}

	pub fn has_vm_support() -> bool {
		*KVM_TEST
	}
}
