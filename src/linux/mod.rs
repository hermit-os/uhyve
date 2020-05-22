pub mod gdb;
pub mod uhyve;
pub mod vcpu;
pub mod virtio;
pub mod virtqueue;

use kvm_ioctls::Kvm;

lazy_static! {
	static ref KVM: Kvm = Kvm::new().unwrap();
	static ref KVM_TEST: bool = Kvm::new().is_ok();
}

trait MemoryRegion {
	fn flags(&self) -> u32;
	fn memory_size(&self) -> usize;
	fn guest_address(&self) -> usize;
	fn host_address(&self) -> usize;
}

pub fn has_vm_support() -> bool {
	*KVM_TEST
}
