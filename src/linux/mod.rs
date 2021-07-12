pub mod gdb;
pub mod uhyve;
pub mod vcpu;
pub mod virtio;
pub mod virtqueue;

pub type HypervisorError = kvm_ioctls::Error;

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
