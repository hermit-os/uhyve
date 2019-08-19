pub mod ehyve;
pub mod vcpu;

use kvm_ioctls::Kvm;

lazy_static! {
	static ref KVM: Kvm = { Kvm::new().unwrap() };
}

trait MemorySlot {
	fn slot_id(&self) -> u32;
	fn flags(&self) -> u32;
	fn memory_size(&self) -> usize;
	fn guest_address(&self) -> u64;
	fn host_address(&self) -> u64;
}
