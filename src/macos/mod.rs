use xhypervisor;

pub mod gdb;
mod ioapic;
pub mod uhyve;
pub mod vcpu;

pub fn has_vm_support() -> bool {
	xhypervisor::create_vm().is_ok()
}