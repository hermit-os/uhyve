pub mod gdb;
mod ioapic;
pub mod uhyve;
pub mod vcpu;

pub type HypervisorError = xhypervisor::Error;
