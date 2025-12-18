pub mod vcpu;
pub(crate) mod virtio_device;

/// The size of a page.
pub const HYPERVISOR_PAGE_SIZE: usize = 0x10000;
