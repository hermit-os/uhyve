// guest_address + OFFSET
pub const FDT_OFFSET: u64 = 0x5000;
pub const BOOT_INFO_OFFSET: u64 = 0x9000;
pub const PAGETABLES_OFFSET: u64 = 0x11000;
pub const PAGETABLES_END: u64 = 0x30000;
pub const KERNEL_OFFSET: u64 = 0x40000;

// The offset of the kernel in the memory.
// Must be larger than BOOT_INFO_OFFSET + KERNEL_STACK_SIZE
pub const MIN_PHYSMEM_SIZE: usize = 0x43000;

pub const KERNEL_STACK_SIZE: u64 = 0x8000;
pub const UHYVE_NET_MTU: usize = 1500;
pub const UHYVE_IRQ_NET: u32 = 11;
