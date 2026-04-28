// guest_address + OFFSET
pub const GDT_OFFSET: u64 = 0x1000;
pub const FDT_OFFSET: u64 = 0x5000;
pub const BOOT_INFO_OFFSET: u64 = 0x9000;
pub const PML4_OFFSET: u64 = 0x10000;
pub const PAGETABLES_OFFSET: u64 = 0x11000;
pub const PAGETABLES_END: u64 = 0x30000;
pub const KERNEL_OFFSET: u64 = 0x40000;

// The offset of the kernel in the memory.
// Must be larger than BOOT_INFO_OFFSET + KERNEL_STACK_SIZE
pub const MIN_PHYSMEM_SIZE: usize = 0x43000;

pub const EFER_LME: u64 = 1 << 8; /* Long mode enable */
pub const EFER_LMA: u64 = 1 << 10; /* Long mode active (read-only) */
pub const EFER_NXE: u64 = 1 << 11; /* PTE No-Execute bit enable */
pub const KERNEL_STACK_SIZE: u64 = 0x8000;
pub const UHYVE_NET_MTU: usize = 1500;
pub const UHYVE_IRQ_NET: u32 = 11;
pub const GICD_BASE_ADDRESS: u64 = 0x800_0000;
pub const GICD_SIZE: usize = 0x10000;
pub const GICR_BASE_ADDRESS: u64 = 0x80A_0000;
pub const GICR_SIZE: usize = 0xf60000;
pub const MSI_BASE_ADDRESS: u64 = 0x808_0000;
pub const MSI_SIZE: usize = 0x20000;
