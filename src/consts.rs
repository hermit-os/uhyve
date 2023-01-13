pub const PAGE_SIZE: usize = 0x1000;
pub const GDT_KERNEL_CODE: u16 = 1;
pub const GDT_KERNEL_DATA: u16 = 2;
pub const APIC_DEFAULT_BASE: u64 = 0xfee00000;
pub const BOOT_GDT: u64 = 0x1000;
pub const BOOT_GDT_NULL: u64 = 0;
pub const BOOT_GDT_CODE: u64 = 1;
pub const BOOT_GDT_DATA: u64 = 2;
pub const BOOT_GDT_MAX: u64 = 3;
pub const BOOT_PML4: u64 = 0x10000;
pub const BOOT_PGT: u64 = BOOT_PML4;
pub const BOOT_PDPTE: u64 = 0x11000;
pub const BOOT_PDE: u64 = 0x12000;
pub const BOOT_INFO_ADDR: u64 = 0x9000;
pub const EFER_SCE: u64 = 1; /* System Call Extensions */
pub const EFER_LME: u64 = 1 << 8; /* Long mode enable */
pub const EFER_LMA: u64 = 1 << 10; /* Long mode active (read-only) */
pub const EFER_NXE: u64 = 1 << 11; /* PTE No-Execute bit enable */
pub const IOAPIC_BASE: u64 = 0xfec00000;
pub const IOAPIC_SIZE: u64 = 0x1000;
pub const KERNEL_STACK_SIZE: u64 = 32_768;
pub const SHAREDQUEUE_START: usize = 0x80000;
pub const UHYVE_NET_MTU: usize = 1500;
pub const UHYVE_QUEUE_SIZE: usize = 8;
pub const UHYVE_IRQ_NET: u32 = 11;

pub const GUEST_PAGE_SIZE: u64 = 0x200000; /* 2 MB pages in guest */

pub const UHYVE_PORT_WRITE: u16 = 0x400;
pub const UHYVE_PORT_OPEN: u16 = 0x440;
pub const UHYVE_PORT_CLOSE: u16 = 0x480;
pub const UHYVE_PORT_READ: u16 = 0x500;
pub const UHYVE_PORT_EXIT: u16 = 0x540;
pub const UHYVE_PORT_LSEEK: u16 = 0x580;

// Networkports
pub const UHYVE_PORT_NETWRITE: u16 = 0x640;
pub const UHYVE_PORT_NETREAD: u16 = 0x680;
pub const UHYVE_PORT_NETSTAT: u16 = 0x700;

/* Ports and data structures for uhyve command line arguments and envp
 * forwarding */
pub const UHYVE_PORT_CMDSIZE: u16 = 0x740;
pub const UHYVE_PORT_CMDVAL: u16 = 0x780;

pub const UHYVE_UART_PORT: u16 = 0x800;
pub const UHYVE_PORT_UNLINK: u16 = 0x840;
