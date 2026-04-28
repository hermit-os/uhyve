// guest_address + OFFSET
pub const PAGETABLES_OFFSET: u64 = 0x11000;
pub const PAGETABLES_END: u64 = 0x30000;

pub const UHYVE_NET_MTU: usize = 1500;
pub const UHYVE_IRQ_NET: u32 = 11;
