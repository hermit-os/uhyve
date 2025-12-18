// guest_address + OFFSET
pub const PAGETABLES_OFFSET: u64 = 0x11000;
pub const PAGETABLES_END: u64 = 0x30000;

pub const GUEST_PAGE_SIZE: u64 = 0x200000; /* 2 MB pages in guest */
