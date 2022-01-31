use crate::consts::UHYVE_UART_PORT;
use bitflags::bitflags;
use core::fmt;
use goblin::elf64::header::EM_AARCH64;

pub const RAM_START: u64 = 0x00;
pub const ELF_HOST_ARCH: u16 = EM_AARCH64;

pub const PT_DEVICE: u64 = 0x707;
pub const PT_PT: u64 = 0x713;
pub const PT_MEM: u64 = 0x713;
pub const PT_MEM_CD: u64 = 0x70F;
pub const PT_SELF: u64 = 1 << 55;

/*
 * Memory types available.
 */
#[allow(non_upper_case_globals)]
pub const MT_DEVICE_nGnRnE: u64 = 0;
#[allow(non_upper_case_globals)]
pub const MT_DEVICE_nGnRE: u64 = 1;
pub const MT_DEVICE_GRE: u64 = 2;
pub const MT_NORMAL_NC: u64 = 3;
pub const MT_NORMAL: u64 = 4;

#[inline(always)]
pub const fn mair(attr: u64, mt: u64) -> u64 {
	attr << (mt * 8)
}

/*
 * TCR flags
 */
pub const TCR_IRGN_WBWA: u64 = ((1) << 8) | ((1) << 24);
pub const TCR_ORGN_WBWA: u64 = ((1) << 10) | ((1) << 26);
pub const TCR_SHARED: u64 = ((3) << 12) | ((3) << 28);
pub const TCR_TBI0: u64 = 1 << 37;
pub const TCR_TBI1: u64 = 1 << 38;
pub const TCR_ASID16: u64 = 1 << 36;
pub const TCR_TG1_16K: u64 = 1 << 30;
pub const TCR_TG1_4K: u64 = 0 << 30;
pub const TCR_FLAGS: u64 = TCR_IRGN_WBWA | TCR_ORGN_WBWA | TCR_SHARED;

/// Number of virtual address bits for 4KB page
pub const VA_BITS: u64 = 48;

#[inline(always)]
pub const fn tcr_size(x: u64) -> u64 {
	((64 - x) << 16) | (64 - x)
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BootInfo {
	pub magic_number: u32,
	pub version: u32,
	pub base: u64,
	pub ram_start: u64,
	pub limit: u64,
	pub image_size: u64,
	pub tls_start: u64,
	pub tls_filesz: u64,
	pub tls_memsz: u64,
	pub tls_align: u64,
	pub current_stack_address: u64,
	pub current_percore_address: u64,
	pub host_logical_addr: u64,
	pub boot_gtod: u64,
	pub cmdline: u64,
	pub cmdsize: u64,
	pub cpu_freq: u32,
	pub boot_processor: u32,
	pub cpu_online: u32,
	pub possible_cpus: u32,
	pub current_boot_id: u32,
	pub uartport: u32,
	pub single_kernel: u8,
	pub uhyve: u8,
	pub hcip: [u8; 4],
	pub hcgateway: [u8; 4],
	pub hcmask: [u8; 4],
}

impl BootInfo {
	pub const fn new() -> Self {
		BootInfo {
			magic_number: 0xC0DE_CAFEu32,
			version: 1,
			base: 0,
			ram_start: RAM_START,
			limit: 0,
			tls_start: 0,
			tls_filesz: 0,
			tls_memsz: 0,
			tls_align: 0,
			image_size: 0,
			current_stack_address: 0,
			current_percore_address: 0,
			host_logical_addr: 0,
			boot_gtod: 0,
			cmdline: 0,
			cmdsize: 0,
			cpu_freq: 0,
			boot_processor: !0,
			cpu_online: 0,
			possible_cpus: 0,
			current_boot_id: 0,
			uartport: UHYVE_UART_PORT as u32,
			single_kernel: 1,
			uhyve: 0,
			hcip: [255, 255, 255, 255],
			hcgateway: [255, 255, 255, 255],
			hcmask: [255, 255, 255, 0],
		}
	}
}

impl fmt::Debug for BootInfo {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		writeln!(f, "magic_number {:#x}", self.magic_number)?;
		writeln!(f, "version {:#x}", self.version)?;
		writeln!(f, "base {:#x}", self.base)?;
		writeln!(f, "ram address {:#x}", self.ram_start)?;
		writeln!(f, "limit {:#x}", self.limit)?;
		writeln!(f, "tls_start {:#x}", self.tls_start)?;
		writeln!(f, "tls_filesz {:#x}", self.tls_filesz)?;
		writeln!(f, "tls_memsz {:#x}", self.tls_memsz)?;
		writeln!(f, "tls_align {:#x}", self.tls_align)?;
		writeln!(f, "image_size {:#x}", self.image_size)?;
		writeln!(f, "current_stack_address {:#x}", self.current_stack_address)?;
		writeln!(
			f,
			"current_percore_address {:#x}",
			self.current_percore_address
		)?;
		writeln!(f, "host_logical_addr {:#x}", self.host_logical_addr)?;
		writeln!(f, "boot_gtod {:#x}", self.boot_gtod)?;
		writeln!(f, "cmdline {:#x}", self.cmdline)?;
		writeln!(f, "cmdsize {:#x}", self.cmdsize)?;
		writeln!(f, "cpu_freq {}", self.cpu_freq)?;
		writeln!(f, "boot_processor {}", self.boot_processor)?;
		writeln!(f, "cpu_online {}", self.cpu_online)?;
		writeln!(f, "possible_cpus {}", self.possible_cpus)?;
		writeln!(f, "current_boot_id {}", self.current_boot_id)?;
		writeln!(f, "uartport {:#x}", self.uartport)?;
		writeln!(f, "single_kernel {}", self.single_kernel)?;
		writeln!(f, "uhyve {}", self.uhyve)
	}
}

bitflags! {
	pub struct PSR: u64 {
		const MODE_EL1H	= 0x00000005;
		/// FIQ mask bit
		const F_BIT	= 0x00000040;
		/// IRQ mask bit
		const I_BIT	= 0x00000080;
		/// SError mask bit
		const A_BIT	= 0x00000100;
		/// Debug mask bit
		const D_BIT	= 0x00000200;
	}
}
