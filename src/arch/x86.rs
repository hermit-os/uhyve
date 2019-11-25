//! Functions to read and write control registers.
//! See Intel Vol. 3a Section 2.5, especially Figure 2-7.

// Code is derived from https://github.com/gz/rust-x86/

use bitflags::*;

bitflags! {
	pub struct Cr0: usize {
		const CR0_ENABLE_PAGING = 1 << 31;
		const CR0_CACHE_DISABLE = 1 << 30;
		const CR0_NOT_WRITE_THROUGH = 1 << 29;
		const CR0_ALIGNMENT_MASK = 1 << 18;
		const CR0_WRITE_PROTECT = 1 << 16;
		const CR0_NUMERIC_ERROR = 1 << 5;
		const CR0_EXTENSION_TYPE = 1 << 4;
		const CR0_TASK_SWITCHED = 1 << 3;
		const CR0_EMULATE_COPROCESSOR = 1 << 2;
		const CR0_MONITOR_COPROCESSOR = 1 << 1;
		const CR0_PROTECTED_MODE = 1 << 0;
	}
}

bitflags! {
	pub struct Cr4: usize {
		/// Enables use of Protection Keys (MPK).
		const CR4_ENABLE_PROTECTION_KEY = 1 << 22;
		/// Enable Supervisor Mode Access Prevention.
		const CR4_ENABLE_SMAP = 1 << 21;
		/// Enable Supervisor Mode Execution Protection.
		const CR4_ENABLE_SMEP = 1 << 20;
		/// Enable XSAVE and Processor Extended States.
		const CR4_ENABLE_OS_XSAVE = 1 << 18;
		/// Enables process-context identifiers (PCIDs).
		const CR4_ENABLE_PCID = 1 << 17;
		/// Enables the instructions RDFSBASE, RDGSBASE, WRFSBASE, and WRGSBASE.
		const CR4_ENABLE_FSGSBASE = 1 << 16;
		/// Enables Safer Mode Extensions (Trusted Execution Technology (TXT)).
		const CR4_ENABLE_SMX = 1 << 14;
		/// Enables Virtual Machine Extensions.
		const CR4_ENABLE_VMX = 1 << 13;
		/// Enables 5-Level Paging.
		const CR4_ENABLE_LA57 = 1 << 12;
		/// Enable User-Mode Instruction Prevention (the SGDT, SIDT, SLDT, SMSW and STR instructions
		/// cannot be executed if CPL > 0).
		const CR4_ENABLE_UMIP = 1 << 11;
		/// Enables unmasked SSE exceptions.
		const CR4_UNMASKED_SSE = 1 << 10;
		/// Enables Streaming SIMD Extensions (SSE) instructions and fast FPU
		/// save & restore FXSAVE and FXRSTOR instructions.
		const CR4_ENABLE_SSE = 1 << 9;
		/// Enable Performance-Monitoring Counters
		const CR4_ENABLE_PPMC = 1 << 8;
		/// Enable shared (PDE or PTE) address translation between address spaces.
		const CR4_ENABLE_GLOBAL_PAGES = 1 << 7;
		/// Enable machine check interrupts.
		const CR4_ENABLE_MACHINE_CHECK = 1 << 6;
		/// Enable: Physical Address Extension (allows to address physical
		/// memory larger than 4 GiB).
		const CR4_ENABLE_PAE = 1 << 5;
		/// Enable Page Size Extensions (allows for pages larger than the traditional 4 KiB size)
		/// Note: If Physical Address Extension (PAE) is used, the size of large pages is reduced
		/// from 4 MiB down to 2 MiB, and PSE is always enabled, regardless of the PSE bit in CR4.
		const CR4_ENABLE_PSE = 1 << 4;
		/// If set, enables debug register based breaks on I/O space access.
		const CR4_DEBUGGING_EXTENSIONS = 1 << 3;
		/// If set, disables ability to take time-stamps.
		const CR4_TIME_STAMP_DISABLE = 1 << 2;
		/// If set, enables support for the virtual interrupt flag (VIF) in protected mode.
		const CR4_VIRTUAL_INTERRUPTS = 1 << 1;
		/// If set, enables support for the virtual interrupt flag (VIF) in virtual-8086 mode.
		const CR4_ENABLE_VME = 1 << 0;
	}
}

bitflags! {
	pub struct Xcr0: u64 {
		const XCR0_PKRU_STATE = 1 << 9;
		const XCR0_HI16_ZMM_STATE = 1 << 7;
		const XCR0_ZMM_HI256_STATE = 1 << 6;
		const XCR0_OPMASK_STATE = 1 << 5;
		const XCR0_BNDCSR_STATE = 1 << 4;
		const XCR0_BNDREG_STATE = 1 << 3;
		const XCR0_AVX_STATE = 1 << 2;
		const XCR0_SSE_STATE = 1 << 1;
		const XCR0_FPU_MMX_STATE = 1 << 0;
	}
}



/// Describe Hardware Break/Watchpoints in a format easily convertible into raw addrs and bits in Dr7 register
#[derive(Copy, Clone)]
pub struct HWBreakpoint {
	pub addr: u64,
	pub is_local: bool,
	pub is_global: bool,
	pub trigger: BreakTrigger,
	pub size: BreakSize,
}

#[derive(Copy, Clone, PartialEq)]
pub enum BreakTrigger {
	Ex = 0b00,
	W  = 0b01,
	RW = 0b11,
}

#[derive(Copy, Clone, PartialEq)]
pub enum BreakSize {
	B1 = 0b00,
	B2 = 0b01,
	B4 = 0b10,
	B8 = 0b11,
}

impl Default for HWBreakpoint {
    fn default() -> Self {
		HWBreakpoint {
			addr: 0,
			is_local: false,
			is_global: false,
			trigger: BreakTrigger::Ex,
			size: BreakSize::B1,
		}
    }
}

#[derive(Copy, Clone, Default)]
pub struct HWBreakpoints (
	pub [HWBreakpoint; 4]
);

/// See https://stackoverflow.com/a/40820763
/// https://www.intel.com/content/dam/support/us/en/documents/processors/pentium4/sb/253669.pdf page 5-7
impl HWBreakpoints {
	/// Return address of breakpoint i
	pub fn get_addr(&self, i: usize) -> Option<u64> {
		self.0.get(i).map(|bp| bp.addr)
	}

	/// Return debug control register DR7
	pub fn get_dr7(&self) -> u64 {
		let mut out = 0;

		/* local and global exact breakpoint enable (bits 8,9)
			This feature is not supported in the P6 family processors, later IA-32 processors,
			and Intel 64 processors. When set, these flags cause the processor to detect the
			exact instruction that caused a data breakpoint condition. For backward and forward
			compatibility with other Intel processors, we recommend that the LE and GE flags be
			set to 1 if exact breakpoints are required
		*/
		out |= (1 << 8) | (1 << 9);

		// Bits 11,12,14,15 are reserved 0
		// Bit 10 is reserved, must be set to 1
		// GD (general detect enable) flag (bit 13), protects debug regs from being changed. Not needed by us
		out |= 1 << 10;

		for (n, bp) in self.0.iter().enumerate() {
			if bp.trigger == BreakTrigger::Ex && bp.size != BreakSize::B1 {
				error!("Instruction breakpoint addresses must have a length specification of 1 byte (the LENn field is set to 00). \
					    Code breakpoints for other operand sizes are undefined");
			}

			out |= (bp.trigger as u64)   << (4*n) << 16;
			out |= (bp.size as u64) << 2 << (4*n) << 16;

			out |= (bp.is_local as u64)       << (2*n);
			out |= (bp.is_global as u64) << 1 << (2*n);
		}

		out
	}
}

#[test]
fn test_hwbreakpoints_dr7() {
	let br = HWBreakpoints ([
		HWBreakpoint {
			addr: 0,
			is_local: false,
			is_global: true,
			trigger: BreakTrigger::W,
			size: BreakSize::B8,
		},
		HWBreakpoint {
			addr: 0,
			is_local: false,
			is_global: true,
			trigger: BreakTrigger::RW,
			size: BreakSize::B4,
		},
		HWBreakpoint {
			addr: 0,
			is_local: true,
			is_global: true,
			trigger: BreakTrigger::Ex,
			size: BreakSize::B1,
		},
		HWBreakpoint {
			addr: 0,
			is_local: true,
			is_global: false,
			trigger: BreakTrigger::W,
			size: BreakSize::B2,
		},
	]);
	assert_eq!(br.get_dr7(), 0b_0101_0000_1011_1101_00000111_01_11_10_10, "dr7 wrong: {:#034b}", br.get_dr7());
}