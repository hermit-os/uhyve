/// Describe Hardware Break/Watchpoints in a format easily convertible into raw addrs and bits in Dr7 register
use log::error;

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
	W = 0b01,
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
pub struct HWBreakpoints(pub [HWBreakpoint; 4]);

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

			out |= (bp.trigger as u64) << (4 * n) << 16;
			out |= (bp.size as u64) << 2 << (4 * n) << 16;

			out |= (bp.is_local as u64) << (2 * n);
			out |= (bp.is_global as u64) << 1 << (2 * n);
		}

		out
	}
}

#[test]
fn test_hwbreakpoints_dr7() {
	let br = HWBreakpoints([
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
	assert_eq!(
		br.get_dr7(),
		0b_0101_0000_1011_1101_00000111_01_11_10_10,
		"dr7 wrong: {:#034b}",
		br.get_dr7()
	);
}
