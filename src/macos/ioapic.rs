/// Number of redirection table entries
const REDIR_ENTRIES: usize = 24;
/// Redirection table base
const IOAPIC_REG_TABLE: usize = 0x0010;

#[derive(Copy, Clone)]
struct RedirectionTable {
	reg: u32,
}

impl RedirectionTable {
	pub fn new() -> Self {
		RedirectionTable { reg: 0 }
	}
}

pub struct IoApic {
	selector: usize,
	rtbl: [RedirectionTable; IOAPIC_REG_TABLE + 2 * REDIR_ENTRIES],
}

impl IoApic {
	pub fn new() -> Self {
		let mut ioapic = IoApic {
			selector: 0,
			rtbl: [RedirectionTable::new(); IOAPIC_REG_TABLE + 2 * REDIR_ENTRIES],
		};

		ioapic.rtbl[1].reg = 0x11 | ((REDIR_ENTRIES as u32 - 1) << 16);

		/* Initialize all redirection entries to mask all interrupts */
		for i in IOAPIC_REG_TABLE..REDIR_ENTRIES {
			ioapic.rtbl[i].reg = 0x00010000u32;
		}

		ioapic
	}

	pub fn write(&mut self, offset: u64, value: u64) {
		match offset {
			0x00 => self.selector = value as usize,
			0x10 => self.rtbl[self.selector].reg = value as u32,
			offset => panic!("Invalid offset {}", offset),
		}
	}

	pub fn read(&mut self, offset: u64) -> u64 {
		match offset {
			0x00 => self.selector as u64,
			0x10 => self.rtbl[self.selector].reg as u64,
			offset => panic!("Invalid offset {}", offset),
		}
	}
}

impl Default for IoApic {
	fn default() -> Self {
		Self::new()
	}
}
