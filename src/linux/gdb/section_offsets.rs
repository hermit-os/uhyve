use gdbstub::target::{self, ext::section_offsets::Offsets};

use super::GdbUhyve;

impl target::ext::section_offsets::SectionOffsets for GdbUhyve {
	fn get_section_offsets(&mut self) -> Result<Offsets<u64>, Self::Error> {
		let offset = self.vm.kernel_start_addr().as_u64();
		Ok(Offsets::Sections {
			text: offset,
			data: offset,
			bss: Some(offset),
		})
	}
}
