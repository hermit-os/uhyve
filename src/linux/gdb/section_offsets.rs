use gdbstub::target::{
	ext::section_offsets::Offsets,
	{self},
};

use super::GdbUhyve;

impl target::ext::section_offsets::SectionOffsets for GdbUhyve {
	fn get_section_offsets(&mut self) -> Result<Offsets<u64>, Self::Error> {
		let offset = self.vm.get_offset();
		Ok(Offsets::Sections {
			text: offset,
			data: offset,
			bss: Some(offset),
		})
	}
}
