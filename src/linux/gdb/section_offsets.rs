use gdbstub::target::{self, ext::section_offsets::Offsets};

impl target::ext::section_offsets::SectionOffsets for crate::gdb::GdbVcpuManager<crate::os::KvmVm> {
	fn get_section_offsets(&mut self) -> Result<Offsets<u64>, Self::Error> {
		let offset = self.kernel_info.kernel_address.as_u64();
		Ok(Offsets::Sections {
			text: offset,
			data: offset,
			bss: Some(offset),
		})
	}
}
