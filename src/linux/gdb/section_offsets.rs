use gdbstub::target::{self, ext::section_offsets::Offsets};

use crate::net::NetworkBackend;

impl<NetBackend: NetworkBackend> target::ext::section_offsets::SectionOffsets
	for super::GdbVcpuManager<NetBackend>
{
	fn get_section_offsets(&mut self) -> Result<Offsets<u64>, Self::Error> {
		let offset = self.kernel_info.kernel_address.as_u64();
		Ok(Offsets::Sections {
			text: offset,
			data: offset,
			bss: Some(offset),
		})
	}
}
