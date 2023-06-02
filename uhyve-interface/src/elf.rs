//! Utility to place the uhyve interface version in the elf header of the hermit kernel.

/// Defines the uhyve interface version in the note section.
///
/// This macro must be used in a module that is guaranteed to be linked.
/// See <https://github.com/rust-lang/rust/issues/99721>.
#[macro_export]
macro_rules! define_uhyve_interface_version {
	() => {
		#[used]
		#[link_section = ".note.hermit.uhyve-interface-version"]
		static INTERFACE_VERSION: $crate::elf::Note = $crate::elf::Note::uhyveif_version();
	};
}

/// Note type for specifying the uhyve interface version in an elf header.
pub const NT_UHYVE_INTERFACE_VERSION: u32 = 0x5b00;

/// A elf note header entry containing the used Uhyve interface version as little-endian 32-bit value.
#[repr(C)]
pub struct Note {
	header: Nhdr32,
	name: [u8; 8],
	data: [u8; 4],
}

impl Note {
	pub const fn uhyveif_version() -> Self {
		Self {
			header: Nhdr32 {
				n_namesz: 8,
				n_descsz: 4,
				n_type: NT_UHYVE_INTERFACE_VERSION,
			},
			name: *b"UHYVEIF\0",
			data: crate::UHYVE_INTERFACE_VERSION.to_be_bytes(),
		}
	}
}

/// The sizes of the fields in [`Note`]
#[repr(C)]
struct Nhdr32 {
	n_namesz: u32,
	n_descsz: u32,
	n_type: u32,
}
