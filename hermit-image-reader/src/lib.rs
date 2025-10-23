#![no_std]

extern crate alloc;

use alloc::vec::Vec;

/// We assume that all images are gzip-compressed
pub fn decompress_image(data: &[u8]) -> Result<Vec<u8>, compression::prelude::CompressionError> {
	use compression::prelude::{DecodeExt as _, GZipDecoder};

	data.iter()
		.copied()
		.decode(&mut GZipDecoder::new())
		.collect()
}

mod tar_parser;
pub use tar_parser::{Filename, ImageFile, ImageParser, ImageParserError, StrFilename};

pub mod config;

pub mod thin_tree;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Format {
	ElfKernel,
	Image,
}

/// Attempts to detect the format of an input file (using magic bytes), whether it is an ELF kernel or an image.
pub fn detect_format(data: &[u8]) -> Option<Format> {
	if data.len() < 8 {
		None
	} else if data[0] == 0x7f
		&& data[1] == b'E'
		&& data[2] == b'L'
		&& data[3] == b'F'
		&& data[7] == 0xff
	{
		// ELF with vendor-specific ABI => assume ELF kernel
		Some(Format::ElfKernel)
	} else if data[0] == 0x1f && data[1] == 0x8b && data[2] == 0x08 {
		// gzip => assume image
		Some(Format::Image)
	} else {
		None
	}
}
