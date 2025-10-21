// Copyright (c) 2025 Hermit contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

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
pub use tar_parser::{ImageFile, ImageParser, ImageParserError};

pub mod config;
