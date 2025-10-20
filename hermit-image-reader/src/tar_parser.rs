use alloc::vec::Vec;
use core::ops::Range;

use crate::filename::{Filename, truncate};

/// A parser for an already decompressed image
#[derive(Clone, Copy)]
pub struct ImageParser<'a> {
	input: &'a [u8],
	offset: usize,
}

impl<'a> ImageParser<'a> {
	pub fn new(input: &'a [u8]) -> Self {
		Self { input, offset: 0 }
	}
}

#[derive(Clone, Debug)]
pub struct ImageFile<'a> {
	pub name: Filename<'a>,
	pub is_exec: bool,
	pub value_range: Range<usize>,
	pub value: &'a [u8],
}

#[derive(Clone, Debug, PartialEq)]
pub enum ImageParserError<'a> {
	UnexpectedEof,
	ParseInt(core::num::ParseIntError),
	FromInt(core::num::TryFromIntError),
	Utf8(core::str::Utf8Error),
	Utf8Opaque,

	FileOverridenWithDirectory(Vec<&'a str>),
}

impl<'a> From<core::num::ParseIntError> for ImageParserError<'a> {
	#[inline(always)]
	fn from(x: core::num::ParseIntError) -> Self {
		Self::ParseInt(x)
	}
}

impl<'a> From<core::num::TryFromIntError> for ImageParserError<'a> {
	#[inline(always)]
	fn from(x: core::num::TryFromIntError) -> Self {
		Self::FromInt(x)
	}
}

impl<'a> From<core::str::Utf8Error> for ImageParserError<'a> {
	#[inline(always)]
	fn from(x: core::str::Utf8Error) -> Self {
		Self::Utf8(x)
	}
}

fn try_parse_octal<'a, T: num_traits::Num>(s: &[u8]) -> Result<T, ImageParserError<'a>>
where
	T::FromStrRadixErr: Into<ImageParserError<'a>>,
{
	T::from_str_radix(str::from_utf8(truncate(s))?, 8).map_err(Into::into)
}

const BLOCK_SIZE: usize = 512;
const BLOCK_SIZE_2POW: u32 = 9;

impl<'a> ImageParser<'a> {
	fn next_intern(&mut self) -> Result<Option<ImageFile<'a>>, ImageParserError<'a>> {
		while self.input.len() >= BLOCK_SIZE {
			// `input` starts with a tar header, padded to 512 bytes (block size)
			let offset = self.offset;
			let (header, rest) = self.input.split_at(BLOCK_SIZE);

			// note that integers are usually encoded as octal numbers
			let name = truncate(&header[0..100]);
			if header.iter().take_while(|i| **i == 0).count() == BLOCK_SIZE {
				// EOF marker
				return Ok(None);
			}
			let is_exec = if let Ok(mode) = try_parse_octal::<u16>(&header[100..108]) {
				mode & 0o111 != 0
			} else {
				false
			};
			let size: usize = try_parse_octal::<u64>(&header[124..136])?.try_into()?;
			let _linkname = &header[157..257];
			let magic = &header[257..263];
			let _version = &header[263..265];
			let prefix = &header[345..500];

			// check if this is a supported file type
			let ret = match header[156] {
				0 | b'0' => {
					// regular file
					let value_offset = offset + BLOCK_SIZE;
					Some(ImageFile {
						name: Filename::One(name),
						is_exec,
						value_range: value_offset..(value_offset + size),
						value: rest.get(..size).ok_or(ImageParserError::UnexpectedEof)?,
					})
				}
				_ => None,
			};

			// finish handling this record
			// header
			self.offset += BLOCK_SIZE;
			// rest (size rounded to next multiple of BLOCK_SIZE)
			let actual_rest_size = {
				let mut tmp = size >> BLOCK_SIZE_2POW;
				if !size.is_multiple_of(BLOCK_SIZE) {
					tmp += 1;
				}
				tmp << BLOCK_SIZE_2POW
			};
			self.offset += actual_rest_size;
			self.input = rest
				.get(actual_rest_size..)
				.ok_or(ImageParserError::UnexpectedEof)?;

			if let Some(mut x) = ret {
				// gather full file name (we might have to honor the ustar prefix)
				if magic == b"ustar\0" && (prefix[0] != 0 || name.contains(&b'\\')) {
					let prefix = truncate(prefix);
					if !prefix.is_empty() {
						x.name = Filename::Two(prefix, name);
					}
				}
				return Ok(Some(x));
			}
		}

		if self.input.is_empty() {
			return Ok(None);
		}
		Err(ImageParserError::UnexpectedEof)
	}
}

impl<'a> Iterator for ImageParser<'a> {
	type Item = Result<ImageFile<'a>, ImageParserError<'a>>;

	fn next(&mut self) -> Option<Self::Item> {
		match self.next_intern() {
			Ok(None) => None,
			Ok(Some(x)) => Some(Ok(x)),
			Err(e) => {
				// make sure we don't get stuck
				self.input = &[];
				Some(Err(e))
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use proptest::prelude::*;

	use super::*;

	proptest! {
		#[test]
		fn doesnt_crash(data: Vec<u8>) {
			ImageParser::new(&*data).count();
		}
	}
}
