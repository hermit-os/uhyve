use alloc::{
	collections::btree_map::BTreeMap,
	string::{String, ToString},
};
use core::ops::Range;

use crate::{ImageParser, ImageParserError, StrFilename};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ThinTree {
	File(Range<usize>),
	Directory(BTreeMap<String, ThinTree>),
}

impl ThinTree {
	/// Populate a thin directory tree, with `entry` pointing to `r`
	pub fn update<'a>(
		&mut self,
		entry: StrFilename<'a>,
		r: Range<usize>,
	) -> Result<(), ImageParserError<'a>> {
		let mut this = self;
		for (n, i) in entry.enumerate() {
			let dir = match this {
				Self::File(r) if r.start == r.end => {
					*this = Self::Directory(BTreeMap::new());
					if let Self::Directory(dir) = this {
						dir
					} else {
						unreachable!()
					}
				}
				Self::File(_) => {
					return Err(ImageParserError::FileOverridenWithDirectory(
						entry.take(n).collect(),
					));
				}
				Self::Directory(dir) => dir,
			};
			this = dir.entry(i.to_string()).or_insert(Self::File(0..0));
		}
		*this = Self::File(r);
		Ok(())
	}

	pub fn try_from_image<'a>(image: &'a [u8]) -> Result<Self, ImageParserError<'a>> {
		let mut content = Self::File(0..0);
		for i in ImageParser::new(image) {
			let i = i?;
			let name = i
				.name
				.try_as_str()
				.ok_or_else(|| ImageParserError::Utf8Opaque)?;
			// multiple entries with the same name might exist,
			// latest entry wins / overwrites existing ones
			content.update(name, i.value_range)?;
		}
		Ok(content)
	}

	pub fn resolve(&self, mut entry: StrFilename<'_>) -> Option<&Self> {
		entry.try_fold(self, move |this, i| {
			if let Self::Directory(dir) = this {
				dir.get(i)
			} else {
				None
			}
		})
	}

	pub fn resolve_mut(&mut self, mut entry: StrFilename<'_>) -> Option<&mut Self> {
		entry.try_fold(self, move |this, i| {
			if let Self::Directory(dir) = this {
				dir.get_mut(i)
			} else {
				None
			}
		})
	}
}

#[derive(Clone, Debug, PartialEq, Eq, yoke::Yokeable)]
pub enum ThinTreeRef<'a> {
	File(&'a [u8]),
	Directory(BTreeMap<&'a str, ThinTreeRef<'a>>),
}

impl<'a> ThinTreeRef<'a> {
	/// Populate a thin directory tree, with `entry` pointing to `r`
	pub fn update(
		&mut self,
		entry: StrFilename<'a>,
		r: &'a [u8],
	) -> Result<(), ImageParserError<'a>> {
		let mut this = self;
		for (n, i) in entry.enumerate() {
			let dir = match this {
				Self::File(r) if r.is_empty() => {
					*this = Self::Directory(BTreeMap::new());
					if let Self::Directory(dir) = this {
						dir
					} else {
						unreachable!()
					}
				}
				Self::File(_) => {
					return Err(ImageParserError::FileOverridenWithDirectory(
						entry.take(n).collect(),
					));
				}
				Self::Directory(dir) => dir,
			};
			this = dir.entry(i).or_insert(Self::File(b""));
		}
		*this = Self::File(r);
		Ok(())
	}

	pub fn try_from_image(image: &'a [u8]) -> Result<Self, ImageParserError<'a>> {
		let mut content = Self::File(b"");
		for i in ImageParser::new(image) {
			let i = i?;
			let name = i
				.name
				.try_as_str()
				.ok_or_else(|| ImageParserError::Utf8Opaque)?;
			// multiple entries with the same name might exist,
			// latest entry wins / overwrites existing ones
			content.update(name, i.value)?;
		}
		Ok(content)
	}

	pub fn resolve(&self, mut entry: StrFilename<'_>) -> Option<&Self> {
		entry.try_fold(self, move |this, i| {
			if let Self::Directory(dir) = this {
				dir.get(i)
			} else {
				None
			}
		})
	}

	pub fn resolve_mut(&mut self, mut entry: StrFilename<'_>) -> Option<&mut Self> {
		entry.try_fold(self, move |this, i| {
			if let Self::Directory(dir) = this {
				dir.get_mut(i)
			} else {
				None
			}
		})
	}
}
