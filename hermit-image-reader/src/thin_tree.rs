// Copyright (c) 2025 Hermit contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use alloc::{
	collections::btree_map::BTreeMap,
	string::{String, ToString},
	vec::Vec,
};
use core::ops::Range;

use crate::{ImageParser, ImageParserError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ThinTree {
	File(Range<usize>),
	Directory(BTreeMap<String, ThinTree>),
}

impl ThinTree {
	/// Populate a thin directory tree, with `entry` pointing to `r`
	pub fn update(&mut self, entry: &[&str], r: Range<usize>) -> Result<(), ImageParserError> {
		let mut this = self;
		for (n, i) in entry.iter().copied().enumerate() {
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
						entry[..=n].iter().map(|i| i.to_string()).collect(),
					));
				}
				Self::Directory(dir) => dir,
			};
			this = dir.entry(i.to_string()).or_insert(ThinTree::File(0..0));
		}
		*this = Self::File(r);
		Ok(())
	}

	pub fn try_from_image(image: &[u8]) -> Result<Self, ImageParserError> {
		let mut content = Self::File(0..0);
		for i in ImageParser::new(image) {
			let i = i?;
			let name = str::from_utf8(&i.name)?;
			// multiple entries with the same name might exist,
			// latest entry wins / overwrites existing ones
			content.update(&name.split('/').collect::<Vec<_>>(), i.value_range)?;
		}
		Ok(content)
	}

	/// Remove an entry from a thin directory tree
	pub fn unlink(&mut self, entry: &[&str]) {
		if entry.is_empty() {
			// we can't remove ourselves.
			return;
		}
		let (lead, to_remove) = entry.split_at(entry.len() - 1);
		let this = self.resolve_mut(lead);
		if let Some(Self::Directory(this)) = this {
			this.remove(to_remove[0]);
		}
	}

	pub fn resolve(&self, entry: &[&str]) -> Option<&ThinTree> {
		entry.iter().try_fold(self, |this, &i| {
			if let Self::Directory(dir) = this {
				dir.get(i)
			} else {
				None
			}
		})
	}

	pub fn resolve_mut(&mut self, entry: &[&str]) -> Option<&mut ThinTree> {
		entry.iter().try_fold(self, |this, &i| {
			if let Self::Directory(dir) = this {
				dir.get_mut(i)
			} else {
				None
			}
		})
	}
}
