use core::fmt;

// taken from `tar-rs`
pub fn truncate(slice: &[u8]) -> &[u8] {
	match slice.iter().position(|i| *i == 0) {
		Some(i) => &slice[..i],
		None => slice,
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Filename<'a> {
	One(&'a [u8]),
	Two(&'a [u8], &'a [u8]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrFilename<'a> {
	One(&'a str),
	Two(&'a str, &'a str),
}

impl<'a> Filename<'a> {
	// NOTE: this doesn't return Result<_, core::str::FromUtf8Error> because we have no way
	// of shifting an error by some amount of bytes (for the ::Two case).
	pub fn try_as_str(&self) -> Option<StrFilename<'a>> {
		Some(match self {
			Filename::One(x) => StrFilename::One(str::from_utf8(x).ok()?),
			Filename::Two(x, y) => {
				StrFilename::Two(str::from_utf8(x).ok()?, str::from_utf8(y).ok()?)
			}
		})
	}
}

impl fmt::Display for StrFilename<'_> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::One(x) => f.write_str(x),
			Self::Two(x, y) => {
				f.write_str(x)?;
				f.write_str("/")?;
				f.write_str(y)
			}
		}
	}
}

impl<'a> From<&'a str> for StrFilename<'a> {
	#[inline]
	fn from(x: &'a str) -> Self {
		// null bytes are the only illegal bytes in a str filename
		debug_assert!(!x.contains('\0'));
		Self::One(x)
	}
}

impl<'a> Iterator for StrFilename<'a> {
	type Item = &'a str;

	fn next(&mut self) -> Option<&'a str> {
		match self {
			Self::One(x) if x.is_empty() => None,
			Self::One(x) => Some(match x.split_once('/') {
				None => {
					let ret = *x;
					*x = "";
					ret
				}
				Some((fi, rest)) => {
					*x = rest;
					fi
				}
			}),
			Self::Two(x, y) => Some(match x.split_once('/') {
				None => {
					let ret = *x;
					*self = Self::One(*y);
					ret
				}
				Some((fi, rest)) => {
					*x = rest;
					fi
				}
			}),
		}
	}
}

#[cfg(test)]
mod tests {
	use alloc::vec::Vec;

	use super::*;

	#[test]
	fn test_filename_iter_one() {
		assert_eq!(
			StrFilename::One("aleph/beta/omicron").collect::<Vec<_>>(),
			["aleph", "beta", "omicron"]
		);
	}

	#[test]
	fn test_filename_iter_two() {
		assert_eq!(
			StrFilename::Two("aleph/beta", "omicron/depth").collect::<Vec<_>>(),
			["aleph", "beta", "omicron", "depth"]
		);
	}
}
