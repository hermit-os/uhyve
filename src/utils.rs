//! Utilities for the binary frontend.
//!
//! These functions are used to parse command line arguments or determining defaults.

use std::{iter, num::ParseIntError};

use either::Either;

/// Parses ranges from strings into discrete steps.
pub fn parse_ranges<'a>(
	ranges: impl IntoIterator<Item = &'a str> + 'a,
) -> impl Iterator<Item = Result<usize, ParseIntError>> + 'a {
	ranges
		.into_iter()
		.map(|range| {
			let range = match range.split_once('-') {
				Some((start, end)) => start.parse()?..=end.parse()?,
				None => {
					let idx = range.parse()?;
					idx..=idx
				}
			};
			Ok(range)
		})
		.flat_map(|range| match range {
			Ok(range) => Either::Left(range.map(Ok)),
			Err(err) => Either::Right(iter::once(Err(err))),
		})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_parse_cpu_affinity() {
		assert_eq!(
			parse_ranges(["8-10", "5", "3", "7-9"])
				.collect::<Result<Vec<_>, _>>()
				.unwrap(),
			[8, 9, 10, 5, 3, 7, 8, 9]
		);

		parse_ranges(["-1-2", "-5"]).for_each(|res| assert!(res.is_err()));
	}
}
