use std::{io, iter, num::ParseIntError};

use either::Either;

/// Checks if the kernel provides support for transparent huge pages
pub fn transparent_hugepages_available() -> io::Result<bool> {
	if cfg!(target_os = "linux") {
		use std::fs;
		use std::path::Path;

		let transp_hugepage_enabled = Path::new("/sys/kernel/mm/transparent_hugepage/enabled");
		if !transp_hugepage_enabled.is_file() {
			debug!(
				"`{}` does not exist. Assuming Hugepages are not available",
				transp_hugepage_enabled.display()
			);
			Ok(false)
		} else {
			match fs::read_to_string(transp_hugepage_enabled) {
				Ok(s) => match s.trim() {
					"[always] madvise never" => Ok(true),
					"always [madvise] never" => Ok(true),
					"always madvise [never]" => Ok(false),
					s => {
						debug!(
							"Could not interpret contents of {}: {}",
							transp_hugepage_enabled.display(),
							s
						);
						Err(io::ErrorKind::InvalidData.into())
					}
				},
				Err(err) => {
					debug!(
						"transparent_hugepages_available: Error reading string: {:?}",
						err
					);
					Err(err)
				}
			}
		}
	} else if cfg!(target_os = "macos") {
		Ok(true)
	} else {
		panic!("Only linux and macos are supported.")
	}
}

/// Parses ranges from strings into discrete steps.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// assert_eq!(
/// 	parse_ranges(["8-10", "5", "3", "7-9"])
/// 		.collect::<Result<Vec<_>, _>>()
/// 		.unwrap(),
/// 	[8, 9, 10, 5, 3, 7, 8, 9]
/// );
/// ```
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
			Ok(range) => Either::Left(range.map(|i| Ok(i))),
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
