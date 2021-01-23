use crate::error::*;

use core_affinity::CoreId;
#[cfg(target_os = "linux")]
use log::debug;
use std::env;

pub fn parse_mem(mem: &str) -> Result<usize> {
	let (num, postfix): (String, String) = mem.chars().partition(|&x| x.is_numeric());
	let num = num.parse::<usize>().map_err(|_| Error::ParseMemory)?;

	let factor = match postfix.as_str() {
		"E" | "e" => 1 << 60,
		"P" | "p" => 1 << 50,
		"T" | "t" => 1 << 40,
		"G" | "g" => 1 << 30,
		"M" | "m" => 1 << 20,
		"K" | "k" => 1 << 10,
		_ => return Err(Error::ParseMemory),
	};

	Ok(num * factor)
}

/// Example:
/// ```rust
/// # use uhyvelib::utils::parse_u32;
/// assert_eq!(parse_u32("15").unwrap(), 15);
/// ```
pub fn parse_u32(s: &str) -> Result<u32> {
	s.parse::<u32>().map_err(|_| Error::ParseMemory)
}

/// Helper function for `parse_bool`
fn parse_bool_str(value: &str) -> Option<bool> {
	match value.to_ascii_lowercase().as_ref() {
		"true" | "yes" => Some(true),
		"false" | "no" => Some(false),
		_ => None,
	}
}

/// Returns a Vec of u32 as specified in the inclusive range s
/// s should only contain digits and a single `-`
/// The second number should be greater than the first
/// A single positive integer is also a valid parameter ( a range of length 1)
/// Example:
/// ```rust
/// # use uhyvelib::utils::parse_u32_range;
/// let s = "5-7";
/// let range = parse_u32_range(s)?;
/// assert_eq!(range, [5, 6, 7]);
/// # Ok::<(), uhyvelib::error::Error>(())
///  ```
pub fn parse_u32_range(s: &str) -> Result<Vec<u32>> {
	let split: Vec<&str> = s.split('-').collect();
	if split.len() == 1 {
		let val = parse_u32(s)?;
		let vec = vec![val; 1];
		Ok(vec) // Into Vec containing a single u32
	} else if split.len() == 2 {
		let range: Vec<u32> = (parse_u32(split[0])?..=parse_u32(split[1])?).collect();
		Ok(range)
	} else {
		Err(Error::InvalidArgument(String::from(s)))
	}
}

pub fn parse_bool(name: &str, default: bool) -> bool {
	env::var(name)
		.map(|x| {
			parse_bool_str(x.as_ref()).unwrap_or(x.parse::<i32>().unwrap_or(default as i32) != 0)
		})
		.unwrap_or(default)
}

/// returns subslice of s at given offset of at most given length. If offset OOB, return empty slice
pub fn get_max_subslice(s: &str, offset: usize, length: usize) -> &str {
	let large = s.get(offset..s.len()).unwrap_or("");
	if large.len() > length {
		&large[0..length]
	} else {
		large
	}
}

/// Checks if the kernel provides support for transparent huge pages
/// If `/sys/kernel/mm/transparent_hugepage/enabled` does not exist
/// then we assume there is no support.
/// If there is an error when reading the file or interpreting the
/// contents we return an Err and let the caller decide
#[cfg(target_os = "linux")]
pub fn transparent_hugepages_available() -> std::result::Result<bool, ()> {
	let transp_hugepage_enabled =
		std::path::Path::new("/sys/kernel/mm/transparent_hugepage/enabled");
	if !transp_hugepage_enabled.is_file() {
		debug!(
			"`{}` does not exist. Assuming Hugepages are not available",
			transp_hugepage_enabled.display()
		);
		Ok(false)
	} else {
		let str_res = std::fs::read_to_string(transp_hugepage_enabled);
		if str_res.is_err() {
			debug!(
				"transparent_hugepages_available: Error reading string: {:?}",
				str_res.unwrap_err()
			);
			Err(())
		} else {
			match str_res.unwrap().trim() {
				"[always] madvise never" => Ok(true),
				"always [madvise] never" => Ok(true),
				"always madvise [never]" => Ok(false),
				s => {
					debug!(
						"Could not interpret contents of {}: {}",
						transp_hugepage_enabled.display(),
						s
					);
					Err(())
				}
			}
		}
	}
}

/// On macos this always returns true
#[cfg(target_os = "macos")]
pub fn transparent_hugepages_available() -> std::result::Result<bool, ()> {
	Ok(true)
}

/// Filter available to only contain the subset of CPUs specified in affinity
pub fn filter_cpu_affinity(available: Vec<CoreId>, affinity: Vec<u32>) -> Vec<CoreId> {
	let filtered_cpu_affinity: Vec<core_affinity::CoreId> = available
		.into_iter()
		.filter(|core_id| affinity.contains(&(core_id.id as u32)))
		.collect();
	filtered_cpu_affinity
}

/// This is a helper function to parse the arguments passed via the commandline argument
/// --cpu_affinity
/// It returns the parsed Result sorted and deduplicated
/// If any of the strings in args was not able to parsed Err is returned
/// Valid strings are all positive numbers representable with an u32
/// as well as inclusive ranges where all numbers are representable as an u32
/// Example:
/// ```rust
/// # use uhyvelib::utils::parse_cpu_affinity;
/// let a =  parse_cpu_affinity(vec!["5", "2-3", "8-9"]);
/// assert_eq!(a.unwrap(), vec![2,3,5,8,9]);
/// ```
pub fn parse_cpu_affinity(args: Vec<&str>) -> Result<Vec<u32>> {
	let mut affinity: Vec<u32> = Vec::new();
	// res is Err if any single parse_u32_range(s) returned Err
	let parsed_affinity: Result<Vec<Vec<u32>>> =
		args.into_iter().map(|s| parse_u32_range(s)).collect();
	match parsed_affinity {
		Err(e) => Err(e),

		Ok(v) => {
			for vec in v {
				affinity.extend(vec);
			}

			affinity.sort_unstable();
			affinity.dedup();
			let affinity = affinity;
			Ok(affinity)
		}
	}
}

mod tests {
	#[cfg(test)]
	use crate::utils::*;

	#[test]
	fn test_parse_u32_range_valid() {
		let str = "1-3";
		assert_eq!(parse_u32_range(str).unwrap(), [1, 2, 3]);
		let str = "0";
		assert_eq!(parse_u32_range(str).unwrap(), [0]);
		let str = "52364-52365";
		assert_eq!(parse_u32_range(str).unwrap(), [52364, 52365]);
		assert_eq!(parse_u32_range("10").unwrap(), [10]);
	}

	#[test]
	#[should_panic]
	fn test_parse_u32_range_invalid() {
		let str = "-3";
		parse_u32_range(str).unwrap();
	}

	#[test]
	fn test_parse_cpu_affinity() {
		assert_eq!(
			parse_cpu_affinity(vec!["10", "5", "325642", "1", "11"]).unwrap(),
			[1, 5, 10, 11, 325642]
		);
		assert_eq!(
			parse_cpu_affinity(vec!["8-10", "5", "3", "7-9"]).unwrap(),
			[3, 5, 7, 8, 9, 10]
		)
	}

	#[test]
	fn test_parse_cpu_affinity_invalid() {
		assert!(parse_cpu_affinity(vec!["-1-2"]).is_err());
		assert!(parse_cpu_affinity(vec!["-2"]).is_err());
		let too_large = u64::from(u32::max_value()) + 1;
		assert!(parse_cpu_affinity(vec![too_large.to_string().as_ref()]).is_err());
	}

	#[test]
	fn test_filter_cpu_affinity() {
		let vec = vec![CoreId { id: 2 }, CoreId { id: 7 }, CoreId { id: 13 }];
		let res = filter_cpu_affinity(vec, vec![7]);
		assert_eq!(res.len(), 1);
		assert_eq!(res[0].id, 7);
		let res = filter_cpu_affinity(vec![CoreId { id: 2 }], vec![]);
		assert_eq!(res.len(), 0);
		let res = filter_cpu_affinity(vec![CoreId { id: 2 }], vec![0, 1, 3, 9, 22, 724]);
		assert_eq!(res.len(), 0);
	}
}
