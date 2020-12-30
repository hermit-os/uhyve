use crate::error::*;
use log::debug;
use std::env;

pub fn parse_mem(mem: &str) -> Result<usize> {
	let (num, postfix): (String, String) = mem.chars().partition(|&x| x.is_numeric());
	let num = num.parse::<usize>().map_err(|_| Error::ParseMemory)?;

	let factor = match postfix.as_str() {
		"E" | "e" => 1 << 60 as usize,
		"P" | "p" => 1 << 50 as usize,
		"T" | "t" => 1 << 40 as usize,
		"G" | "g" => 1 << 30 as usize,
		"M" | "m" => 1 << 20 as usize,
		"K" | "k" => 1 << 10 as usize,
		_ => return Err(Error::ParseMemory),
	};

	Ok(num * factor)
}

pub fn parse_u32(s: &str) -> Result<u32> {
	s.parse::<u32>().map_err(|_| Error::ParseMemory)
}

/// Helper function for `parse_bool`
fn parse_bool_str(name: &str) -> Option<bool> {
	match name.to_ascii_lowercase().as_ref() {
		"true" | "yes" => Some(true),
		"false" | "no" => Some(false),
		_ => None,
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
