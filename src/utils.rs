use crate::error::*;
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
/// FIXME: this doesn't actually have to be a range, could also be single value
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
		.map(|x| x.parse::<i32>().unwrap_or(default as i32) != 0)
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

/// This is a helper function to parse the arguments passed via the commandline argument
/// --cpu_affinity
/// FIXME move filtering to seperate function, to make tests cleaner
pub fn parse_cpu_affinity(args: Vec<&str>, num_cpus: u32) -> Result<Vec<core_affinity::CoreId>> {
	let mut affinity_params: Vec<u32> = Vec::new();
	let _ = args
		.into_iter()
		.map(|s| parse_u32_range(s))
		.map(|range| affinity_params.extend(range.expect("Invalid parameters for CPU_AFFINITY")));
	affinity_params.sort();
	affinity_params.dedup();
	let affinity_params = affinity_params;

	// According to https://github.com/Elzair/core_affinity_rs/issues/3
	// on linux this gives a list of CPUs the process is allowed to run on
	// (as opposed to all CPUs available on the system as the docs suggest)
	let core_ids = core_affinity::get_core_ids().ok_or_else(|| Error::InternalError)?;
	// Filter core_ids to contain only the CPUs specified by CPU_AFFINITY
	let filtered_cpu_affinity: Vec<core_affinity::CoreId> = core_ids
		.into_iter()
		.filter(|core_id| affinity_params.contains(&(core_id.id as u32)))
		.collect();
	if filtered_cpu_affinity.len() == num_cpus as usize {
		Ok(filtered_cpu_affinity)
	} else {
		Err(Error::InvalidArgument(String::from(
			"When specifying the CPU affinity, a valid affinity must be specified for \
		 				   every CPU that uhyve spawns",
		)))
	}
}

mod tests {
	use crate::utils::*;

	#[test]
	fn test_parse_u32_range_valid() {
		let str = "1-3";
		assert_eq!(parse_u32_range(str).unwrap(), [1, 2, 3]);
		let str = "0";
		assert_eq!(parse_u32_range(str).unwrap(), [0]);
		let str = "52364-52365";
		assert_eq!(parse_u32_range(str).unwrap(), [52364, 52365]);
	}

	#[test]
	#[should_panic]
	fn test_parse_u32_range_invalid() {
		let str = "-3";
		parse_u32_range(str).unwrap();
	}
}
