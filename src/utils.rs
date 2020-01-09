use error::*;
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
