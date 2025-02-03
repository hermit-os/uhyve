use std::{
	collections::HashMap,
	convert::Infallible,
	fmt,
	num::{NonZeroU32, ParseIntError, TryFromIntError},
	path::PathBuf,
	str::FromStr,
};

use byte_unit::{Byte, Unit};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Params {
	/// Guest RAM size
	pub memory_size: GuestMemorySize,

	/// Advise Transparent Hugepages
	#[cfg(target_os = "linux")]
	pub thp: bool,

	/// Advise Kernel Samepage Merging
	#[cfg(target_os = "linux")]
	pub ksm: bool,

	/// Number of guest CPUs
	pub cpu_count: CpuCount,

	/// Create a PIT
	#[cfg(target_os = "linux")]
	pub pit: bool,

	/// GDB server port
	pub gdb_port: Option<u16>,

	/// Arguments to forward to the kernel
	pub kernel_args: Vec<String>,

	/// Mapped paths between the guest and host OS
	pub file_mapping: Vec<String>,

	/// Path to create temporary directory on
	pub tempdir: Option<String>,

	/// Kernel output handling
	pub output: Output,

	/// Collect run statistics
	pub stats: bool,

	/// Environment variables of the kernel
	pub env: EnvVars,
}

#[allow(clippy::derivable_impls)]
impl Default for Params {
	fn default() -> Self {
		Self {
			memory_size: Default::default(),
			#[cfg(target_os = "linux")]
			thp: false,
			#[cfg(target_os = "linux")]
			ksm: false,
			#[cfg(target_os = "linux")]
			pit: false,
			cpu_count: Default::default(),
			gdb_port: Default::default(),
			file_mapping: Default::default(),
			tempdir: Default::default(),
			kernel_args: Default::default(),
			output: Default::default(),
			stats: false,
			env: EnvVars::default(),
		}
	}
}

#[derive(Debug, Clone, Copy)]
pub struct CpuCount(NonZeroU32);

impl CpuCount {
	pub fn get(self) -> u32 {
		self.0.get()
	}
}

impl Default for CpuCount {
	fn default() -> Self {
		let default = 1.try_into().unwrap();
		Self(default)
	}
}

impl fmt::Display for CpuCount {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		self.0.fmt(f)
	}
}

impl TryFrom<u32> for CpuCount {
	type Error = TryFromIntError;

	fn try_from(value: u32) -> Result<Self, Self::Error> {
		value.try_into().map(Self)
	}
}

impl FromStr for CpuCount {
	type Err = ParseIntError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let count = s.parse()?;
		Ok(Self(count))
	}
}

#[derive(Debug, Clone, Copy)]
pub struct GuestMemorySize(Byte);

impl GuestMemorySize {
	const fn minimum() -> Byte {
		let Some(byte) = Byte::from_u64_with_unit(16, Unit::MiB) else {
			panic!()
		};
		byte
	}

	pub fn get(self) -> usize {
		self.0.as_u64().try_into().unwrap()
	}
}

impl Default for GuestMemorySize {
	fn default() -> Self {
		Self(Byte::from_u64_with_unit(64, Unit::MiB).unwrap())
	}
}

impl fmt::Display for GuestMemorySize {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.0.get_adjusted_unit(Unit::MiB))
	}
}

#[derive(Debug, Clone)]
pub enum Output {
	StdIo,
	File(PathBuf),
	Buffer,
	None,
}
impl Default for Output {
	fn default() -> Self {
		Self::StdIo
	}
}
impl FromStr for Output {
	type Err = Infallible;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"none" | "None" => Ok(Self::None),
			p => Ok(Self::File(p.into())),
		}
	}
}

#[derive(Error, Debug)]
pub enum InvalidGuestMemorySizeError {
	#[error(
		"Not enough guest memory. Must be at least {min:#} (is {cur:#.3})",
		min = GuestMemorySize::minimum().get_adjusted_unit(Unit::MiB),
		cur = .0.get_adjusted_unit(Unit::MiB),
	)]
	MemoryTooSmall(Byte),
	#[error(
		"Invalid amount of guest memory. Must be a multiple of 2 MiB (is {cur:#.3})",
		cur = .0.get_adjusted_unit(Unit::MiB),
	)]
	NotAHugepage(Byte),
}

impl TryFrom<Byte> for GuestMemorySize {
	type Error = InvalidGuestMemorySizeError;

	fn try_from(value: Byte) -> Result<Self, Self::Error> {
		if value < Self::minimum() {
			Err(InvalidGuestMemorySizeError::MemoryTooSmall(value))
		} else if value.as_u64() % Byte::from_u64_with_unit(2, Unit::MiB).unwrap().as_u64() != 0 {
			Err(InvalidGuestMemorySizeError::NotAHugepage(value))
		} else {
			Ok(Self(value))
		}
	}
}

#[derive(Error, Debug)]
pub enum ParseByteError {
	#[error(transparent)]
	Parse(#[from] byte_unit::ParseError),

	#[error(transparent)]
	InvalidMemorySize(#[from] InvalidGuestMemorySizeError),
}

impl FromStr for GuestMemorySize {
	type Err = ParseByteError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let requested = Byte::from_str(s)?;
		let memory_size = requested.try_into()?;
		Ok(memory_size)
	}
}

/// Configure the kernels environment variables.
#[derive(Debug, Clone, PartialEq)]
pub enum EnvVars {
	/// Pass all env vars of the host to the kernel.
	Host,
	/// Pass a certain set of env vars to the kernel.
	Set(HashMap<String, String>),
}
impl Default for EnvVars {
	fn default() -> Self {
		Self::Set(HashMap::new())
	}
}
impl<S: AsRef<str> + std::fmt::Debug + PartialEq<S> + From<&'static str>> From<&[S]> for EnvVars {
	fn from(v: &[S]) -> Self {
		debug!("v: {v:?}");
		if v.contains(&S::from("host")) {
			return Self::Host;
		}
		Self::Set(
			v.iter()
				.map(|s| {
					let sep_pos = s
						.as_ref()
						.find('=')
						.expect("Invalid environment variable format. Must be var=value");
					let split = s.as_ref().split_at(sep_pos);
					(String::from(split.0), String::from(&split.1[1..]))
				})
				.collect(),
		)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_env_vars() {
		let strings = [String::from("ASDF=asdf"), String::from("EMOJI=🤷")];

		let env_vars = EnvVars::from(strings.as_slice());
		match env_vars {
			EnvVars::Host => panic!(),
			EnvVars::Set(map) => {
				assert_eq!(map.get("ASDF").unwrap(), "asdf");
				assert_eq!(map.get("EMOJI").unwrap(), "🤷");
			}
		}

		let env_vars = EnvVars::from(&["host", "OTHER=asdf"] as &[&str]);
		assert_eq!(env_vars, EnvVars::Host);
	}
}
