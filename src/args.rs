#![warn(rust_2018_idioms)]

use std::{fmt, iter, num::ParseIntError, ops::RangeInclusive, path::PathBuf, str::FromStr};

use clap::{Command, Parser, error::ErrorKind};
use core_affinity::CoreId;
use either::Either;
use serde::{
	de::{Deserialize, SeqAccess, Visitor},
	*,
};
use thiserror::Error;

use crate::params::{CpuCount, EnvVars, GuestMemorySize, Params};

/*
 * Few notes:
 * Although clap offers the convenient default_value_t macro, which would otherwise
 * help us avoid using Option<T> everywhere, this was removed from structs like
 * UhyveArgs, CpuArgs, etc., for two reasons:
 *
 * 1. toml-rs does not have a similar macro, instead choosing to rely on Option<T>.
 * 2. The structs, derived from both CLI arguments (clap) and TOML configuration files
 *    (toml-rs), are fed to Params. Params implements a Default type itself.
 *
 * There is no need to have the structs representing the command line or configuration
 * file interface decide on defaults, as such defaults are decided upon by Params.
 * Params is ultimately what defines, or should define, how Uhyve will actually work.
 * Params should contain a composition of configurations collected both by clap and
 * by toml-rs.
 *
 * Both interfaces should only strictly require a configuration if determining a
 * default is not possible, e.g. the location of a kernel. In the future, it might be
 * possible to infer a certain default from one interface but not for the other (e.g.
 * using the pathname of a TOML configuration file to substitute the `kernel` argument.)
 */

/// This is the config that defines a set of parameters for a given Hermit machine image.
///
/// Note that the field names are relevant for the TOML's tables.
///
/// TODO: Figure out how to adapt file isolation.
#[derive(Debug, Deserialize)]
pub struct UhyveGuestConfig {
	pub(crate) memory: MemoryArgs,
	pub cpu: CpuArgs,
	pub guest: GuestArgs,
}

#[derive(Default, Parser, Debug, Deserialize)]
pub struct MemoryArgs {
	/// Guest RAM size
	#[clap(short = 'm', long, env = "HERMIT_MEMORY_SIZE")]
	pub memory_size: Option<GuestMemorySize>,

	/// Disable ASLR
	#[clap(long)]
	pub no_aslr: Option<bool>,

	/// Transparent Hugepages
	///
	/// Advise the kernel to enable Transparent Hugepages [THP] on the virtual RAM.
	///
	/// [THP]: https://www.kernel.org/doc/html/latest/admin-guide/mm/transhuge.html
	#[clap(long)]
	#[cfg(target_os = "linux")]
	pub thp: Option<bool>,

	/// Kernel Samepage Merging
	///
	/// Advise the kernel to enable Kernel Samepage Merging [KSM] on the virtual RAM.
	///
	/// [KSM]: https://www.kernel.org/doc/html/latest/admin-guide/mm/ksm.html
	#[clap(long)]
	#[cfg(target_os = "linux")]
	pub ksm: Option<bool>,
}

/// Arguments for the CPU resources allocated to the guest.
#[derive(Default, Parser, Debug, Clone, Deserialize)]
pub struct CpuArgs {
	/// Number of guest CPUs
	#[clap(short, long, env = "HERMIT_CPU_COUNT")]
	pub cpu_count: CpuCount,

	/// Create a PIT
	#[clap(long)]
	#[cfg(target_os = "linux")]
	pub pit: Option<bool>,

	/// Bind guest vCPUs to host cpus
	///
	/// A list of host CPU numbers onto which the guest vCPUs should be bound to obtain performance benefits.
	/// List items may be single numbers or inclusive ranges.
	/// List items may be separated with commas or spaces.
	///
	/// # Examples
	///
	/// * `--affinity "0 1 2"`
	///
	/// * `--affinity 0-1,2`
	#[clap(short, long, name = "CPUs")]
	pub affinity: Option<Affinity>,
}

#[derive(Debug, Clone)]
pub struct Affinity(Vec<CoreId>);

impl Affinity {
	pub fn parse_ranges_iter<'a>(
		ranges: impl IntoIterator<Item = &'a str> + 'a,
	) -> impl Iterator<Item = Result<usize, ParseIntError>> + 'a {
		struct ParsedRange(RangeInclusive<usize>);

		impl FromStr for ParsedRange {
			type Err = ParseIntError;

			fn from_str(s: &str) -> Result<Self, Self::Err> {
				let range = match s.split_once('-') {
					Some((start, end)) => start.parse()?..=end.parse()?,
					None => {
						let idx = s.parse()?;
						idx..=idx
					}
				};
				Ok(Self(range))
			}
		}

		ranges
			.into_iter()
			.map(ParsedRange::from_str)
			.flat_map(|range| match range {
				Ok(range) => Either::Left(range.0.map(Ok)),
				Err(err) => Either::Right(iter::once(Err(err))),
			})
	}

	fn parse_ranges(ranges: &str) -> Result<Vec<usize>, ParseIntError> {
		Self::parse_ranges_iter(ranges.split([' ', ','].as_slice())).collect()
	}
}

#[derive(Error, Debug)]
pub enum ParseAffinityError {
	#[error(transparent)]
	Parse(#[from] ParseIntError),

	#[error("Available cores: {available_cores:?}, requested affinities: {requested_affinities:?}")]
	InvalidValue {
		available_cores: Vec<usize>,
		requested_affinities: Vec<usize>,
	},
}

impl FromStr for Affinity {
	type Err = ParseAffinityError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let available_cores = core_affinity::get_core_ids()
			.unwrap()
			.into_iter()
			.map(|core_id| core_id.id)
			.collect::<Vec<_>>();

		let requested_affinities = Self::parse_ranges(s)?;

		if !requested_affinities
			.iter()
			.all(|affinity| available_cores.contains(affinity))
		{
			return Err(ParseAffinityError::InvalidValue {
				available_cores,
				requested_affinities,
			});
		}

		let core_ids = requested_affinities
			.into_iter()
			.map(|affinity| CoreId { id: affinity })
			.collect();
		Ok(Self(core_ids))
	}
}

impl<'de> Deserialize<'de> for Affinity {
	/// Takes a list of core IDs and attempts to iteratively deserialize them.
	///
	/// **Note:** Heavily inspired from https://serde.rs/impl-deserialize.html
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		struct AffinityVisitor;

		impl<'de> Visitor<'de> for AffinityVisitor {
			type Value = Affinity;

			fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
				formatter.write_str(
					"a list of core IDs (usize) or range of core IDs (String, e.g. '1-3')",
				)
			}

			fn visit_seq<A>(self, mut seq: A) -> Result<Affinity, A::Error>
			where
				A: SeqAccess<'de>,
			{
				/// In a TOML configuration file, strings containing ranges or digits (e.g. '4-5', '4'),
				/// as well as ordinary digits (e.g. 4) are supported.
				///
				/// This means that a combination such as ['4-5', '6', 7] is allowed in the TOML config.
				/// This is a byproduct of the preexisting clap interface the FromStr trait implementation
				/// of Affinity, but there wasn't too much of a reason to restrict it; we can support both,
				/// but merely document combinations like ['4-5', 6] instead.
				#[derive(Deserialize)]
				#[serde(untagged)]
				enum AffinityInputTypes {
					String(String),
					Usize(usize),
				}

				let mut cores: Vec<CoreId> = Vec::new();
				while let Some(entry) = seq.next_element::<AffinityInputTypes>()? {
					match entry {
						AffinityInputTypes::String(core_id_range) => {
							// This takes advantage of Affinity's FromStr range that was used before for clap,
							// then it extracts the resulting core IDs from the vector itself.
							//
							// CoreId may be part of the core_affinity crate, but we can control Affinity, so.
							cores.extend(
								Affinity::from_str(core_id_range.as_str()).unwrap().0.iter(),
							);
						}
						AffinityInputTypes::Usize(id) => cores.push(CoreId { id }),
					}
				}
				Ok(Affinity(cores))
			}
		}

		deserializer.deserialize_seq(AffinityVisitor)
	}
}

impl CpuArgs {
	pub fn get_affinity(self, app: &mut Command) -> Option<Vec<CoreId>> {
		self.affinity.map(|affinity| {
			let affinity_num_vals = affinity.0.len();
			let cpus_num_vals = usize::try_from(self.cpu_count.get()).unwrap();
			if affinity_num_vals != cpus_num_vals {
				let affinity_arg = app
					.get_arguments()
					.find(|arg| arg.get_id() == "affinity")
					.unwrap();
				let cpus_arg = app
					.get_arguments()
					.find(|arg| arg.get_id() == "cpus")
					.unwrap();
				let verb = if affinity_num_vals > 1 { "were" } else { "was" };
				let message = format!(
					"The argument '{affinity_arg}' requires {cpus_num_vals} values (matching '{cpus_arg}'), but {affinity_num_vals} {verb} provided",
				);
				app.error(ErrorKind::WrongNumberOfValues, message).exit()
			} else {
				affinity.0
			}
		})
	}
}

/// Arguments for the guest OS and guest runtime-related configurations
#[derive(Parser, Debug, Deserialize)]
pub struct GuestArgs {
	/// The kernel to execute
	#[clap(value_parser)]
	pub kernel: PathBuf,

	/// Arguments to forward to the kernel
	pub kernel_args: Option<Vec<String>>,

	/// Environment variables of the guest as env=value paths
	///
	/// `-e host` passes all variables of the parent process to the kernel (discarding any other passed environment variables).
	///
	/// Example: --env_vars ASDF=jlk -e TERM=uhyveterm2000
	#[clap(short, long)]
	pub env_vars: Option<Vec<String>>,
}

impl From<UhyveGuestConfig> for Params {
	fn from(guest_config: UhyveGuestConfig) -> Self {
		let UhyveGuestConfig {
			memory:
				MemoryArgs {
					memory_size,
					no_aslr,
					#[cfg(target_os = "linux")]
					thp,
					#[cfg(target_os = "linux")]
					ksm,
				},
			cpu:
				CpuArgs {
					cpu_count,
					#[cfg(target_os = "linux")]
					pit,
					affinity: _,
				},
			guest: GuestArgs {
				kernel: _,
				kernel_args,
				env_vars,
			},
		} = guest_config;
		Self {
			memory_size: memory_size.unwrap_or_default(),
			#[cfg(target_os = "linux")]
			thp: thp.unwrap_or_default(),
			#[cfg(target_os = "linux")]
			ksm: ksm.unwrap_or_default(),
			aslr: !no_aslr.unwrap_or_default(),
			cpu_count,
			#[cfg(target_os = "linux")]
			pit: pit.unwrap_or_default(),
			kernel_args: kernel_args.unwrap_or_default(),
			env: EnvVars::try_from(env_vars.unwrap_or_default().as_slice()).unwrap(),
			..Default::default()
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	// TODO: Make kernel_args optional
	// TODO: make thp/pit/ksm optional, use defaults if they don't exist
	// TODO: split boilerplate (linux-specific or not)

	#[test]
	fn test_toml_affinity_strings() {
		// TODO: Fix affinity
		// TODO: Make kernel_args optional
		let config_affinity_mixed: UhyveGuestConfig = toml::from_str(
			r#"
			[memory]
			memory_size = '4M'
			no_aslr = false
			thp = false
			pit = true
			ksm = true

			[cpu]
			cpu_count = 4
			pit = false
			affinity = ['1-2', '3']

			[guest]
			kernel = './data/x86_64/hello_c'
			kernel_args = ['foo=bar']
			env_vars = ['bar=foo']
		"#,
		)
		.unwrap();

		assert_eq!(
			config_affinity_mixed.cpu.affinity.unwrap().0,
			Affinity::from_str("1,2,3").unwrap().0
		);
	}

	#[test]
	fn test_toml_affinity_strings_two() {
		let config_affinity_mixed: UhyveGuestConfig = toml::from_str(
			r#"
			[memory]
			memory_size = '4M'
			no_aslr = false
			thp = false
			pit = true
			ksm = true

			[cpu]
			cpu_count = 4
			pit = false
			affinity = ['1,2', '3']

			[guest]
			kernel = './data/x86_64/hello_c'
			kernel_args = ['foo=bar']
			env_vars = ['bar=foo']
		"#,
		)
		.unwrap();

		assert_eq!(
			config_affinity_mixed.cpu.affinity.unwrap().0,
			Affinity::from_str("1,2,3").unwrap().0
		);
	}

	#[test]
	fn test_toml_affinity_usize() {
		let _config_affinity_usize: UhyveGuestConfig = toml::from_str(
			r#"
			[memory]
			memory_size = '4M'
			no_aslr = false
			thp = false
			pit = true
			ksm = true

			[cpu]
			cpu_count = 4
			pit = false
			affinity = [1, 2, 3]

			[guest]
			kernel = './data/x86_64/hello_c'
			kernel_args = ['foo=bar']
			env_vars = ['bar=foo']
		"#,
		)
		.unwrap();
	}
}
