#![warn(rust_2018_idioms)]

use std::{iter, num::ParseIntError, ops::RangeInclusive, path::PathBuf, process, str::FromStr};

use clap::{Command, CommandFactory, Parser, error::ErrorKind};
use core_affinity::CoreId;
use either::Either;
use env_logger::Builder;
use log::LevelFilter;
use merge::Merge;
use serde::Deserialize;
use thiserror::Error;
#[cfg(target_os = "linux")]
use uhyvelib::params::FileSandboxMode;
use uhyvelib::{
	params::{CpuCount, EnvVars, GuestMemorySize, Output, Params},
	vm::UhyveVm,
};

#[cfg(feature = "instrument")]
fn setup_trace() {
	use rftrace_frontend::Events;

	static mut EVENTS: Option<&mut Events> = None;

	extern "C" fn dump_trace() {
		unsafe {
			if let Some(e) = &mut EVENTS {
				rftrace_frontend::dump_full_uftrace(e, "uhyve_trace", "uhyve", true)
					.expect("Saving trace failed");
			}
		}
	}

	let events = rftrace_frontend::init(1000000, true);
	rftrace_frontend::enable();

	unsafe {
		EVENTS = Some(events);
		libc::atexit(dump_trace);
	}
}

/// Used by clap to derive CLI parameters for Uhyve, as well as
/// by the TOML extension to derive a _subset_ of the CLI arguments.
#[derive(Debug, Default, Deserialize, Merge, Parser)]
#[cfg_attr(test, derive(PartialEq))]
#[clap(version, author, about)]
#[serde(default)]
struct Args {
	#[clap(flatten, next_help_heading = "Uhyve OPTIONS")]
	uhyve: UhyveArgs,

	#[clap(flatten, next_help_heading = "Memory OPTIONS")]
	memory: MemoryArgs,

	#[clap(flatten, next_help_heading = "Cpu OPTIONS")]
	cpu: CpuArgs,

	#[clap(flatten, next_help_heading = "Guest OPTIONS")]
	guest: GuestArgs,
}

impl Args {
	pub fn get_config_file(&self) -> Option<&PathBuf> {
		self.uhyve.config.as_ref()
	}
}

/// Arguments for Uhyve runtime-related configurations.
#[derive(Debug, Default, Deserialize, Merge, Parser)]
#[cfg_attr(test, derive(PartialEq))]
#[serde(default)]
struct UhyveArgs {
	/// Kernel output redirection.
	///
	/// None discards all output, Omit for stdout
	#[clap(short, long, value_name = "FILE")]
	#[serde(default)]
	#[merge(strategy = merge::option::overwrite_none)]
	output: Option<String>,

	/// Display statistics after the execution
	#[clap(long, action = clap::ArgAction::SetTrue)]
	#[serde(default)]
	#[merge(strategy = merge::option::overwrite_none)]
	stats: Option<bool>,

	/// Paths that the kernel should be able to view, read or write.
	///
	/// Desired paths must be explicitly defined after a colon.
	///
	/// Example: --file-mapping host_dir:guest_dir --file-mapping file.txt:guest_file.txt
	#[clap(long)]
	#[serde(skip)]
	#[merge(strategy = merge::vec::append)]
	file_mapping: Vec<String>,

	/// The path that should be used for temporary directories storing unmapped files.
	///
	/// This is useful for manually created tmpfs filesystems and for selecting
	/// directories not managed by a temporary file cleaner, which can remove open files
	/// manually. In most cases, mapping the guest path /root/ instead should be sufficient.
	///
	/// Defaults to /tmp.
	#[clap(long)]
	#[serde(default)]
	#[merge(strategy = merge::option::overwrite_none)]
	tempdir: Option<String>,

	/// File isolation (none, normal, strict)
	///
	/// - 'none' disables all file isolation features
	///
	/// - 'normal' enables all file isolation features supported on the host system
	///
	/// - 'strict' enforces the highest amount of file isolation possible, fails on systems
	///   that do not support them (e.g. a Linux kernel without Landlock support)
	///
	/// [default: normal]
	#[clap(long)]
	#[serde(default)]
	#[merge(strategy = merge::option::overwrite_none)]
	#[cfg(target_os = "linux")]
	file_isolation: Option<String>,

	/// GDB server port
	///
	/// Starts a GDB server on the provided port and waits for a connection.
	#[clap(short = 's', long, env = "HERMIT_GDB_PORT")]
	#[serde(default)]
	#[merge(strategy = merge::option::overwrite_none)]
	#[cfg(target_os = "linux")]
	gdb_port: Option<u16>,

	/// TOML configuration file
	///
	/// Reads configurations from a locally given path.
	#[clap(long, env = "HERMIT_CONFIG")]
	#[serde(skip)]
	#[merge(strategy = merge::option::overwrite_none)]
	pub config: Option<PathBuf>,
}

/// Arguments for memory resources allocated to the guest (both guest and host).
#[derive(Debug, Default, Deserialize, Merge, Parser)]
#[cfg_attr(test, derive(PartialEq))]
#[serde(default)]
#[merge(strategy = merge::option::overwrite_none)]
pub struct MemoryArgs {
	/// Guest RAM size
	#[clap(short = 'm', long, env = "HERMIT_MEMORY_SIZE")]
	memory_size: Option<GuestMemorySize>,

	/// Disable ASLR
	#[clap(long, action = clap::ArgAction::SetTrue)]
	no_aslr: Option<bool>,

	/// Transparent Hugepages
	///
	/// Advise the kernel to enable Transparent Hugepages [THP] on the virtual RAM.
	///
	/// [THP]: https://www.kernel.org/doc/html/latest/admin-guide/mm/transhuge.html
	#[clap(long, action = clap::ArgAction::SetTrue)]
	#[cfg(target_os = "linux")]
	thp: Option<bool>,

	/// Kernel Samepage Merging
	///
	/// Advise the kernel to enable Kernel Samepage Merging [KSM] on the virtual RAM.
	///
	/// [KSM]: https://www.kernel.org/doc/html/latest/admin-guide/mm/ksm.html
	#[clap(long, action = clap::ArgAction::SetTrue)]
	#[cfg(target_os = "linux")]
	ksm: Option<bool>,
}

/// Arguments for the CPU resources allocated to the guest.
#[derive(Clone, Debug, Default, Deserialize, Merge, Parser)]
#[cfg_attr(test, derive(PartialEq))]
#[serde(default)]
#[merge(strategy = merge::option::overwrite_none)]
struct CpuArgs {
	/// Number of guest CPUs
	#[clap(short, long, env = "HERMIT_CPU_COUNT")]
	cpu_count: Option<CpuCount>,

	/// Create a PIT
	#[clap(long, action = clap::ArgAction::SetTrue)]
	#[cfg(target_os = "linux")]
	pit: Option<bool>,

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
	affinity: Option<Affinity>,
}

impl CpuArgs {
	fn get_affinity(self, app: &mut Command) -> Option<Vec<CoreId>> {
		self.affinity.map(|affinity| {
			let affinity_num_vals = affinity.0.len();
			let cpus_num_vals = usize::try_from(self.cpu_count.unwrap_or_default().get()).unwrap();
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

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
struct Affinity(Vec<CoreId>);

impl Affinity {
	fn parse_ranges_iter<'a>(
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
enum ParseAffinityError {
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

struct AffinityVisitor;

impl<'de> serde::de::Visitor<'de> for AffinityVisitor {
	type Value = Affinity;

	fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		formatter.write_str("an Affinity, e.g. \"1-3,5\" or [1,2,3,5]")
	}

	fn visit_str<E>(self, s: &str) -> Result<Affinity, E>
	where
		E: serde::de::Error,
	{
		s.parse()
			.map_err(|_| serde::de::Error::invalid_value(serde::de::Unexpected::Str(s), &self))
	}

	fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
	where
		A: serde::de::SeqAccess<'de>,
	{
		let mut values = Vec::<CoreId>::new();
		while let Some(value) = seq.next_element()? {
			values.push(CoreId { id: value });
		}
		Ok(Affinity(values))
	}
}

impl<'de> serde::de::Deserialize<'de> for Affinity {
	fn deserialize<D>(deserializer: D) -> Result<Affinity, D::Error>
	where
		D: serde::de::Deserializer<'de>,
	{
		deserializer.deserialize_any(AffinityVisitor)
	}
}

/// Arguments for the guest OS and guest runtime-related configurations.
#[derive(Debug, Default, Deserialize, Merge, Parser)]
#[cfg_attr(test, derive(PartialEq))]
struct GuestArgs {
	/// The kernel to execute
	#[clap(value_parser)]
	#[serde(skip)]
	#[merge(skip)]
	kernel: PathBuf,

	/// Arguments to forward to the kernel
	#[serde(skip)]
	#[merge(skip)]
	pub kernel_args: Vec<String>,

	/// Environment variables of the guest as env=value paths
	///
	/// `-e host` passes all variables of the parent process to the kernel (discarding any other passed environment variables).
	///
	/// Example: --env_vars ASDF=jlk -e TERM=uhyveterm2000
	#[clap(short, long)]
	#[serde(default)]
	#[merge(strategy = merge::vec::append)]
	pub env_vars: Vec<String>,
}

impl From<Args> for Params {
	fn from(args: Args) -> Self {
		let Args {
			uhyve:
				UhyveArgs {
					output,
					stats,
					file_mapping,
					tempdir,
					#[cfg(target_os = "linux")]
					file_isolation,
					#[cfg(target_os = "linux")]
					gdb_port,
					config: _,
				},
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
		} = args;
		Self {
			memory_size: memory_size.unwrap_or_default(),
			#[cfg(target_os = "linux")]
			thp: thp.unwrap_or_default(),
			#[cfg(target_os = "linux")]
			ksm: ksm.unwrap_or_default(),
			aslr: !no_aslr.unwrap_or_default(),
			cpu_count: cpu_count.unwrap_or_default(),
			#[cfg(target_os = "linux")]
			pit: pit.unwrap_or_default(),
			file_mapping,
			#[cfg(target_os = "linux")]
			gdb_port,
			#[cfg(target_os = "macos")]
			gdb_port: None,
			kernel_args,
			tempdir,
			#[cfg(target_os = "linux")]
			file_isolation: if let Some(file_isolation) = file_isolation {
				FileSandboxMode::from_str(&file_isolation).unwrap()
			} else {
				FileSandboxMode::default()
			},
			// TODO
			output: if let Some(outp) = output {
				Output::from_str(&outp).unwrap()
			} else {
				Output::StdIo
			},
			stats: stats.unwrap_or_default(),
			env: EnvVars::try_from(env_vars.as_slice()).unwrap(),
		}
	}
}

fn run_uhyve() -> i32 {
	#[cfg(feature = "instrument")]
	setup_trace();

	/*
	 * 1. CLI parameters are parsed into Args.
	 * 2. Get config file location using the CLI parameters' config.
	 * 3. Override missing CLI configs ("None") with configs obtained from config file.
	 *
	 * (Done wherever the user has not explicitly defined an option using the CLI)
	 */

	let mut env_builder = Builder::new();
	env_builder.filter_level(LevelFilter::Warn);
	env_builder.parse_env("RUST_LOG");
	env_builder.format_timestamp(None);
	env_builder.init();

	let mut app = Args::command();
	let mut args = Args::parse();
	// Tries to read arguments from a configuration file. If it doesn't exist or if
	// parsing is not possible, continue using args as-is.
	//
	// TODO: Attempt to read configuration file from default locations (cwd, .config, etc.)
	let config_file = args.get_config_file();
	if let Some(config_file) = config_file {
		if let Ok(contents) = std::fs::read_to_string(config_file) {
			let toml_args: Result<Args, toml::de::Error> = toml::from_str(&contents);
			if let Ok(toml_args) = toml_args {
				args.merge(toml_args);
			}
		}
	}

	let stats = args.uhyve.stats.unwrap_or_default();
	let kernel_path = args.guest.kernel.clone();
	let affinity = args.cpu.clone().get_affinity(&mut app);
	let params = Params::from(args);

	let vm = UhyveVm::new(kernel_path, params).unwrap_or_else(|e| panic!("Error: {e}"));

	let res = vm.run(affinity);
	if stats && let Some(stats) = res.stats {
		println!("Run statistics:");
		println!("{stats}");
	}
	res.code
}

fn main() {
	process::exit(run_uhyve())
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Tests whether the input '0-1,2' for Affinity works like in the CLI.
	///
	/// Implicitly, this tests the same program path as the one used in the CLI.
	#[test]
	fn test_toml_affinity_strings() {
		let config: Args = toml::from_str(
			r#"
			[cpu]
			cpu_count = 3
			affinity = '0-1,2'
		"#,
		)
		.unwrap();

		assert_eq!(
			config.cpu.clone().affinity.unwrap().0,
			Affinity::from_str("0,1,2").unwrap().0
		);

		let mut app = Args::command();
		// This should not panic, CPU number is equal.
		let _affinity = config.cpu.get_affinity(&mut app);
	}

	/// Tests whether the input '[0,1,2]' (entering different usizes)
	/// is parsed correctly. TOML-config file only.
	#[test]
	fn test_toml_affinity_usize_array() {
		let config: Args = toml::from_str(
			r#"
			[cpu]
			cpu_count = 3
			affinity = [0, 1, 2]
		"#,
		)
		.unwrap();

		assert_eq!(
			config.cpu.clone().affinity.unwrap().0,
			Affinity::from_str("0,1,2").unwrap().0
		);

		let mut app = Args::command();
		// This should not panic, CPU number is equal.
		let _affinity = config.cpu.get_affinity(&mut app);
	}

	/// Tests whether an error appears if the defined affinity does
	/// not match that of the assigned CPU cores.
	#[test]
	#[should_panic]
	fn test_affinity_errors_when_lacking_cpu_cores() {
		let config: Args = toml::from_str(
			r#"
			[cpu]
			cpu_count = 1
			affinity = [0, 1, 2]
		"#,
		)
		.unwrap();

		let mut app = Args::command();
		let _affinity: Option<Vec<CoreId>> = config.cpu.get_affinity(&mut app);
	}

	/// Tests whether the fields that are not supposed to belong to
	/// the Uhyve-wide configuration are actually skipped.
	///
	/// Note: Althuogh env_vars and kernel_args can be understood as
	/// "specific to images", it is assumed that we will be able to
	/// just append Uhyve-wide and image-specific configurations.
	#[test]
	fn test_toml_are_fields_actually_skipped() {
		let config: Args = toml::from_str(
			r#"
			[uhyve]
			file_mapping = ['foo:bar']
			config = "/ilikerecursion"

			[guest]
			kernel = './data/x86_64/hello_c'
		"#,
		)
		.unwrap();

		assert!(&config.uhyve.file_mapping.is_empty());
		assert!(&config.uhyve.config.is_none());
		assert!(&config.guest.kernel.to_str().unwrap().is_empty())
	}

	/// Tests whether TOML merge works as expected.
	#[test]
	fn test_toml_merge() {
		let mut cli_args = Args {
			uhyve: UhyveArgs {
				output: None,
				stats: None,
				file_mapping: vec![String::from_str("./host:/root/guest.txt").unwrap()],
				tempdir: None,
				#[cfg(target_os = "linux")]
				file_isolation: None,
				#[cfg(target_os = "linux")]
				gdb_port: None,
				config: Some(PathBuf::from("config.txt")),
			},
			memory: MemoryArgs {
				memory_size: None,
				no_aslr: None,
				#[cfg(target_os = "linux")]
				thp: None,
				#[cfg(target_os = "linux")]
				ksm: None,
			},
			cpu: CpuArgs {
				cpu_count: None,
				affinity: None,
				#[cfg(target_os = "linux")]
				pit: None,
			},
			guest: GuestArgs {
				kernel: PathBuf::from_str("my_kernel.hermit").unwrap(),
				kernel_args: Default::default(),
				env_vars: Default::default(),
			},
		};

		let config_file: Args = toml::from_str(
			r#"
			[uhyve]
			output = 'test.txt'
			stats = true
			tempdir = '/tmp/'
			file_isolation = 'strict'
			gdb_port = 1

			[memory]
			memory_size = '16MiB'
			no_aslr = true
			thp = true
			ksm = true

			[cpu]
			cpu_count = 4
			affinity = [0,1,2]
			pit = true

			[guest]
			env_vars = ['foo=bar']
		"#,
		)
		.unwrap();

		let cli_args_postmerge = Args {
			uhyve: UhyveArgs {
				output: Some(String::from_str("test.txt").unwrap()),
				stats: Some(true),
				file_mapping: vec![String::from_str("./host:/root/guest.txt").unwrap()],
				tempdir: Some(String::from_str("/tmp/").unwrap()),
				#[cfg(target_os = "linux")]
				file_isolation: Some(String::from_str("strict").unwrap()),
				#[cfg(target_os = "linux")]
				gdb_port: Some(1),
				config: Some(PathBuf::from("config.txt")),
			},
			memory: MemoryArgs {
				memory_size: Some(GuestMemorySize::from_str("16MiB").unwrap()),
				no_aslr: Some(true),
				#[cfg(target_os = "linux")]
				thp: Some(true),
				#[cfg(target_os = "linux")]
				ksm: Some(true),
			},
			cpu: CpuArgs {
				cpu_count: Some(CpuCount::from_str("4").unwrap()),
				affinity: Some(Affinity::from_str("0,1,2").unwrap()),
				#[cfg(target_os = "linux")]
				pit: Some(true),
			},
			guest: GuestArgs {
				kernel: PathBuf::from_str("my_kernel.hermit").unwrap(),
				kernel_args: Default::default(),
				env_vars: vec![String::from("foo=bar")],
			},
		};

		cli_args.merge(config_file);
		assert_eq!(cli_args, cli_args_postmerge);
	}
}
