#![warn(rust_2018_idioms)]

use std::{fs, num::ParseIntError, path::PathBuf, process, str::FromStr};

use clap::{Command, CommandFactory, Parser, error::ErrorKind};
use core_affinity::CoreId;
use env_logger::Builder;
use log::{LevelFilter, info};
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
extern crate rftrace as _;
#[cfg(feature = "instrument")]
use rftrace_frontend as rftrace;

#[cfg(feature = "instrument")]
fn setup_trace(out_dir: String) {
	use std::sync::OnceLock;

	use rftrace::Events;

	static OUT_DIR: OnceLock<String> = OnceLock::new();
	static mut EVENTS: Option<&mut Events> = None;

	#[allow(static_mut_refs)]
	extern "C" fn dump_trace() {
		unsafe {
			if let Some(e) = &mut EVENTS {
				rftrace::dump_full_uftrace(e, OUT_DIR.get().unwrap(), "uhyve")
					.expect("Saving trace failed");
			}
		}
	}

	OUT_DIR.set(out_dir).unwrap();
	let events = rftrace_frontend::init(1000000, true);
	rftrace::enable();

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
	/// Defaults to /tmp/uhyve-{uid}
	#[clap(long)]
	#[serde(default)]
	#[merge(strategy = merge::option::overwrite_none)]
	tempdir: Option<PathBuf>,

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

	/// I/O mode (default, hostdirect, hostdirectsync)
	///
	/// Sets an I/O mode that enforces certain flags to file open hypercalls,
	/// which influence I/O operations to the host filesystem (i.e. write, read).
	/// Primarily intended for benchmarking; not likely useful for general use.
	///
	/// - `default`: No extra flags will be appended.
	///
	/// - `host=direct`: Appends the O_DIRECT flag to ensure that file
	///   operations do not go through the host page cache.
	///
	/// - `host=sync`: Appends the O_SYNC flag to ensure that file operations will only
	///   return once the host OS "confirms" that all data has been written to the disk.
	///   This is useful when wanting to ensure that e.g. write operations will continue
	///   to block until the device controller informs the host OS that all data has been
	///   written to the storage.
	///
	/// - `host=direct,sync`: Combines `host=direct` and `host=sync`. This should be the
	///   slowest option, but may be considered the most "fair" one in benchmarking
	///   contexts.

	#[clap(long)]
	#[serde(default)]
	#[merge(strategy = merge::option::overwrite_none)]
	#[cfg(target_os = "linux")]
	io_mode: Option<String>,

	/// GDB server port
	///
	/// Starts a GDB server on the provided port and waits for a connection.
	///
	/// [default: 6677]
	#[clap(short = 's', long, env = "HERMIT_GDB_PORT", num_args(0..=1), default_missing_value("6677"))]
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

	/// Directory to store traces (using rftrace)
	///
	/// By using this setting, tracing will be enabled when running Uhyve.
	/// The given directory will be used to store the resulting dumped traces.
	/// The directory must exist on the host.
	///
	/// [default: "uhyve_trace"]
	#[clap(long, num_args(0..=1), default_missing_value("./uhyve_trace"))]
	#[serde(skip)]
	#[merge(skip)]
	#[cfg(feature = "instrument")]
	pub trace: Option<PathBuf>,
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

	/// Allows the guest to manage host CPU power state.
	///
	/// This decreases the latency for the guest, but increases latency for other processes on the same host CPU.
	/// This works best when the host CPUs are not overcommitted.
	/// The host estimates incorrect CPU usage, due to not knowing about guest idle time.
	#[clap(long, action = clap::ArgAction::SetTrue)]
	#[cfg(target_os = "linux")]
	cpu_pm: Option<bool>,

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
	#[cfg_attr(test, allow(unreachable_code))]
	fn get_affinity(self, app: &mut Command) -> Option<Vec<CoreId>> {
		self.affinity.map(|affinity| {
			if let Err(e) = affinity.validate() {
				app.error(ErrorKind::ValueValidation, e).exit()
			}
			let affinity_num_vals = affinity.0.len();
			let cpus_num_vals = usize::try_from(self.cpu_count.unwrap_or_default().get()).unwrap();
			if affinity_num_vals != cpus_num_vals {
				let verb = if affinity_num_vals > 1 { "were" } else { "was" };
				// NOTE: albeit one might ask `clap` to format the arguments `affinity` and `cpu_count`,
				// this runs into an internal error in clap (panic in clap_builder::builder::arg::Arg::get_min_vals)
				let message = format!(
					"The argument '--affinity <CPUs>' requires {cpus_num_vals} values (matching '--cpu-count <CPU_COUNT>'), but {affinity_num_vals} {verb} provided",
				);

				#[cfg(test)]
				panic!("{message}");

				app.error(ErrorKind::WrongNumberOfValues, message).exit()
			} else {
				affinity.0
			}
		})
	}
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
struct Affinity(Vec<CoreId>);

#[derive(Error, Debug)]
enum ParseAffinityError {
	#[error(transparent)]
	ParseInt(#[from] ParseIntError),

	#[error("Unexpected format of affinity string")]
	ParseParts,
}

#[derive(Error, Debug)]
#[error("Available cores: {available_cores:?}, requested affinities: {requested_affinities:?}")]
struct InvalidAffinityValueError {
	available_cores: Vec<CoreId>,
	requested_affinities: Vec<CoreId>,
}

impl FromStr for Affinity {
	type Err = ParseAffinityError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let mut ret = Vec::new();
		for i in s.split([',', ' ']) {
			let mut j = i.splitn(2, '-');
			let first = match j.next() {
				Some(x) => x.parse::<usize>().map_err(ParseAffinityError::ParseInt)?,
				None => return Err(ParseAffinityError::ParseParts),
			};
			match j.next() {
				Some(x) => {
					let second = x.parse::<usize>().map_err(ParseAffinityError::ParseInt)?;
					ret.extend((first..=second).map(|id| CoreId { id }));
				}
				None => {
					ret.push(CoreId { id: first });
				}
			}
		}
		Ok(Self(ret))
	}
}

impl Affinity {
	/// Validates the core affinity against currently available cores
	fn validate(&self) -> Result<(), InvalidAffinityValueError> {
		let available_cores = core_affinity::get_core_ids().unwrap();

		if self
			.0
			.iter()
			.all(|affinity| available_cores.contains(affinity))
		{
			Ok(())
		} else {
			Err(InvalidAffinityValueError {
				available_cores,
				requested_affinities: self.0.clone(),
			})
		}
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
					io_mode,
					#[cfg(target_os = "linux")]
					gdb_port,
					config: _,
					#[cfg(feature = "instrument")]
					trace,
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
					cpu_pm,
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
			cpu_pm: cpu_pm.unwrap_or_default(),
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
			#[cfg(target_os = "linux")]
			io_mode: io_mode.into(),
			// TODO
			output: if let Some(outp) = output {
				Output::from_str(&outp).unwrap()
			} else {
				Output::StdIo
			},
			stats: stats.unwrap_or_default(),
			env: EnvVars::try_from(env_vars.as_slice()).unwrap(),
			#[cfg(feature = "instrument")]
			trace,
		}
	}
}

/// Attempts to read config file and parse contents
fn read_toml_contents(toml_path: &PathBuf) -> Result<Args, Box<dyn std::error::Error>> {
	let contents = fs::read_to_string(toml_path)?;
	let args = toml::from_str::<'_, Args>(&contents)?;
	Ok(args)
}

/// Attempts machine image-specific config from clap, cwd or the config directory.
///
/// This overrides missing CLI configs (None) with configs obtained from config file.
fn load_vm_config(args: &mut Args) {
	// Tries to read arguments from a configuration file. If it doesn't exist or if
	// parsing is not possible, panic.
	if let Some(config_file) = args.get_config_file() {
		args.merge(read_toml_contents(config_file).unwrap());
	} else if let Ok(cwd) = std::env::current_dir()
		&& let cwd_config = [cwd, "uhyve.toml".into()].iter().collect::<PathBuf>()
		&& cwd_config.exists()
	{
		info!("Using uhyve.toml config from current working directory.");
		args.merge(read_toml_contents(&cwd_config).unwrap());
	} else if let Ok(config_home) = std::env::var("XDG_CONFIG_HOME")
		&& !config_home.is_empty()
		&& let config_path = [
			PathBuf::from(config_home),
			"uhyve".into(),
			"uhyve.toml".into(),
		]
		.iter()
		.collect::<PathBuf>()
		&& config_path.exists()
	{
		info!("Using config from {}.", config_path.display());
		args.merge(read_toml_contents(&config_path).unwrap());
	}
}

fn run_uhyve() -> i32 {
	let mut env_builder = Builder::new();
	env_builder
		.filter_level(LevelFilter::Warn)
		.parse_env("RUST_LOG")
		.format_timestamp(None)
		.init();

	let mut app = Args::command();
	let mut args = Args::parse();

	load_vm_config(&mut args);

	#[cfg(feature = "instrument")]
	if let Some(trace) = args.uhyve.trace.as_ref() {
		let trace_outdir_str = trace.to_str().unwrap();
		info!("Setting up trace output directory: {}", trace_outdir_str);
		setup_trace(String::from(trace_outdir_str));
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
	use std::env;

	use tempfile::tempdir;

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
				file_mapping: vec![String::from("./host:/root/guest.txt")],
				tempdir: None,
				#[cfg(target_os = "linux")]
				file_isolation: None,
				#[cfg(target_os = "linux")]
				io_mode: None,
				#[cfg(target_os = "linux")]
				gdb_port: None,
				config: Some(PathBuf::from("config.txt")),
				#[cfg(feature = "instrument")]
				trace: Some(PathBuf::from(".")),
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
				#[cfg(target_os = "linux")]
				cpu_pm: None,
				affinity: None,
				#[cfg(target_os = "linux")]
				pit: None,
			},
			guest: GuestArgs {
				kernel: PathBuf::from("my_kernel.hermit"),
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
			io_mode = 'direct'
			gdb_port = 1

			[memory]
			memory_size = '16MiB'
			no_aslr = true
			thp = true
			ksm = true

			[cpu]
			cpu_count = 4
			cpu_pm = true
			affinity = [0,1,2]
			pit = true

			[guest]
			env_vars = ['foo=bar']
		"#,
		)
		.unwrap();

		let cli_args_postmerge = Args {
			uhyve: UhyveArgs {
				output: Some(String::from("test.txt")),
				stats: Some(true),
				file_mapping: vec![String::from("./host:/root/guest.txt")],
				tempdir: Some(PathBuf::from("/tmp/")),
				#[cfg(target_os = "linux")]
				file_isolation: Some(String::from("strict")),
				#[cfg(target_os = "linux")]
				io_mode: Some(String::from("direct")),
				#[cfg(target_os = "linux")]
				gdb_port: Some(1),
				config: Some(PathBuf::from("config.txt")),
				#[cfg(feature = "instrument")]
				trace: Some(PathBuf::from(".")),
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
				#[cfg(target_os = "linux")]
				cpu_pm: Some(true),
				affinity: Some(Affinity::from_str("0,1,2").unwrap()),
				#[cfg(target_os = "linux")]
				pit: Some(true),
			},
			guest: GuestArgs {
				kernel: PathBuf::from("my_kernel.hermit"),
				kernel_args: Default::default(),
				env_vars: vec![String::from("foo=bar")],
			},
		};

		cli_args.merge(config_file);
		assert_eq!(cli_args, cli_args_postmerge);
	}

	#[test]
	fn test_load_config_from_args_path() {
		let mut expected_args = Args::default();
		let config_path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "data/uhyve.toml"]
			.iter()
			.collect();
		expected_args.merge(read_toml_contents(&config_path).unwrap());

		let mut cwd_args = Args::default();
		cwd_args.uhyve.config = Some(config_path);
		load_vm_config(&mut cwd_args);
		// load_vm_config doesn't modify the config field.
		// We have to set it back to None.
		cwd_args.uhyve.config = None;
		assert_eq!(expected_args, cwd_args);
	}

	#[test]
	fn test_load_config_from_cwd() {
		let mut expected_args = Args::default();
		let config_dir: PathBuf = [env!("CARGO_MANIFEST_DIR"), "data"].iter().collect();
		let config_file: PathBuf = config_dir.join("uhyve.toml");
		expected_args.merge(read_toml_contents(&config_file).unwrap());

		env::set_current_dir(config_dir).unwrap();
		let mut cwd_args = Args::default();
		load_vm_config(&mut cwd_args);
		assert_eq!(expected_args, cwd_args);
	}

	#[test]
	fn test_load_config_from_config_dir() {
		let mut expected_args = Args::default();
		let sample_config_file: PathBuf = [env!("CARGO_MANIFEST_DIR"), "data", "uhyve.toml"]
			.iter()
			.collect();
		expected_args.merge(read_toml_contents(&sample_config_file).unwrap());

		// Create config directory and copy the sample config file to it.
		let config_dir = tempdir().unwrap();
		let uhyve_config_dir = config_dir.path().join("uhyve");
		unsafe { env::set_var("XDG_CONFIG_HOME", config_dir.path().to_str().unwrap()) };
		fs::create_dir(&uhyve_config_dir).unwrap();
		let config_file = uhyve_config_dir.join("uhyve.toml");
		fs::copy(sample_config_file, config_file).unwrap();

		let mut cwd_args = Args::default();
		load_vm_config(&mut cwd_args);
		assert_eq!(expected_args, cwd_args);
	}
}
