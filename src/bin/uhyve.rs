#![warn(rust_2018_idioms)]

use std::{iter, num::ParseIntError, ops::RangeInclusive, path::PathBuf, process, str::FromStr};

use clap::{Command, CommandFactory, Parser, error::ErrorKind};
use core_affinity::CoreId;
use either::Either;
use env_logger::Builder;
use log::LevelFilter;
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
fn setup_trace() {
	use rftrace::Events;

	static mut EVENTS: Option<&mut Events> = None;

	#[allow(static_mut_refs)]
	extern "C" fn dump_trace() {
		unsafe {
			if let Some(e) = &mut EVENTS {
				rftrace::dump_full_uftrace(e, "uhyve_trace", "uhyve").expect("Saving trace failed");
			}
		}
	}

	let events = rftrace_frontend::init(1000000, true);
	rftrace::enable();

	unsafe {
		EVENTS = Some(events);
		libc::atexit(dump_trace);
	}
}

#[derive(Parser, Debug)]
#[clap(version, author, about)]
struct Args {
	/// Kernel output redirection.
	///
	/// None discards all output, Omit for stdout
	#[clap(short, long, value_name = "FILE")]
	output: Option<String>,

	/// Display statistics after the execution
	#[clap(long)]
	stats: bool,

	/// Paths that the kernel should be able to view, read or write.
	///
	/// Desired paths must be explicitly defined after a colon.
	///
	/// Example: --file-mapping host_dir:guest_dir --file-mapping file.txt:guest_file.txt
	#[clap(long)]
	file_mapping: Vec<String>,

	/// The path that should be used for temporary directories storing unmapped files.
	///
	/// This is useful for manually created tmpfs filesystems and for selecting
	/// directories not managed by a temporary file cleaner, which can remove open files
	/// manually. In most cases, mapping the guest path /root/ instead should be sufficient.
	///
	/// Defaults to /tmp.
	#[clap(long)]
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
	#[cfg(target_os = "linux")]
	file_isolation: Option<String>,

	/// GDB server port
	///
	/// Starts a GDB server on the provided port and waits for a connection.
	#[clap(short = 's', long, env = "HERMIT_GDB_PORT")]
	#[cfg(target_os = "linux")]
	gdb_port: Option<u16>,

	/// Environment variables of the guest as env=value paths
	///
	/// `-e host` passes all variables of the parent process to the kernel (discarding any other passed environment variables).
	///
	/// Example: --env_vars ASDF=jlk -e TERM=uhyveterm2000
	#[clap(short, long)]
	env_vars: Vec<String>,

	#[clap(flatten, next_help_heading = "Memory OPTIONS")]
	memory_args: MemoryArgs,

	#[clap(flatten, next_help_heading = "Cpu OPTIONS")]
	cpu_args: CpuArgs,

	/// The kernel to execute
	#[clap(value_parser)]
	kernel: PathBuf,

	/// Arguments to forward to the kernel
	kernel_args: Vec<String>,
}

#[derive(Parser, Debug)]
struct MemoryArgs {
	/// Guest RAM size
	#[clap(short = 'm', long, default_value_t, env = "HERMIT_MEMORY_SIZE")]
	memory_size: GuestMemorySize,

	/// Disable ASLR
	#[clap(long)]
	no_aslr: bool,

	/// Transparent Hugepages
	///
	/// Advise the kernel to enable Transparent Hugepages [THP] on the virtual RAM.
	///
	/// [THP]: https://www.kernel.org/doc/html/latest/admin-guide/mm/transhuge.html
	#[clap(long)]
	#[cfg(target_os = "linux")]
	thp: bool,

	/// Kernel Samepage Merging
	///
	/// Advise the kernel to enable Kernel Samepage Merging [KSM] on the virtual RAM.
	///
	/// [KSM]: https://www.kernel.org/doc/html/latest/admin-guide/mm/ksm.html
	#[clap(long)]
	#[cfg(target_os = "linux")]
	ksm: bool,
}

#[derive(Debug, Clone)]
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

#[derive(Parser, Debug, Clone)]
struct CpuArgs {
	/// Number of guest CPUs
	#[clap(short, long, default_value_t, env = "HERMIT_CPU_COUNT")]
	cpu_count: CpuCount,

	/// Create a PIT
	#[clap(long)]
	#[cfg(target_os = "linux")]
	pit: bool,

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

impl From<Args> for Params {
	fn from(args: Args) -> Self {
		let Args {
			memory_args:
				MemoryArgs {
					memory_size,
					no_aslr,
					#[cfg(target_os = "linux")]
					thp,
					#[cfg(target_os = "linux")]
					ksm,
				},
			cpu_args:
				CpuArgs {
					cpu_count,
					#[cfg(target_os = "linux")]
					pit,
					affinity: _,
				},
			#[cfg(target_os = "linux")]
			gdb_port,
			file_mapping,
			tempdir,
			#[cfg(target_os = "linux")]
			file_isolation,
			kernel: _,
			kernel_args,
			output,
			stats,
			env_vars,
		} = args;
		Self {
			memory_size,
			#[cfg(target_os = "linux")]
			thp,
			#[cfg(target_os = "linux")]
			ksm,
			aslr: !no_aslr,
			cpu_count,
			#[cfg(target_os = "linux")]
			pit,
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
			stats,
			env: EnvVars::try_from(env_vars.as_slice()).unwrap(),
		}
	}
}

fn run_uhyve() -> i32 {
	#[cfg(feature = "instrument")]
	setup_trace();

	let mut env_builder = Builder::new();
	env_builder.filter_level(LevelFilter::Warn);
	env_builder.parse_env("RUST_LOG");
	env_builder.format_timestamp(None);
	env_builder.init();

	let mut app = Args::command();
	let args = Args::parse();
	let stats = args.stats;
	let kernel_path = args.kernel.clone();
	let affinity = args.cpu_args.clone().get_affinity(&mut app);
	let params = Params::from(args);

	let vm = UhyveVm::new(kernel_path, params)
		.expect("Unable to create VM! Is the hypervisor interface (e.g. KVM) activated? Is hypervisor signed on macOS?");

	let res = vm.run(affinity);
	if stats {
		if let Some(stats) = res.stats {
			println!("Run statistics:");
			println!("{stats}");
		}
	}
	res.code
}

fn main() {
	process::exit(run_uhyve())
}
