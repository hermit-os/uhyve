#![warn(rust_2018_idioms)]

use std::ffi::OsString;
use std::iter;
use std::net::Ipv4Addr;
use std::num::ParseIntError;
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::process;
use std::str::FromStr;

use clap::{App, ErrorKind, IntoApp, Parser};
use core_affinity::CoreId;
use either::Either;
use mac_address::MacAddress;
use thiserror::Error;

use uhyvelib::params::{CpuCount, GuestMemorySize, Params};
use uhyvelib::Uhyve;

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

#[derive(Parser, Debug)]
#[clap(version, author, about)]
struct Args {
	/// Print kernel messages
	#[clap(short, long)]
	verbose: bool,

	#[clap(flatten, help_heading = "MEMORY")]
	memory_args: MemoryArgs,

	#[clap(flatten, help_heading = "CPU")]
	cpu_args: CpuArgs,

	/// GDB server port
	///
	/// Starts a GDB server on the provided port and waits for a connection.
	#[clap(short = 's', long, env = "HERMIT_GDB_PORT")]
	gdb_port: Option<u16>,

	// #[clap(flatten, help_heading = "NETWORK")]
	#[clap(skip)]
	network_args: NetworkArgs,

	/// The kernel to execute
	#[clap(parse(from_os_str))]
	kernel: PathBuf,

	/// Arguments to forward to the kernel
	#[clap(parse(from_os_str))]
	kernel_args: Vec<OsString>,
}

#[derive(Parser, Debug)]
struct MemoryArgs {
	/// Guest RAM size
	#[clap(short = 'm', long, default_value_t, env = "HERMIT_MEMORY_SIZE")]
	memory_size: GuestMemorySize,

	/// No Transparent Hugepages
	///
	/// Don't advise the kernel to enable Transparent Hugepages [THP] on the virtual RAM.
	///
	/// [THP]: https://www.kernel.org/doc/html/latest/admin-guide/mm/transhuge.html
	#[clap(long)]
	no_thp: bool,

	/// Kernel Samepage Merging
	///
	/// Advise the kernel to enable Kernel Samepage Merging [KSM] on the virtual RAM.
	///
	/// [KSM]: https://www.kernel.org/doc/html/latest/admin-guide/mm/ksm.html
	#[clap(long)]
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

	#[error(
		"Available cores: {available_cores:?}, requested affinities: {requested_affinities:?}"
	)]
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
	fn get_affinity(self, app: &mut App<'_>) -> Option<Vec<CoreId>> {
		self.affinity.map(|affinity| {
			let affinity_num_vals = affinity.0.len();
			let cpus_num_vals = self.cpu_count.get().try_into().unwrap();
			if affinity_num_vals != cpus_num_vals {
				let affinity_arg = app
					.get_arguments()
					.find(|arg| arg.get_name() == "affinity")
					.unwrap();
				let cpus_arg = app
					.get_arguments()
					.find(|arg| arg.get_name() == "cpus")
					.unwrap();
				let verb = if affinity_num_vals > 1 { "were" } else { "was" };
				let message = format!(
					"The argument '{affinity_arg}' requires {cpus_num_vals} values (matching '{cpus_arg}'), but {affinity_num_vals} {verb} provided",
					affinity_arg = affinity_arg,
					cpus_num_vals = cpus_num_vals,
					cpus_arg = cpus_arg,
					affinity_num_vals = affinity_num_vals,
					verb = verb,
				);
				app.error(ErrorKind::WrongNumberOfValues, message).exit()
			} else {
				affinity.0
			}
		})
	}
}

#[derive(Parser, Debug, Default)]
struct NetworkArgs {
	/// Guest IP address
	#[clap(long, env = "HERMIT_IP")]
	ip: Option<Ipv4Addr>,

	/// Guest gateway address
	#[clap(long, env = "HERMIT_GATEWAY")]
	gateway: Option<Ipv4Addr>,

	/// Guest network mask
	#[clap(long, env = "HERMIT_MASK")]
	mask: Option<Ipv4Addr>,

	/// Name of the network interface
	#[clap(long, env = "HERMIT_NETIF")]
	nic: Option<String>,

	/// MAC address of the network interface
	#[clap(long, env = "HERMIT_MAC")]
	_mac: Option<MacAddress>,
}

impl From<Args> for Params {
	fn from(args: Args) -> Self {
		let Args {
			verbose,
			memory_args: MemoryArgs {
				memory_size,
				no_thp,
				ksm,
			},
			cpu_args: CpuArgs {
				cpu_count,
				affinity: _,
			},
			gdb_port,
			network_args: NetworkArgs {
				ip,
				gateway,
				mask,
				nic,
				_mac,
			},
			kernel: _,
			kernel_args: _kernel_args,
		} = args;
		Self {
			verbose,
			memory_size,
			thp: !no_thp,
			ksm,
			cpu_count,
			ip,
			gateway,
			mask,
			nic,
			gdb_port,
		}
	}
}

fn run_uhyve() -> i32 {
	#[cfg(feature = "instrument")]
	setup_trace();

	env_logger::init();

	let mut app = Args::into_app();
	let args = Args::parse();
	let kernel = args.kernel.clone();
	let affinity = args.cpu_args.clone().get_affinity(&mut app);
	let params = Params::from(args);

	Uhyve::new(kernel, params)
		.expect("Unable to create VM! Is the hypervisor interface (e.g. KVM) activated?")
		.run(affinity)
}

fn main() {
	process::exit(run_uhyve())
}
