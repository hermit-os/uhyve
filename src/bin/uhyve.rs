#![warn(rust_2018_idioms)]

use std::ffi::OsString;
use std::net::Ipv4Addr;
use std::num::{NonZeroU32, ParseIntError, TryFromIntError};
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::process;
use std::str::FromStr;
use std::{fmt, iter};

use byte_unit::{AdjustedByte, Byte, ByteError};
use clap::{App, ErrorKind, IntoApp, Parser};
use core_affinity::CoreId;
use either::Either;
use mac_address::MacAddress;
use thiserror::Error;

use uhyvelib::{vm, Uhyve};

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

#[derive(Debug, Clone, Copy)]
pub struct GuestMemorySize(Byte);

impl GuestMemorySize {
	const fn minimum() -> Byte {
		Byte::from_bytes(16 * 1024 * 1024)
	}

	pub fn get(self) -> usize {
		self.0.get_bytes().try_into().unwrap()
	}
}

impl Default for GuestMemorySize {
	fn default() -> Self {
		Self(Byte::from_bytes(64 * 1024 * 1024))
	}
}

impl fmt::Display for GuestMemorySize {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		self.0.get_appropriate_unit(true).fmt(f)
	}
}

#[derive(Error, Debug)]
#[error("invalid amount of guest memory (minimum: {}, found {0})", GuestMemorySize::minimum().get_appropriate_unit(true))]
pub struct InvalidGuestMemorySizeError(AdjustedByte);

impl TryFrom<Byte> for GuestMemorySize {
	type Error = InvalidGuestMemorySizeError;

	fn try_from(value: Byte) -> Result<Self, Self::Error> {
		if value >= Self::minimum() {
			Ok(Self(value))
		} else {
			let value = value.get_appropriate_unit(true);
			Err(InvalidGuestMemorySizeError(value))
		}
	}
}

#[derive(Error, Debug)]
pub enum ParseByteError {
	#[error(transparent)]
	Parse(#[from] ByteError),

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

fn run_uhyve() -> i32 {
	#[cfg(feature = "instrument")]
	setup_trace();

	env_logger::init();

	let mut app = Args::into_app();
	let Args {
		verbose,
		memory_args,
		cpu_args,
		gdb_port,
		network_args: NetworkArgs {
			ip,
			gateway,
			mask,
			nic,
			_mac,
		},
		kernel,
		kernel_args: _kernel_args,
	} = Args::parse();
	let cpu_count = cpu_args.cpu_count;
	let affinity = cpu_args.get_affinity(&mut app);

	let ip = ip.map(|ip| ip.to_string());
	let gateway = gateway.map(|ip| ip.to_string());
	let mask = mask.map(|ip| ip.to_string());

	let params = vm::Parameter {
		mem_size: memory_args.memory_size.get(),
		num_cpus: cpu_count.get(),
		verbose,
		hugepage: !memory_args.no_thp,
		mergeable: memory_args.ksm,
		ip: ip.as_deref(),
		gateway: gateway.as_deref(),
		mask: mask.as_deref(),
		nic: nic.as_deref(),
		gdbport: gdb_port,
	};

	Uhyve::new(kernel, &params)
		.expect("Unable to create VM! Is the hypervisor interface (e.g. KVM) activated?")
		.run(affinity)
}

fn main() {
	process::exit(run_uhyve())
}
