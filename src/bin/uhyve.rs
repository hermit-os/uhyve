#![warn(rust_2018_idioms)]

#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::process;

use clap::{CommandFactory, Parser};
use env_logger::Builder;
use log::LevelFilter;
use uhyvelib::{
	args::{CpuArgs, GuestArgs, MemoryArgs, UhyveGuestConfig},
	params::Params,
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
use std::str::FromStr;

#[cfg(target_os = "linux")]
use uhyvelib::params::FileSandboxMode;
use uhyvelib::params::{EnvVars, Output};

/// Used by clap to derive CLI parameters for Uhyve.
#[derive(Parser, Debug)]
#[clap(version, author, about)]
pub struct Args {
	#[clap(flatten, next_help_heading = "Uhyve OPTIONS")]
	pub uhyve_args: UhyveArgs,

	#[clap(flatten, next_help_heading = "Memory OPTIONS")]
	pub memory_args: MemoryArgs,

	#[clap(flatten, next_help_heading = "Cpu OPTIONS")]
	pub cpu_args: CpuArgs,

	#[clap(flatten, next_help_heading = "Guest OPTIONS")]
	pub guest_args: GuestArgs,
}

/// Arguments for Uhyve runtime-related configurations.
#[derive(Parser, Debug)]
pub struct UhyveArgs {
	/// Kernel output redirection.
	///
	/// None discards all output, Omit for stdout
	#[clap(short, long, value_name = "FILE")]
	pub output: Option<String>,

	/// Display statistics after the execution
	#[clap(long)]
	pub stats: Option<bool>,

	/// Paths that the kernel should be able to view, read or write.
	///
	/// Desired paths must be explicitly defined after a colon.
	///
	/// Example: --file-mapping host_dir:guest_dir --file-mapping file.txt:guest_file.txt
	#[clap(long)]
	pub file_mapping: Option<Vec<String>>,

	/// The path that should be used for temporary directories storing unmapped files.
	///
	/// This is useful for manually created tmpfs filesystems and for selecting
	/// directories not managed by a temporary file cleaner, which can remove open files
	/// manually. In most cases, mapping the guest path /root/ instead should be sufficient.
	///
	/// Defaults to /tmp.
	#[clap(long)]
	pub tempdir: Option<String>,

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
	pub file_isolation: Option<String>,

	/// GDB server port
	///
	/// Starts a GDB server on the provided port and waits for a connection.
	#[clap(short = 's', long, env = "HERMIT_GDB_PORT")]
	#[cfg(target_os = "linux")]
	pub gdb_port: Option<u16>,

	/// TOML configuration file
	///
	/// Reads configurations from a locally given path.
	///
	/// FIXME: Replace the default -K copied from curl (?)
	#[clap(short = 'K', long, env = "HERMIT_CONFIG")]
	#[cfg(target_os = "linux")]
	pub config: Option<PathBuf>,
}

impl From<Args> for Params {
	fn from(args: Args) -> Self {
		let Args {
			uhyve_args:
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
					affinity,
				},
			guest_args: GuestArgs {
				kernel,
				kernel_args,
				env_vars,
			},
		} = args;

		Self {
			kernel,
			memory_size: memory_size.unwrap_or_default(),
			#[cfg(target_os = "linux")]
			thp: thp.unwrap_or_default(),
			#[cfg(target_os = "linux")]
			ksm: ksm.unwrap_or_default(),
			aslr: !no_aslr.unwrap_or_default(),
			cpu_count: cpu_count.unwrap_or_default(),
			affinity,
			#[cfg(target_os = "linux")]
			pit: pit.unwrap_or_default(),
			file_mapping: file_mapping.unwrap_or_default(),
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

use merge::Merge;

fn run_uhyve() -> i32 {
	#[cfg(feature = "instrument")]
	setup_trace();

	let mut env_builder = Builder::new();
	env_builder.filter_level(LevelFilter::Warn);
	env_builder.parse_env("RUST_LOG");
	env_builder.format_timestamp(None);
	env_builder.init();

	let mut app = Args::command();
	let mut args = Args::parse();

	// FIXME: remove the unwraps
	let file_config_params: Option<UhyveGuestConfig> = {
		let config_contents =
			std::fs::read_to_string(args.uhyve_args.config.as_ref().unwrap()).unwrap();
		toml::from_str(&config_contents).ok()
	};

	if let Some(params) = file_config_params {
		// FIXME: Providing the kernel in the config file causes Uhyve to hang.
		args.memory_args.merge(params.memory);
		args.cpu_args.merge(params.cpu);
		args.guest_args.merge(params.guest);
	}

	// FIXME: Investigate moving this arg to Params
	let stats = args.uhyve_args.stats.unwrap_or_default();
	let affinity = args.cpu_args.clone().get_affinity(&mut app);
	let params = Params::from(args);
	let kernel_path = params.kernel.clone().unwrap();

	// FIXME: Optimize params usage.
	let vm = UhyveVm::new(kernel_path, params.clone()).unwrap_or_else(|e| panic!("Error: {e}"));

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
