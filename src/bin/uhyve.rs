#![warn(rust_2018_idioms)]

use std::process;

use clap::{CommandFactory, Parser};
use env_logger::Builder;
use log::LevelFilter;
use uhyvelib::{
	args::{CpuArgs, GuestArgs, MemoryArgs, UhyveArgs},
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
					affinity: _,
				},
			guest_args: GuestArgs {
				kernel: _,
				kernel_args,
				env_vars,
			},
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
	// TODO: Read UhyveFileConfig, merge with exising args (but do not overwrite Args fields)
	let args = Args::parse();
	// TODO: Remove pubs, move these to Params
	let stats = args.uhyve_args.stats;
	let kernel_path = args.guest_args.kernel.clone();
	let affinity = args.cpu_args.clone().get_affinity(&mut app);
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
