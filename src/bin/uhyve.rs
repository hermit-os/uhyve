use std::process;

use clap::{CommandFactory, Parser};
use env_logger::Builder;
use log::LevelFilter;
use uhyvelib::{args::Args, params::Params, vm::UhyveVm};

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
