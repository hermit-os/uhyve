#[macro_use]
extern crate log;
#[macro_use]
extern crate clap;

#[cfg(feature = "instrument")]
extern crate rftrace;
#[cfg(feature = "instrument")]
extern crate rftrace_frontend;

use std::env;
use std::hint;
use std::sync::Arc;
use std::thread;

use uhyvelib::utils;
use uhyvelib::vm;
use uhyvelib::vm::Vm;

use clap::{App, Arg};
use core_affinity::CoreId;
#[cfg(feature = "instrument")]
use rftrace_frontend::Events;
use uhyvelib::utils::{filter_cpu_affinity, parse_cpu_affinity};

const MINIMAL_GUEST_SIZE: usize = 16 * 1024 * 1024;
const DEFAULT_GUEST_SIZE: usize = 64 * 1024 * 1024;

#[cfg(feature = "instrument")]
static mut EVENTS: Option<Box<&mut Events>> = None;

#[cfg(feature = "instrument")]
extern "C" fn dump_trace() {
	unsafe {
		if let Some(ref mut e) = EVENTS {
			rftrace_frontend::dump_full_uftrace(&mut *e, "uhyve_trace", "uhyve", true)
				.expect("Saving trace failed");
		}
	}
}

// Note that we end main with `std::process::exit` to set the return value and
// as a result destructors are not run and cleanup may not happen.
fn main() {
	#[cfg(feature = "instrument")]
	{
		let events = Box::new(rftrace_frontend::init(1000000, true));
		rftrace_frontend::enable();

		unsafe {
			EVENTS = Some(events);
			libc::atexit(dump_trace);
		}
	}

	env_logger::init();

	let matches = App::new("uhyve")
		.version(crate_version!())
		.setting(clap::AppSettings::TrailingVarArg)
		.setting(clap::AppSettings::AllowLeadingHyphen)
		.author(crate_authors!("\n"))
		.about("A minimal hypervisor for RustyHermit")
		.arg(
			Arg::with_name("VERBOSE")
				.short("v")
				.long("verbose")
				.help("Print also kernel messages"),
		)
		.arg(
			Arg::with_name("DISABLE_HUGEPAGE")
				.long("disable-hugepages")
				.help("Disable the usage of huge pages"),
		)
		.arg(
			Arg::with_name("MERGEABLE")
				.long("mergeable")
				.help("Enable kernel feature to merge same pages"),
		)
		.arg(
			Arg::with_name("MEM")
				.short("m")
				.long("memsize")
				.value_name("MEM")
				.help("Memory size of the guest")
				.takes_value(true)
				.env("HERMIT_MEM"),
		)
		.arg(
			Arg::with_name("CPUS")
				.short("c")
				.long("cpus")
				.value_name("CPUS")
				.help("Number of guest processors")
				.takes_value(true)
				.env("HERMIT_CPUS"),
		)
		.arg(
			Arg::with_name("CPU_AFFINITY")
				.short("a")
				.long("affinity")
				.value_name("cpulist")
				.help("CPU Affinity of guest CPUs on Host")
				.long_help(
					"A list of CPUs delimited by commas onto which
					 the virtual CPUs should be bound. This may improve 
					performance.
					",
				),
		)
		.arg(
			Arg::with_name("GDB_PORT")
				.short("s")
				.long("gdb_port")
				.value_name("GDB_PORT")
				.help("Enables GDB-Stub on given port")
				.takes_value(true)
				.env("HERMIT_GDB_PORT"),
		)
		.arg(
			Arg::with_name("NETIF")
				.long("nic")
				.value_name("NETIF")
				.help("Name of the network interface")
				.takes_value(true)
				.env("HERMIT_NETIF"),
		)
		/*.arg(
			Arg::with_name("IP")
				.long("ip")
				.value_name("IP")
				.help("IP address of the guest")
				.takes_value(true)
				.env("HERMIT_IP"),
		)
		.arg(
			Arg::with_name("GATEWAY")
				.long("gateway")
				.value_name("GATEWAY")
				.help("Gateway address")
				.takes_value(true)
				.env("HERMIT_GATEWAY"),
		)
		.arg(
			Arg::with_name("MASK")
				.long("mask")
				.value_name("MASK")
				.help("Network mask")
				.takes_value(true)
				.env("HERMIT_MASK"),
		)
		.arg(
			Arg::with_name("MAC")
				.long("mac")
				.value_name("MAC")
				.help("MAC address of the network interface")
				.takes_value(true)
				.env("HERMIT_MASK"),
		)*/
		.arg(
			Arg::with_name("KERNEL")
				.help("Sets path to the kernel")
				.required(true)
				.index(1),
		)
		.arg(
			Arg::with_name("ARGUMENTS")
				.help("Arguments of the unikernel")
				.required(false)
				.multiple(true)
				.max_values(255),
		)
		.get_matches();

	let path = matches
		.value_of("KERNEL")
		.expect("Expect path to the kernel!");
	let mem_size: usize = matches
		.value_of("MEM")
		.map(|x| {
			let mem = utils::parse_mem(&x).unwrap_or(DEFAULT_GUEST_SIZE);
			if mem < MINIMAL_GUEST_SIZE {
				warn!("Resize guest memory to {} MByte", DEFAULT_GUEST_SIZE >> 20);
				DEFAULT_GUEST_SIZE
			} else {
				mem
			}
		})
		.unwrap_or(DEFAULT_GUEST_SIZE);
	let num_cpus: u32 = matches
		.value_of("CPUS")
		.map(|x| utils::parse_u32(&x).unwrap_or(1))
		.unwrap_or(1);

	let set_cpu_affinity = matches.is_present("CPU_AFFINITY");
	let cpu_affinity: Option<Vec<core_affinity::CoreId>> = if set_cpu_affinity {
		let args: Vec<&str> = matches
			.values_of("CPU_AFFINITY")
			.unwrap()
			.into_iter()
			.collect();

		// According to https://github.com/Elzair/core_affinity_rs/issues/3
		// on linux this gives a list of CPUs the process is allowed to run on
		// (as opposed to all CPUs available on the system as the docs suggest)
		let parsed_affinity =
			parse_cpu_affinity(args).expect("Invalid parameters passed for CPU_AFFINITY");
		let core_ids = core_affinity::get_core_ids()
			.expect("Dependency core_affinity failed to find any available CPUs");
		let filtered_core_ids = filter_cpu_affinity(core_ids, parsed_affinity);
		if num_cpus as usize != filtered_core_ids.len() {
			panic!(
				"Uhyve was specified to use {} CPUs, but only the following CPUs from the CPU mask \
				are available: {:?}",
				num_cpus,
				filtered_core_ids
			);
		}
		Some(filtered_core_ids)
	} else {
		None
	};
	let ip = None; //matches.value_of("IP").or(None);
	let gateway = None; // matches.value_of("GATEWAY").or(None);
	let mask = None; //matches.value_of("MASK").or(None);
	let nic = None; //matches.value_of("NETIF").or(None);

	let mut mergeable: bool = utils::parse_bool("HERMIT_MERGEABLE", false);
	if matches.is_present("MERGEABLE") {
		mergeable = true;
	}
	// per default we use huge page to improve the performace,
	// if the kernel supports transparent hugepages
	let hugepage_default = utils::transparent_hugepages_available().unwrap_or(true);
	info!("Default hugepages set to: {}", hugepage_default);
	// HERMIT_HUGEPAGES overrides the default we detected.
	let mut hugepage: bool = utils::parse_bool("HERMIT_HUGEPAGE", hugepage_default);
	if matches.is_present("DISABLE_HUGEPAGE") {
		hugepage = false;
	}
	let mut verbose: bool = utils::parse_bool("HERMIT_VERBOSE", false);
	if matches.is_present("VERBOSE") {
		verbose = true;
	}
	let gdbport = matches
		.value_of("GDB_PORT")
		.map(|p| p.parse::<u32>().expect("Could not parse gdb port"))
		.or_else(|| {
			env::var("HERMIT_GDB_PORT")
				.ok()
				.map(|p| p.parse::<u32>().expect("Could not parse gdb port"))
		});

	// create and initialize the VM
	let vm = Arc::new({
		let mut vm = vm::create_vm(
			path.to_string(),
			&vm::Parameter::new(
				mem_size, num_cpus, verbose, hugepage, mergeable, ip, gateway, mask, nic, gdbport,
			),
		)
		.expect("Unable to create VM! Is the hypervisor interface (e.g. KVM) activated?");
		unsafe {
			vm.load_kernel().expect("Unabled to load the kernel");
		}
		vm
	});

	let num_cpus = vm.num_cpus();
	let threads: Vec<_> = (0..num_cpus)
		.map(|tid| {
			let vm = vm.clone();

			let local_cpu_affinity: Option<CoreId> = match &cpu_affinity {
				Some(vec) => vec.get(tid as usize).cloned(),
				None => None,
			};

			// create thread for each CPU
			thread::spawn(move || -> Option<i32> {
				debug!("Create thread for CPU {}", tid);
				match local_cpu_affinity {
					Some(core_id) => {
						debug!("Trying to pin thread {} to CPU {}", tid, core_id.id);
						core_affinity::set_for_current(core_id); // This does not return an error if it fails :(
					}
					None => debug!("No affinity specified, not binding thread"),
				}

				let mut cpu = vm.create_cpu(tid).unwrap();
				cpu.init(vm.get_entry_point()).unwrap();

				// only one core is able to enter startup code
				// => the wait for the predecessor core
				while tid != vm.cpu_online() {
					hint::spin_loop();
				}

				// jump into the VM and excute code of the guest
				let result = cpu.run();
				match result {
					Err(x) => {
						error!("CPU {} crashes! {}", tid, x);
						None
					}
					Ok(exit_code) => {
						if let Some(code) = exit_code {
							std::process::exit(code);
						}

						None
					}
				}
			})
		})
		.collect();

	for t in threads {
		t.join().unwrap();
	}
}
