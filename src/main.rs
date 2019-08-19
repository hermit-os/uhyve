#![feature(untagged_unions)]
#![feature(core_intrinsics)]
#![allow(dead_code)]

extern crate aligned_alloc;
extern crate elf;
extern crate libc;
extern crate memmap;
extern crate x86;
#[macro_use]
extern crate clap;
#[macro_use]
extern crate lazy_static;
extern crate kvm_bindings;
extern crate kvm_ioctls;

#[macro_use]
extern crate log;
extern crate env_logger;
extern crate raw_cpuid;

pub mod consts;
pub mod error;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
pub mod utils;
mod vm;
#[cfg(target_os = "windows")]
mod windows;

use clap::{App, Arg};
use consts::*;
use std::sync::Arc;
use std::thread;
use vm::*;

fn main() {
	env_logger::init();

	let matches = App::new("uhyve")
		.version(crate_version!())
		.author("Stefan Lankes <slankes@eonerc.rwth-aachen.de>")
		.about("A minimal hypervisor for HermitCore")
		.arg(
			Arg::with_name("VERBOSE")
				.short("v")
				.long("verbose")
				.help("Print also kernel messages"),
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
			Arg::with_name("KERNEL")
				.help("Sets path to the kernel")
				.required(true)
				.index(1),
		)
		.get_matches();

	let path = matches
		.value_of("KERNEL")
		.expect("Expect path to the kernel!");
	let mem_size: usize = matches
		.value_of("MEM")
		.map(|x| utils::parse_mem(&x).unwrap_or(DEFAULT_GUEST_SIZE))
		.unwrap_or(DEFAULT_GUEST_SIZE);
	let num_cpus: u32 = matches
		.value_of("CPUS")
		.map(|x| utils::parse_u32(&x).unwrap_or(1))
		.unwrap_or(1);

	let mut verbose: bool = utils::parse_bool("HERMIT_VERBOSE", false);
	if matches.is_present("VERBOSE") {
		verbose = true;
	}

	let mut vm = create_vm(path.to_string(), VmParameter::new(mem_size, num_cpus)).unwrap();
	let num_cpus = vm.num_cpus();

	vm.load_kernel().unwrap();

	let vm = Arc::new(vm);
	let threads: Vec<_> = (0..num_cpus)
		.map(|tid| {
			let vm = vm.clone();

			thread::spawn(move || {
				debug!("Create thread for CPU {}", tid);

				let mut cpu = vm.create_cpu(tid).unwrap();
				cpu.init(vm.get_entry_point()).unwrap();

				let result = cpu.run(verbose);
				match result {
					Ok(()) => {}
					Err(x) => {
						error!("CPU {} crashes! {}", tid, x);
					}
				}
			})
		})
		.collect();

	for t in threads {
		t.join().unwrap();
	}
}
