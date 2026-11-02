use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

use uhyve_interface::{
	GuestPhysAddr,
	v1::{self, MAX_ARGC_ENVC},
};

use crate::{mem::MmapMemory, params::EnvVars};

/// Copies the arguments of the application into the VM's memory to the destinations specified in `syscmdval`.
pub(super) fn copy_argv(
	path: &OsStr,
	argv: &[String],
	syscmdval: &v1::parameters::CmdvalParams,
	mem: &MmapMemory,
) {
	// copy kernel path as first argument
	let argvp = mem
		.host_address(syscmdval.argv)
		.expect("Systemcall parameters for Cmdval are invalid") as *const GuestPhysAddr;
	let arg_addrs = unsafe { std::slice::from_raw_parts(argvp, argv.len() + 1) };

	{
		let len = path.len();
		// Safety: we drop path_dest before anything else is done with mem
		let path_dest = unsafe {
			mem.slice_at_mut(arg_addrs[0], len + 1)
				.expect("Systemcall parameters for Cmdval are invalid")
		};

		path_dest[0..len].copy_from_slice(path.as_bytes());
		path_dest[len] = 0; // argv strings are zero terminated
	}

	// Copy the application arguments into the vm memory
	for (argument, &arg_dest_addr) in argv.iter().zip(arg_addrs.iter()) {
		let len = argument.len();
		let arg_dest = unsafe {
			mem.slice_at_mut(arg_dest_addr, len + 1)
				.expect("Systemcall parameters for Cmdval are invalid")
		};
		arg_dest[0..len].copy_from_slice(argument.as_bytes());
		arg_dest[len] = 0;
	}
}

/// Copies the environment variables into the VM's memory to the destinations specified in `syscmdval`.
pub(super) fn copy_env(env: &EnvVars, syscmdval: &v1::parameters::CmdvalParams, mem: &MmapMemory) {
	let envp = mem
		.host_address(syscmdval.envp)
		.expect("Systemcall parameters for Cmdval are invalid") as *const GuestPhysAddr;

	let env: Vec<(String, String)> = match env {
		EnvVars::Host => std::env::vars().collect(),
		EnvVars::Set(map) => map
			.iter()
			.map(|(a, b)| (a.to_owned(), b.to_owned()))
			.collect(),
	};
	if env.len() >= MAX_ARGC_ENVC {
		warn!(
			"Environment is larger than the maximum that can be copied to the VM. Remaining environment is ignored"
		);
	}
	let env_addrs = unsafe { std::slice::from_raw_parts(envp, env.len()) };

	// Copy the environment variables into the vm memory
	for ((key, value), &env_dest_addr) in env.iter().take(MAX_ARGC_ENVC).zip(env_addrs.iter()) {
		let len = key.len() + value.len() + 1;
		let env_dest = unsafe {
			mem.slice_at_mut(env_dest_addr, len + 1)
				.expect("Systemcall parameters for Cmdval are invalid")
		};
		//write_env_into_mem(env_dest, key.as_bytes(), value.as_bytes());
		let len = key.len() + value.len() + 1;
		env_dest[0..key.len()].copy_from_slice(key.as_bytes());
		env_dest[key.len()] = b'=';
		env_dest[key.len() + 1..len].copy_from_slice(value.as_bytes());
		env_dest[len] = 0;
	}
}
