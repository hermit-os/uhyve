use std::vec::Vec;

use landlock::{
	Access, AccessFs, PathBeneath, PathFd, PathFdError, RestrictionStatus, Ruleset, RulesetAttr,
	RulesetCreatedAttr, RulesetError, ABI,
};
use thiserror::Error;

use crate::isolation::split_guest_and_host_path;

/// Contains types of errors that may occur during Landlock's initialization.
#[derive(Debug, Error)]
pub enum LandlockRestrictError {
	#[error(transparent)]
	Ruleset(#[from] RulesetError),
	#[error(transparent)]
	AddRule(#[from] PathFdError),
}

// Interface for Landlock crate.
#[derive(Clone, Debug)]
pub struct UhyveLandlockWrapper {
	whitelisted_paths: Vec<String>,
	uhyve_paths: Vec<String>,
}

impl UhyveLandlockWrapper {
	/// Adds host paths to WHITELISTED_PATHS and UHYVE_PATHS for isolation-related purposes.
	pub fn new(mappings: &[String], kernel_path: &str, temp_dir: &str) -> UhyveLandlockWrapper {
		#[cfg(not(target_os = "linux"))]
		#[cfg(feature = "landlock")]
		compile_error!("Landlock is only available on Linux.");

		// TODO: Check whether host OS (Linux, of course) actually supports Landlock.
		// TODO: Introduce parameter that lets the user manually disable Landlock.
		// TODO: Reduce code repetition (wrt. `crate::isolation::filemap`).
		// TODO: What to do with files that don't exist yet?
		#[cfg(target_os = "linux")]
		#[cfg(feature = "landlock")]
		{
			let whitelisted_paths = mappings
				.iter()
				.map(String::as_str)
				.map(split_guest_and_host_path)
				.map(|(guest_path, host_path)| { (guest_path, host_path) }.0)
				.collect();

			// This segment "whitelists" the following immediately before reading the kernel:
			//
			// - The kernel path.
			// - /dev/urandom: For good measure.
			// - /sys/devices/system, /proc/cpuinfo, /proc/stat: Useful for sysinfo.
			//
			//   See: https://github.com/GuillaumeGomez/sysinfo/blob/8fd58b8/src/unix/linux/cpu.rs#L420
			//
			// Primarily intended for Landlock: Useful for "process-wide" file isolation.
			// It is not necessary to whitelist e.g. /dev/kvm, as the isolation will be
			// enforced _after_ KVM is initialized.
			//
			// Given that we cannot enumerate all of these locations in advance,
			// some problems may occur if...
			// - sysinfo decides to read data from a different location in the future.
			// - Uhyve is being run on a system with a non-"standard" directory structure.

			let uhyve_paths = vec![
				kernel_path.to_string(),
				temp_dir.to_string(),
				String::from("/dev/urandom"),
				String::from("/sys/devices/system"),
				String::from("/proc/cpuinfo"),
				String::from("/proc/stat"),
			];

			UhyveLandlockWrapper {
				whitelisted_paths,
				uhyve_paths,
			}
		}
	}

	/// This function attempts to enforce different layers of file-related isolation.
	/// This is currently only used for Landlock. It can be extended for other isolation
	/// layers, as well as operating system-specific implementations.
	pub fn enforce_isolation(&self) {
		#[cfg(feature = "landlock")]
		{
			#[cfg(target_os = "linux")]
			{
				let _status = match Self::initialize_landlock(self) {
					Ok(status) => status,
					Err(error) => panic!("Unable to initialize Landlock: {error:?}"),
				};
			}
		}
	}

	/// Initializes Landlock by providing R/W-access to user-defined and
	/// Uhyve-defined paths.
	pub fn initialize_landlock(&self) -> Result<RestrictionStatus, LandlockRestrictError> {
		// This should be incremented regularly.
		let abi = ABI::V5;
		// Used for explicitly whitelisted files (read & write).
		let access_all: landlock::BitFlags<AccessFs, u64> = AccessFs::from_all(abi);
		// Used for the kernel itself, as well as "system directories" that we only read from.
		let access_read: landlock::BitFlags<AccessFs, u64> = AccessFs::from_read(abi);

		Ok(Ruleset::default()
			.handle_access(access_all)?
			.create()?
			.add_rules(
				self.whitelisted_paths
					.as_slice()
					.iter()
					.map::<Result<_, LandlockRestrictError>, _>(|p| {
						Ok(PathBeneath::new(PathFd::new(p)?, access_all))
					}),
			)?
			.add_rules(
				self.uhyve_paths
					.as_slice()
					.iter()
					.map::<Result<_, LandlockRestrictError>, _>(|p| {
						Ok(PathBeneath::new(PathFd::new(p)?, access_read))
					}),
			)?
			.restrict_self()?)
	}
}
