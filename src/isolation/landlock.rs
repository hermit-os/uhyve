use std::{ffi::OsString, path::PathBuf, vec::Vec};

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

/// Interface for Landlock crate.
#[derive(Clone, Debug)]
pub struct UhyveLandlockWrapper {
	rw_paths: Vec<String>,
	ro_paths: Vec<String>,
}

impl UhyveLandlockWrapper {
	pub fn new(
		mappings: &[String],
		uhyve_rw_paths: &mut Vec<String>,
		uhyve_ro_paths: &[String],
	) -> UhyveLandlockWrapper {
		#[cfg(not(target_os = "linux"))]
		compile_error!("Landlock is only available on Linux.");

		// TODO: Check whether host OS (Linux, of course) actually supports Landlock.
		// TODO: Introduce parameter that lets the user manually disable Landlock.
		// TODO: Reduce code repetition (wrt. `crate::isolation::filemap`).
		// TODO: What to do with files that don't exist yet?
		let mut rw_paths: Vec<String> = mappings
			.iter()
			.map(String::as_str)
			.map(split_guest_and_host_path)
			.map(Result::unwrap)
			.map(|(guest_path, host_path)| (guest_path, host_path).1)
			.map(Self::get_parent_directory)
			.collect();
		rw_paths.append(uhyve_rw_paths);

		UhyveLandlockWrapper {
			rw_paths,
			ro_paths: uhyve_ro_paths.to_vec(),
		}
	}

	/// This function attempts to enforce different layers of file-related isolation.
	/// This is currently only used for Landlock. It can be extended for other isolation
	/// layers, as well as operating system-specific implementations.
	pub fn enforce_isolation(&self) {
		{
			let _status = match Self::enforce_landlock(self) {
				Ok(status) => status,
				Err(error) => panic!("Unable to initialize Landlock: {error:?}"),
			};
		}
	}

	/// If the file does not exist, we add the parent directory instead. This might have practical
	/// security implications, however, combined with the other security measures implemented into
	/// Uhyve, this should be fine.
	///
	/// TODO: Inform the user in the docs.
	/// TODO: Make the amount of iterations configurable.
	pub fn get_parent_directory(host_path: OsString) -> String {
		let iterations = 2;
		let mut host_pathbuf: PathBuf = host_path.into();
		for _i in 0..iterations {
			if host_pathbuf.exists() {
				return host_pathbuf.to_str().unwrap().to_owned();
			} else {
				host_pathbuf.pop();
			}
		}
		panic!(
			"The mapped file's parent directory wasn't found within {} iteration(s).",
			iterations
		);
	}

	/// Initializes Landlock by providing R/W-access to user-defined and
	/// Uhyve-defined paths.
	pub fn enforce_landlock(&self) -> Result<RestrictionStatus, LandlockRestrictError> {
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
				self.rw_paths
					.as_slice()
					.iter()
					.map::<Result<_, LandlockRestrictError>, _>(|p| {
						Ok(PathBeneath::new(PathFd::new(p)?, access_all))
					}),
			)?
			.add_rules(
				self.ro_paths
					.as_slice()
					.iter()
					.map::<Result<_, LandlockRestrictError>, _>(|p| {
						Ok(PathBeneath::new(PathFd::new(p)?, access_read))
					}),
			)?
			.restrict_self()?)
	}
}
