use std::{
	ffi::OsString,
	io::{Error, ErrorKind},
	os::fd::{AsFd, AsRawFd, RawFd},
	path::PathBuf,
	sync::Mutex,
	vec::Vec,
};

use landlock::{
	ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, PathFdError,
	RestrictionStatus, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError, RulesetStatus,
};
use thiserror::Error;

use crate::params::FileSandboxMode;

/// Makes Uhyve aware of an already-existing Landlock policy previously enforced by Uhyve.
static LANDLOCK_ENABLED: Mutex<bool> = Mutex::new(false);

/// Contains types of errors that may occur during Landlock's initialization.
#[derive(Debug, Error)]
pub(crate) enum RestrictError {
	#[error(transparent)]
	Ruleset(#[from] RulesetError),
	#[error(transparent)]
	AddRule(#[from] PathFdError),
}

/// Interface for Landlock crate.
#[derive(Clone, Debug)]
pub(crate) struct UhyveLandlockWrapper {
	rw_paths: Vec<String>,
	ro_paths: Vec<String>,
	ro_dirs: Vec<String>,
	compat_level: landlock::CompatLevel,
}

impl UhyveLandlockWrapper {
	/// Create a new instance of UhyveLandlockWrapper
	///
	/// - `sandbox_mode` - User-provided [`crate::params::FileSandboxMode`]
	/// - `rw_paths` - Paths that Uhyve should have read-write access to
	/// - `ro_paths` - Paths that Uhyve should have read-only access to
	/// - `ro_dirs` - Directories with "read-only" access. Internally, this
	///   is used for the parent directories of the files stored in rw_paths
	///   intended to be used by the VM. The directories won't actually be
	///   "read-only", as the given directories will also have removable files
	///   and directories (but won't be readable). See [`Self::enforce_landlock`].
	fn new(
		sandbox_mode: FileSandboxMode,
		rw_paths: &[String],
		ro_paths: &[String],
		ro_dirs: &[String],
	) -> UhyveLandlockWrapper {
		#[cfg(not(target_os = "linux"))]
		compile_error!("Landlock is only available on Linux.");

		UhyveLandlockWrapper {
			rw_paths: rw_paths.to_vec(),
			ro_paths: ro_paths.to_vec(),
			ro_dirs: ro_dirs.to_vec(),
			compat_level: Self::determine_compat_level(sandbox_mode),
		}
	}

	/// Enforce Landlock rulesets.
	///
	/// By running [`Self::enforce_landlock`] (and panicking if an error occurs),
	/// this function is the "public interface" to be used by
	/// [`UhyveVm::new`](crate::vm::UhyveVm::new) after the necessary rulesets have
	/// been provided and "stored" in UhyveLandlockWrapper. The restrictions have
	/// a process-wide effect.
	pub(crate) fn apply_landlock_restrictions(&self) {
		debug!(
			"Enabling Landlock path isolation with following compatibility mode: {:?}",
			self.compat_level
		);

		let mut is_already_enabled = LANDLOCK_ENABLED.lock().unwrap();
		if *is_already_enabled {
			if self.compat_level == CompatLevel::HardRequirement {
				panic!("Landlock has been enabled already. Failing because of strict sandbox mode.")
			} else {
				warn!(
					"Landlock has been enabled already. Further policies will not affect existing ones."
				);
			}
		} else {
			*is_already_enabled = true;
		}

		Self::enforce_landlock(self)
			.unwrap_or_else(|error| panic!("Unable to initialize Landlock: {error:?}"));
	}

	/// Using the file sandbox mode provided by the user, we derive the corresponding
	/// Landlock compatibility mode. This deliberately omits the CompatLevel::SoftRequirement
	/// possibility, while leaving room for future enhancements to the host file access
	/// layer.
	///
	/// - `sandbox_mode` - User-provided [`crate::params::FileSandboxMode`]
	fn determine_compat_level(sandbox_mode: FileSandboxMode) -> CompatLevel {
		match sandbox_mode {
			FileSandboxMode::None => unreachable!(),
			FileSandboxMode::Normal => CompatLevel::BestEffort,
			FileSandboxMode::Strict => CompatLevel::HardRequirement,
		}
	}

	/// Internal Landlock enforcement function used by [`Self::apply_landlock_restrictions`].
	///
	/// This function directly interfaces with the [`landlock`] crate, and is responsible for
	/// enforcing the policies defined in [`UhyveVm::new`](crate::vm::UhyveVm::new).
	fn enforce_landlock(&self) -> Result<RestrictionStatus, RestrictError> {
		// Target: Ubuntu 24.04 LTS (Linux Kernel: 6.8.0)
		let abi = ABI::V4;
		// Used for explicitly whitelisted files (read & write).
		let access_all: landlock::BitFlags<AccessFs, u64> = AccessFs::from_all(abi);

		// LANDLOCK_ACCESS_FS_REMOVE_FILE and LANDLOCK_ACCESS_FS_REMOVE_DIR do not apply to
		// whitelisted files themselves, but apply to the contents of directories transitively.
		// This means that we have to give Uhyve read-only access to the parent directory with
		// some additional permissions so as to support fs::remove_file and removing the temporary
		// directory.
		let access_dir_with_rm: landlock::BitFlags<AccessFs, u64> =
			AccessFs::ReadDir | AccessFs::RemoveDir | AccessFs::RemoveFile;

		let res_status = Ruleset::default()
			.handle_access(access_all)?
			.create()?
			.add_rules(
				self.rw_paths
					.as_slice()
					.iter()
					.map::<Result<_, RestrictError>, _>(|p| {
						debug!("Adding read-write path ruleset for {:#?}", *p);
						Self::determine_ruleset(PathFd::new(p)?, abi)
					}),
			)?
			.set_compatibility(self.compat_level)
			.add_rules(
				self.ro_paths
					.as_slice()
					.iter()
					.map::<Result<_, RestrictError>, _>(|p| {
						debug!("Adding read-only path ruleset for {:#?}", *p);
						Self::determine_ruleset(PathFd::new(p)?, abi)
					}),
			)?
			.set_compatibility(self.compat_level)
			.add_rules(
				self.ro_dirs
					.as_slice()
					.iter()
					.map::<Result<_, RestrictError>, _>(|p| {
						debug!("Adding read-only directory ruleset for {:#?}", *p);
						Ok(PathBeneath::new(PathFd::new(p)?, access_dir_with_rm))
					}),
			)?
			.set_compatibility(self.compat_level)
			.set_no_new_privs(true)
			.restrict_self()?;

		debug!(
			"Landlock ruleset status: {:#?} (no_new_privs: {:#?})",
			res_status.ruleset, res_status.no_new_privs
		);

		// Adapted from Mickaël Salaün's Rust Landlock library, which is distributed
		// under the terms of the MIT and Apache 2.0 licenses.
		//
		// For the original source code authored by Mickaël Salaün, see:
		// https://github.com/landlock-lsm/rust-landlock/blob/07f2a9a7/examples/sandboxer.rs#L133C1-L135C6
		if res_status.ruleset == RulesetStatus::NotEnforced {
			panic!(
				"Landlock is not supported by the running kernel. You can disable Landlock using `--file-isolation none`."
			);
		}

		Ok(res_status)
	}

	/// Derive a suitable Landlock policy for a given file descriptor.
	///
	/// Although applying directory-specific access rights to a file will just result in those rights being ignored
	/// in "best effort mode", this is not the case when running Uhyve
	/// in strict mode. Therefore, this function omits directory-specific
	/// access rights to "R/W" files.
	///
	/// - `fd` - File descriptor (of type [`PathFd`])
	/// - `abi` - Landlock ABI version
	fn determine_ruleset(fd: PathFd, abi: ABI) -> Result<PathBeneath<PathFd>, RestrictError> {
		let is_file = is_file(fd.as_fd().as_raw_fd());
		match is_file {
			true => Ok(PathBeneath::new(fd, AccessFs::from_file(abi))),
			false => Ok(PathBeneath::new(fd, AccessFs::from_all(abi))),
		}
	}
}

/// Gets the parent directory of a given host path.
///
/// If the parent found by this function is not a directory, an error is returned instead.
///
/// We also derive the parent directory of files that _do_ exist, so as to give
/// VMs the ability to remove them. See
/// [`apply_landlock_restrictions`](crate::isolation::landlock::UhyveLandlockWrapper::apply_landlock_restrictions).
///
/// * `host_path` - Path whose parent directory should be derived
fn get_file_or_parent(host_path: &OsString) -> Result<PathBuf, Error> {
	// TODO: Make iteration amount configurable
	let iterations = 2;
	let mut host_pathbuf: PathBuf = host_path.into();
	for i in 0..iterations {
		if !host_pathbuf.exists() {
			warn!("Mapped file {:#?} not found. Popping...", host_pathbuf);
			host_pathbuf.pop();
			continue;
		}

		if host_pathbuf.is_dir() {
			debug!("Adding directory {:#?}.", host_pathbuf);
			return Ok(host_pathbuf);
		} else if !host_pathbuf.is_dir() && i == 0 {
			// "File" means "all paths that don't have a directory on them but exist".
			debug!("Mapped file {:#?} found.", host_pathbuf);
			return Ok(host_pathbuf);
		} else {
			return Err(Error::new(
				ErrorKind::NotADirectory,
				"Found parent is not a directory.",
			));
		}
	}
	panic!(
		"Mapped file's parent directory not found within {} iterations.",
		iterations
	);
}

/// Checks whether a raw file descriptor represents a file using [`libc::fstat`].
/// Only used to differentiate directories and files for ruleset derivation.
///
/// Adapted from Mickaël Salaün's Rust Landlock library, which is distributed
/// under the terms of the MIT and Apache 2.0 licenses.
///
/// For the original source code authored by Mickaël Salaün, see:
/// https://github.com/landlock-lsm/rust-landlock/blob/aaccff53/src/fs.rs#L198-L210
///
/// * `rawfd` - Raw file descriptor ([`RawFd`])
fn is_file(rawfd: RawFd) -> bool {
	unsafe {
		let mut stat = std::mem::zeroed();
		match libc::fstat(rawfd, &mut stat) {
			0 => (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR,
			// Should not be practically reachable under optimal circumstances,
			// but we'll assume otherwise.
			_ => panic!("stat against fd {:?} failed", rawfd),
		}
	}
}

/// Initializes Landlock using parameters provided by [`UhyveVm::new`](crate::vm::UhyveVm::new).
///
/// If the file does not exist, we add the parent directory instead. This might have practical
/// security implications, however, combined with the other security measures implemented into
/// Uhyve, this should be fine.
///
/// * `sandbox_mode` - File isolation sandbox mode set by the user
/// * `kernel_path` - Location of the unikernel image
/// * `output` - Output of Uhyve, used for adding file outputs to Landlock (if applicable)
/// * `host_paths` - List of host paths derived from mappings by the user
/// * `temp_dir` - Location of the temporary directory for unmapped files
pub(crate) fn initialize(
	sandbox_mode: FileSandboxMode,
	kernel_path: String,
	output: &crate::params::Output,
	host_paths: &mut [OsString],
	temp_dir: String,
) -> UhyveLandlockWrapper {
	// This segment adds certain paths necessary for Uhyve to function before we
	// enforce Landlock, such as the kernel path and a couple of paths useful for sysinfo.
	//
	// See: https://github.com/GuillaumeGomez/sysinfo/blob/8fd58b8/src/unix/linux/cpu.rs#L420
	let uhyve_ro_paths = [
		kernel_path,
		String::from("/etc/"),
		String::from("/sys/devices/system"),
		String::from("/proc/cpuinfo"),
		String::from("/proc/stat"),
	]
	.to_vec();

	let mut uhyve_rw_paths: Vec<String> = [String::from("/dev/kvm")].to_vec();
	let mut uhyve_ro_dirs = Vec::<String>::new();

	host_paths.iter_mut().for_each(|host_path| {
		let host_pathbuf = PathBuf::from(host_path.clone());
		if host_pathbuf.exists() {
			uhyve_rw_paths.push(host_pathbuf.display().to_string());
			if let Some(parent_dir) = PathBuf::from(host_pathbuf).parent() {
				uhyve_ro_dirs.push(parent_dir.display().to_string());
			}
		} else {
			uhyve_rw_paths.push(get_file_or_parent(host_path).unwrap().display().to_string());
		}
	});

	if let crate::params::Output::File(path) = output {
		uhyve_rw_paths.push(path.display().to_string());
	}

	uhyve_rw_paths.push(temp_dir.clone());
	if let Some(tmp) = PathBuf::from(temp_dir).parent() {
		uhyve_ro_dirs.push(tmp.display().to_string());
	}

	UhyveLandlockWrapper::new(
		sandbox_mode,
		&uhyve_rw_paths,
		&uhyve_ro_paths,
		&uhyve_ro_dirs,
	)
}

#[cfg(test)]
mod tests {
	use std::panic;

	use super::*;

	#[test]
	fn test_get_file_or_parent() {
		assert_eq!(
			get_file_or_parent(&OsString::from("/dev/zero"))
				.unwrap()
				.display()
				.to_string(),
			"/dev/zero".to_string()
		);

		assert_eq!(
			get_file_or_parent(&OsString::from("/dev/doesntexist"))
				.unwrap()
				.display()
				.to_string(),
			"/dev".to_string()
		);

		assert_eq!(
			get_file_or_parent(&OsString::from("/dev/zero/doesntexist"))
				.err()
				.unwrap()
				.kind(),
			ErrorKind::NotADirectory
		);
	}

	#[test]
	fn test_landlock_strict_mode() {
		let landlock = UhyveLandlockWrapper::new(
			FileSandboxMode::Strict,
			&["/dev/null".to_string()],
			&["/dev/zero".to_string()],
			&["/dev/".to_string()],
		);

		landlock.apply_landlock_restrictions();
		// Assume that the second time will fail.
		let result = panic::catch_unwind(|| landlock.apply_landlock_restrictions());
		assert!(result.is_err());
	}
}
