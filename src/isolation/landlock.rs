use std::{ffi::OsString, path::PathBuf, vec::Vec};

use landlock::{
	ABI, Access, AccessFs, PathBeneath, PathFd, PathFdError, RestrictionStatus, Ruleset,
	RulesetAttr, RulesetCreatedAttr, RulesetError,
};
use thiserror::Error;

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
}

impl UhyveLandlockWrapper {
	/// Create a new instance of UhyveLandlockWrapper
	///
	/// - `rw_paths` - Paths that Uhyve should have read-write access to
	/// - `ro_paths` - Paths that Uhyve should have read-only access to
	/// - `ro_dirs` - Directories with "read-only" access. Internally, this
	///   is used for the parent directories of the files stored in rw_paths
	///   intended to be used by the VM. The directories won't actually be
	///   "read-only", as the given directories will also have removable files
	///   and directories (but won't be readable). See [`Self::enforce_landlock`].
	pub(crate) fn new(
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
		Self::enforce_landlock(self)
			.unwrap_or_else(|error| panic!("Unable to initialize Landlock: {error:?}"));
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
		// Used for the kernel itself, as well as "system directories" that we only read from.
		let access_read: landlock::BitFlags<AccessFs, u64> = AccessFs::from_read(abi);

		// LANDLOCK_ACCESS_FS_REMOVE_FILE and LANDLOCK_ACCESS_FS_REMOVE_DIR do not apply to
		// whitelisted files themselves, but apply to the contents of directories transitively.
		// This means that we have to give Uhyve read-only access to the parent directory with
		// some additional permissions so as to support fs::remove_file and removing the temporary
		// directory.
		let access_dir_with_rm: landlock::BitFlags<AccessFs, u64> =
			AccessFs::ReadDir | AccessFs::RemoveDir | AccessFs::RemoveFile;

		Ok(Ruleset::default()
			.handle_access(access_all)?
			.create()?
			.add_rules(
				self.rw_paths
					.as_slice()
					.iter()
					.map::<Result<_, RestrictError>, _>(|p| {
						Ok(PathBeneath::new(PathFd::new(p)?, AccessFs::from_all(abi)))
					}),
			)?
			.add_rules(
				self.ro_paths
					.as_slice()
					.iter()
					.map::<Result<_, RestrictError>, _>(|p| {
						Ok(PathBeneath::new(PathFd::new(p)?, access_read))
					}),
			)?
			.add_rules(
				self.ro_dirs
					.as_slice()
					.iter()
					.map::<Result<_, RestrictError>, _>(|p| {
						Ok(PathBeneath::new(PathFd::new(p)?, access_dir_with_rm))
					}),
			)?
			.set_no_new_privs(true)
			.restrict_self()?)
	}
}

/// Gets the parent directory of a given host path.
///
/// If the file does not exist, we add the parent directory instead. This might have practical
/// security implications, however, combined with the other security measures implemented into
/// Uhyve, this should be fine.
///
/// We also derive the parent directory of files that _do_ exist, so as to give
/// VMs the ability to remove them. See
/// [`apply_landlock_restrictions`](crate::isolation::landlock::UhyveLandlockWrapper::apply_landlock_restrictions).
///
/// * `host_path` - Path whose parent directory should be derived
fn get_parent_directory(host_path: &OsString) -> PathBuf {
	// TODO: Make iteration amount configurable
	// TODO: Inform user about default in docs.
	let iterations = 2;
	let mut host_pathbuf: PathBuf = host_path.into();
	for _i in 0..iterations {
		if !host_pathbuf.exists() {
			warn!("Mapped file {:#?} not found. Popping...", host_pathbuf);
			host_pathbuf.pop();
			continue;
		}
		debug!("Adding {:#?} to Landlock", host_pathbuf);
		return host_pathbuf;
	}
	panic!(
		"The mapped file's parent directory wasn't found within {} iteration(s).",
		iterations
	);
}

/// Initializes Landlock using parameters provided by [`UhyveVm::new`](crate::vm::UhyveVm::new).
///
/// If the file does not exist, we add the parent directory instead. This might have practical
/// security implications, however, combined with the other security measures implemented into
/// Uhyve, this should be fine.
///
/// * `kernel_path` - Location of the unikernel image
/// * `output` - Output of Uhyve, used for adding file outputs to Landlock (if applicable)
/// * `host_paths` - List of host paths derived from mappings by the user
/// * `temp_dir` - Location of the temporary directory for unmapped files
pub(crate) fn initialize_landlock_vm(
	kernel_path: String,
	output: &crate::params::Output,
	host_paths: &mut [OsString],
	temp_dir: String,
) -> UhyveLandlockWrapper {
	// This segment adds certain paths necessary for Uhyve to function before we
	// enforce Landlock, such as the kernel path and a couple of paths useful for sysinfo.
	//
	// See: https://github.com/GuillaumeGomez/sysinfo/blob/8fd58b8/src/unix/linux/cpu.rs#L420
	//
	// It is not necessary to whitelist e.g. /dev/kvm, as isolation should be enforced
	// after KVM is initialized and before the kernel is loaded.
	let uhyve_ro_paths = [
		kernel_path,
		String::from("/etc/"),
		String::from("/sys/devices/system"),
		String::from("/proc/cpuinfo"),
		String::from("/proc/stat"),
	]
	.to_vec();

	let mut uhyve_rw_paths: Vec<String> = [String::from("/dev/kvm")].to_vec();
	let mut uhyve_ro_dirs: Vec<String> = Default::default();

	host_paths.iter_mut().for_each(|host_path| {
		let host_pathbuf = PathBuf::from(host_path.clone());
		if host_pathbuf.exists() {
			uhyve_rw_paths.push(host_pathbuf.display().to_string());
			if let Some(parent_dir) = PathBuf::from(host_pathbuf).parent() {
				uhyve_ro_dirs.push(parent_dir.display().to_string());
			}
		} else {
			uhyve_rw_paths.push(get_parent_directory(host_path).display().to_string());
		}
	});

	if let crate::params::Output::File(path) = output {
		uhyve_rw_paths.push(path.display().to_string());
	}

	uhyve_rw_paths.push(temp_dir.clone());
	if let Some(tmp) = PathBuf::from(temp_dir).parent() {
		uhyve_ro_dirs.push(tmp.display().to_string());
	}

	UhyveLandlockWrapper::new(&uhyve_rw_paths, &uhyve_ro_paths, &uhyve_ro_dirs)
}
