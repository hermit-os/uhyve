use std::{
	fs::{DirBuilder, Permissions},
	os::unix::fs::{DirBuilderExt, PermissionsExt},
	path::PathBuf,
};

use tempfile::{Builder, TempDir, env};
use uuid::Uuid;

/// Creates a temporary directory.
///
/// To keep the temporary directory clean and because we need to include the
/// parent directory in [`crate::isolation::landlock::initialize`], a subdirectory
/// called `uhyve-{uid}` (e.g. `/tmp/uhyve-1000`) is used by Uhyve for creating
/// temporary directories for each instance of Uhyve.
///
/// After creating a directory, the permissions are set to 0o700 (read, write, execute
/// for the user). Those permissions are checked during the runtime.
///
/// * `dir_path` - The location in which the temporary directory should be created.
pub fn create_temp_dir(dir_path: Option<PathBuf>) -> TempDir {
	Builder::new()
		.permissions(Permissions::from_mode(0o700))
		.prefix("uhyve-")
		.suffix(&Uuid::new_v4().to_string())
		.tempdir_in(dir_path.unwrap_or_else(|| {
			let env_temp_dir = {
				let mut env_temp_dir = env::temp_dir();
				// Sane environments presumed to have world-writable temporary directory.
				debug_assert!(!env_temp_dir.metadata().unwrap().permissions().readonly());

				// getpid should never fail or modify errno, unsafe call is fine.
				env_temp_dir.push(format!("uhyve-{}", unsafe { libc::getuid() }));
				env_temp_dir
			};

			// To workaround racy parallel `env_temp_dir` creation,
			// retry on failures of the kind:
			// 1. .metadata() fails with NotFound
			// 2. but mkdir fails with AlreadyExists
			for i in 0..3 {
				use std::io::ErrorKind;
				if i == 2 {
					panic!(
						"Could not create temporary directory {}",
						env_temp_dir.display(),
					);
				}
				// If the subfolder doesn't exist, try to create it.
				// If that isn't possible, panic.
				match env_temp_dir.metadata() {
					Ok(metadata) => {
						// Ensure permissions of directory are correct.
						// Implicitly also checks if this is a directory.
						let temp_dir_mode = metadata.permissions().mode();
						assert_eq!(
							temp_dir_mode, 0o40700,
							"Uhyve's preexisting tempdir has incorrect mode ({temp_dir_mode:#o}, expected: 0o40700)."
						);
						break;
					}
					Err(ref e) if e.kind() == ErrorKind::NotFound => {
						DirBuilder::new()
							.mode(0o700)
							.create(&env_temp_dir)
							.unwrap_or_else(|e| {
								if e.kind() != ErrorKind::AlreadyExists {
									panic!(
										"Could not create temporary directory {}: {e}",
										env_temp_dir.display(),
									);
								}
							});
					}
					Err(e) => panic!(
						"Could not create temporary directory {}: {e}",
						env_temp_dir.display()
					),
				}
				warn!("Race during tempdir creation, retrying...");
			}

			env_temp_dir
		}))
		.expect("The temporary directory could not be created.")
}

#[cfg(test)]
mod tests {
	use std::fs::remove_dir;

	use super::*;

	#[test]
	fn test_create_with_dir_path() {
		let env_tempdir = env::temp_dir();
		let tempdir = create_temp_dir(Some(env_tempdir.clone()));
		// Assertions deferred for later to clean up directory first.
		// e.g. /tmp/uhyve-1000/uhyve-8Mubdtc4246409-1913-4123-b4b4-88cb4953a1ea
		let in_tmp_path: bool = tempdir.path().starts_with(&env_tempdir);
		let in_tmp_subfolder: bool = tempdir
			.path()
			.starts_with(env_tempdir.join(format!("uhyve-{}", unsafe { libc::getuid() })));

		remove_dir(tempdir.path()).unwrap_or_else(|e| {
			panic!(
				"Unable to remove directory used for test (in_tmp_path: {}, in_tmp_subfolder: {}): {}",
				in_tmp_path, in_tmp_subfolder, e
			);
		});

		assert!(in_tmp_path, "directory: {}", tempdir.path().display());
		assert!(!in_tmp_subfolder, "directory: {}", tempdir.path().display());
	}

	#[test]
	fn test_create_without_dir_path() {
		let tempdir = create_temp_dir(None);
		// Assertions deferred for later to clean up directory first.
		// e.g. /tmp/uhyve-8Mubdtc4246409-1913-4123-b4b4-88cb4953a1ea
		let in_tmp_subfolder: bool = tempdir
			.path()
			.starts_with(env::temp_dir().join(format!("uhyve-{}", unsafe { libc::getuid() })));

		remove_dir(tempdir.path()).unwrap_or_else(|e| {
			panic!(
				"Unable to remove directory used for test (in_tmp_subfolder: {}): {}",
				in_tmp_subfolder, e
			);
		});

		assert!(
			in_tmp_subfolder,
			"directory: {:?}",
			tempdir.path().display()
		);
	}
}
