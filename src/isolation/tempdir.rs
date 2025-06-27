use std::{fs::Permissions, os::unix::fs::PermissionsExt, path::PathBuf};

use tempfile::{Builder, TempDir, env};
use uuid::Uuid;

/// Creates a temporary directory.
///
/// * `dir_path` - The location in which the temporary directory should be created.
pub fn create_temp_dir(dir_path: &Option<String>) -> TempDir {
	let dir = Builder::new()
		.permissions(Permissions::from_mode(0o700))
		.prefix("uhyve-")
		.suffix(&Uuid::new_v4().to_string())
		.tempdir_in(
			dir_path
				.as_ref()
				.map(PathBuf::from)
				.unwrap_or_else(env::temp_dir),
		)
		.ok()
		.unwrap_or_else(|| panic!("The temporary directory could not be created."));

	assert!(!dir.path().metadata().unwrap().permissions().readonly());

	dir
}
