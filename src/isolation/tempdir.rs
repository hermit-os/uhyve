use std::{fs::Permissions, os::unix::fs::PermissionsExt};

use tempfile::{Builder, TempDir};
use uuid::Uuid;
/// Creates a temporary directory.
pub fn create_temp_dir() -> TempDir {
	let dir = Builder::new()
		.permissions(Permissions::from_mode(0o700))
		.prefix("uhyve-")
		.suffix(&Uuid::new_v4().to_string())
		.tempdir()
		.ok()
		.unwrap_or_else(|| panic!("The temporary directory could not be created."));

	let dir_permissions = dir.path().metadata().unwrap().permissions();
	assert!(!dir_permissions.readonly());

	dir
}
