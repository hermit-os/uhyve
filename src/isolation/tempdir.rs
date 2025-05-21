// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::{fs::Permissions, os::unix::fs::PermissionsExt};

use tempfile::{Builder, TempDir};
use uuid::Uuid;

/// Creates a temporary directory.
///
/// * `dir_path` - The location in which the temporary directory should be created.
pub fn create_temp_dir(dir_path: &Option<String>) -> TempDir {
	let dir: TempDir;
	if let Some(dir_path) = dir_path {
		dir = Builder::new()
			.permissions(Permissions::from_mode(0o700))
			.prefix("uhyve-")
			.suffix(&Uuid::new_v4().to_string())
			.tempdir_in(dir_path)
			.ok()
			.unwrap_or_else(|| panic!("The temporary directory could not be created."));
	} else {
		dir = Builder::new()
			.permissions(Permissions::from_mode(0o700))
			.prefix("uhyve-")
			.suffix(&Uuid::new_v4().to_string())
			.tempdir()
			.ok()
			.unwrap_or_else(|| panic!("The temporary directory could not be created."));
	}

	let dir_permissions = dir.path().metadata().unwrap().permissions();
	assert!(!dir_permissions.readonly());

	dir
}
