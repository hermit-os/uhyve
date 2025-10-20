use std::{
	collections::HashMap,
	ffi::{CStr, CString, OsStr},
	fmt,
	fs::{File, canonicalize},
	ops::Range,
	os::unix::ffi::OsStrExt,
	path::{Path, PathBuf},
	sync::Arc,
};

use clean_path::clean;
use tempfile::TempDir;
use uuid::Uuid;

use crate::isolation::{
	fd::UhyveFileDescriptorLayer, split_guest_and_host_path, tempdir::create_temp_dir,
};

/// A "mounted" hermit image, the decompressed contents of it are mmap'ed into this process
pub struct HermitImage {
	origin: PathBuf,
	_file: File,
	mmap: memmap2::Mmap,
}

impl fmt::Debug for HermitImage {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "HermitImage({})", self.origin.display())
	}
}

impl core::ops::Index<Range<usize>> for HermitImage {
	type Output = [u8];

	#[inline]
	fn index(&self, index: Range<usize>) -> &[u8] {
		&self.mmap[index]
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HermitImageThinFile {
	File(Range<usize>),
	Directory(HashMap<String, HermitImageThinFile>),
}

impl HermitImageThinFile {
	/// Populate a thin directory tree, with `entry` pointing to `r`
	pub fn update(&mut self, entry: &[&str], r: Range<usize>) {
		let mut this = self;
		for i in entry {
			let dir = match this {
				Self::File(r) if r.start == r.end => {
					*this = Self::Directory(HashMap::new());
					if let Self::Directory(dir) = this {
						dir
					} else {
						unreachable!()
					}
				}
				Self::File(_) => panic!("file in hermit image got overridden"),
				Self::Directory(dir) => dir,
			};
			this = dir
				.entry(i.to_string())
				.or_insert(HermitImageThinFile::File(0..0));
		}
		*this = Self::File(r);
	}

	/// Remove an entry from a thin directory tree
	pub fn unlink(&mut self, entry: &[&str]) {
		if entry.is_empty() {
			// we can't remove ourselves.
			return;
		}
		let (lead, to_remove) = entry.split_at(entry.len() - 1);
		let this = self.resolve_mut(lead);
		if let Some(Self::Directory(this)) = this {
			this.remove(to_remove[0]);
		}
	}

	pub fn resolve(&self, entry: &[&str]) -> Option<&HermitImageThinFile> {
		entry.iter().try_fold(self, |this, &i| {
			if let Self::Directory(dir) = this {
				dir.get(i)
			} else {
				None
			}
		})
	}

	pub fn resolve_mut(&mut self, entry: &[&str]) -> Option<&mut HermitImageThinFile> {
		entry.iter().try_fold(self, |this, &i| {
			if let Self::Directory(dir) = this {
				dir.get_mut(i)
			} else {
				None
			}
		})
	}
}

#[derive(Clone, Debug)]
pub enum MappedFile {
	OnHost(PathBuf),
	InImage {
		image: Arc<HermitImage>,
		thin: HermitImageThinFile,
	},
}

#[derive(Debug)]
pub enum MappedFileMutRef<'a> {
	OnHost(PathBuf),
	InImage {
		image: &'a Arc<HermitImage>,
		thin: &'a mut HermitImageThinFile,
	},
}

impl MappedFileMutRef<'_> {
	#[cfg(test)]
	fn unwrap_on_host(self) -> PathBuf {
		if let Self::OnHost(p) = self {
			p
		} else {
			panic!("unexpected mapped file ref: {:?}", self)
		}
	}
}

impl MappedFile {
	pub fn resolve_mut(&mut self, entry: &Path) -> Option<MappedFileMutRef<'_>> {
		match self {
			MappedFile::OnHost(host_path) => {
				let host_path = if Path::new("") == entry {
					host_path.clone()
				} else {
					host_path.join(entry)
				};
				// Handles symbolic links.
				Some(MappedFileMutRef::OnHost(
					canonicalize(&host_path)
						.map_or(host_path.into_os_string(), PathBuf::into_os_string)
						.into(),
				))
			}
			MappedFile::InImage { image, thin } => Some(MappedFileMutRef::InImage {
				image,
				thin: thin.resolve_mut(&entry.to_str()?.split('/').collect::<Vec<_>>())?,
			}),
		}
	}
}

/// Wrapper around a `HashMap` to map guest paths to arbitrary host paths and track file descriptors.
#[derive(Debug)]
pub struct UhyveFileMap {
	files: HashMap<PathBuf, MappedFile>,
	tempdir: TempDir,
	pub fdmap: UhyveFileDescriptorLayer,
}

impl UhyveFileMap {
	/// Creates a UhyveFileMap.
	///
	/// * `mappings` - A list of host->guest path mappings with the format
	///   "./host_path.txt:guest.txt" or "./hermit_image.hermit:contained.txt:guest.txt"
	/// * `tempdir` - Path to create temporary directory on
	pub fn new(mappings: &[String], tempdir: &Option<String>) -> UhyveFileMap {
		let tempdir = create_temp_dir(tempdir);

		let mut files = HashMap::new();
		let mut hermit_images = HashMap::new();

		for i in mappings {
			let (guest_path, maybe_in_image_str, host_path) = split_guest_and_host_path(i).unwrap();
			if let Some(x) = maybe_in_image_str {
				use std::io::Write;

				use memmap2::MmapOptions;
				// TODO: panic error messages should mention the image file name

				let image = hermit_images.entry(host_path.clone()).or_insert_with(|| {
					// unpack archive
					let data = std::fs::read(&host_path).expect("unable to read hermit image file");
					let decompressed = hermit_image_reader::decompress_image(&data[..])
						.expect("unable to decompress hermit image file");
					let mut tmpf = tempfile::Builder::new()
						.disable_cleanup(true)
						.suffix(".hermit.unpacked")
						.tempfile_in(tempdir.path())
						.expect(
							"unable to create temporary file for hermit image decompression result",
						);
					tmpf.write_all(&decompressed[..])
						.expect("unable to write decompressed hermit image file");

					// create mmap of unpacked archive
					let mmap = unsafe { MmapOptions::new().map(tmpf.as_file()) }
						.expect("unable to mmap decompressed hermit image file");

					let mut content = HermitImageThinFile::File(0..0);
					for i in hermit_image_reader::ImageParser::new(&mmap[..]) {
						let i = i.expect("unable to read hermit image entry");
						if let Ok(name) = str::from_utf8(&i.name) {
							// multiple entries with the same name might exist,
							// latest entry wins / overwrites existing ones
							content.update(&name.split('/').collect::<Vec<_>>(), i.value_range);
						}
					}

					(
						Arc::new(HermitImage {
							origin: host_path.clone(),
							_file: tmpf.keep().unwrap().0,
							mmap,
						}),
						content,
					)
				});

				// resolve file
				if let Some(resolved) = image.1.resolve(&x.split('/').collect::<Vec<_>>()) {
					files.insert(
						guest_path,
						MappedFile::InImage {
							image: Arc::clone(&image.0),
							thin: resolved.clone(),
						},
					);
				} else {
					warn!(
						"In hermit image {}: unable to find file {:?} -> {}",
						host_path.display(),
						x,
						guest_path.display()
					);
				}
			} else {
				files.insert(guest_path, MappedFile::OnHost(host_path));
			}
		}

		UhyveFileMap {
			files,
			tempdir,
			fdmap: UhyveFileDescriptorLayer::default(),
		}
	}

	/// Returns the host_path on the host filesystem given a requested guest_path, if it exists.
	///
	/// * `guest_path` - The guest path that is to be looked up in the map.
	pub fn get_host_path(&mut self, guest_path: &CStr) -> Option<MappedFileMutRef<'_>> {
		if self.files.is_empty() {
			debug!("UhyveFileMap is empty, returning None...");
			return None;
		}

		// TODO: Replace clean-path in favor of Path::normalize_lexically, which has not
		// been implemented yet. See: https://github.com/rust-lang/libs-team/issues/396
		let guest_pathbuf = clean(OsStr::from_bytes(guest_path.to_bytes()));

		for searched_parent_guest in guest_pathbuf.ancestors() {
			// If one of the guest paths' parent directories (parent_host) is mapped,
			// use the mapped host path and push the "remainder" (the path's components
			// that come after the mapped guest path) onto the host path.

			// Work-around for infamous rust issue: https://github.com/rust-lang/rust/issues/54663
			if self.files.contains_key(searched_parent_guest) {
				let parent_host = self.files.get_mut(searched_parent_guest).unwrap();
				let guest_path_remainder =
					guest_pathbuf.strip_prefix(searched_parent_guest).unwrap();
				return parent_host.resolve_mut(guest_path_remainder);
			}
		}
		debug!("The file is not in a child directory, returning None...");
		None
	}

	/// Returns an array of all host paths (for Landlock).
	#[cfg(target_os = "linux")]
	pub(crate) fn get_all_host_paths(&self) -> impl Iterator<Item = &std::ffi::OsStr> {
		self.files.values().filter_map(|i| match i {
			MappedFile::OnHost(f) => Some(f.as_os_str()),
			_ => None,
		})
	}

	/// Returns the path to the temporary directory (for Landlock).
	#[cfg(target_os = "linux")]
	pub(crate) fn get_temp_dir(&self) -> &Path {
		self.tempdir.path()
	}

	/// Inserts an opened temporary file into the file map. Returns a CString so that
	/// the file can be directly used by [crate::hypercall::open].
	///
	/// * `guest_path` - The requested guest path.
	pub fn create_temporary_file(&mut self, guest_path: &CStr) -> CString {
		let host_path = self.tempdir.path().join(Uuid::new_v4().to_string());
		trace!("create_temporary_file (host_path): {host_path:#?}");
		let ret = CString::new(host_path.as_os_str().as_bytes()).unwrap();
		self.files.insert(
			PathBuf::from(OsStr::from_bytes(guest_path.to_bytes())),
			MappedFile::OnHost(host_path),
		);
		ret
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_uhyvefilemap() {
		// Our files are in `$CARGO_MANIFEST_DIR/data/fixtures/fs`.
		let mut fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
		fixture_path.push("tests/data/fixtures/fs");
		assert!(fixture_path.is_dir());
		let path_prefix = fixture_path.to_str().unwrap().to_owned();

		let map_results = [
			path_prefix.clone() + "/README.md",
			path_prefix.clone() + "/this_folder_exists",
			path_prefix.clone() + "/this_symlink_exists",
			path_prefix.clone() + "/this_symlink_is_dangling",
			path_prefix.clone() + "/this_file_does_not_exist",
			// Special case: the file's corresponding parameter uses a symlink,
			// which should be successfully resolved first.
			path_prefix.clone() + "/this_folder_exists/file_in_folder.txt",
		];

		let map_parameters = [
			map_results[0].clone() + ":readme_file.md",
			map_results[1].clone() + ":guest_folder",
			map_results[2].clone() + ":guest_symlink",
			map_results[3].clone() + ":guest_dangling_symlink",
			map_results[4].clone() + ":guest_file",
			path_prefix.clone() + "/this_symlink_leads_to_a_file" + ":guest_file_symlink",
		];

		let mut map = UhyveFileMap::new(&map_parameters, &None);

		assert_eq!(
			map.get_host_path(c"readme_file.md")
				.unwrap()
				.unwrap_on_host(),
			PathBuf::from(&map_results[0])
		);
		assert_eq!(
			map.get_host_path(c"guest_folder").unwrap().unwrap_on_host(),
			PathBuf::from(&map_results[1])
		);
		assert_eq!(
			map.get_host_path(c"guest_symlink")
				.unwrap()
				.unwrap_on_host(),
			PathBuf::from(&map_results[2])
		);
		assert_eq!(
			map.get_host_path(c"guest_dangling_symlink")
				.unwrap()
				.unwrap_on_host(),
			PathBuf::from(&map_results[3])
		);
		assert_eq!(
			map.get_host_path(c"guest_file").unwrap().unwrap_on_host(),
			PathBuf::from(&map_results[4])
		);
		assert_eq!(
			map.get_host_path(c"guest_file_symlink")
				.unwrap()
				.unwrap_on_host(),
			PathBuf::from(&map_results[5])
		);

		assert!(map.get_host_path(c"this_file_is_not_mapped").is_none());
	}

	#[test]
	fn test_uhyvefilemap_directory() {
		let mut fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
		fixture_path.push("tests/data/fixtures/fs");
		assert!(fixture_path.is_dir());

		// Tests successful directory traversal starting from file in child
		// directory of a mapped directory.
		let mut guest_path_map = PathBuf::from("this_folder_exists");
		let mut host_path_map = fixture_path.clone();
		host_path_map.push("this_folder_exists");

		let mut target_guest_path =
			PathBuf::from("this_folder_exists/folder_in_folder/file_in_second_folder.txt");
		let mut target_host_path = fixture_path.clone();
		target_host_path.push(target_guest_path.clone());

		let mut uhyvefilemap_params = [format!(
			"{}:{}",
			host_path_map.to_str().unwrap(),
			guest_path_map.to_str().unwrap()
		)];
		let mut map = UhyveFileMap::new(&uhyvefilemap_params, &None);

		let mut found_host_path = map.get_host_path(
			CString::new(target_guest_path.as_os_str().as_bytes())
				.unwrap()
				.as_c_str(),
		);

		assert_eq!(
			found_host_path.unwrap().unwrap_on_host(),
			target_host_path.as_os_str()
		);

		// Tests successful directory traversal of the child directory.
		// The pop() just removes the text file.
		// guest_path.pop();
		target_host_path.pop();
		target_guest_path.pop();

		found_host_path = map.get_host_path(
			CString::new(target_guest_path.as_os_str().as_bytes())
				.unwrap()
				.as_c_str(),
		);
		assert_eq!(
			found_host_path.unwrap().unwrap_on_host(),
			target_host_path.as_os_str()
		);

		// Tests directory traversal leading to valid symbolic link with an
		// empty guest_path_map.
		host_path_map = fixture_path.clone();
		guest_path_map = PathBuf::from("/root");
		uhyvefilemap_params = [format!(
			"{}:{}",
			host_path_map.to_str().unwrap(),
			guest_path_map.to_str().unwrap()
		)];

		map = UhyveFileMap::new(&uhyvefilemap_params, &None);

		target_guest_path = PathBuf::from("/root/this_symlink_leads_to_a_file");
		target_host_path = fixture_path.clone();
		target_host_path.push("this_folder_exists/file_in_folder.txt");
		found_host_path = map.get_host_path(
			CString::new(target_guest_path.as_os_str().as_bytes())
				.unwrap()
				.as_c_str(),
		);
		assert_eq!(
			found_host_path.unwrap().unwrap_on_host(),
			target_host_path.as_os_str()
		);

		// Tests directory traversal with no maps
		let empty_array: [String; 0] = [];
		map = UhyveFileMap::new(&empty_array, &None);
		found_host_path = map.get_host_path(
			CString::new(target_guest_path.as_os_str().as_bytes())
				.unwrap()
				.as_c_str(),
		);
		assert!(found_host_path.is_none());
	}
}
