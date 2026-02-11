use std::{
	collections::HashMap,
	ffi::OsStr,
	fmt, fs,
	os::unix::ffi::OsStrExt,
	path::{Path, PathBuf},
	sync::Arc,
};

pub(super) type Directory = HashMap<Box<str>, Node>;

/// A virtual file, which can either resolve to an on-host path or a virtual read-only file.
#[derive(Clone)]
pub enum Leaf {
	/// A file on the host
	OnHost(PathBuf),

	/// An in-memory file
	#[allow(dead_code)]
	Virtual(Arc<[u8]>),
}

impl fmt::Debug for Leaf {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::OnHost(hp) => write!(f, "OnHost({:?})", hp),
			Self::Virtual(slice) => write!(f, "Virtual(len={})", slice.len()),
		}
	}
}

impl Leaf {
	#[cfg(test)]
	pub(super) fn unwrap_on_host(self) -> PathBuf {
		match self {
			Self::OnHost(hp) => hp,
			_ => panic!("expected on-host file path, got something else: {self:?}"),
		}
	}
}

/// A virtual directory tree node, possibly with links to on-host and virtual read-only files.
#[derive(Clone, Debug)]
pub(super) enum Node {
	Leaf(Leaf),
	Directory(Directory),
}

/// Returns the remainder between the end of `component` until the end of `guest_path`.
///
/// SAFETY: `component` must be a substring of `guest_path`.
unsafe fn compute_guest_path_remainder<'a>(guest_path: &'a str, component: &'a str) -> &'a str {
	// TODO: use .remainder() instead once it is stabilized.
	// See: https://github.com/rust-lang/rust/issues/77998

	let end = component.as_bytes().as_ptr_range().end;
	let main_end = guest_path.as_bytes().as_ptr_range().end;

	assert!(end <= main_end);

	// SAFETY: both `start` and `end` are derived from the same allocation `guest_pathstr`.
	//
	// TODO: `from_utf8` can be replaced by str::from_raw_parts, once it is stabilized.
	// See: https://github.com/rust-lang/rust/issues/119206
	let guest_path_remainder = core::str::from_utf8(unsafe {
		core::slice::from_raw_parts(end, main_end.offset_from_unsigned(end))
	})
	.unwrap();

	// mark guest path as relative
	if let Some(guest_path_remainder) = guest_path_remainder.strip_prefix("/") {
		guest_path_remainder
	} else {
		guest_path_remainder
	}
}

/// Clean up a path given by the guest into one that is
/// compatible with our expectations of no redundant path components
/// and without a leading slash.
fn prepare_guest_path(guest_path: &[u8]) -> Option<String> {
	// TODO: Replace clean-path in favor of Path::normalize_lexically, which has not
	// been implemented yet. See: https://github.com/rust-lang/libs-team/issues/396
	//
	// NOTE: Although we use `Path`/`PathBuf` here, these are not semantically correct,
	// given that the meaning of a path on the guest and the host can differ.
	let guest_pathbuf = clean_path::clean(OsStr::from_bytes(guest_path));

	// Here, we expect all input paths to be valid UTF-8 strings,
	// which is also what the Hermit kernel currently internally uses.
	let mut guest_pathstr = match guest_pathbuf.into_os_string().into_string() {
		Ok(x) => x,
		Err(e) => {
			debug!("prepare_guest_path {e:?}: Guest requested non-UTF-8 path, rejecting...");
			return None;
		}
	};

	// Mark guest path as relative
	if guest_pathstr.starts_with('/') {
		guest_pathstr.remove(0);
	}

	Some(guest_pathstr)
}

fn host_path_concat_remainder(host_path: &Path, guest_path_remainder: &str) -> PathBuf {
	let mut ret = host_path.to_path_buf();

	if !guest_path_remainder.is_empty() {
		ret.push(guest_path_remainder);
	}

	ret
}

/// Returns the [`Leaf`] corresponding to given a requested guest_path, if it can exist.
///
/// * `guest_path` - The guest path that is to be looked up in the directory.
pub fn resolve_guest_path(mut this: &Directory, guest_path: &[u8]) -> Option<Leaf> {
	let guest_pathstr = prepare_guest_path(guest_path)?;
	for component in guest_pathstr.split('/') {
		let leaf = match this.get(component) {
			None => {
				debug!(
					"resolve_guest_path {guest_pathstr:?}: Guest reguested to open a path that was not mapped."
				);
				return None;
			}
			Some(Node::Directory(subdir)) => {
				this = subdir;
				continue;
			}
			Some(Node::Leaf(leaf)) => leaf,
		};

		let guest_path_remainder =
			unsafe { compute_guest_path_remainder(&guest_pathstr, component) };

		return match leaf {
			Leaf::OnHost(host_path) => {
				let host_path = host_path_concat_remainder(host_path, guest_path_remainder);
				// Handle symbolic links
				let resolved = match fs::canonicalize(&host_path) {
					Ok(x) => x,
					Err(_) => host_path,
				};

				debug!("resolve_guest_path {guest_pathstr:?}: Resolved to host path {resolved:?}");
				Some(Leaf::OnHost(resolved))
			}
			Leaf::Virtual(v) => {
				if guest_path_remainder.is_empty() {
					debug!("resolve_guest_path {guest_pathstr:?}: Resolved to virtual file");
					Some(Leaf::Virtual(v.clone()))
				} else {
					debug!(
						"resolve_guest_path {guest_pathstr:?}: Tried to recurse into virtual file, rejecting..."
					);
					None
				}
			}
		};
	}

	None
}

/// Returns an iterator over all host directories.
#[cfg(target_os = "linux")]
pub fn get_all_host_paths(this: &Directory) -> impl Iterator<Item = &Path> {
	let mut stack = vec![this.values()];

	core::iter::from_fn(move || {
		while let Some(mut top) = stack.pop() {
			match top.next() {
				// NOTE: this intentionally doesn't put
				// finished directories back on the stack.
				None => continue,
				Some(Node::Directory(dir)) => {
					stack.push(dir.values());
				}
				Some(Node::Leaf(Leaf::Virtual(_))) => {}
				Some(Node::Leaf(Leaf::OnHost(hp))) => {
					stack.push(top);
					return Some(hp.as_path());
				}
			}
			stack.push(top);
		}
		None
	})
}

/// Returns an iterator over all mountable guest directories.
pub fn get_all_guest_dirs(this: &Directory) -> impl Iterator<Item = String> {
	let mut stack = vec![(String::new(), this.iter(), false)];

	core::iter::from_fn(move || {
		while let Some((prefix, mut top, mut marked)) = stack.pop() {
			match top.next() {
				None => {
					// NOTE: this intentionally doesn't put
					// finished directories back on the stack.
					//
					// It also skips the root ("/") for now.
					// (because it would be impossible to mount that into Hermit anyways)
					if marked && !prefix.is_empty() {
						return Some(prefix);
					} else {
						continue;
					}
				}
				Some((component, Node::Directory(dir))) => {
					let mut new_prefix = prefix.clone();
					new_prefix.push('/');
					new_prefix.push_str(component);
					stack.push((new_prefix, dir.iter(), false));
				}
				Some((_, Node::Leaf(Leaf::Virtual(_)))) => {
					marked = true;
				}
				Some((component, Node::Leaf(Leaf::OnHost(hp)))) => {
					// We check the hp filetype, and return the parent directory for everything non-file.
					if let Ok(hp_metadata) = fs::metadata(hp) {
						if hp_metadata.is_dir() {
							let mut new_prefix = prefix.clone();
							new_prefix.push('/');
							new_prefix.push_str(component);
							stack.push((prefix, top, marked));
							return Some(new_prefix);
						} else if hp_metadata.is_file() {
							marked = true;
						} else if hp_metadata.is_symlink() {
							// NOTE: fs::metadata traverses symlinks.
							error!("{} is an unresolvable symlink", hp.display());
						} else {
							marked = true;
						}
					} else if let Some(parent_path) = hp.parent()
						&& let Ok(parent_metadata) = fs::metadata(parent_path)
						&& parent_metadata.is_dir()
					{
						// Parent directory exists, so this is a mounted file.
						marked = true;
					} else {
						error!("{} isn't a valid host path", hp.display());
					}
				}
			}
			stack.push((prefix, top, marked));
		}
		None
	})
}

/// Insert a file (which might be an [`Leaf::OnHost`] mount point) into the directory tree.
///
/// This fails if any parent of the specified `guest_path` is a file or mount point instead of a directory.
pub fn create_leaf(mut this: &mut Directory, guest_path: &[u8], leaf_data: Leaf) -> bool {
	use std::collections::hash_map::Entry;

	let guest_pathstr = match prepare_guest_path(guest_path) {
		Some(x) => x,
		None => return false,
	};
	let mut it = guest_pathstr.split('/');
	let leaf = match it.next_back() {
		None | Some("") => {
			debug!("create_leaf invoked on empty path, rejecting...");
			return false;
		}
		Some(leaf) => leaf,
	};

	for component in it {
		match this.entry(component.to_string().into_boxed_str()) {
			Entry::Vacant(vac) => {
				// Create a new directory
				this = match vac.insert(Node::Directory(Directory::new())) {
					Node::Directory(x) => x,
					_ => unreachable!(),
				};
			}
			Entry::Occupied(occ) => match occ.into_mut() {
				Node::Directory(subdir) => {
					this = subdir;
				}
				_ => {
					debug!(
						"create_leaf {guest_pathstr:?}: Guest reguested to create a file inside of an already mapped file."
					);
					return false;
				}
			},
		}
	}

	match this.entry(leaf.to_string().into_boxed_str()) {
		Entry::Vacant(vac) => {
			trace!("create_leaf {guest_pathstr:?} <- {leaf_data:?}");
			vac.insert(Node::Leaf(leaf_data));
			true
		}
		Entry::Occupied(_) => {
			debug!(
				"create_leaf {guest_pathstr:?}: Guest reguested to create a file, but it already exists"
			);
			false
		}
	}
}

/// Remove a file or empty directory.
///
/// Note that if `guest_path` points to a mount point (`Leaf::Onhost`) or virtual file (`Leaf::Virtual`),
/// then that entry is removed.
///
/// TODO: Introduce proper error return type for this.
pub fn unlink(mut this: &mut Directory, guest_path: &[u8]) -> Result<Option<PathBuf>, ()> {
	use std::collections::hash_map::Entry;

	let guest_pathstr = prepare_guest_path(guest_path).ok_or(())?;
	let mut it = guest_pathstr.split('/');
	let leaf = match it.next_back() {
		None | Some("") => {
			debug!("unlink invoked on empty path, rejecting...");
			return Err(());
		}
		Some(leaf) => leaf,
	};

	for component in it {
		let leaf_data = match this.get_mut(component) {
			None => {
				debug!(
					"unlink {guest_pathstr:?}: Guest reguested to open a path that was not mapped."
				);
				return Err(());
			}
			Some(Node::Directory(subdir)) => {
				this = subdir;
				continue;
			}
			Some(Node::Leaf(leaf_data)) => leaf_data,
		};

		let guest_path_remainder =
			unsafe { compute_guest_path_remainder(&guest_pathstr, component) };

		return match leaf_data {
			Leaf::OnHost(host_path) => {
				let host_path = host_path_concat_remainder(host_path, guest_path_remainder);
				debug!("unlink {guest_pathstr:?}: Resolved to host path {host_path:?}");
				Ok(Some(host_path))
			}
			Leaf::Virtual(_) => {
				debug!(
					"unlink {guest_pathstr:?}: Tried to recurse into virtual file, rejecting..."
				);
				Err(())
			}
		};
	}

	match this.entry(leaf.to_string().into_boxed_str()) {
		Entry::Vacant(_) => {
			trace!("unlink {guest_pathstr:?}: File not found");
			Err(())
		}
		Entry::Occupied(occ) => {
			let mut ret = None;
			debug!("unlink {guest_pathstr:?}: Resolved to {:?}", occ.get());
			match occ.remove_entry() {
				(_, Node::Leaf(Leaf::OnHost(oh))) => {
					ret = Some(oh);
				}
				(_, Node::Leaf(Leaf::Virtual(_))) => {}
				(_, Node::Directory(dir)) if dir.is_empty() => {}
				(leaf, Node::Directory(dir)) => {
					debug!(
						"unlink {guest_pathstr:?}: Tried to unlink non-empty directory, rejecting..."
					);
					this.insert(leaf, Node::Directory(dir));
					return Err(());
				}
			}
			Ok(ret)
		}
	}
}
