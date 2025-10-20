use std::{
	collections::HashMap,
	fmt,
	fs::canonicalize,
	path::{Path, PathBuf},
	sync::Arc,
};

use yoke::Yoke;

/// A "mounted" hermit image, the decompressed contents of it are mmap'ed into this process
pub type HermitImage = Box<hermit_entry::tar_parser::Bytes>;

#[derive(Clone)]
pub enum MappedFile {
	OnHost(PathBuf),
	InImage(Yoke<hermit_entry::ThinTree<'static>, Arc<HermitImage>>),
}

impl fmt::Debug for MappedFile {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			MappedFile::OnHost(oh) => write!(f, "OnHost({:?})", oh),
			MappedFile::InImage(_) => write!(f, "InImage(..)"),
		}
	}
}

impl MappedFile {
	#[cfg(test)]
	pub(super) fn unwrap_on_host(self) -> PathBuf {
		if let Self::OnHost(p) = self {
			p
		} else {
			panic!("unexpected mapped file: {:?}", self)
		}
	}

	pub fn resolve(&self, entry: &Path) -> Option<Self> {
		match self {
			MappedFile::OnHost(host_path) => {
				let host_path = if Path::new("") == entry {
					host_path.clone()
				} else {
					host_path.join(entry)
				};
				// Handles symbolic links.
				Some(MappedFile::OnHost(
					canonicalize(&host_path)
						.map_or(host_path.into_os_string(), PathBuf::into_os_string)
						.into(),
				))
			}
			MappedFile::InImage(yoked) => Some(MappedFile::InImage({
				let entry = entry.to_str()?;
				yoked
					.try_map_project_cloned(move |yk: &hermit_entry::ThinTree<'_>, _| {
						let ret: Result<hermit_entry::ThinTree<'_>, ()> =
							yk.resolve(entry.into()).ok_or(()).cloned();
						ret
					})
					.ok()?
			})),
		}
	}
}

/// A cache for decompressed hermit images
#[derive(Default)]
pub struct Cache {
	images: HashMap<PathBuf, Yoke<hermit_entry::ThinTree<'static>, Arc<HermitImage>>>,
}

impl Cache {
	pub fn register_with_data(
		&mut self,
		host_path: &Path,
		data: impl FnOnce(&Path) -> Vec<u8>,
	) -> &Yoke<hermit_entry::ThinTree<'static>, Arc<HermitImage>> {
		self.images
			.entry(host_path.to_path_buf())
			.or_insert_with(move || {
				let data = data(host_path);
				let decompressed = hermit_entry::decompress_image(&data[..]).unwrap_or_else(|e| {
					panic!(
						"{}: unable to decompress hermit image file: {}",
						host_path.display(),
						e,
					)
				});

				let image: Arc<HermitImage> = Arc::new(decompressed);

				Yoke::attach_to_cart(image, |image| {
					hermit_entry::ThinTree::try_from_image(image).unwrap_or_else(|e| {
						panic!(
							"{}: unable to parse hermit image file entry: {:?}",
							host_path.display(),
							e,
						)
					})
				})
			})
	}

	pub fn register(
		&mut self,
		host_path: &Path,
	) -> &Yoke<hermit_entry::ThinTree<'static>, Arc<HermitImage>> {
		self.register_with_data(host_path, |host_path| {
			std::fs::read(host_path).unwrap_or_else(|e| {
				panic!(
					"{}: unable to read hermit image: {}",
					host_path.display(),
					e
				)
			})
		})
	}
}
