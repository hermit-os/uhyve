use std::{
	collections::HashMap,
	fs::canonicalize,
	path::{Path, PathBuf},
	sync::Arc,
};

pub use hermit_image_reader::thin_tree::ThinTreeRef as HermitImageThinTree;
use yoke::Yoke;

/// A "mounted" hermit image, the decompressed contents of it are mmap'ed into this process
pub type HermitImage = [u8];

#[derive(Clone, Debug)]
pub enum MappedFile {
	OnHost(PathBuf),
	InImage(Yoke<HermitImageThinTree<'static>, Arc<HermitImage>>),
}

#[derive(Debug)]
pub enum MappedFileRef<'a> {
	OnHost(PathBuf),
	InImage(&'a HermitImageThinTree<'a>),
}

impl MappedFileRef<'_> {
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
	pub fn resolve(&self, entry: &Path) -> Option<MappedFileRef<'_>> {
		match self {
			MappedFile::OnHost(host_path) => {
				let host_path = if Path::new("") == entry {
					host_path.clone()
				} else {
					host_path.join(entry)
				};
				// Handles symbolic links.
				Some(MappedFileRef::OnHost(
					canonicalize(&host_path)
						.map_or(host_path.into_os_string(), PathBuf::into_os_string)
						.into(),
				))
			}
			MappedFile::InImage(yoked) => Some(MappedFileRef::InImage(
				yoked.get().resolve(entry.to_str()?.into())?,
			)),
		}
	}
}

/// A cache for decompressed hermit images
#[derive(Default)]
pub struct Cache {
	images: HashMap<PathBuf, Yoke<HermitImageThinTree<'static>, Arc<HermitImage>>>,
}

impl Cache {
	pub fn register(
		&mut self,
		host_path: PathBuf,
	) -> &Yoke<HermitImageThinTree<'static>, Arc<HermitImage>> {
		self.images.entry(host_path.clone()).or_insert_with(|| {
			let data = std::fs::read(&host_path).unwrap_or_else(|e| {
				panic!(
					"{}: unable to read hermit image: {}",
					host_path.display(),
					e
				)
			});
			let decompressed =
				hermit_image_reader::decompress_image(&data[..]).unwrap_or_else(|e| {
					panic!(
						"{}: unable to decompress hermit image file: {}",
						host_path.display(),
						e,
					)
				});

			let image: Arc<[u8]> = decompressed.into();

			Yoke::attach_to_cart(image, |image| {
				HermitImageThinTree::try_from_image(&image[..]).unwrap_or_else(|e| {
					panic!(
						"{}: unable to parse hermit image file entry: {:?}",
						host_path.display(),
						e,
					)
				})
			})
		})
	}
}
