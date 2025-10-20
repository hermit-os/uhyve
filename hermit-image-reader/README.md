# hermit-image-reader

This Rust crate implements a basic reader for Hermit images.
Overall, these are just `.tar.gz` (i.e. gzipped tar) files.

For performance reasons, it should be preferred to put the config and kernel
as the first two entries of the image (tar files don't have any sorting or index,
except that normally, the latest entry of the file takes precedence).
If this condition is not adhered to, some hermit / uhyve tools might refuse
to work with the image, or emit a warning.

They contain at least 2 special entries:
* The config file (in TOML format), at `hermit_config.toml` in the image root.
  The expected entries are described in the crate documentation in `hermit_image_reader::config::Config`.
* A Hermit Kernel ELF file, whose path is specified in the config.

The image itself is mapped (from the Hermit kernel perspective) into a path
(`mount_point`) specified in the config file.

