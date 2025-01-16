//! Serial output functionality
use std::{
	fs::{File, OpenOptions},
	io::{self, Write},
	str,
	sync::{Arc, Mutex},
};

use crate::{params, HypervisorResult};

/// The destination of the kernels serial output.
#[derive(Debug)]
pub enum Destination {
	/// Same IO as the Uhyve process.
	StdIo,
	/// Redirect output to a file.
	File(Arc<Mutex<File>>),
	/// Redirect output to a buffer.
	Buffer(Arc<Mutex<String>>),
	/// Ignore all serial output.
	None,
}
impl Default for Destination {
	fn default() -> Self {
		Self::StdIo
	}
}

/// Handles serial output functionality.
pub(crate) struct UhyveSerial {
	pub(crate) destination: Destination,
}
impl UhyveSerial {
	pub fn from_params(params: &params::Output) -> HypervisorResult<Self> {
		Ok(Self {
			destination: match params {
				params::Output::None => Destination::None,
				params::Output::StdIo => Destination::StdIo,
				params::Output::Buffer => {
					Destination::Buffer(Arc::new(Mutex::new(String::with_capacity(8096))))
				}
				params::Output::File(ref path) => {
					let f = OpenOptions::new()
						.read(false)
						.write(true)
						.create_new(true)
						.open(path)
						.map_err(|e| {
							error!("Cant create kernel output file: {e}");
							// TODO: proper error handling
							#[cfg(target_os = "macos")]
							panic!();
							#[cfg(not(target_os = "macos"))]
							e
						})?;
					Destination::File(Arc::new(Mutex::new(f)))
				}
			},
		})
	}

	/// Output a utf8 buffer to the configured output destination.
	pub fn output(&self, buf: &[u8]) -> io::Result<()> {
		match &self.destination {
			Destination::StdIo => io::stdout().write_all(buf),
			Destination::None => Ok(()),
			Destination::Buffer(b) => {
				b.lock().unwrap().push_str(str::from_utf8(buf).map_err(|e| {
					io::Error::new(
						io::ErrorKind::InvalidData,
						format!("invalid UTF-8 bytes in output: {e:?}"),
					)
				})?);
				Ok(())
			}
			Destination::File(f) => f.lock().unwrap().write_all(buf),
		}
	}
}
