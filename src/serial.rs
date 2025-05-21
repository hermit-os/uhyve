// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Serial output functionality
use std::{
	fs::{File, OpenOptions},
	io::{self, Write},
	sync::{Arc, Mutex},
};

use crate::{HypervisorResult, params};

/// The destination of the kernels serial output.
#[derive(Debug, Clone)]
pub enum Destination {
	/// Same IO as the Uhyve process.
	StdIo,
	/// Redirect output to a file.
	File(Arc<Mutex<File>>),
	/// Redirect output to a buffer.
	Buffer(Arc<Mutex<Vec<u8>>>),
	/// Ignore all serial output.
	None,
}
impl Default for Destination {
	fn default() -> Self {
		Self::StdIo
	}
}

/// Handles serial output functionality.
#[derive(Debug, Clone)]
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
					Destination::Buffer(Arc::new(Mutex::new(Vec::with_capacity(8096))))
				}
				params::Output::File(path) => {
					let f = OpenOptions::new()
						.read(false)
						.write(true)
						.create_new(true)
						.open(path)
						.map_err(|e| {
							error!("Cant create kernel output file: {e}");
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
				b.lock().unwrap().extend_from_slice(buf);
				Ok(())
			}
			Destination::File(f) => f.lock().unwrap().write_all(buf),
		}
	}
}
