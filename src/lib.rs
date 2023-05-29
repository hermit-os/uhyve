#![warn(rust_2018_idioms)]
#![allow(unused_macros)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::useless_conversion)]
#![allow(clippy::extra_unused_type_parameters)]
#![feature(core_intrinsics)]
#![feature(const_trait_impl)]

#[macro_use]
mod macros;

#[macro_use]
extern crate log;

mod arch;
pub mod consts;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux as os;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos as os;
pub mod params;
#[cfg(target_os = "linux")]
pub mod shared_queue;
pub mod vm;

pub use arch::*;
pub use os::uhyve::Uhyve;

pub mod net;
