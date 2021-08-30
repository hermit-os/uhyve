#![warn(rust_2018_idioms)]
#![allow(unused_macros)]
#![allow(clippy::missing_safety_doc)]

#[macro_use]
mod macros;

#[macro_use]
extern crate log;

pub mod arch;
pub mod consts;
pub mod debug_manager;
pub mod gdb_parser;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux as os;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos as os;
pub mod paging;
#[cfg(target_os = "linux")]
pub mod shared_queue;
pub mod utils;
pub mod vm;

pub use arch::*;
pub use os::uhyve::Uhyve;
