#![allow(unused_macros)]

#[cfg(target_os = "linux")]
extern crate kvm_bindings;
#[cfg(target_os = "linux")]
extern crate kvm_ioctls;
#[cfg(target_os = "linux")]
extern crate tun_tap;
#[cfg(target_os = "linux")]
extern crate vmm_sys_util;
#[cfg(target_os = "macos")]
extern crate xhypervisor;

#[macro_use]
mod macros;

pub mod arch;
pub mod consts;
pub mod debug_manager;
pub mod error;
pub mod gdb_parser;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
pub mod paging;
#[cfg(target_os = "linux")]
pub mod shared_queue;
pub mod utils;
pub mod vm;

pub use arch::*;
