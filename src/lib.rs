#![allow(unused_macros)]

extern crate aligned_alloc;
extern crate elf;
extern crate libc;
extern crate memmap;
extern crate nix;
#[macro_use]
extern crate bitflags;
#[cfg(target_os = "linux")]
extern crate tun_tap;
#[macro_use]
extern crate lazy_static;
#[cfg(target_os = "linux")]
extern crate kvm_bindings;
#[cfg(target_os = "linux")]
extern crate kvm_ioctls;
#[cfg(target_os = "linux")]
extern crate vmm_sys_util;
#[cfg(target_os = "macos")]
extern crate xhypervisor;

extern crate burst;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate raw_cpuid;
extern crate x86;

#[macro_use]
extern crate nom;
extern crate strum;
#[macro_use]
extern crate strum_macros;
extern crate byteorder;
extern crate gdb_protocol;
extern crate rustc_serialize;

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
