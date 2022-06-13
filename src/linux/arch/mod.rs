#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "riscv64")]
pub mod riscv;

#[cfg(target_arch = "x86_64")]
pub use self::x86_64::vcpu;

#[cfg(target_arch = "riscv64")]
pub use self::riscv::vcpu;
