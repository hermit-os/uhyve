//! Uhyve hypercall re-implementation for in application use

use uhyve_interface::v2::parameters::SerialWriteBufferParams;

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::{uhyve_hypercall, virtual_to_physical};
#[cfg(target_arch = "aarch64")]
mod aarch64;
use core::ptr;

#[cfg(target_arch = "aarch64")]
pub use aarch64::{uhyve_hypercall, virtual_to_physical};
use uhyve_interface::{GuestVirtAddr, v2::Hypercall};

#[inline]
fn data_addr<T>(data: &T) -> u64 {
	virtual_to_physical(GuestVirtAddr::from_ptr(ptr::from_ref(data)))
		.unwrap()
		.as_u64()
}

#[inline]
fn hypercall_data(hypercall: &Hypercall<'_>) -> u64 {
	match hypercall {
		Hypercall::Exit(exit_code) => u64::from((*exit_code) as u32),
		Hypercall::FileClose(data) => data_addr(*data),
		Hypercall::FileLseek(data) => data_addr(*data),
		Hypercall::FileOpen(data) => data_addr(*data),
		Hypercall::FileRead(data) => data_addr(*data),
		Hypercall::FileUnlink(data) => data_addr(*data),
		Hypercall::FileWrite(data) => data_addr(*data),
		Hypercall::Getdents(data) => data_addr(*data),
		Hypercall::FileStat(data) => data_addr(*data),
		Hypercall::FileFstat(data) => data_addr(*data),
		Hypercall::Mkdir(data) => data_addr(*data),
		Hypercall::SerialWriteBuffer(data) => data_addr(*data),
		Hypercall::SerialWriteByte(byte) => u64::from(*byte),
		h => todo!("unimplemented hypercall {h:?}"),
	}
}

pub fn serial_buf_hypercall(buf: &[u8]) {
	let p = SerialWriteBufferParams {
		buf: virtual_to_physical(GuestVirtAddr::from_ptr(ptr::from_ref(buf))).unwrap(),
		len: buf.len() as u64,
	};
	uhyve_hypercall(Hypercall::SerialWriteBuffer(&p));
}
