use std::ptr;

#[cfg(target_os = "hermit")]
use hermit as _;
use uhyve_interface::{
	GuestPhysAddr,
	v2::{Hypercall, HypercallAddress, parameters::SerialWriteBufferParams},
};
#[cfg(target_arch = "x86_64")]
use x86_64::{
	VirtAddr,
	structures::paging::{PageTable, RecursivePageTable},
};

unsafe fn get_page_table() -> RecursivePageTable<'static> {
	let level_4_table_addr: u64 = 0xFFFF_FFFF_FFFF_F000;
	unsafe {
		let level_4_table = &mut *(level_4_table_addr as *mut PageTable);
		RecursivePageTable::new(level_4_table).unwrap()
	}
}

/// Translate a virtual memory address to a physical one.
pub fn virtual_to_physical(virtual_address: VirtAddr) -> Option<GuestPhysAddr> {
	use x86_64::structures::paging::mapper::Translate;

	let page_table = unsafe { get_page_table() };
	page_table
		.translate_addr(virtual_address)
		.map(|addr| GuestPhysAddr::new(addr.as_u64()))
}

pub(crate) fn serial_buf_hypercall(buf: &[u8]) {
	let p = SerialWriteBufferParams {
		buf: virtual_to_physical(VirtAddr::from_ptr(core::ptr::from_ref::<[u8]>(buf))).unwrap(),
		len: buf.len(),
	};
	uhyve_hypercall(Hypercall::SerialWriteBuffer(&p));
}

#[inline]
fn data_addr<T>(data: &T) -> u64 {
	virtual_to_physical(VirtAddr::from_ptr(ptr::from_ref(data)))
		.unwrap()
		.as_u64()
}

#[inline]
#[allow(unused_variables)] // until riscv64 is implemented
pub(crate) fn uhyve_hypercall(hypercall: Hypercall<'_>) {
	let ptr = HypercallAddress::from(&hypercall) as u64;
	let data = match hypercall {
		Hypercall::SerialWriteBuffer(data) => data_addr(data),
		_ => unimplemented!(),
	};

	#[cfg(target_arch = "x86_64")]
	{
		let ptr = ptr as *mut u64;
		unsafe { ptr.write_volatile(data) };
	}

	#[cfg(target_arch = "aarch64")]
	unsafe {
		use core::arch::asm;
		asm!(
			"str x8, [{ptr}]",
			ptr = in(reg) ptr,
			in("x8") data,
			options(nostack),
		);
	}

	#[cfg(target_arch = "riscv64")]
	todo!()
}

fn main() {
	println!("Hello from serial!");
	// let mut serial_buf_port = HypercallAddress::SerialBufferWrite;
	let testtext = "1234ASDF!@#$\n";
	serial_buf_hypercall(testtext.as_bytes());
}
