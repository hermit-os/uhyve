#![feature(strict_provenance)]
#[cfg(target_os = "hermit")]
use hermit_sys as _;
use uhyve_interface::{parameters::SerialWriteBufferParams, HypercallAddress};
#[cfg(target_arch = "x86_64")]
use x86_64::{
	instructions::port::Port, structures::paging::RecursivePageTable, PhysAddr, VirtAddr,
};

unsafe fn get_page_table() -> RecursivePageTable<'static> {
	let level_4_table_addr = 0xFFFF_FFFF_FFFF_F000;
	let level_4_table_ptr = core::ptr::from_exposed_addr_mut(level_4_table_addr);
	unsafe {
		let level_4_table = &mut *(level_4_table_ptr);
		RecursivePageTable::new(level_4_table).unwrap()
	}
}

/// Translate a virtual memory address to a physical one.
pub fn virtual_to_physical(virtual_address: VirtAddr) -> Option<PhysAddr> {
	use x86_64::structures::paging::mapper::Translate;

	let page_table = unsafe { get_page_table() };
	page_table
		.translate_addr(virtual_address)
		.map(|addr| PhysAddr::new(addr.as_u64()))
}

fn main() {
	println!("Test");

	let mut serial_byte_port = Port::new(HypercallAddress::Uart as u16);
	for c in "ABCD\n".bytes() {
		unsafe { serial_byte_port.write(c) };
	}

	let mut serial_buf_port = Port::new(HypercallAddress::SerialBufferWrite as u16);
	let testtext = "1234ASDF!@#$\n";
	let serial_write_params = SerialWriteBufferParams {
		buf: virtual_to_physical(VirtAddr::new(
			core::ptr::addr_of!(*testtext) as *const u8 as u64
		))
		.unwrap(),
		len: testtext.bytes().len(),
	};
	let params_addr = virtual_to_physical(VirtAddr::new(
		core::ptr::addr_of!(serial_write_params) as u64
	))
	.unwrap();

	unsafe { serial_buf_port.write(params_addr.as_u64() as u32) };
}
