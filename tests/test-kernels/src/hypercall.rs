//! Uhyve hypercall re-implementation for in application use

#[cfg(not(target_arch = "x86_64"))]
use uhyve_interface::v2::Hypercall;

#[cfg(target_arch = "x86_64")]
mod x86_64_imp {
	use core::ptr;

	use uhyve_interface::{
		GuestPhysAddr,
		v2::{Hypercall, HypercallAddress, parameters::SerialWriteBufferParams},
	};
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

	/// Translate a guest virtual address to a physical one (recursive map).
	pub fn virtual_to_physical(virtual_address: VirtAddr) -> Option<GuestPhysAddr> {
		use x86_64::structures::paging::mapper::Translate;

		let page_table = unsafe { get_page_table() };
		page_table
			.translate_addr(virtual_address)
			.map(|addr| GuestPhysAddr::new(addr.as_u64()))
	}

	#[inline]
	fn data_addr<T>(data: &T) -> u64 {
		virtual_to_physical(VirtAddr::from_ptr(ptr::from_ref(data)))
			.unwrap()
			.as_u64()
	}

	#[inline]
	fn hypercall_data(hypercall: &Hypercall<'_>) -> u64 {
		match hypercall {
			// As we are encoding an exit code (max 32 bits) into "an
			// address", and memory_addresses complains if an address
			// has any bits above the 48th one set to 1, we encode
			// potential negative numbers into a u32, then a u64.
			Hypercall::Exit(exit_code) => u64::from((*exit_code) as u32),
			Hypercall::FileClose(data) => data_addr(*data),
			Hypercall::FileLseek(data) => data_addr(*data),
			Hypercall::FileOpen(data) => data_addr(*data),
			Hypercall::FileRead(data) => data_addr(*data),
			Hypercall::FileUnlink(data) => data_addr(*data),
			Hypercall::FileWrite(data) => data_addr(*data),
			Hypercall::SerialWriteBuffer(data) => data_addr(*data),
			Hypercall::SerialWriteByte(byte) => u64::from(*byte),
			h => todo!("unimplemented hypercall {h:?}"),
		}
	}

	/// Perform a hypercall to the uhyve hypervisor.
	#[inline]
	pub fn uhyve_hypercall(hypercall: Hypercall<'_>) {
		let ptr = HypercallAddress::from(&hypercall) as u16;
		let data = hypercall_data(&hypercall);
		unsafe {
			use core::arch::asm;
			asm!(
				"out dx, eax",
				in("dx") ptr,
				in("eax") 0x1234u32,
				in("rdi") data,
				options(nostack, preserves_flags)
			);
		}
	}

	pub fn serial_buf_hypercall(buf: &[u8]) {
		let p = SerialWriteBufferParams {
			buf: virtual_to_physical(VirtAddr::from_ptr(ptr::from_ref(buf))).unwrap(),
			len: buf.len() as u64,
		};
		uhyve_hypercall(Hypercall::SerialWriteBuffer(&p));
	}
}

#[cfg(target_arch = "x86_64")]
pub use x86_64_imp::{serial_buf_hypercall, uhyve_hypercall, virtual_to_physical};

#[cfg(not(target_arch = "x86_64"))]
pub fn uhyve_hypercall(_hypercall: Hypercall<'_>) {
	panic!("uhyve test-kernel hypercalls are only implemented for x86_64");
}

#[cfg(not(target_arch = "x86_64"))]
pub fn serial_buf_hypercall(_buf: &[u8]) {
	panic!("uhyve test-kernel hypercalls are only implemented for x86_64");
}
