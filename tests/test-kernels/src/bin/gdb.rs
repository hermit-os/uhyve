#![feature(asm)]

#[cfg(target_os = "hermit")]
use hermit_sys as _;

static mut WATCH: u8 = 2;

fn main() {
	let _x = 5;
	let _x = 3.5;

	fn break1() {}
	break1();

	let _x: u64;
	unsafe {
		asm!("mov rax, rcx", out("rax") _x, out("rcx") _);
	}

	let mut _x = 0;
	unsafe { WATCH = 3 }
	_x = 1;

	let _x = unsafe { WATCH };

	fn break2() {}
	break2();
}
