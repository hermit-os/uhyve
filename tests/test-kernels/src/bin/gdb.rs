#[cfg(target_os = "hermit")]
use hermit as _;

static mut WATCH: u8 = 2;

fn main() {
	let _x = 5;
	opaque(_x);
	let _x = 3.5;

	fn break1() {}
	break1();

	let _x: u64;
	unsafe {
		std::arch::asm!("mov rax, rcx", out("rax") _x, out("rcx") _);
	}

	let mut _x = 0;
	unsafe { WATCH = 3 }
	_x = 1;

	let _x = unsafe { WATCH };

	fn break2() {}
	break2();
}

// See https://github.com/rust-lang/rust/pull/107404
fn opaque(_: i32) {}
