#[cfg(target_os = "hermit")]
use hermit as _;

static mut WATCH: u8 = 2;

fn main() {
	println!("Hello from gdb!");

	let _x = 5;
	opaque(_x);
	let _x = 3.5;

	fn break1() {}
	break1();

	let _x: u64;
	#[cfg(target_arch = "x86_64")]
	unsafe {
		std::arch::asm!("mov rax, rcx", out("rax") _x, out("rcx") _);
	}
	#[cfg(target_arch = "aarch64")]
	unsafe {
		std::arch::asm!("mov x0, x1", out("x0") _x, out("x1") _);
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
