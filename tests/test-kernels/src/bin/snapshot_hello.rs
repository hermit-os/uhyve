#[cfg(target_os = "hermit")]
use hermit as _;

unsafe extern "C" {
	fn sys_snapshot() -> u32;
}

fn main() {
	unsafe {
		sys_snapshot();
	}

	println!("Hello world!");
}
