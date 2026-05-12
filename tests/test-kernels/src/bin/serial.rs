#[cfg(target_os = "hermit")]
use hermit as _;
use uhyve_interface::v2::Hypercall;
use uhyve_test_kernels::hypercall::{serial_buf_hypercall, uhyve_hypercall};

fn main() {
	println!("Hello from serial!");
	for c in "ABCD\n".bytes() {
		uhyve_hypercall(Hypercall::SerialWriteByte(c));
	}
	let testtext = "1234ASDF!@#$\n";
	serial_buf_hypercall(testtext.as_bytes());
}
