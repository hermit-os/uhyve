#[cfg(target_os = "hermit")]
use hermit as _;
use uhyve_interface::{
	GuestVirtAddr,
	v2::{Hypercall, parameters::SnapshotParams},
};
use uhyve_test_kernels::hypercall::{uhyve_hypercall, virtual_to_physical};

fn main() {
	let new_args_buf = [0u8; 256];
	let new_args_phys = virtual_to_physical(GuestVirtAddr::from_ptr(new_args_buf.as_ptr()))
		.expect("virt->phys for new_args_buf");

	let mut params = SnapshotParams {
		new_args: new_args_phys,
		new_args_len: new_args_buf.len() as u64,
		..Default::default()
	};

	uhyve_hypercall(Hypercall::Snapshot(&mut params));

	if params.restored {
		let n = (params.new_args_len as usize).min(new_args_buf.len());
		let s = core::str::from_utf8(&new_args_buf[..n]).unwrap_or("<non-utf8>");
		println!("hello-snapshot: restored execution continued");
		println!("hello-snapshot: new_args_len={}", params.new_args_len);
		println!("hello-snapshot: new_args={s}");
	} else {
		println!("hello-snapshot: snapshot captured (not restored)");
	}
}
