use crate::vm::HypervisorResult;
use crate::vm::VcpuStopReason;
use crate::vm::VirtualCPU;
use log::debug;
use std::path::Path;
use std::path::PathBuf;

pub struct UhyveCPU {
	id: u32,
	kernel_path: PathBuf,
	//vcpu: vCPU,
	vm_start: usize,
}

impl UhyveCPU {
	pub fn new(id: u32, kernel_path: PathBuf, vm_start: usize) -> UhyveCPU {
		Self {
			id: id,
			kernel_path,
			//vcpu: vCPU::new().unwrap(),
			vm_start: vm_start,
		}
	}
}

impl VirtualCPU for UhyveCPU {
	fn init(&mut self, entry_point: u64) -> HypervisorResult<()> {
		Ok(())
	}

	fn kernel_path(&self) -> &Path {
		self.kernel_path.as_path()
	}

	fn host_address(&self, addr: usize) -> usize {
		addr + self.vm_start
	}

	fn virt_to_phys(&self, addr: usize) -> usize {
		0
	}

	fn r#continue(&mut self) -> HypervisorResult<VcpuStopReason> {
		loop {}
	}

	fn run(&mut self) -> HypervisorResult<Option<i32>> {
		match self.r#continue()? {
			VcpuStopReason::Debug(_) => {
				unreachable!("reached debug exit without running in debugging mode")
			}
			VcpuStopReason::Exit(code) => Ok(Some(code)),
			VcpuStopReason::Kick => Ok(None),
		}
	}

	fn print_registers(&self) {}
}

impl Drop for UhyveCPU {
	fn drop(&mut self) {
		debug!("Drop virtual CPU {}", self.id);
		//let _ = self.vcpu.destroy();
	}
}
