use xhypervisor::{create_vm, map_mem, MemPerm};

use crate::{mem::MmapMemory, HypervisorResult};

pub fn initialize_xhyve(mem: &mut MmapMemory) -> HypervisorResult<()> {
	debug!("Create VM...");
	create_vm()?;

	debug!("Map guest memory...");
	map_mem(unsafe { mem.as_slice_mut() }, 0, MemPerm::ExecAndWrite)?;
	Ok(())
}
