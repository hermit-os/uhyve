use crate::consts::*;
use crate::linux::arch::riscv::consts::*;
use crate::vm::HypervisorResult;
use crate::vm::VcpuStopReason;
use crate::vm::{BootInfo, VirtualCPU};
use kvm_bindings::*;
use kvm_ioctls::{VcpuExit, VcpuFd};
use std::cell::RefCell;
use std::path::Path;
use std::path::PathBuf;
use std::ptr::write;
use std::slice;

thread_local!(static SBI_UTF_BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::new()));
pub struct UhyveCPU {
	id: u32,
	vcpu: VcpuFd,
	vm_start: usize,
	kernel_path: PathBuf,
}

impl UhyveCPU {
	pub unsafe fn memory(&mut self, start_addr: u64, len: usize) -> &mut [u8] {
		let host = self.host_address(start_addr as usize);
		slice::from_raw_parts_mut(host as *mut u8, len)
	}

	pub fn new(id: u32, kernel_path: PathBuf, vcpu: VcpuFd, vm_start: usize) -> UhyveCPU {
		UhyveCPU {
			id,
			vcpu,
			vm_start,
			kernel_path,
		}
	}

	pub fn get_vcpu(&self) -> &VcpuFd {
		&self.vcpu
	}

	pub fn get_vcpu_mut(&mut self) -> &mut VcpuFd {
		&mut self.vcpu
	}
}

impl VirtualCPU for UhyveCPU {
	fn init(&mut self, entry_point: u64, boot_info: *const BootInfo) -> HypervisorResult<()> {
		// be sure that the multiprocessor is runable
		let mp_state = kvm_mp_state {
			mp_state: KVM_MP_STATE_RUNNABLE,
		};

		self.vcpu.set_mp_state(mp_state)?;

		self.vcpu
			.set_one_reg(KVM_REG_RISCV_CORE_PC, entry_point)
			.expect("Failed to set pc register");

		let isa = self
			.vcpu
			.get_one_reg(KVM_REG_RISCV_CONFIG_ISA)
			.expect("Failed to read ISA!");
		debug!("Detected ISA {:X}", isa);
		let timebase_freq = self
			.vcpu
			.get_one_reg(KVM_REG_RISCV_TIMER_FREQUENCY)
			.expect("Failed to read timebase freq!");
		debug!("Detected a timebase frequency of {} Hz", timebase_freq);
		unsafe {
			write(
				&mut (*(boot_info as *mut BootInfo)).timebase_freq,
				timebase_freq,
			)
		};

		self.vcpu
			.set_one_reg(KVM_REG_RISCV_CORE_A0, self.id as u64)
			.expect("Failed to set a0 register");

		self.vcpu
			.set_one_reg(KVM_REG_RISCV_CORE_A1, BOOT_INFO_ADDR)
			.expect("Failed to set a1 register");

		Ok(())
	}

	fn kernel_path(&self) -> &Path {
		self.kernel_path.as_path()
	}

	fn host_address(&self, addr: usize) -> usize {
		addr + self.vm_start
	}

	fn virt_to_phys(&self, addr: usize) -> usize {
		addr
	}

	fn r#continue(&mut self) -> HypervisorResult<VcpuStopReason> {
		loop {
			match self.vcpu.run() {
				Ok(vcpu_stop_reason) => match vcpu_stop_reason {
					VcpuExit::Hlt => {
						// Ignore `VcpuExit::Hlt`
						debug!("{:?}", VcpuExit::Hlt);
					}
					VcpuExit::Shutdown => {
						return Ok(VcpuStopReason::Exit(0));
					}
					VcpuExit::Debug(debug) => {
						info!("Caught Debug Interrupt!");
						return Ok(VcpuStopReason::Debug(debug));
					}
					VcpuExit::Sbi(sbi_reason) => {
						//debug!("SBI {:?}", sbi_reason);
						match sbi_reason.extension_id {
							SBI_CONSOLE_PUTCHAR => {
								SBI_UTF_BUFFER.with(|buffer_cell| {
									let mut buffer = buffer_cell.borrow_mut();
									buffer.push((sbi_reason.args[0] & 0xFF) as u8);
									self.uart(&buffer).unwrap();
									buffer.clear();
								});
								/* let c = char::from_u32((sbi_reason.args[0] & 0xFF) as u32);
								assert!(c.is_some(), "Error: {:#X}", sbi_reason.args[0]);
								self.uart(c.unwrap().to_string())
									.expect("UART failed"); */
							}
							_ => info!("Unhandled SBI call: {:?}", sbi_reason),
						}
					}
					VcpuExit::SystemEvent(ev_type, ev_flags) => match ev_type {
						KVM_SYSTEM_EVENT_SHUTDOWN => {
							debug!("Shutdown Exit, flags: {}", ev_flags);
							return Ok(VcpuStopReason::Exit(0));
						}
						_ => info!("Unhandled SystemEvent: {}", ev_type),
					},
					VcpuExit::InternalError => {
						panic!("{:?}", VcpuExit::InternalError)
					}
					vcpu_exit => {
						unimplemented!("{:?}", vcpu_exit)
					}
				},
				Err(err) => match err.errno() {
					libc::EINTR => return Ok(VcpuStopReason::Kick),
					_ => return Err(err),
				},
			}
		}
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

	fn print_registers(&self) {
		let regs = Registers::from_kvm(self.get_vcpu());

		println!();
		println!("Dump state of CPU {}", self.id);
		println!();
		println!("Registers:");
		println!("----------");
		println!("{:x?}", regs);
	}
}

impl Drop for UhyveCPU {
	fn drop(&mut self) {
		debug!("Drop vCPU {}", self.id);
		self.print_registers();
	}
}

#[derive(Default, Debug)]
pub struct Registers {
	// Gotten from gnu-binutils/gdb/riscv-tdep.c
	pub zero: Option<u64>,
	pub ra: Option<u64>,
	pub sp: Option<u64>,
	pub gp: Option<u64>,
	pub tp: Option<u64>,
	pub t0: Option<u64>,
	pub t1: Option<u64>,
	pub t2: Option<u64>,
	pub s0: Option<u64>,
	pub s1: Option<u64>,
	pub a0: Option<u64>,
	pub a1: Option<u64>,
	pub a2: Option<u64>,
	pub a3: Option<u64>,
	pub a4: Option<u64>,
	pub a5: Option<u64>,
	pub a6: Option<u64>,
	pub a7: Option<u64>,
	pub s2: Option<u64>,
	pub s3: Option<u64>,
	pub s4: Option<u64>,
	pub s5: Option<u64>,
	pub s6: Option<u64>,
	pub s7: Option<u64>,
	pub s8: Option<u64>,
	pub s9: Option<u64>,
	pub s10: Option<u64>,
	pub s11: Option<u64>,
	pub t3: Option<u64>,
	pub t4: Option<u64>,
	pub t5: Option<u64>,
	pub t6: Option<u64>,
	pub pc: Option<u64>,
}

impl Registers {
	/// Loads the register set from kvm into the register struct
	pub fn from_kvm(cpu: &VcpuFd) -> Self {
		let mut registers = Registers::default();
		registers.zero = Some(0);
		registers.ra = cpu.get_one_reg(KVM_REG_RISCV_CORE_RA).ok();
		registers.sp = cpu.get_one_reg(KVM_REG_RISCV_CORE_SP).ok();
		registers.gp = cpu.get_one_reg(KVM_REG_RISCV_CORE_GP).ok();
		registers.tp = cpu.get_one_reg(KVM_REG_RISCV_CORE_TP).ok();
		registers.t0 = cpu.get_one_reg(KVM_REG_RISCV_CORE_T0).ok();
		registers.t1 = cpu.get_one_reg(KVM_REG_RISCV_CORE_T1).ok();
		registers.t2 = cpu.get_one_reg(KVM_REG_RISCV_CORE_T2).ok();
		registers.s0 = cpu.get_one_reg(KVM_REG_RISCV_CORE_S0).ok();
		registers.s1 = cpu.get_one_reg(KVM_REG_RISCV_CORE_S1).ok();
		registers.a0 = cpu.get_one_reg(KVM_REG_RISCV_CORE_A0).ok();
		registers.a1 = cpu.get_one_reg(KVM_REG_RISCV_CORE_A1).ok();
		registers.a2 = cpu.get_one_reg(KVM_REG_RISCV_CORE_A2).ok();
		registers.a3 = cpu.get_one_reg(KVM_REG_RISCV_CORE_A3).ok();
		registers.a4 = cpu.get_one_reg(KVM_REG_RISCV_CORE_A4).ok();
		registers.a5 = cpu.get_one_reg(KVM_REG_RISCV_CORE_A5).ok();
		registers.a6 = cpu.get_one_reg(KVM_REG_RISCV_CORE_A6).ok();
		registers.a7 = cpu.get_one_reg(KVM_REG_RISCV_CORE_A7).ok();
		registers.s2 = cpu.get_one_reg(KVM_REG_RISCV_CORE_S2).ok();
		registers.s3 = cpu.get_one_reg(KVM_REG_RISCV_CORE_S3).ok();
		registers.s4 = cpu.get_one_reg(KVM_REG_RISCV_CORE_S4).ok();
		registers.s5 = cpu.get_one_reg(KVM_REG_RISCV_CORE_S5).ok();
		registers.s6 = cpu.get_one_reg(KVM_REG_RISCV_CORE_S6).ok();
		registers.s7 = cpu.get_one_reg(KVM_REG_RISCV_CORE_S7).ok();
		registers.s8 = cpu.get_one_reg(KVM_REG_RISCV_CORE_S8).ok();
		registers.s9 = cpu.get_one_reg(KVM_REG_RISCV_CORE_S9).ok();
		registers.s10 = cpu.get_one_reg(KVM_REG_RISCV_CORE_S10).ok();
		registers.s11 = cpu.get_one_reg(KVM_REG_RISCV_CORE_S11).ok();
		registers.t3 = cpu.get_one_reg(KVM_REG_RISCV_CORE_T3).ok();
		registers.t4 = cpu.get_one_reg(KVM_REG_RISCV_CORE_T4).ok();
		registers.t5 = cpu.get_one_reg(KVM_REG_RISCV_CORE_T5).ok();
		registers.t6 = cpu.get_one_reg(KVM_REG_RISCV_CORE_T6).ok();
		registers.pc = cpu.get_one_reg(KVM_REG_RISCV_CORE_PC).ok();

		registers
	}
}
