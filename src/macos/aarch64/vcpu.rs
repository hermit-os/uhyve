#![allow(non_snake_case)]

use crate::aarch64::PSR;
use crate::consts::{BOOT_INFO_ADDR, UHYVE_UART_PORT};
use crate::vm::HypervisorResult;
use crate::vm::VcpuStopReason;
use crate::vm::VirtualCPU;
use log::debug;
use std::path::Path;
use std::path::PathBuf;
use xhypervisor;
use xhypervisor::{Register, SystemRegister, VirtualCpuExitReason};

pub struct UhyveCPU {
	id: u32,
	kernel_path: PathBuf,
	vcpu: xhypervisor::VirtualCpu,
	vm_start: usize,
}

impl UhyveCPU {
	pub fn new(id: u32, kernel_path: PathBuf, vm_start: usize) -> UhyveCPU {
		Self {
			id,
			kernel_path,
			vcpu: xhypervisor::VirtualCpu::new().unwrap(),
			vm_start,
		}
	}
}

impl VirtualCPU for UhyveCPU {
	fn init(&mut self, entry_point: u64) -> HypervisorResult<()> {
		debug!("Initialize VirtualCPU");

		/* pstate = all interrupts masked */
		let pstate: PSR = PSR::D_BIT | PSR::A_BIT | PSR::I_BIT | PSR::F_BIT | PSR::MODE_EL1H;
		self.vcpu.write_register(Register::CPSR, pstate.bits())?;
		self.vcpu.write_register(Register::PC, entry_point)?;
		self.vcpu.write_register(Register::X0, BOOT_INFO_ADDR)?;

		self.print_registers();

		Ok(())
	}

	fn kernel_path(&self) -> &Path {
		self.kernel_path.as_path()
	}

	fn host_address(&self, addr: usize) -> usize {
		addr + self.vm_start
	}

	fn virt_to_phys(&self, _addr: usize) -> usize {
		0
	}

	fn r#continue(&mut self) -> HypervisorResult<VcpuStopReason> {
		loop {
			self.vcpu.run()?;

			let reason = self.vcpu.exit_reason();
			match reason {
				VirtualCpuExitReason::Exception { exception } => {
					let ec = (exception.syndrome >> 26) & 0x3f;

					// data abort from lower or current level
					if ec == 0b100100u64 || ec == 0b100101u64 {
						let addr: u32 = exception.physical_address.try_into().unwrap();
						let pc = self.vcpu.read_register(Register::PC)?;

						match addr {
							UHYVE_UART_PORT => {
								let x8 = (self.vcpu.read_register(Register::X8)? & 0xFF) as u8;
								//println!("X8 = {}", x8);
								//self.print_registers();
								self.uart(&[x8]).unwrap();

								self.vcpu.write_register(Register::PC, pc + 4)?;
							}
							_ => {
								error!("Unable to handle exception {:?}", exception);
								self.print_registers();
								return Err(xhypervisor::Error::Error);
							}
						}
					} else {
						error!("Unsupported exception class: 0x{:x}", ec);
						self.print_registers();
						return Err(xhypervisor::Error::Error);
					}
				}
				_ => {
					error!("Unknown exit reason: {:?}", reason);
					return Err(xhypervisor::Error::Error);
				}
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
		println!("\nDump state of CPU {}", self.id);

		let pc = self.vcpu.read_register(Register::PC).unwrap();
		let cpsr = self.vcpu.read_register(Register::CPSR).unwrap();
		let sp = self
			.vcpu
			.read_system_register(SystemRegister::SP_EL1)
			.unwrap();
		let sctlr = self
			.vcpu
			.read_system_register(SystemRegister::SCTLR_EL1)
			.unwrap();
		let lr = self.vcpu.read_register(Register::LR).unwrap();
		let x0 = self.vcpu.read_register(Register::X0).unwrap();
		let x1 = self.vcpu.read_register(Register::X1).unwrap();
		let x2 = self.vcpu.read_register(Register::X2).unwrap();
		let x3 = self.vcpu.read_register(Register::X3).unwrap();
		let x4 = self.vcpu.read_register(Register::X4).unwrap();
		let x5 = self.vcpu.read_register(Register::X5).unwrap();
		let x6 = self.vcpu.read_register(Register::X6).unwrap();
		let x7 = self.vcpu.read_register(Register::X7).unwrap();
		let x8 = self.vcpu.read_register(Register::X8).unwrap();
		let x9 = self.vcpu.read_register(Register::X9).unwrap();
		let x10 = self.vcpu.read_register(Register::X10).unwrap();
		let x11 = self.vcpu.read_register(Register::X11).unwrap();
		let x12 = self.vcpu.read_register(Register::X12).unwrap();
		let x13 = self.vcpu.read_register(Register::X13).unwrap();
		let x14 = self.vcpu.read_register(Register::X14).unwrap();
		let x15 = self.vcpu.read_register(Register::X15).unwrap();
		let x16 = self.vcpu.read_register(Register::X16).unwrap();
		let x17 = self.vcpu.read_register(Register::X17).unwrap();
		let x18 = self.vcpu.read_register(Register::X18).unwrap();
		let x19 = self.vcpu.read_register(Register::X19).unwrap();
		let x20 = self.vcpu.read_register(Register::X20).unwrap();
		let x21 = self.vcpu.read_register(Register::X21).unwrap();
		let x22 = self.vcpu.read_register(Register::X22).unwrap();
		let x23 = self.vcpu.read_register(Register::X23).unwrap();
		let x24 = self.vcpu.read_register(Register::X24).unwrap();
		let x25 = self.vcpu.read_register(Register::X25).unwrap();
		let x26 = self.vcpu.read_register(Register::X26).unwrap();
		let x27 = self.vcpu.read_register(Register::X27).unwrap();
		let x28 = self.vcpu.read_register(Register::X28).unwrap();
		let x29 = self.vcpu.read_register(Register::X29).unwrap();

		println!("\nRegisters:");
		println!("----------");
		println!(
			"PC : {:016x}   LR : {:016x}   CPSR: {:016x}\n\
		     SP : {:016x}   SCTLR : {:016x}",
			pc, lr, cpsr, sp, sctlr
		);
		print!(
			"x0 : {:016x}   x1 : {:016x}    x2 : {:016x}\n\
			 x3 : {:016x}   x4 : {:016x}    x5 : {:016x}\n\
			 x6 : {:016x}   x7 : {:016x}    x8 : {:016x}\n\
			 x9 : {:016x}   x10: {:016x}    x11: {:016x}\n\
			 x12: {:016x}   x13: {:016x}    x14: {:016x}\n\
			 x15: {:016x}   x16: {:016x}    x17: {:016x}\n\
			 x18: {:016x}   x19: {:016x}    x20: {:016x}\n\
			 x21: {:016x}   x22: {:016x}    x23: {:016x}\n\
			 x24: {:016x}   x25: {:016x}    x26: {:016x}\n\
			 x27: {:016x}   x28: {:016x}    x29: {:016x}\n",
			x0,
			x1,
			x2,
			x3,
			x4,
			x5,
			x6,
			x7,
			x8,
			x9,
			x10,
			x11,
			x12,
			x13,
			x14,
			x15,
			x16,
			x17,
			x18,
			x19,
			x20,
			x21,
			x22,
			x23,
			x24,
			x25,
			x26,
			x27,
			x28,
			x29,
		);
	}
}

impl Drop for UhyveCPU {
	fn drop(&mut self) {
		debug!("Drop virtual CPU {}", self.id);
		//self.print_registers();

		let _ = self.vcpu.destroy();
	}
}
