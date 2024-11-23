#![allow(non_snake_case)]
#![allow(clippy::identity_op)]

use std::sync::Arc;

use log::debug;
use uhyve_interface::{GuestPhysAddr, Hypercall, HypercallAddress};
use xhypervisor::{
	self, create_vm, map_mem, MemPerm, Register, SystemRegister, VirtualCpuExitReason,
};

use crate::{
	aarch64::{
		mair, tcr_size, MT_DEVICE_nGnRE, MT_DEVICE_nGnRnE, MT_DEVICE_GRE, MT_NORMAL, MT_NORMAL_NC,
		PSR, TCR_FLAGS, TCR_TG1_4K, VA_BITS,
	},
	consts::*,
	hypercall::{self, copy_argv, copy_env},
	mem::MmapMemory,
	params::Params,
	stats::{CpuStats, VmExit},
	vcpu::{VcpuStopReason, VirtualCPU},
	vm::{UhyveVm, VirtualizationBackend},
	HypervisorResult,
};

pub struct XhyveVm {}
impl VirtualizationBackend for XhyveVm {
	type VCPU = XhyveCpu;
	const NAME: &str = "XhyveVm";

	fn new_cpu(
		&self,
		id: u32,
		parent_vm: Arc<UhyveVm<XhyveVm>>,
		enable_stats: bool,
	) -> HypervisorResult<XhyveCpu> {
		let mut vcpu = XhyveCpu {
			id,
			parent_vm: parent_vm.clone(),
			vcpu: xhypervisor::VirtualCpu::new().unwrap(),
			stats: if enable_stats {
				Some(CpuStats::new(id as usize))
			} else {
				None
			},
		};
		vcpu.init(parent_vm.get_entry_point(), parent_vm.stack_address(), id)?;

		Ok(vcpu)
	}

	fn new(mem: &MmapMemory, _params: &Params) -> HypervisorResult<Self> {
		debug!("Create VM...");
		create_vm()?;

		debug!("Map guest memory...");
		map_mem(unsafe { mem.as_slice_mut() }, 0, MemPerm::ExecAndWrite)?;
		Ok(Self {})
	}
}

pub struct XhyveCpu {
	id: u32,
	vcpu: xhypervisor::VirtualCpu,
	parent_vm: Arc<UhyveVm<XhyveVm>>,
	stats: Option<CpuStats>,
}

impl XhyveCpu {
	fn init(&mut self, entry_point: u64, stack_address: u64, cpu_id: u32) -> HypervisorResult<()> {
		debug!("Initialize VirtualCPU");

		/* pstate = all interrupts masked */
		let pstate: PSR = PSR::D_BIT | PSR::A_BIT | PSR::I_BIT | PSR::F_BIT | PSR::MODE_EL1H;
		self.vcpu.write_register(Register::CPSR, pstate.bits())?;
		self.vcpu.write_register(Register::PC, entry_point)?;
		self.vcpu
			.write_system_register(SystemRegister::SP_EL1, stack_address)?;
		self.vcpu
			.write_register(Register::X0, BOOT_INFO_ADDR.as_u64())?;
		self.vcpu.write_register(Register::X1, cpu_id.into())?;

		/*
		 * Setup memory attribute type tables
		 *
		 * Memory regioin attributes for LPAE:
		 *
		 *   n = AttrIndx[2:0]
		 *                      n       MAIR
		 *   DEVICE_nGnRnE      000     00000000 (0x00)
		 *   DEVICE_nGnRE       001     00000100 (0x04)
		 *   DEVICE_GRE         010     00001100 (0x0c)
		 *   NORMAL_NC          011     01000100 (0x44)
		 *   NORMAL             100     11111111 (0xff)
		 */
		let mair_el1 = mair(0x00, MT_DEVICE_nGnRnE)
			| mair(0x04, MT_DEVICE_nGnRE)
			| mair(0x0c, MT_DEVICE_GRE)
			| mair(0x44, MT_NORMAL_NC)
			| mair(0xff, MT_NORMAL);
		self.vcpu
			.write_system_register(SystemRegister::MAIR_EL1, mair_el1)?;

		/*
		 * Setup translation control register (TCR)
		 */
		let aa64mmfr0_el1 = self
			.vcpu
			.read_system_register(SystemRegister::ID_AA64MMFR0_EL1)?;
		let tcr = ((aa64mmfr0_el1 & 0xF) << 32) | (tcr_size(VA_BITS) | TCR_TG1_4K | TCR_FLAGS);
		let tcr_el1 = (tcr & 0xFFFFFFF0FFFFFFFFu64) | ((aa64mmfr0_el1 & 0xFu64) << 32);
		self.vcpu
			.write_system_register(SystemRegister::TCR_EL1, tcr_el1)?;

		/*
		 * Enable FP/ASIMD in Architectural Feature Access Control Register,
		 */
		let cpacr_el1 = self.vcpu.read_system_register(SystemRegister::CPACR_EL1)? | (3 << 20);
		self.vcpu
			.write_system_register(SystemRegister::CPACR_EL1, cpacr_el1)?;

		/*
		 * Reset debug control register
		 */
		self.vcpu
			.write_system_register(SystemRegister::MDSCR_EL1, 0)?;

		// Load TTBRx
		self.vcpu
			.write_system_register(SystemRegister::TTBR1_EL1, 0)?;
		self.vcpu
			.write_system_register(SystemRegister::TTBR0_EL1, BOOT_PGT.as_u64())?;

		/*
		* Prepare system control register (SCTRL)
		* Todo: - Verify if all of these bits actually should be explicitly set
			   - Link origin of this documentation and check to which instruction set versions
				 it applies (if applicable)
			   - Fill in the missing Documentation for some of the bits and verify if we care about them
				 or if loading and not setting them would be the appropriate action.
		*/
		let sctrl_el1: u64 = 0
		 | (1 << 26) 	    /* UCI	Enables EL0 access in AArch64 for DC CVAU, DC CIVAC,
									DC CVAC and IC IVAU instructions */
		 | (0 << 25)		/* EE	Explicit data accesses at EL1 and Stage 1 translation
									table walks at EL1 & EL0 are little-endian */
		 | (0 << 24)		/* EOE	Explicit data accesses at EL0 are little-endian */
		 | (1 << 23)
		 | (1 << 22)
		 | (1 << 20)
		 | (0 << 19)		/* WXN	Regions with write permission are not forced to XN */
		 | (1 << 18)		/* nTWE	WFE instructions are executed as normal */
		 | (0 << 17)
		 | (1 << 16)		/* nTWI	WFI instructions are executed as normal */
		 | (1 << 15)		/* UCT	Enables EL0 access in AArch64 to the CTR_EL0 register */
		 | (1 << 14)		/* DZE	Execution of the DC ZVA instruction is allowed at EL0 */
		 | (0 << 13)
		 | (1 << 12)		/* I	Instruction caches enabled at EL0 and EL1 */
		 | (1 << 11)
		 | (0 << 10)
		 | (0 << 9)			/* UMA	Disable access to the interrupt masks from EL0 */
		 | (1 << 8)			/* SED	The SETEND instruction is available */
		 | (0 << 7)			/* ITD	The IT instruction functionality is available */
		 | (0 << 6)			/* THEE	ThumbEE is disabled */
		 | (0 << 5)			/* CP15BEN	CP15 barrier operations disabled */
		 | (1 << 4)			/* SA0	Stack Alignment check for EL0 enabled */
		 | (1 << 3)			/* SA	Stack Alignment check enabled */
		 | (1 << 2)			/* C	Data and unified enabled */
		 | (0 << 1)			/* A	Alignment fault checking disabled */
		 | (1 << 0)			/* M	MMU enable */
		;
		self.vcpu
			.write_system_register(SystemRegister::SCTLR_EL1, sctrl_el1)?;

		Ok(())
	}
}

impl VirtualCPU for XhyveCpu {
	type VirtIf = XhyveVm;
	fn r#continue(&mut self) -> HypervisorResult<VcpuStopReason> {
		loop {
			self.vcpu.run()?;

			let reason = self.vcpu.exit_reason();
			match reason {
				VirtualCpuExitReason::Exception { exception } => {
					let ec = (exception.syndrome >> 26) & 0x3f;

					// data abort from lower or current level
					if ec == 0b100100u64 || ec == 0b100101u64 {
						let addr: u16 = exception.physical_address.try_into().unwrap();
						let pc = self.vcpu.read_register(Register::PC)?;

						let data_addr = GuestPhysAddr::new(self.vcpu.read_register(Register::X8)?);
						if let Some(hypercall) = unsafe {
							hypercall::address_to_hypercall(&self.parent_vm.mem, addr, data_addr)
						} {
							if let Some(s) = self.stats.as_mut() {
								s.increment_val(VmExit::Hypercall(HypercallAddress::from(
									&hypercall,
								)))
							}
							match hypercall {
								Hypercall::SerialWriteByte(_char) => {
									let x8 = (self.vcpu.read_register(Register::X8)? & 0xFF) as u8;
									self.parent_vm
										.serial_output(&[x8])
										.unwrap_or_else(|e| error!("{e:?}"));
								}
								Hypercall::SerialWriteBuffer(sysserialwrite) => {
									// safety: as this buffer is only read and not used afterwards, we don't create multiple aliasing
									let buf = unsafe {
										self.parent_vm.mem.slice_at(sysserialwrite.buf, sysserialwrite.len)
           .expect("Systemcall parameters for SerialWriteBuffer are invalid")
									};

									self.parent_vm
										.serial_output(buf)
										.unwrap_or_else(|e| error!("{e:?}"))
								}
								Hypercall::Exit(sysexit) => {
									return Ok(VcpuStopReason::Exit(sysexit.arg));
								}
								Hypercall::Cmdsize(syssize) => syssize
									.update(self.parent_vm.kernel_path(), self.parent_vm.args()),
								Hypercall::Cmdval(syscmdval) => {
									copy_argv(
										self.parent_vm.kernel_path().as_os_str(),
										self.parent_vm.args(),
										syscmdval,
										&self.parent_vm.mem,
									);
									copy_env(syscmdval, &self.parent_vm.mem);
								}
								Hypercall::FileClose(sysclose) => hypercall::close(sysclose),
								Hypercall::FileLseek(syslseek) => hypercall::lseek(syslseek),
								Hypercall::FileOpen(sysopen) => hypercall::open(
									&self.parent_vm.mem,
									sysopen,
									&mut self.parent_vm.mount.lock().unwrap(),
									&self.parent_vm.tempdir,
								),
								Hypercall::FileRead(sysread) => {
									hypercall::read(&self.parent_vm.mem, sysread)
								}
								Hypercall::FileWrite(syswrite) => {
									hypercall::write(&self.parent_vm, syswrite).unwrap()
								}
								Hypercall::FileUnlink(sysunlink) => {
									hypercall::unlink(&self.parent_vm.mem, sysunlink)
								}
								_ => {
									panic! {"Hypercall {hypercall:?} not implemented on macos-aarch64"}
								}
							}
							// increase the pc to the instruction after the exception to continue execution
							self.vcpu.write_register(Register::PC, pc + 4)?;
						} else {
							#[allow(clippy::match_single_binding)]
							match addr {
								_ => {
									error!("Unable to handle exception {:?}", exception);
									self.print_registers();
									return Err(xhypervisor::Error::Error);
								}
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

	fn run(&mut self) -> HypervisorResult<(Option<i32>, Option<CpuStats>)> {
		if let Some(stats) = self.stats.as_mut() {
			stats.start_time_measurement();
		}
		let res = match self.r#continue()? {
			VcpuStopReason::Debug(_) => {
				unreachable!("reached debug exit without running in debugging mode")
			}
			VcpuStopReason::Exit(code) => Some(code),
			VcpuStopReason::Kick => None,
		};
		if let Some(stats) = self.stats.as_mut() {
			stats.stop_time_measurement();
		}
		Ok((res, self.stats.take()))
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
		let ttbr0 = self
			.vcpu
			.read_system_register(SystemRegister::TTBR0_EL1)
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
			"PC    : {pc:016x}  LR    : {lr:016x}  CPSR  : {cpsr:016x}\n\
		     SP    : {sp:016x}  SCTLR : {sctlr:016x}  TTBR0 : {ttbr0:016x}",
		);
		print!(
			"x0    : {x0:016x}  x1    : {x1:016x}  x2    : {x2:016x}\n\
			 x3    : {x3:016x}  x4    : {x4:016x}  x5    : {x5:016x}\n\
			 x6    : {x6:016x}  x7    : {x7:016x}  x8    : {x8:016x}\n\
			 x9    : {x9:016x}  x10   : {x10:016x}  x11   : {x11:016x}\n\
			 x12   : {x12:016x}  x13   : {x13:016x}  x14   : {x14:016x}\n\
			 x15   : {x15:016x}  x16   : {x16:016x}  x17   : {x17:016x}\n\
			 x18   : {x18:016x}  x19   : {x19:016x}  x20   : {x20:016x}\n\
			 x21   : {x21:016x}  x22   : {x22:016x}  x23   : {x23:016x}\n\
			 x24   : {x24:016x}  x25   : {x25:016x}  x26   : {x26:016x}\n\
			 x27   : {x27:016x}  x28   : {x28:016x}  x29   : {x29:016x}\n",
		);
	}
}

impl Drop for XhyveCpu {
	fn drop(&mut self) {
		self.vcpu.destroy().unwrap();
	}
}
