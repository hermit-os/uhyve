use std::{num::NonZeroU32, sync::Arc};

use log::debug;
use uhyve_interface::{GuestPhysAddr, v1::Hypercall};
use xhypervisor::{
	self, Gic, MemPerm, Register, SystemRegister, VirtualCpuExitReason, create_vm, map_mem,
	protect_mem,
};

use crate::{
	HypervisorResult,
	aarch64::{
		MT_DEVICE_GRE, MT_DEVICE_nGnRE, MT_DEVICE_nGnRnE, MT_NORMAL, MT_NORMAL_NC, PSR, TCR_FLAGS,
		TCR_TG1_4K, VA_BITS, mair, tcr_size,
	},
	consts::{
		BOOT_INFO_OFFSET, GICD_BASE_ADDRESS, GICR_BASE_ADDRESS, MSI_BASE_ADDRESS, PGT_OFFSET,
	},
	hypercall::{self, copy_argv, copy_env},
	params::Params,
	stats::{CpuStats, VmExit},
	vcpu::{VcpuStopReason, VirtualCPU},
	vm::{
		KernelInfo, VirtualizationBackend, VmPeripherals, internal::VirtualizationBackendInternal,
	},
};

pub struct XhyveVm {
	peripherals: Arc<VmPeripherals>,
	#[expect(
		dead_code,
		reason = "Gic should be created and stored throughout the struct's lifetime, not used actively"
	)]
	gic: Gic,
}
impl VirtualizationBackendInternal for XhyveVm {
	type VCPU = XhyveCpu;
	const NAME: &str = "XhyveVm";

	fn new_cpu(
		&self,
		id: u32,
		kernel_info: Arc<KernelInfo>,
		enable_stats: bool,
	) -> HypervisorResult<XhyveCpu> {
		Ok(XhyveCpu {
			id,
			peripherals: self.peripherals.clone(),
			kernel_info: kernel_info.clone(),
			vcpu: None,
			stats: if enable_stats {
				Some(CpuStats::new(id as usize))
			} else {
				None
			},
		})
	}

	fn new(
		peripherals: Arc<VmPeripherals>,
		_params: &Params,
		guest_addr: GuestPhysAddr,
	) -> HypervisorResult<Self> {
		trace!("Create VM...");
		create_vm()?;

		trace!("Map guest memory...");
		map_mem(
			unsafe { peripherals.mem.as_slice_mut() },
			guest_addr.as_u64(),
			MemPerm::ExecReadWrite,
		)?;
		// protect the first page for hypercall
		// Apple uses on aarch64 default page size of 16K
		protect_mem(guest_addr.as_u64(), 0x4000, MemPerm::None)?;

		trace!("Create GIC...");
		let gic = Gic::new(GICD_BASE_ADDRESS, GICR_BASE_ADDRESS, MSI_BASE_ADDRESS)?;

		Ok(Self { peripherals, gic })
	}
}

impl VirtualizationBackend for XhyveVm {
	type BACKEND = Self;
}

pub struct XhyveCpu {
	id: u32,
	vcpu: Option<xhypervisor::VirtualCpu>,
	peripherals: Arc<VmPeripherals>,
	// TODO: Remove once the getenv/getargs hypercalls are removed
	kernel_info: Arc<KernelInfo>,
	stats: Option<CpuStats>,
}
unsafe impl Send for XhyveCpu {}

impl XhyveCpu {
	pub fn get_root_pagetable(&self) -> GuestPhysAddr {
		GuestPhysAddr::new(
			self.vcpu
				.as_ref()
				.unwrap()
				.read_system_register(SystemRegister::TTBR0_EL1)
				.unwrap(),
		)
	}
}

impl VirtualCPU for XhyveCpu {
	fn thread_local_init(&mut self) -> HypervisorResult<()> {
		debug!("Initialize VirtualCPU {}", self.id);

		let KernelInfo {
			entry_point,
			stack_address,
			guest_address,
			..
		} = &*self.kernel_info;

		// Initialize CPU
		let vcpu = xhypervisor::VirtualCpu::new(self.id)?;

		/* pstate = all interrupts masked */
		let pstate: PSR = PSR::D_BIT | PSR::A_BIT | PSR::I_BIT | PSR::F_BIT | PSR::MODE_EL1H;
		vcpu.write_register(Register::CPSR, pstate.bits())?;
		vcpu.write_register(Register::PC, entry_point.as_u64())?;
		vcpu.write_system_register(SystemRegister::SP_EL1, stack_address.as_u64())?;
		vcpu.write_register(Register::X0, (*guest_address + BOOT_INFO_OFFSET).as_u64())?;
		vcpu.write_register(Register::X1, self.id.into())?;

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
		vcpu.write_system_register(SystemRegister::MAIR_EL1, mair_el1)?;

		/*
		 * Setup translation control register (TCR)
		 */
		let aa64mmfr0_el1 = vcpu.read_system_register(SystemRegister::ID_AA64MMFR0_EL1)?;
		let tcr = ((aa64mmfr0_el1 & 0xF) << 32) | (tcr_size(VA_BITS) | TCR_TG1_4K | TCR_FLAGS);
		let tcr_el1 = (tcr & 0xFFFFFFF0FFFFFFFFu64) | ((aa64mmfr0_el1 & 0xFu64) << 32);
		vcpu.write_system_register(SystemRegister::TCR_EL1, tcr_el1)?;

		/*
		 * Enable FP/ASIMD in Architectural Feature Access Control Register,
		 */
		let cpacr_el1 = vcpu.read_system_register(SystemRegister::CPACR_EL1)? | (3 << 20);
		vcpu.write_system_register(SystemRegister::CPACR_EL1, cpacr_el1)?;

		/*
		 * Reset debug control register
		 */
		vcpu.write_system_register(SystemRegister::MDSCR_EL1, 0)?;

		// Load TTBRx
		vcpu.write_system_register(SystemRegister::TTBR1_EL1, 0)?;
		vcpu.write_system_register(
			SystemRegister::TTBR0_EL1,
			(*guest_address + PGT_OFFSET).as_u64(),
		)?;

		/*
		* Prepare system control register (SCTRL)
		* Todo: - Verify if all of these bits actually should be explicitly set
			   - Link origin of this documentation and check to which instruction set versions
				 it applies (if applicable)
			   - Fill in the missing Documentation for some of the bits and verify if we care about them
				 or if loading and not setting them would be the appropriate action.
		*/
		#[expect(clippy::identity_op)]
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
		vcpu.write_system_register(SystemRegister::SCTLR_EL1, sctrl_el1)?;

		self.vcpu = Some(vcpu);

		Ok(())
	}

	fn r#continue(&mut self) -> HypervisorResult<VcpuStopReason> {
		if let Some(vcpu) = &mut self.vcpu {
			loop {
				vcpu.run()?;

				let reason = vcpu.exit_reason();
				match reason {
					VirtualCpuExitReason::Exception { exception } => {
						let ec = (exception.syndrome >> 26) & 0x3f;

						// data abort from lower or current level
						if ec == 0b100100u64 || ec == 0b100101u64 {
							let addr: u64 = exception.physical_address;
							let pc = vcpu.read_register(Register::PC)?;

							let data_addr = GuestPhysAddr::new(vcpu.read_register(Register::X8)?);
							if let Some(hypercall) = unsafe {
								hypercall::address_to_hypercall(
									&self.peripherals.mem,
									(addr - self.kernel_info.guest_address.as_u64())
										.try_into()
										.unwrap(),
									data_addr,
								)
							} {
								if let Some(s) = self.stats.as_mut() {
									s.increment_val(VmExit::Hypercall(HypercallAddress::from(
										&hypercall,
									)))
								}
								match hypercall {
									Hypercall::SerialWriteByte(_char) => {
										let x8 = (vcpu.read_register(Register::X8)? & 0xFF) as u8;
										self.peripherals
											.serial
											.output(&[x8])
											.unwrap_or_else(|e| error!("{e:?}"));
									}
									Hypercall::SerialWriteBuffer(sysserialwrite) => {
										// safety: as this buffer is only read and not used afterwards, we don't create multiple aliasing
										let buf = unsafe {
											self.peripherals
												.mem
												.slice_at(sysserialwrite.buf, sysserialwrite.len)
												.expect(
													"Systemcall parameters for SerialWriteBuffer are invalid",
												)
										};

										self.peripherals
											.serial
											.output(buf)
											.unwrap_or_else(|e| error!("{e:?}"))
									}
									Hypercall::Exit(sysexit) => {
										return Ok(VcpuStopReason::Exit(sysexit.arg));
									}
									Hypercall::Cmdsize(syssize) => syssize.update(
										&self.kernel_info.path,
										&self.kernel_info.params.kernel_args,
									),
									Hypercall::Cmdval(syscmdval) => {
										copy_argv(
											self.kernel_info.path.as_os_str(),
											&self.kernel_info.params.kernel_args,
											syscmdval,
											&self.peripherals.mem,
										);
										copy_env(
											&self.kernel_info.params.env,
											syscmdval,
											&self.peripherals.mem,
										);
									}
									Hypercall::FileClose(sysclose) => hypercall::close(
										sysclose,
										&mut self.peripherals.file_mapping.lock().unwrap(),
									),
									Hypercall::FileLseek(syslseek) => hypercall::lseek(
										syslseek,
										&mut self.peripherals.file_mapping.lock().unwrap(),
									),
									Hypercall::FileOpen(sysopen) => hypercall::open(
										&self.peripherals.mem,
										sysopen,
										&mut self.peripherals.file_mapping.lock().unwrap(),
									),
									Hypercall::FileRead(sysread) => hypercall::read(
										&self.peripherals.mem,
										sysread,
										GuestPhysAddr::new(
											vcpu.read_system_register(SystemRegister::TTBR0_EL1)?,
										),
										&mut self.peripherals.file_mapping.lock().unwrap(),
									),
									Hypercall::FileWrite(syswrite) => hypercall::write(
										&self.peripherals,
										syswrite,
										GuestPhysAddr::new(
											vcpu.read_system_register(SystemRegister::TTBR0_EL1)?,
										),
										&mut self.peripherals.file_mapping.lock().unwrap(),
									)
									.unwrap(),
									Hypercall::FileUnlink(sysunlink) => hypercall::unlink(
										&self.peripherals.mem,
										sysunlink,
										&mut self.peripherals.file_mapping.lock().unwrap(),
									),
									_ => {
										panic! {"Hypercall {hypercall:?} not implemented on macos-aarch64"}
									}
								}
								// increase the pc to the instruction after the exception to continue execution
								vcpu.write_register(Register::PC, pc + 4)?;
							} else {
								error!("Unable to handle exception {exception:?}");
								self.print_registers();
								return Err(xhypervisor::Error::Error.into());
							}
						} else {
							error!("Unsupported exception class: 0x{ec:x}");
							self.print_registers();
							return Err(xhypervisor::Error::Error.into());
						}
					}
					_ => {
						error!("Unknown exit reason: {reason:?}");
						return Err(xhypervisor::Error::Error.into());
					}
				}
			}
		}

		panic!("vCPU isn't initialized!");
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
		if let Some(vcpu) = &self.vcpu {
			println!("{vcpu:?}");
		}
	}

	fn get_cpu_frequency(&self) -> Option<NonZeroU32> {
		warn!("CPU base frequency detection not implemented!");
		None
	}
}

impl Drop for XhyveCpu {
	fn drop(&mut self) {
		if let Some(vcpu) = &self.vcpu {
			vcpu.destroy().unwrap();
		}
	}
}
