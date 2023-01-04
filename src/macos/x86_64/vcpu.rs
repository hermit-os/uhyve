#![allow(non_snake_case)]

use std::{
	arch::x86_64::__cpuid_count,
	ffi::OsString,
	path::{Path, PathBuf},
	sync::{Arc, Mutex},
};

use burst::x86::{disassemble_64, InstructionOperation, OperandType};
use lazy_static::lazy_static;
use log::{debug, trace};
use uhypercall_interface::{Hypercall, UHYVE_UART_PORT};
use x86_64::{
	registers::control::{Cr0Flags, Cr4Flags},
	structures::{gdt::SegmentSelector, paging::PageTableFlags},
	PrivilegeLevel,
};
use xhypervisor::{
	self,
	consts::{
		vmcs::*,
		vmx_cap::{
			CPU_BASED2_APIC_REG_VIRT, CPU_BASED2_RDTSCP, CPU_BASED_MONITOR, CPU_BASED_MSR_BITMAPS,
			CPU_BASED_MWAIT, CPU_BASED_SECONDARY_CTLS, CPU_BASED_TPR_SHADOW, CPU_BASED_TSC_OFFSET,
			PIN_BASED_INTR, PIN_BASED_NMI, PIN_BASED_VIRTUAL_NMI, VMENTRY_GUEST_IA32E,
			VMENTRY_LOAD_EFER,
		},
		vmx_exit,
	},
	read_vmx_cap, Register,
};

use crate::{
	consts::*,
	macos::x86_64::ioapic::IoApic,
	vm::{HypervisorResult, VcpuStopReason, VirtualCPU},
};

/// Extracted from `x86::msr`.
mod msr {
	/// See Section 17.13, Time-Stamp Counter.
	pub const TSC: u32 = 0x10;

	/// APIC Location and Status (R/W) See Table 35-2. See Section 10.4.4, Local APIC  Status and Location.
	pub const IA32_APIC_BASE: u32 = 0x1b;

	/// CS register target for CPL 0 code (R/W) See Table 35-2. See Section 5.8.7, Performing Fast Calls to  System Procedures with the SYSENTER and  SYSEXIT Instructions.
	pub const IA32_SYSENTER_CS: u32 = 0x174;

	/// Stack pointer for CPL 0 stack (R/W) See Table 35-2. See Section 5.8.7, Performing Fast Calls to  System Procedures with the SYSENTER and  SYSEXIT Instructions.
	pub const IA32_SYSENTER_ESP: u32 = 0x175;

	/// CPL 0 code entry point (R/W) See Table 35-2. See Section 5.8.7, Performing  Fast Calls to System Procedures with the SYSENTER and SYSEXIT Instructions.
	pub const IA32_SYSENTER_EIP: u32 = 0x176;

	pub const IA32_MISC_ENABLE: u32 = 0x1a0;

	/// x2APIC Task Priority register (R/W)
	pub const IA32_X2APIC_TPR: u32 = 0x808;

	/// x2APIC End of Interrupt. If ( CPUID.01H:ECX.\[bit 21\]  = 1 )
	pub const IA32_X2APIC_EOI: u32 = 0x80b;

	/// x2APIC Spurious Interrupt Vector register (R/W)
	pub const IA32_X2APIC_SIVR: u32 = 0x80f;

	/// x2APIC Interrupt Command register (R/W)
	pub const IA32_X2APIC_ICR: u32 = 0x830;

	/// x2APIC LVT Timer Interrupt register (R/W)
	pub const IA32_X2APIC_LVT_TIMER: u32 = 0x832;

	/// x2APIC LVT Thermal Sensor Interrupt register (R/W)
	pub const IA32_X2APIC_LVT_THERMAL: u32 = 0x833;

	/// x2APIC LVT Performance Monitor register (R/W)
	pub const IA32_X2APIC_LVT_PMI: u32 = 0x834;

	/// If ( CPUID.01H:ECX.\[bit 21\]  = 1 )
	pub const IA32_X2APIC_LVT_LINT0: u32 = 0x835;

	/// If ( CPUID.01H:ECX.\[bit 21\]  = 1 )
	pub const IA32_X2APIC_LVT_LINT1: u32 = 0x836;

	/// If ( CPUID.01H:ECX.\[bit 21\]  = 1 )
	pub const IA32_X2APIC_LVT_ERROR: u32 = 0x837;

	/// If (  CPUID.80000001.EDX.\[bit  20\] or  CPUID.80000001.EDX.\[bit 29\])
	pub const IA32_EFER: u32 = 0xc0000080;

	/// System Call Target Address (R/W)  See Table 35-2.
	pub const IA32_STAR: u32 = 0xc0000081;

	/// IA-32e Mode System Call Target Address (R/W)  See Table 35-2.
	pub const IA32_LSTAR: u32 = 0xc0000082;

	/// System Call Target Address the compatibility mode.
	pub const IA32_CSTAR: u32 = 0xc0000083;

	/// System Call Flag Mask (R/W)  See Table 35-2.
	pub const IA32_FMASK: u32 = 0xc0000084;

	/// Map of BASE Address of FS (R/W)  See Table 35-2.
	pub const IA32_FS_BASE: u32 = 0xc0000100;

	/// Map of BASE Address of GS (R/W)  See Table 35-2.
	pub const IA32_GS_BASE: u32 = 0xc0000101;

	/// Swap Target of BASE Address of GS (R/W) See Table 35-2.
	pub const IA32_KERNEL_GSBASE: u32 = 0xc0000102;

	/// AUXILIARY TSC Signature. (R/W) See Table 35-2 and Section  17.13.2, IA32_TSC_AUX Register and RDTSCP Support.
	pub const IA32_TSC_AUX: u32 = 0xc0000103;
}

use msr::*;

/* desired control word constrained by hardware/hypervisor capabilities */
fn cap2ctrl(cap: u64, ctrl: u64) -> u64 {
	(ctrl | (cap & 0xffffffff)) & (cap >> 32)
}

lazy_static! {
	static ref CAP_PINBASED: u64 = {
		let cap: u64 = { read_vmx_cap(&xhypervisor::VMXCap::PINBASED).unwrap() };
		cap2ctrl(cap, PIN_BASED_INTR | PIN_BASED_NMI | PIN_BASED_VIRTUAL_NMI)
	};
	static ref CAP_PROCBASED: u64 =
		{
			let cap: u64 = { read_vmx_cap(&xhypervisor::VMXCap::PROCBASED).unwrap() };
			cap2ctrl(
				cap,
				CPU_BASED_SECONDARY_CTLS
					| CPU_BASED_MWAIT | CPU_BASED_MSR_BITMAPS
					| CPU_BASED_MONITOR | CPU_BASED_TSC_OFFSET
					| CPU_BASED_TPR_SHADOW,
			)
		};
	static ref CAP_PROCBASED2: u64 = {
		let cap: u64 = { read_vmx_cap(&xhypervisor::VMXCap::PROCBASED2).unwrap() };
		cap2ctrl(cap, CPU_BASED2_RDTSCP | CPU_BASED2_APIC_REG_VIRT)
	};
	static ref CAP_ENTRY: u64 = {
		let cap: u64 = { read_vmx_cap(&xhypervisor::VMXCap::ENTRY).unwrap() };
		cap2ctrl(cap, VMENTRY_LOAD_EFER | VMENTRY_GUEST_IA32E)
	};
	static ref CAP_EXIT: u64 = {
		let cap: u64 = { read_vmx_cap(&xhypervisor::VMXCap::EXIT).unwrap() };
		cap2ctrl(cap, 0)
	};
}

pub struct UhyveCPU {
	id: u32,
	kernel_path: PathBuf,
	args: Vec<OsString>,
	vcpu: xhypervisor::VirtualCpu,
	vm_start: usize,
	apic_base: u64,
	ioapic: Arc<Mutex<IoApic>>,
}

impl UhyveCPU {
	pub fn new(
		id: u32,
		kernel_path: PathBuf,
		args: Vec<OsString>,
		vm_start: usize,
		ioapic: Arc<Mutex<IoApic>>,
	) -> UhyveCPU {
		UhyveCPU {
			id,
			kernel_path,
			args,
			vcpu: xhypervisor::VirtualCpu::new().unwrap(),
			vm_start,
			apic_base: APIC_DEFAULT_BASE,
			ioapic,
		}
	}

	fn setup_system_gdt(&mut self) -> Result<(), xhypervisor::Error> {
		debug!("Setup GDT");

		self.vcpu.write_vmcs(VMCS_GUEST_CS_LIMIT, 0)?;
		self.vcpu.write_vmcs(VMCS_GUEST_CS_BASE, 0)?;
		self.vcpu.write_vmcs(VMCS_GUEST_CS_AR, 0x209B)?;
		self.vcpu.write_vmcs(VMCS_GUEST_SS_LIMIT, 0)?;
		self.vcpu.write_vmcs(VMCS_GUEST_SS_BASE, 0)?;
		self.vcpu.write_vmcs(VMCS_GUEST_SS_AR, 0x4093)?;
		self.vcpu.write_vmcs(VMCS_GUEST_DS_LIMIT, 0)?;
		self.vcpu.write_vmcs(VMCS_GUEST_DS_BASE, 0)?;
		self.vcpu.write_vmcs(VMCS_GUEST_DS_AR, 0x4093)?;
		self.vcpu.write_vmcs(VMCS_GUEST_ES_LIMIT, 0)?;
		self.vcpu.write_vmcs(VMCS_GUEST_ES_BASE, 0)?;
		self.vcpu.write_vmcs(VMCS_GUEST_ES_AR, 0x4093)?;
		self.vcpu.write_vmcs(VMCS_GUEST_FS_LIMIT, 0)?;
		self.vcpu.write_vmcs(VMCS_GUEST_FS_BASE, 0)?;
		self.vcpu.write_vmcs(VMCS_GUEST_FS_AR, 0x4093)?;
		self.vcpu.write_vmcs(VMCS_GUEST_GS_LIMIT, 0)?;
		self.vcpu.write_vmcs(VMCS_GUEST_GS_BASE, 0)?;
		self.vcpu.write_vmcs(VMCS_GUEST_GS_AR, 0x4093)?;

		self.vcpu.write_vmcs(VMCS_GUEST_GDTR_BASE, BOOT_GDT)?;
		self.vcpu.write_vmcs(
			VMCS_GUEST_GDTR_LIMIT,
			((std::mem::size_of::<u64>() * BOOT_GDT_MAX as usize) - 1) as u64,
		)?;
		self.vcpu.write_vmcs(VMCS_GUEST_IDTR_BASE, 0)?;
		self.vcpu.write_vmcs(VMCS_GUEST_IDTR_LIMIT, 0xffff)?;

		self.vcpu.write_vmcs(VMCS_GUEST_TR, 0)?;
		self.vcpu.write_vmcs(VMCS_GUEST_TR_LIMIT, 0xffff)?;
		self.vcpu.write_vmcs(VMCS_GUEST_TR_AR, 0x8b)?;
		self.vcpu.write_vmcs(VMCS_GUEST_TR_BASE, 0)?;

		self.vcpu.write_vmcs(VMCS_GUEST_LDTR, 0)?;
		self.vcpu.write_vmcs(VMCS_GUEST_LDTR_LIMIT, 0xffff)?;
		self.vcpu.write_vmcs(VMCS_GUEST_LDTR_AR, 0x82)?;
		self.vcpu.write_vmcs(VMCS_GUEST_LDTR_BASE, 0)?;
		// Reload the segment descriptors
		self.vcpu.write_register(
			&Register::CS,
			SegmentSelector::new(GDT_KERNEL_CODE, PrivilegeLevel::Ring0).0 as u64,
		)?;
		self.vcpu.write_register(
			&Register::DS,
			SegmentSelector::new(GDT_KERNEL_DATA, PrivilegeLevel::Ring0).0 as u64,
		)?;
		self.vcpu.write_register(
			&Register::ES,
			SegmentSelector::new(GDT_KERNEL_DATA, PrivilegeLevel::Ring0).0 as u64,
		)?;
		self.vcpu.write_register(
			&Register::SS,
			SegmentSelector::new(GDT_KERNEL_DATA, PrivilegeLevel::Ring0).0 as u64,
		)?;
		self.vcpu.write_register(
			&Register::FS,
			SegmentSelector::new(GDT_KERNEL_DATA, PrivilegeLevel::Ring0).0 as u64,
		)?;
		self.vcpu.write_register(
			&Register::GS,
			SegmentSelector::new(GDT_KERNEL_DATA, PrivilegeLevel::Ring0).0 as u64,
		)?;

		Ok(())
	}

	fn setup_system_64bit(&mut self) -> Result<(), xhypervisor::Error> {
		debug!("Setup 64bit mode");

		let cr0 = Cr0Flags::PROTECTED_MODE_ENABLE
			| Cr0Flags::EXTENSION_TYPE
			| Cr0Flags::NUMERIC_ERROR
			| Cr0Flags::PAGING;
		let cr4 = Cr4Flags::PHYSICAL_ADDRESS_EXTENSION | Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS;

		self.vcpu
			.write_vmcs(VMCS_GUEST_IA32_EFER, EFER_LME | EFER_LMA)?;

		self.vcpu.write_vmcs(
			VMCS_CTRL_CR0_MASK,
			(Cr0Flags::CACHE_DISABLE | Cr0Flags::NOT_WRITE_THROUGH | cr0).bits(),
		)?;
		self.vcpu.write_vmcs(VMCS_CTRL_CR0_SHADOW, cr0.bits())?;
		self.vcpu.write_vmcs(VMCS_CTRL_CR4_MASK, cr4.bits())?;
		self.vcpu.write_vmcs(VMCS_CTRL_CR4_SHADOW, cr4.bits())?;

		self.vcpu.write_register(&Register::CR0, cr0.bits())?;
		self.vcpu.write_register(&Register::CR4, cr4.bits())?;
		self.vcpu.write_register(&Register::CR3, BOOT_PML4)?;
		self.vcpu.write_register(&Register::DR7, 0)?;
		self.vcpu.write_vmcs(VMCS_GUEST_SYSENTER_ESP, 0)?;
		self.vcpu.write_vmcs(VMCS_GUEST_SYSENTER_EIP, 0)?;

		Ok(())
	}

	fn setup_msr(&mut self) -> Result<(), xhypervisor::Error> {
		debug!("Enable MSR registers");

		self.vcpu.enable_native_msr(IA32_FS_BASE, true)?;
		self.vcpu.enable_native_msr(IA32_GS_BASE, true)?;
		self.vcpu.enable_native_msr(IA32_KERNEL_GSBASE, true)?;
		self.vcpu.enable_native_msr(IA32_SYSENTER_CS, true)?;
		self.vcpu.enable_native_msr(IA32_SYSENTER_EIP, true)?;
		self.vcpu.enable_native_msr(IA32_SYSENTER_ESP, true)?;
		self.vcpu.enable_native_msr(IA32_STAR, true)?;
		self.vcpu.enable_native_msr(IA32_LSTAR, true)?;
		self.vcpu.enable_native_msr(IA32_CSTAR, true)?;
		self.vcpu.enable_native_msr(IA32_FMASK, true)?;
		self.vcpu.enable_native_msr(TSC, true)?;
		self.vcpu.enable_native_msr(IA32_TSC_AUX, true)?;

		Ok(())
	}

	fn setup_capabilities(&mut self) -> Result<(), xhypervisor::Error> {
		debug!("Setup VMX capabilities");

		self.vcpu.write_vmcs(VMCS_CTRL_PIN_BASED, *CAP_PINBASED)?;
		debug!(
			"Pin-Based VM-Execution Controls 0x{:x}",
			self.vcpu.read_vmcs(VMCS_CTRL_PIN_BASED)?
		);
		self.vcpu.write_vmcs(VMCS_CTRL_CPU_BASED, *CAP_PROCBASED)?;
		debug!(
			"Primary Processor-Based VM-Execution Controls 0x{:x}",
			self.vcpu.read_vmcs(VMCS_CTRL_CPU_BASED)?
		);
		self.vcpu
			.write_vmcs(VMCS_CTRL_CPU_BASED2, *CAP_PROCBASED2)?;
		debug!(
			"Secondary Processor-Based VM-Execution Controls 0x{:x}",
			self.vcpu.read_vmcs(VMCS_CTRL_CPU_BASED2)?
		);
		self.vcpu
			.write_vmcs(VMCS_CTRL_VMENTRY_CONTROLS, *CAP_ENTRY)?;
		debug!(
			"VM-Entry Controls 0x{:x}",
			self.vcpu.read_vmcs(VMCS_CTRL_VMENTRY_CONTROLS)?
		);
		self.vcpu.write_vmcs(VMCS_CTRL_VMEXIT_CONTROLS, *CAP_EXIT)?;
		debug!(
			"VM-Exit Controls 0x{:x}",
			self.vcpu.read_vmcs(VMCS_CTRL_VMEXIT_CONTROLS)?
		);

		Ok(())
	}

	fn emulate_cpuid(&mut self, rip: u64) -> HypervisorResult<()> {
		let len = self.vcpu.read_vmcs(VMCS_RO_VMEXIT_INSTR_LEN)?;
		let rax = self.vcpu.read_register(&Register::RAX)?;
		let rcx = self.vcpu.read_register(&Register::RCX)?;

		match rax {
			0x80000002 => {
				// create own processor string (first part)
				let mut id_reg_values: [u32; 4] = [0; 4];
				let id = b"uhyve - unikerne";
				unsafe {
					std::ptr::copy_nonoverlapping(
						id.as_ptr(),
						id_reg_values.as_mut_ptr() as *mut u8,
						id.len(),
					);
				}

				self.vcpu
					.write_register(&Register::RAX, id_reg_values[0] as u64)?;
				self.vcpu
					.write_register(&Register::RBX, id_reg_values[1] as u64)?;
				self.vcpu
					.write_register(&Register::RCX, id_reg_values[2] as u64)?;
				self.vcpu
					.write_register(&Register::RDX, id_reg_values[3] as u64)?;
			}
			0x80000003 => {
				// create own processor string (second part)
				let mut id_reg_values: [u32; 4] = [0; 4];
				let id = b"l hypervisor\0";
				unsafe {
					std::ptr::copy_nonoverlapping(
						id.as_ptr(),
						id_reg_values.as_mut_ptr() as *mut u8,
						id.len(),
					);
				}

				self.vcpu
					.write_register(&Register::RAX, id_reg_values[0] as u64)?;
				self.vcpu
					.write_register(&Register::RBX, id_reg_values[1] as u64)?;
				self.vcpu
					.write_register(&Register::RCX, id_reg_values[2] as u64)?;
				self.vcpu
					.write_register(&Register::RDX, id_reg_values[3] as u64)?;
			}
			0x80000004 => {
				self.vcpu.write_register(&Register::RAX, 0)?;
				self.vcpu.write_register(&Register::RBX, 0)?;
				self.vcpu.write_register(&Register::RCX, 0)?;
				self.vcpu.write_register(&Register::RDX, 0)?;
			}
			_ => {
				let extended_features = (rax == 7) && (rcx == 0);
				let processor_info = rax == 1;
				let result = unsafe { __cpuid_count(rax as u32, rcx as u32) };

				let rax = result.eax as u64;
				let mut rbx = result.ebx as u64;
				let mut rcx = result.ecx as u64;
				let rdx = result.edx as u64;

				if processor_info {
					// inform that the kernel is running within a hypervisor
					rcx |= 1 << 31;
				}

				if extended_features {
					// disable SGX support
					rbx &= !(1 << 2);
				}

				self.vcpu.write_register(&Register::RAX, rax)?;
				self.vcpu.write_register(&Register::RBX, rbx)?;
				self.vcpu.write_register(&Register::RCX, rcx)?;
				self.vcpu.write_register(&Register::RDX, rdx)?;
			}
		}

		self.vcpu.write_register(&Register::RIP, rip + len)?;

		Ok(())
	}

	fn emulate_rdmsr(&mut self, rip: u64) -> HypervisorResult<()> {
		let len = self.vcpu.read_vmcs(VMCS_RO_VMEXIT_INSTR_LEN)?;
		let rcx = self.vcpu.read_register(&Register::RCX)? & 0xFFFFFFFF;

		match rcx as u32 {
			IA32_EFER => {
				let efer = self.vcpu.read_vmcs(VMCS_GUEST_IA32_EFER)?;
				let rax = efer & 0xFFFFFFFF;
				let rdx = efer >> 32;

				self.vcpu.write_register(&Register::RAX, rax)?;
				self.vcpu.write_register(&Register::RDX, rdx)?;
			}
			IA32_MISC_ENABLE => {
				self.vcpu.write_register(&Register::RAX, 0)?;
				self.vcpu.write_register(&Register::RDX, 0)?;
			}
			IA32_APIC_BASE => {
				self.vcpu
					.write_register(&Register::RAX, self.apic_base & 0xFFFFFFFF)?;
				self.vcpu
					.write_register(&Register::RDX, (self.apic_base >> 32) & 0xFFFFFFFF)?;
			}
			rcx => {
				panic!("Unable to read msr 0x{rcx:x}!")
			}
		}

		self.vcpu.write_register(&Register::RIP, rip + len)?;

		Ok(())
	}

	fn emulate_wrmsr(&mut self, rip: u64) -> HypervisorResult<()> {
		let len = self.vcpu.read_vmcs(VMCS_RO_VMEXIT_INSTR_LEN)?;
		let rcx = self.vcpu.read_register(&Register::RCX)? & 0xFFFFFFFF;

		match rcx as u32 {
			IA32_EFER => {
				let rax = self.vcpu.read_register(&Register::RAX)? & 0xFFFFFFFF;
				let rdx = self.vcpu.read_register(&Register::RDX)? & 0xFFFFFFFF;
				let efer = (rdx << 32) | rax;

				self.vcpu.write_vmcs(VMCS_GUEST_IA32_EFER, efer)?;
			}
			IA32_APIC_BASE => {
				let rax = self.vcpu.read_register(&Register::RAX)? & 0xFFFFFFFF;
				let rdx = self.vcpu.read_register(&Register::RDX)? & 0xFFFFFFFF;
				let base = (rdx << 32) | rax;

				self.apic_base = base;
				self.vcpu.set_apic_addr(base & !0xFFF)?;
			}
			IA32_X2APIC_TPR => {}
			IA32_X2APIC_SIVR => {}
			IA32_X2APIC_LVT_TIMER => {}
			IA32_X2APIC_LVT_THERMAL => {}
			IA32_X2APIC_LVT_PMI => {}
			IA32_X2APIC_LVT_LINT0 => {}
			IA32_X2APIC_LVT_LINT1 => {}
			IA32_X2APIC_LVT_ERROR => {}
			IA32_X2APIC_EOI => {}
			IA32_X2APIC_ICR => {}
			rcx => {
				panic!("Unable to write msr 0x{rcx:x}!")
			}
		}

		self.vcpu.write_register(&Register::RIP, rip + len)?;

		Ok(())
	}

	fn emulate_xsetbv(&mut self, rip: u64) -> HypervisorResult<()> {
		let len = self.vcpu.read_vmcs(VMCS_RO_VMEXIT_INSTR_LEN)?;
		let eax = self.vcpu.read_register(&Register::RAX)? & 0xFFFFFFFF;
		let edx = self.vcpu.read_register(&Register::RDX)? & 0xFFFFFFFF;
		let xcr0: u64 = (edx << 32) | eax;

		self.vcpu.write_register(&Register::XCR0, xcr0)?;
		self.vcpu.write_register(&Register::RIP, rip + len)?;

		Ok(())
	}

	fn emulate_ioapic(&mut self, rip: u64, address: u64) -> HypervisorResult<()> {
		let len = self.vcpu.read_vmcs(VMCS_RO_VMEXIT_INSTR_LEN)?;
		let qualification = self.vcpu.read_vmcs(VMCS_RO_EXIT_QUALIFIC)?;
		let read = (qualification & (1 << 0)) != 0;
		let write = (qualification & (1 << 1)) != 0;
		let code =
			unsafe { std::slice::from_raw_parts(self.host_address(rip as usize) as *const u8, 8) };

		if let Ok(instr) = disassemble_64(code, rip as usize, code.len()) {
			match instr.operation {
				InstructionOperation::MOV => {
					if write {
						let val = match instr.operands[1].operand {
							OperandType::IMM => instr.operands[1].immediate as u64,
							OperandType::REG_EDI => {
								self.vcpu.read_register(&Register::RDI)? & 0xFFFFFFFF
							}
							OperandType::REG_ESI => {
								self.vcpu.read_register(&Register::RSI)? & 0xFFFFFFFF
							}
							OperandType::REG_EBP => {
								self.vcpu.read_register(&Register::RBP)? & 0xFFFFFFFF
							}
							OperandType::REG_EAX => {
								self.vcpu.read_register(&Register::RAX)? & 0xFFFFFFFF
							}
							OperandType::REG_EBX => {
								self.vcpu.read_register(&Register::RBX)? & 0xFFFFFFFF
							}
							OperandType::REG_ECX => {
								self.vcpu.read_register(&Register::RCX)? & 0xFFFFFFFF
							}
							OperandType::REG_EDX => {
								self.vcpu.read_register(&Register::RDX)? & 0xFFFFFFFF
							}
							_ => {
								panic!("IO-APIC write failed: {:?}", instr.operands)
							}
						};

						self.ioapic
							.lock()
							.unwrap()
							.write(address - IOAPIC_BASE, val);
					}

					if read {
						let value = self.ioapic.lock().unwrap().read(address - IOAPIC_BASE);

						match instr.operands[0].operand {
							OperandType::REG_EDI => {
								self.vcpu.write_register(&Register::RDI, value)?;
							}
							OperandType::REG_ESI => {
								self.vcpu.write_register(&Register::RSI, value)?;
							}
							OperandType::REG_EBP => {
								self.vcpu.write_register(&Register::RBP, value)?;
							}
							OperandType::REG_EAX => {
								self.vcpu.write_register(&Register::RAX, value)?;
							}
							OperandType::REG_EBX => {
								self.vcpu.write_register(&Register::RBX, value)?;
							}
							OperandType::REG_ECX => {
								self.vcpu.write_register(&Register::RCX, value)?;
							}
							OperandType::REG_EDX => {
								self.vcpu.write_register(&Register::RDX, value)?;
							}
							_ => {
								panic!("IO-APIC read failed: {:?}", instr.operands)
							}
						}
					}
				}
				_ => {
					panic!("IO-APIC Emulation failed");
				}
			}
		};

		self.vcpu.write_register(&Register::RIP, rip + len)?;

		Ok(())
	}

	pub fn get_vcpu(&self) -> &xhypervisor::VirtualCpu {
		&self.vcpu
	}
}

impl VirtualCPU for UhyveCPU {
	fn init(&mut self, entry_point: u64, stack_address: u64, cpu_id: u32) -> HypervisorResult<()> {
		self.setup_capabilities()?;
		self.setup_msr()?;

		self.vcpu
			.write_vmcs(VMCS_CTRL_EXC_BITMAP, (1 << 3) | (1 << 1))?;
		self.vcpu.write_vmcs(VMCS_CTRL_TPR_THRESHOLD, 0)?;
		self.vcpu.write_vmcs(VMCS_GUEST_SYSENTER_EIP, 0)?;
		self.vcpu.write_vmcs(VMCS_GUEST_SYSENTER_ESP, 0)?;

		debug!("Setup general purpose registers");
		self.vcpu.write_register(&Register::RIP, entry_point)?;
		self.vcpu.write_register(&Register::RFLAGS, 0x2)?;
		self.vcpu.write_register(&Register::RSP, stack_address)?;
		self.vcpu.write_register(&Register::RBP, 0)?;
		self.vcpu.write_register(&Register::RAX, 0)?;
		self.vcpu.write_register(&Register::RBX, 0)?;
		self.vcpu.write_register(&Register::RCX, 0)?;
		self.vcpu.write_register(&Register::RDX, 0)?;
		self.vcpu.write_register(&Register::RSI, cpu_id.into())?;
		self.vcpu.write_register(&Register::RDI, BOOT_INFO_ADDR)?;
		self.vcpu.write_register(&Register::R8, 0)?;
		self.vcpu.write_register(&Register::R9, 0)?;
		self.vcpu.write_register(&Register::R10, 0)?;
		self.vcpu.write_register(&Register::R11, 0)?;
		self.vcpu.write_register(&Register::R12, 0)?;
		self.vcpu.write_register(&Register::R13, 0)?;
		self.vcpu.write_register(&Register::R14, 0)?;
		self.vcpu.write_register(&Register::R15, 0)?;
		self.setup_system_gdt()?;
		self.setup_system_64bit()?;

		Ok(())
	}

	fn kernel_path(&self) -> &Path {
		self.kernel_path.as_path()
	}

	fn args(&self) -> &[OsString] {
		self.args.as_slice()
	}

	fn host_address(&self, addr: usize) -> usize {
		addr + self.vm_start
	}

	fn virt_to_phys(&self, addr: usize) -> usize {
		/// Number of Offset bits of a virtual address for a 4 KiB page, which are shifted away to get its Page Frame Number (PFN).
		pub const PAGE_BITS: usize = 12;

		/// Number of bits of the index in each table (PML4, PDPT, PDT, PGT).
		pub const PAGE_MAP_BITS: usize = 9;

		let executable_disable_mask = !usize::try_from(PageTableFlags::NO_EXECUTE.bits()).unwrap();
		let mut page_table = self.host_address(BOOT_PML4 as usize) as *const usize;
		let mut page_bits = 39;
		let mut entry: usize = 0;

		for _i in 0..4 {
			let index = (addr >> page_bits) & ((1 << PAGE_MAP_BITS) - 1);
			entry = unsafe { *page_table.add(index) & executable_disable_mask };

			// bit 7 is set if this entry references a 1 GiB (PDPT) or 2 MiB (PDT) page.
			if entry & usize::try_from(PageTableFlags::HUGE_PAGE.bits()).unwrap() != 0 {
				return (entry & ((!0usize) << page_bits)) | (addr & !((!0usize) << page_bits));
			} else {
				page_table = self.host_address(entry & !((1 << PAGE_BITS) - 1)) as *const usize;
				page_bits -= PAGE_MAP_BITS;
			}
		}

		(entry & ((!0usize) << PAGE_BITS)) | (addr & !((!0usize) << PAGE_BITS))
	}

	fn r#continue(&mut self) -> HypervisorResult<VcpuStopReason> {
		loop {
			/*if self.extint_pending == true {
				let irq_info = self.vcpu.read_vmcs(VMCS_CTRL_VMENTRY_IRQ_INFO)?;
				let flags = self.vcpu.read_register(&Register::RFLAGS)?;
				let ignore_irq = self.vcpu.read_vmcs(VMCS_GUEST_IGNORE_IRQ)?;

				if ignore_irq & 1 != 1
					&& irq_info & (1 << 31) != (1 << 31)
					&& flags & (1 << 9) == (1 << 9)
				{
					// deliver timer interrupt, we don't support other kind of interrupts
					// => see table 24-15 of the Intel Manual
					let info = 0x20 | (0 << 8) | (1 << 31);
					self.vcpu.write_vmcs(VMCS_CTRL_VMENTRY_IRQ_INFO, info)?;
					self.extint_pending = false;
				}
			}*/

			self.vcpu.run()?;

			let reason = self.vcpu.read_vmcs(VMCS_RO_EXIT_REASON)? & 0xffff;
			let rip = self.vcpu.read_register(&Register::RIP)?;

			match reason {
				vmx_exit::VMX_REASON_EXC_NMI => {
					let irq_info = self.vcpu.read_vmcs(VMCS_RO_VMEXIT_IRQ_INFO)?;
					let irq_vec = irq_info & 0xFF;
					//let irq_type = (irq_info >> 8) & 0xFF;
					let valid = (irq_info & (1 << 31)) != 0;
					let trap_or_breakpoint = (irq_vec == 3) || (irq_vec == 1);

					assert!(
						valid && trap_or_breakpoint,
						"Received exception or non-maskable interrupt {irq_vec}!"
					);
					debug!("Handle breakpoint exception");
					return Ok(VcpuStopReason::Debug(()));
				}
				vmx_exit::VMX_REASON_CPUID => {
					self.emulate_cpuid(rip)?;
				}
				vmx_exit::VMX_REASON_RDMSR => {
					self.emulate_rdmsr(rip)?;
				}
				vmx_exit::VMX_REASON_WRMSR => {
					self.emulate_wrmsr(rip)?;
				}
				vmx_exit::VMX_REASON_XSETBV => {
					self.emulate_xsetbv(rip)?;
				}
				vmx_exit::VMX_REASON_IRQ => {
					trace!("Exit reason {} - External interrupt", reason);
				}
				vmx_exit::VMX_REASON_EPT_VIOLATION => {
					let gpa = self.vcpu.read_vmcs(VMCS_GUEST_PHYSICAL_ADDRESS)?;
					trace!("Exit reason {} - EPT violation at 0x{:x}", reason, gpa);

					if (IOAPIC_BASE..IOAPIC_BASE + IOAPIC_SIZE).contains(&gpa) {
						self.emulate_ioapic(rip, gpa)?;
					}
				}
				vmx_exit::VMX_REASON_RDRAND => {
					debug!("Exit reason {} - VMX_REASON_RDRAND", reason);
				}
				vmx_exit::VMX_REASON_IO => {
					let qualification = self.vcpu.read_vmcs(VMCS_RO_EXIT_QUALIFIC)?;
					let input = (qualification & 8) != 0;
					let len = self.vcpu.read_vmcs(VMCS_RO_VMEXIT_INSTR_LEN)?;
					let port: u16 = ((qualification >> 16) & 0xFFFF) as u16;

					assert!(!input, "Invalid I/O operation");

					let data_addr: u64 = self.vcpu.read_register(&Register::RAX)? & 0xFFFFFFFF;
					if let Some(hypercall) = self.port_to_hypercall(port, data_addr as usize) {
						match hypercall {
							Hypercall::Cmdsize(syssize) => self.cmdsize(syssize),
							Hypercall::Cmdval(syscmdval) => self.cmdval(syscmdval),
							Hypercall::Exit(sysexit) => {
								return Ok(VcpuStopReason::Exit(self.exit(sysexit)))
							}
							Hypercall::FileClose(sysclose) => self.close(sysclose),
							Hypercall::FileLseek(syslseek) => self.lseek(syslseek),
							Hypercall::FileOpen(sysopen) => self.open(sysopen),
							Hypercall::FileRead(sysread) => self.read(sysread),
							Hypercall::FileWrite(syswrite) => {
								// Return an error for proper handling
								self.write(syswrite).unwrap()
							}
							Hypercall::FileUnlink(sysunlink) => self.unlink(sysunlink),
							_ => panic!("Got unknown hypercall {:?}", hypercall),
						}
						self.vcpu.write_register(&Register::RIP, rip + len)?;
					} else {
						match port {
							// TODO: Deprecate (not used in Linux anyway)
							SHUTDOWN_PORT => {
								return Ok(VcpuStopReason::Exit(0));
							}
							UHYVE_UART_PORT => {
								let al = (self.vcpu.read_register(&Register::RAX)? & 0xFF) as u8;

								self.uart(&[al]).unwrap();
								self.vcpu.write_register(&Register::RIP, rip + len)?;
							}
							_ => {
								error!("Receive unhandled output command at port 0x{:x}", port);
								self.vcpu.write_register(&Register::RIP, rip + len)?;
							}
						}
					}
				}
				vmx_reason => {
					unimplemented!("{:?}", vmx_reason)
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
		println!("VMCS:");
		println!("-----");
		println!(
			"CR0: mask {:016x}  shadow {:016x}",
			self.vcpu.read_vmcs(VMCS_CTRL_CR0_MASK).unwrap(),
			self.vcpu.read_vmcs(VMCS_CTRL_CR0_SHADOW).unwrap()
		);
		println!(
			"CR4: mask {:016x}  shadow {:016x}",
			self.vcpu.read_vmcs(VMCS_CTRL_CR4_MASK).unwrap(),
			self.vcpu.read_vmcs(VMCS_CTRL_CR4_SHADOW).unwrap()
		);
		println!(
			"Pinbased: {:016x}\n1st:      {:016x}\n2nd:      {:016x}",
			self.vcpu.read_vmcs(VMCS_CTRL_PIN_BASED).unwrap(),
			self.vcpu.read_vmcs(VMCS_CTRL_CPU_BASED).unwrap(),
			self.vcpu.read_vmcs(VMCS_CTRL_CPU_BASED2).unwrap()
		);
		println!(
			"Entry:    {:016x}\nExit:     {:016x}",
			self.vcpu.read_vmcs(VMCS_CTRL_VMENTRY_CONTROLS).unwrap(),
			self.vcpu.read_vmcs(VMCS_CTRL_VMEXIT_CONTROLS).unwrap()
		);

		println!("\nRegisters:");
		println!("----------");

		let rip = self.vcpu.read_register(&Register::RIP).unwrap();
		let rflags = self.vcpu.read_register(&Register::RFLAGS).unwrap();
		let rsp = self.vcpu.read_register(&Register::RSP).unwrap();
		let rbp = self.vcpu.read_register(&Register::RBP).unwrap();
		let rax = self.vcpu.read_register(&Register::RAX).unwrap();
		let rbx = self.vcpu.read_register(&Register::RBX).unwrap();
		let rcx = self.vcpu.read_register(&Register::RCX).unwrap();
		let rdx = self.vcpu.read_register(&Register::RDX).unwrap();
		let rsi = self.vcpu.read_register(&Register::RSI).unwrap();
		let rdi = self.vcpu.read_register(&Register::RDI).unwrap();
		let r8 = self.vcpu.read_register(&Register::R8).unwrap();
		let r9 = self.vcpu.read_register(&Register::R9).unwrap();
		let r10 = self.vcpu.read_register(&Register::R10).unwrap();
		let r11 = self.vcpu.read_register(&Register::R11).unwrap();
		let r12 = self.vcpu.read_register(&Register::R12).unwrap();
		let r13 = self.vcpu.read_register(&Register::R13).unwrap();
		let r14 = self.vcpu.read_register(&Register::R14).unwrap();
		let r15 = self.vcpu.read_register(&Register::R15).unwrap();

		print!(
			"rip: {rip:016x}   rsp: {rsp:016x} flags: {rflags:016x}\n\
			rax: {rax:016x}   rbx: {rbx:016x}   rcx: {rcx:016x}\n\
			rdx: {rdx:016x}   rsi: {rsi:016x}   rdi: {rdi:016x}\n\
			rbp: {rbp:016x}    r8: {r8:016x}    r9: {r9:016x}\n\
			r10: {r10:016x}   r11: {r11:016x}   r12: {r12:016x}\n\
			r13: {r13:016x}   r14: {r14:016x}   r15: {r15:016x}\n"
		);

		let cr0 = self.vcpu.read_register(&Register::CR0).unwrap();
		let cr2 = self.vcpu.read_register(&Register::CR2).unwrap();
		let cr3 = self.vcpu.read_register(&Register::CR3).unwrap();
		let cr4 = self.vcpu.read_register(&Register::CR4).unwrap();
		let efer = self.vcpu.read_vmcs(VMCS_GUEST_IA32_EFER).unwrap();

		println!(
			"cr0: {cr0:016x}   cr2: {cr2:016x}   cr3: {cr3:016x}\ncr4: {cr4:016x}  efer: {efer:016x}"
		);

		println!("\nSegment registers:");
		println!("------------------");
		println!("register  selector  base              limit     type  p dpl db s l g avl");

		let cs = self.vcpu.read_register(&Register::CS).unwrap();
		let ds = self.vcpu.read_register(&Register::DS).unwrap();
		let es = self.vcpu.read_register(&Register::ES).unwrap();
		let ss = self.vcpu.read_register(&Register::SS).unwrap();
		let fs = self.vcpu.read_register(&Register::FS).unwrap();
		let gs = self.vcpu.read_register(&Register::GS).unwrap();
		let tr = self.vcpu.read_register(&Register::TR).unwrap();
		let ldtr = self.vcpu.read_register(&Register::LDTR).unwrap();

		let cs_limit = self.vcpu.read_vmcs(VMCS_GUEST_CS_LIMIT).unwrap();
		let cs_base = self.vcpu.read_vmcs(VMCS_GUEST_CS_BASE).unwrap();
		let cs_ar = self.vcpu.read_vmcs(VMCS_GUEST_CS_AR).unwrap();
		let ss_limit = self.vcpu.read_vmcs(VMCS_GUEST_SS_LIMIT).unwrap();
		let ss_base = self.vcpu.read_vmcs(VMCS_GUEST_SS_BASE).unwrap();
		let ss_ar = self.vcpu.read_vmcs(VMCS_GUEST_SS_AR).unwrap();
		let ds_limit = self.vcpu.read_vmcs(VMCS_GUEST_DS_LIMIT).unwrap();
		let ds_base = self.vcpu.read_vmcs(VMCS_GUEST_DS_BASE).unwrap();
		let ds_ar = self.vcpu.read_vmcs(VMCS_GUEST_DS_AR).unwrap();
		let es_limit = self.vcpu.read_vmcs(VMCS_GUEST_ES_LIMIT).unwrap();
		let es_base = self.vcpu.read_vmcs(VMCS_GUEST_ES_BASE).unwrap();
		let es_ar = self.vcpu.read_vmcs(VMCS_GUEST_ES_AR).unwrap();
		let fs_limit = self.vcpu.read_vmcs(VMCS_GUEST_FS_LIMIT).unwrap();
		let fs_base = self.vcpu.read_vmcs(VMCS_GUEST_FS_BASE).unwrap();
		let fs_ar = self.vcpu.read_vmcs(VMCS_GUEST_FS_AR).unwrap();
		let gs_limit = self.vcpu.read_vmcs(VMCS_GUEST_GS_LIMIT).unwrap();
		let gs_base = self.vcpu.read_vmcs(VMCS_GUEST_GS_BASE).unwrap();
		let gs_ar = self.vcpu.read_vmcs(VMCS_GUEST_GS_AR).unwrap();
		let tr_limit = self.vcpu.read_vmcs(VMCS_GUEST_TR_LIMIT).unwrap();
		let tr_base = self.vcpu.read_vmcs(VMCS_GUEST_TR_BASE).unwrap();
		let tr_ar = self.vcpu.read_vmcs(VMCS_GUEST_TR_AR).unwrap();
		let ldtr_limit = self.vcpu.read_vmcs(VMCS_GUEST_LDTR_LIMIT).unwrap();
		let ldtr_base = self.vcpu.read_vmcs(VMCS_GUEST_LDTR_BASE).unwrap();
		let ldtr_ar = self.vcpu.read_vmcs(VMCS_GUEST_LDTR_AR).unwrap();

		/*
		 * Format of Access Rights
		 * -----------------------
		 * 3-0 : Segment type
		 * 4   : S — Descriptor type (0 = system; 1 = code or data)
		 * 6-5 : DPL — Descriptor privilege level
		 * 7   : P — Segment present
		 * 11-8: Reserved
		 * 12  : AVL — Available for use by system software
		 * 13  : L — 64-bit mode active (for CS only)
		 * 14  : D/B — Default operation size (0 = 16-bit segment; 1 = 32-bit segment)
		 * 15  : G — Granularity
		 * 16  : Segment unusable (0 = usable; 1 = unusable)
		 *
		 * Output sequence: type p dpl db s l g avl
		 */
		println!("cs        {:04x}      {:016x}  {:08x}  {:02x}    {:x} {:x}   {:x}  {:x} {:x} {:x} {:x}",
			cs, cs_base, cs_limit, (cs_ar) & 0xf, (cs_ar >> 7) & 0x1, (cs_ar >> 5) & 0x3, (cs_ar >> 14) & 0x1,
			(cs_ar >> 4) & 0x1, (cs_ar >> 13) & 0x1, (cs_ar >> 15) & 0x1, (cs_ar >> 12) & 1);
		println!("ss        {:04x}      {:016x}  {:08x}  {:02x}    {:x} {:x}   {:x}  {:x} {:x} {:x} {:x}",
			ss, ss_base, ss_limit, (ss_ar) & 0xf, (ss_ar >> 7) & 0x1, (ss_ar >> 5) & 0x3, (ss_ar >> 14) & 0x1,
			(ss_ar >> 4) & 0x1, (ss_ar >> 13) & 0x1, (ss_ar >> 15) & 0x1, (ss_ar >> 12) & 1);
		println!("ds        {:04x}      {:016x}  {:08x}  {:02x}    {:x} {:x}   {:x}  {:x} {:x} {:x} {:x}",
			ds, ds_base, ds_limit, (ds_ar) & 0xf, (ds_ar >> 7) & 0x1, (ds_ar >> 5) & 0x3, (ds_ar >> 14) & 0x1,
			(ds_ar >> 4) & 0x1, (ds_ar >> 13) & 0x1, (ds_ar >> 15) & 0x1, (ds_ar >> 12) & 1);
		println!("es        {:04x}      {:016x}  {:08x}  {:02x}    {:x} {:x}   {:x}  {:x} {:x} {:x} {:x}",
			es, es_base, es_limit, (es_ar) & 0xf, (es_ar >> 7) & 0x1, (es_ar >> 5) & 0x3, (es_ar >> 14) & 0x1,
			(es_ar >> 4) & 0x1, (es_ar >> 13) & 0x1, (es_ar >> 15) & 0x1, (es_ar >> 12) & 1);
		println!("fs        {:04x}      {:016x}  {:08x}  {:02x}    {:x} {:x}   {:x}  {:x} {:x} {:x} {:x}",
			fs, fs_base, fs_limit, (fs_ar) & 0xf, (fs_ar >> 7) & 0x1, (fs_ar >> 5) & 0x3, (fs_ar >> 14) & 0x1,
			(fs_ar >> 4) & 0x1, (fs_ar >> 13) & 0x1, (fs_ar >> 15) & 0x1, (fs_ar >> 12) & 1);
		println!("gs        {:04x}      {:016x}  {:08x}  {:02x}    {:x} {:x}   {:x}  {:x} {:x} {:x} {:x}",
			gs, gs_base, gs_limit, (gs_ar) & 0xf, (gs_ar >> 7) & 0x1, (gs_ar >> 5) & 0x3, (gs_ar >> 14) & 0x1,
			(gs_ar >> 4) & 0x1, (gs_ar >> 13) & 0x1, (gs_ar >> 15) & 0x1, (gs_ar >> 12) & 1);
		println!("tr        {:04x}      {:016x}  {:08x}  {:02x}    {:x} {:x}   {:x}  {:x} {:x} {:x} {:x}",
			tr, tr_base, tr_limit, (tr_ar) & 0xf, (tr_ar >> 7) & 0x1, (tr_ar >> 5) & 0x3, (tr_ar >> 14) & 0x1,
			(tr_ar >> 4) & 0x1, (tr_ar >> 13) & 0x1, (tr_ar >> 15) & 0x1, (tr_ar >> 12) & 1);
		println!("ldt       {:04x}      {:016x}  {:08x}  {:02x}    {:x} {:x}   {:x}  {:x} {:x} {:x} {:x}",
			ldtr, ldtr_base, ldtr_limit, (ldtr_ar) & 0xf, (ldtr_ar >> 7) & 0x1, (ldtr_ar >> 5) & 0x3, (ldtr_ar >> 14) & 0x1,
			(ldtr_ar >> 4) & 0x1, (ldtr_ar >> 13) & 0x1, (ldtr_ar >> 15) & 0x1, (ldtr_ar >> 12) & 1);

		let gdt_base = self.vcpu.read_vmcs(VMCS_GUEST_GDTR_BASE).unwrap();
		let gdt_limit = self.vcpu.read_vmcs(VMCS_GUEST_GDTR_LIMIT).unwrap();
		println!("gdt                 {gdt_base:016x}  {gdt_limit:08x}");
		let idt_base = self.vcpu.read_vmcs(VMCS_GUEST_IDTR_BASE).unwrap();
		let idt_limit = self.vcpu.read_vmcs(VMCS_GUEST_IDTR_LIMIT).unwrap();
		println!("idt                 {idt_base:016x}  {idt_limit:08x}");
		println!(
			"VMCS link pointer   {:016x}",
			self.vcpu.read_vmcs(VMCS_GUEST_LINK_POINTER).unwrap()
		);
	}
}

impl Drop for UhyveCPU {
	fn drop(&mut self) {
		self.vcpu.destroy().unwrap();
	}
}
