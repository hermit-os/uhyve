//! Flattened Device Trees (FDT).

use std::{fmt::Write, ops::Range};

use uhyve_interface::GuestPhysAddr;
use vm_fdt::{FdtWriter, FdtWriterNode, FdtWriterResult};

#[cfg(target_arch = "aarch64")]
use crate::{
	consts::{
		GICD_BASE_ADDRESS, GICD_SIZE, GICR_BASE_ADDRESS, GICR_SIZE, MSI_BASE_ADDRESS, MSI_SIZE,
	},
	params::CpuCount,
};

/// A builder for an FDT.
pub struct Fdt {
	writer: FdtWriter,
	root_node: FdtWriterNode,
	kernel_args: String,
	app_args: String,
}

impl Fdt {
	/// Creates a new FDT builder.
	pub fn new() -> FdtWriterResult<Self> {
		let mut writer = FdtWriter::new()?;

		let root_node = writer.begin_node("")?;
		writer.property_string("compatible", "hermit,uhyve")?;
		writer.property_u32("#address-cells", 0x2)?;
		writer.property_u32("#size-cells", 0x2)?;

		let kernel_args = String::new();
		let app_args = String::new();

		Ok(Self {
			writer,
			root_node,
			kernel_args,
			app_args,
		})
	}

	/// Builds and returns the FDT.
	pub fn finish(mut self) -> FdtWriterResult<Vec<u8>> {
		// The bootargs have the format `[KERNEL_ARGS] -- [APP_ARGS]`
		let bootargs = match (self.kernel_args.as_str(), self.app_args.as_str()) {
			("", "") => String::new(),
			(_kernel_args, "") => self.kernel_args,
			("", app_args) => format!("-- {app_args}"),
			(kernel_args, app_args) => format!("{kernel_args} -- {app_args}"),
		};

		let chosen_node = self.writer.begin_node("chosen")?;
		self.writer.property_string("bootargs", &bootargs)?;
		self.writer.end_node(chosen_node)?;

		self.writer.end_node(self.root_node)?;

		self.writer.finish()
	}

	/// Adds a `/hermit,tsc` node to the FDT.
	pub fn tsc_khz(mut self, tsc_khz: u32) -> FdtWriterResult<Self> {
		let tsc_khz_node = self.writer.begin_node("hermit,tsc")?;
		self.writer.property_u32("khz", tsc_khz)?;
		self.writer.end_node(tsc_khz_node)?;

		Ok(self)
	}

	#[cfg(target_arch = "aarch64")]
	fn cpu(&mut self, id: u32) -> FdtWriterResult<()> {
		let node_name = format!("cpu@{}", id);

		let cpu_node = self.writer.begin_node(&node_name)?;
		self.writer
			.property_string("compatible", "arm,cortex-a72")?;
		self.writer.property_string("device_type", "cpu")?;
		self.writer.end_node(cpu_node)?;

		Ok(())
	}

	#[cfg(target_arch = "aarch64")]
	fn its(&mut self) -> FdtWriterResult<()> {
		let node_name = format!("its@{:x}", MSI_BASE_ADDRESS);
		let reg = &[MSI_BASE_ADDRESS, MSI_SIZE.try_into().unwrap()][..];

		let its_node = self.writer.begin_node(&node_name)?;
		self.writer.property_u32("#msi-cells", 0x1)?;
		self.writer.property_array_u64("reg", reg)?;
		self.writer
			.property_string("compatible", "arm,gic-v3-its")?;
		self.writer.property_string("msi-controller", "[]")?;
		self.writer.end_node(its_node)?;

		Ok(())
	}

	#[cfg(target_arch = "aarch64")]
	pub fn cpus(mut self, cpu_count: CpuCount) -> FdtWriterResult<Self> {
		let node_name = "cpus";

		let cpus_node = self.writer.begin_node(node_name)?;
		self.writer.property_u32("#address-cells", 0x1)?;
		self.writer.property_u32("#size-cells", 0x0)?;
		for i in 0..cpu_count.get() {
			self.cpu(i)?;
		}
		self.writer.end_node(cpus_node)?;

		Ok(self)
	}

	#[cfg(target_arch = "aarch64")]
	pub fn gic(mut self) -> FdtWriterResult<Self> {
		let node_name = format!("intc@{:x}", GICD_BASE_ADDRESS);
		let reg = &[
			GICD_BASE_ADDRESS,
			GICD_SIZE.try_into().unwrap(),
			GICR_BASE_ADDRESS,
			GICR_SIZE.try_into().unwrap(),
		][..];

		let gic_node = self.writer.begin_node(&node_name)?;
		self.writer.property_string("compatible", "arm,gic-v3")?;
		self.writer.property_u32("#address-cells", 0x2)?;
		self.writer.property_u32("#size-cells", 0x2)?;
		self.writer.property_array_u64("reg", reg)?;
		self.its()?;
		self.writer.end_node(gic_node)?;

		Ok(self)
	}

	/// Adds a `/memory` node to the FDT.
	pub fn memory(mut self, memory: Range<GuestPhysAddr>) -> FdtWriterResult<Self> {
		let node_name = format!("memory@{:x}", memory.start);
		let reg = &[memory.start.as_u64(), memory.end - memory.start][..];

		let memory_node = self.writer.begin_node(&node_name)?;
		self.writer.property_string("device_type", "memory")?;
		self.writer.property_array_u64("reg", reg)?;
		self.writer.end_node(memory_node)?;

		Ok(self)
	}

	/// Adds a kernel argument to the FDT.
	pub fn kernel_arg(mut self, kernel_arg: &str) -> Self {
		if !self.kernel_args.is_empty() {
			self.kernel_args.push(' ');
		}

		self.kernel_args.push_str(kernel_arg);

		self
	}

	/// Adds kernel arguments to the FDT.
	pub fn kernel_args(mut self, kernel_args: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
		for arg in kernel_args {
			self = self.kernel_arg(arg.as_ref());
		}

		self
	}

	/// Adds an environment variable to the FDT.
	pub fn env(mut self, key: &str, value: &str) -> Self {
		if !self.kernel_args.is_empty() {
			self.kernel_args.push(' ');
		}

		let key = shell_words::quote(key);
		let value = shell_words::quote(value);

		write!(&mut self.kernel_args, "env={key}={value}").unwrap();

		self
	}

	/// Adds environment variables to the FDT.
	pub fn envs(
		mut self,
		envs: impl IntoIterator<Item = (impl AsRef<str>, impl AsRef<str>)>,
	) -> Self {
		for (key, value) in envs {
			self = self.env(key.as_ref(), value.as_ref());
		}

		self
	}

	/// Adds an app argument to the FDT.
	pub fn app_arg(mut self, app_arg: &str) -> Self {
		if !self.app_args.is_empty() {
			self.app_args.push(' ');
		}

		self.app_args.push_str(app_arg);

		self
	}

	/// Adds app arguments to the FDT.
	pub fn app_args(mut self, app_args: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
		for arg in app_args {
			self = self.app_arg(arg.as_ref());
		}

		self
	}
}
