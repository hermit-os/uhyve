use std::fmt::Write;

use vm_fdt::{FdtWriter, FdtWriterNode, FdtWriterResult};

pub struct Fdt {
	writer: FdtWriter,
	root_node: FdtWriterNode,
	kernel_args: String,
	app_args: String,
}

impl Fdt {
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

	pub fn finish(mut self) -> FdtWriterResult<Vec<u8>> {
		let chosen_node = self.writer.begin_node("chosen")?;
		let bootargs = match (self.kernel_args.as_str(), self.app_args.as_str()) {
			("", "") => String::new(),
			(_kernel_args, "") => self.kernel_args,
			("", app_args) => format!("-- {app_args}"),
			(kernel_args, app_args) => format!("{kernel_args} -- {app_args}"),
		};
		self.writer.property_string("bootargs", &bootargs)?;
		self.writer.end_node(chosen_node)?;

		self.writer.end_node(self.root_node)?;

		self.writer.finish()
	}

	pub fn kernel_arg(mut self, kernel_arg: &str) -> Self {
		if !self.kernel_args.is_empty() {
			self.kernel_args.push(' ');
		}

		self.kernel_args.push_str(kernel_arg);

		self
	}

	pub fn kernel_args(mut self, kernel_args: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
		for arg in kernel_args {
			self = self.kernel_arg(arg.as_ref());
		}

		self
	}

	pub fn env(mut self, key: &str, value: &str) -> Self {
		if !self.kernel_args.is_empty() {
			self.kernel_args.push(' ');
		}

		let key = shell_words::quote(key);
		let value = shell_words::quote(value);

		write!(&mut self.kernel_args, "env={key}={value}").unwrap();

		self
	}

	pub fn envs(
		mut self,
		envs: impl IntoIterator<Item = (impl AsRef<str>, impl AsRef<str>)>,
	) -> Self {
		for (key, value) in envs {
			self = self.env(key.as_ref(), value.as_ref());
		}

		self
	}

	pub fn app_arg(mut self, app_arg: &str) -> Self {
		if !self.app_args.is_empty() {
			self.app_args.push(' ');
		}

		self.app_args.push_str(app_arg);

		self
	}

	pub fn app_args(mut self, app_args: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
		for arg in app_args {
			self = self.app_arg(arg.as_ref());
		}

		self
	}
}
