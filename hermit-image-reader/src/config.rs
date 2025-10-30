use alloc::{string::String, vec::Vec};

pub const DEFAULT_CONFIG_NAME: &str = "hermit_config.toml";
pub type ParserError = toml::de::Error;

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
/// The image `hermit_config.toml` config file format.
///
/// All file paths are relative to the iamge root.
pub struct Config {
	pub input: Input,
	pub requirements: Requirements,

	pub kernel: String,
	pub mount_point: String,
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Input {
	/// Arguments to be passed to the kernel
	pub kernel_args: Vec<String>,

	/// Arguments to be passed to the application
	pub app_args: Vec<String>,

	/// Environment variables
	pub env_vars: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Requirements {
	pub memory: Option<byte_unit::Byte>,

	#[serde(default)]
	pub cpus: u32,
}

#[inline]
pub fn parse(data: &[u8]) -> Result<Config, ParserError> {
	toml::from_slice(data)
}
