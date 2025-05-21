// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::env;

#[cfg(target_os = "hermit")]
use hermit as _;

fn main() {
	println!("Environment Test");
	for (key, value) in env::vars() {
		println!("ENVIRONMENT: {key}: {value}");
	}
}
