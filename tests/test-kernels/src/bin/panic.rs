// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(target_os = "hermit")]
use hermit as _;

fn main() {
	println!("This test panics");
	panic!("Aaaaaaaaargh!!!");
}
