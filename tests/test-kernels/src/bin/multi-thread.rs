// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::{hint::black_box, thread, time::Instant};

#[cfg(target_os = "hermit")]
use hermit as _;

fn gauss_sum(n: u64) -> u64 {
	if n == 0 {
		return 0;
	}
	n + gauss_sum(n - 1)
}

fn main() {
	println!("Multi threading test");

	const CNT: usize = 50000;
	const NR_THREADS: usize = 4;

	let start = Instant::now();
	for _ in 0..CNT {
		let _result = black_box(gauss_sum(black_box(10000)));
	}
	let duration_single_thread = start.elapsed(); // Calculate elapsed time
	println!("Duration single thread: {duration_single_thread:?}");

	let mut threads = Vec::with_capacity(NR_THREADS);
	let start = Instant::now();
	for _ in 0..NR_THREADS {
		threads.push(thread::spawn(|| {
			for _ in 0..(CNT / NR_THREADS) {
				let _result = black_box(gauss_sum(black_box(10000)));
			}
		}));
	}
	for t in threads {
		t.join().unwrap();
	}

	let duration_multi_thread = start.elapsed(); // Calculate elapsed time
	println!("Duration mutli thread: {duration_multi_thread:?}");
	println!(
		"Speedup: {}us / {}us = {:.3}",
		duration_single_thread.as_micros(),
		duration_multi_thread.as_micros(),
		duration_single_thread.as_micros() as f64 / duration_multi_thread.as_micros() as f64
	);
}
