use std::{
	env,
	hint::black_box,
	sync::{Arc, Barrier},
	thread,
};

#[cfg(target_os = "hermit")]
use hermit as _;
use rand::{SeedableRng, rngs::SmallRng, seq::SliceRandom};

const MIB: usize = 1024 * 1024;
const THREAD_STACK_SIZE: usize = 256 * 1024;
/// Estimated memory used by the kernel itself.
const KERNEL_RESERVE: usize = 20 * MIB;

/// Estimated heap size that leaves room for the kernel and `threads` thread stacks.
fn heap_budget(ram: usize, threads: usize) -> usize {
	ram - KERNEL_RESERVE - threads * THREAD_STACK_SIZE
}

/// Value of element `index` in the chunk with id `id`. Unique for ids and indices below 2^32.
fn pattern(id: usize, index: usize) -> u64 {
	((id as u64) << 32) | index as u64
}

/// Allocates a chunk of `size` bytes, where element `j` holds `pattern(id, j)`. Returns `None`
/// if the allocation fails.
fn try_alloc_chunk(size: usize, id: usize) -> Option<Vec<u64>> {
	let len = size / size_of::<u64>();
	let mut chunk = Vec::new();
	chunk.try_reserve_exact(len).ok()?;
	chunk.extend((0..len).map(|j| pattern(id, j)));
	Some(chunk)
}

/// Allocates `total / chunk_size` chunks, where chunk `i` gets the id `pattern_base + i`.
/// Panics if an allocation fails.
fn alloc_chunks(total: usize, chunk_size: usize, pattern_base: usize) -> Vec<Vec<u64>> {
	let count = total / chunk_size;
	let mut chunks = Vec::with_capacity(count);
	for i in 0..count {
		let chunk = try_alloc_chunk(chunk_size, pattern_base + i).unwrap_or_else(|| {
			panic!(
				"Allocation failed after {} of {} bytes",
				i * chunk_size,
				total
			)
		});
		chunks.push(chunk);
	}
	chunks
}

/// Checks that chunk `i` holds the pattern of id `pattern_base + i`.
fn check_chunks(chunks: &[Vec<u64>], pattern_base: usize) {
	for (i, chunk) in chunks.iter().enumerate() {
		let id = pattern_base + i;
		if let Some(j) = (0..chunk.len()).find(|&j| chunk[j] != pattern(id, j)) {
			panic!(
				"Pattern mismatch in chunk {i} at byte offset {}",
				j * size_of::<u64>()
			);
		}
	}
}

/// Spawns `threads` threads that each fill 64 KiB of their stack, wait twice at `barrier` and
/// then check their stack content. `barrier` must be shared with the caller.
fn spawn_stack_users(threads: usize, barrier: &Arc<Barrier>) -> Vec<thread::JoinHandle<()>> {
	(0..threads)
		.map(|_| {
			let barrier = barrier.clone();
			thread::Builder::new()
				.stack_size(THREAD_STACK_SIZE)
				.spawn(move || {
					let mut stack = [0u64; 64 * 1024 / size_of::<u64>()];
					for (i, x) in stack.iter_mut().enumerate() {
						*x = i as u64;
					}
					barrier.wait();
					barrier.wait();
					assert!(
						black_box(&stack)
							.iter()
							.enumerate()
							.all(|(i, &x)| x == i as u64),
						"Stack content corrupted"
					);
				})
				.expect("Unable to spawn thread")
		})
		.collect()
}

/// Fills the [`heap_budget`] with heap allocations, then spawns `threads`
/// threads to validate their stack allocations work. Repeats the spawning
/// to check that the stacks of finished threads are reused.
fn heap_then_stacks(ram: usize, threads: usize) {
	let chunks = alloc_chunks(heap_budget(ram, threads), MIB, 1);
	let barrier = Arc::new(Barrier::new(threads + 1));
	for _ in 0..2 {
		let handles = spawn_stack_users(threads, &barrier);
		// All threads are running with their stacks in use.
		barrier.wait();
		check_chunks(&chunks, 1);
		barrier.wait();
		for h in handles {
			h.join().unwrap();
		}
	}
}

/// Counterpart to [`heap_then_stacks`]: Keeps `threads` threads alive while
/// filling the [`heap_budget`] with heap allocations. Afterwards, spawns the threads again
/// while the heap is still filled, to check that the stacks of finished threads are reused.
fn stacks_then_heap(ram: usize, threads: usize) {
	let barrier = Arc::new(Barrier::new(threads + 1));
	let handles = spawn_stack_users(threads, &barrier);
	// All threads are running with their stacks in use.
	barrier.wait();
	let chunks = alloc_chunks(heap_budget(ram, threads), MIB, 2);
	check_chunks(&chunks, 2);
	barrier.wait();
	for h in handles {
		h.join().unwrap();
	}

	let handles = spawn_stack_users(threads, &barrier);
	barrier.wait();
	check_chunks(&chunks, 2);
	barrier.wait();
	for h in handles {
		h.join().unwrap();
	}
}

/// Repeatedly doubles a vector, starting at 1 MiB, then grows it once more into the remaining
/// [`heap_budget`]. Checks after each reallocation that the content survived.
fn realloc_growth(ram: usize) {
	let budget = heap_budget(ram, 0);
	/// Returns the number of freed bytes, if the vector was moved.
	fn grow(v: &mut Vec<u64>, new_len: usize) -> usize {
		let len = v.len();
		let old_ptr = v.as_ptr();
		let old_size = v.capacity() * size_of::<u64>();
		v.reserve_exact(new_len - len);
		assert!(
			v.iter().enumerate().all(|(i, &x)| x == i as u64),
			"Content lost when growing to {} MiB",
			new_len * size_of::<u64>() / MIB
		);
		v.extend(len as u64..new_len as u64);
		if v.as_ptr() == old_ptr { 0 } else { old_size }
	}

	let mut v: Vec<u64> = (0..(MIB / size_of::<u64>()) as u64).collect();
	// Without growing in place, the heap holds the freed previous buffers (~1x), the current
	// buffer (1x) and the new one (2x).
	// The freed buffers are too small for reuse in this setting:
	// | 1 | 2 | 4 | 8 | 16 |        32        |    free ...   |
	// |    freed: 31 MiB   |     current      | next (64 MiB) |

	let mut freed = 0;
	while 4 * size_of_val(v.as_slice()) <= budget {
		let new_len = 2 * v.len();
		println!("Growing vec to {} MiB", new_len * size_of::<u64>() / MIB);
		freed += grow(&mut v, new_len);
	}
	// Fill up rm
	let last_len = budget.saturating_sub(2 * size_of_val(v.as_slice())) / size_of::<u64>();
	if last_len > v.len() {
		println!(
			"Growing vec by remaining {} KiB",
			(last_len - v.len()) * size_of::<u64>() / 1024
		);
		freed += grow(&mut v, last_len);
	}
	println!("Vec final size: {} KiB", size_of_val(v.as_slice()) / 1024);

	// The freed buffers are reusable.
	println!("Allocating a new vec with {} KiB", freed / 1024);
	let chunk = try_alloc_chunk(freed, 0)
		.unwrap_or_else(|| panic!("Unable to reuse {} MiB of freed buffers", freed / MIB));
	let v_size = size_of_val(v.as_slice());
	let chunk_size = size_of_val(chunk.as_slice());
	println!(
		"Allocated two vecs with {} KiB + {} KiB = {} MiB",
		v_size / 1024,
		chunk_size / 1024,
		(v_size + chunk_size) as f64 / MIB as f64
	);
	check_chunks(&[chunk], 0);
	println!("Success");
}

/// In three rounds, `threads` threads concurrently allocate a quarter of the RAM in total. The
/// chunks are checked once all threads hold their allocations.
fn concurrent_growth(ram: usize, nr_threads: usize) {
	const CHUNK: usize = 256 * 1024;
	let per_thread = ram / (4 * nr_threads);
	for round in 0..3 {
		let barrier = Arc::new(Barrier::new(nr_threads));
		let handles: Vec<_> = (0..nr_threads)
			.map(|t| {
				let barrier = barrier.clone();
				thread::spawn(move || {
					let pattern_base = (round * nr_threads + t) * (per_thread / CHUNK);
					barrier.wait();
					let chunks = alloc_chunks(per_thread, CHUNK, pattern_base);
					barrier.wait();
					check_chunks(&chunks, pattern_base);
				})
			})
			.collect();
		for h in handles {
			h.join().unwrap();
		}
	}
}

/// Allocates a single contiguous buffer of half the RAM and verifies it.
fn fill_verify(ram: usize) {
	let memory = try_alloc_chunk(ram / 2, 0)
		.unwrap_or_else(|| panic!("Unable to allocate {} MiB", ram / 2 / MIB));
	check_chunks(&[memory], 0);
}

/// Alternately allocates large and small blocks until the heap is exhausted. Whenever a large
/// block no longer fits, the large size is halved, so the remaining memory is used up as well.
fn mixed_sizes(ram: usize) {
	const SMALL_SIZES: [usize; 4] = [16, 100, 512, 4000];
	const MIN_LARGE: usize = 64 * 1024;
	let mut large = 4 * MIB;
	let mut blocks: Vec<Vec<u64>> = Vec::new();
	loop {
		if blocks.try_reserve(2).is_err() {
			break;
		}
		let Some(block) = try_alloc_chunk(large, blocks.len()) else {
			println!("no space left for large chunk of size {large}");
			if large <= MIN_LARGE {
				break;
			}
			large /= 2;
			continue;
		};
		println!("allocated large chunk of size {large}");
		blocks.push(block);
		let small = SMALL_SIZES[blocks.len() % SMALL_SIZES.len()];
		let Some(block) = try_alloc_chunk(small, blocks.len()) else {
			println!("no space left for small chunk of size {small}");
			break;
		};
		println!("allocated small chunk of size {small}");
		blocks.push(block);
	}

	let used: usize = blocks.iter().map(|b| size_of_val(b.as_slice())).sum();
	println!("Allocated {} MiB in {} blocks", used / MIB, blocks.len());
	assert!(used >= ram / 2, "Only {} MiB allocated", used / MIB);
	check_chunks(&blocks, 0);
}

/// Pushes chunks into `chunks` until the heap is exhausted, without growing `chunks` beyond its
/// capacity.
/// Afterwards, at least `HEAP_RESERVE` bytes are freed again, to permit kernel allocations.
/// Chunk `i` gets the id `pattern_base + i`.
/// Returns the number of allocated bytes.
fn fill_heap(chunks: &mut Vec<Vec<u64>>, max_size: usize, pattern_base: usize) -> usize {
	const HEAP_RESERVE: usize = 64 * 1024;
	let mut size = max_size;
	let mut total = 0;
	while chunks.len() < chunks.capacity() && size >= size_of::<u64>() {
		match try_alloc_chunk(size, pattern_base + chunks.len()) {
			Some(chunk) => {
				chunks.push(chunk);
				total += size;
			}
			None => size /= 2,
		}
	}
	assert!(
		chunks.len() < chunks.capacity(),
		"Chunk list too small to fill the heap"
	);
	let mut freed = 0;
	while freed < HEAP_RESERVE
		&& let Some(chunk) = chunks.pop()
	{
		freed += size_of_val(chunk.as_slice());
	}
	total - freed
}

/// Fills the whole heap with chunks, frees them in random order and fills the heap again,
/// expecting at least the same amount of memory to be available.
fn random_free(ram: usize) {
	const CHUNK: usize = 64 * 1024;
	// remainder of the ram get's filled with smaller chunks, so we account for these extra chunks.
	let max_chunks = ram / CHUNK + (CHUNK / size_of::<u64>()).ilog2() as usize;
	let mut chunks = Vec::with_capacity(max_chunks);
	let allocated = fill_heap(&mut chunks, CHUNK, 0);
	let count = chunks.len();
	println!("Allocated {} KiB in {count} chunks", allocated / 1024);
	check_chunks(&chunks, 0);

	// Deallocate in (reproducible) shuffled order.
	chunks.shuffle(&mut SmallRng::seed_from_u64(0x1234));
	let mut i = 0;
	while let Some(chunk) = chunks.pop() {
		println!("{}/{count}: dropping chunk {}", i + 1, chunk[0] >> 32);
		drop(chunk);
		i += 1;
	}

	// New ids, so stale data from the first round doesn't match.
	let reallocated = fill_heap(&mut chunks, CHUNK, count);
	check_chunks(&chunks, count);
	assert!(
		reallocated >= allocated,
		"Only {} of {} KiB could be reallocated",
		reallocated / 1024,
		allocated / 1024
	);
}

/// Allocates 1 MiB chunks without touching them until an allocation fails.
fn oom(ram: usize) {
	let mut chunks: Vec<Vec<u8>> = Vec::with_capacity(2 * ram / MIB);
	loop {
		let mut chunk = Vec::<u8>::new();
		if let Err(e) = chunk.try_reserve_exact(MIB) {
			println!("Allocation failed after {} MiB: {e}", chunks.len());
			break;
		}
		chunks.push(chunk);
	}
}

/// Expects the arguments `testname=<scenario> ram_mib=<VM memory size> threads=<n>`.
fn main() {
	let args: Vec<String> = env::args().collect();
	let arg_value = |i: usize| args[i].split_once('=').unwrap().1;
	let scenario = arg_value(1);
	let ram = arg_value(2).parse::<usize>().unwrap() * MIB;
	let threads = arg_value(3).parse::<usize>().unwrap();
	println!(
		"Memory test - {scenario} with {} MiB RAM, {threads} threads",
		ram / MIB
	);

	match scenario {
		"heap_then_stacks" => heap_then_stacks(ram, threads),
		"stacks_then_heap" => stacks_then_heap(ram, threads),
		"realloc_growth" => realloc_growth(ram),
		"concurrent_growth" => concurrent_growth(ram, threads),
		"fill_verify" => fill_verify(ram),
		"mixed_sizes" => mixed_sizes(ram),
		"random_free" => random_free(ram),
		"oom" => oom(ram),
		_ => panic!("scenario {scenario} not found"),
	}
	println!("memory: {scenario} done");
}
