macro_rules! align_down {
	($value:expr, $alignment:expr) => {
		$value & !($alignment - 1)
	};
}

macro_rules! align_up {
	($value:expr, $alignment:expr) => {
		align_down!($value + ($alignment - 1), $alignment)
	};
}

macro_rules! write_data {
	($registers:expr, $address:expr, $value:expr) => {
		let iter = std::mem::size_of_val(&$value);
		for i in 0..iter {
			$registers[$address + i] = ($value >> (i * 8) & 0xFF) as u8;
		}
	};
}
