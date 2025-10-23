fn main() {
	for f in std::env::args().skip(1) {
		println!("# File {}:", f);
		let data = std::fs::read(f).expect("unable to read image file");
		let decompressed = hermit_image_reader::decompress_image(&data[..])
			.expect("unable to decompress image file");
		for i in hermit_image_reader::ImageParser::new(&decompressed[..]) {
			let i = i.expect("unable to read image entry");
			print!("  Entry ");
			let maybe_name = i.name.try_as_str();
			if let Some(name) = maybe_name {
				print!("{:?}", name);
			} else {
				print!("{:?}", i.name);
			}
			if i.is_exec {
				print!(" (executable)");
			}
			print!(" :: {:?} :: starts with: ", i.value_range);
			let value_start = &i.value[..core::cmp::min(20, i.value.len())];

			if let Ok(value_start) = str::from_utf8(value_start) {
				println!("{:?}", value_start);
			} else {
				println!("{:?}", value_start);
			}

			if let Some(name) = maybe_name {
				if name
					== hermit_image_reader::StrFilename::One(
						hermit_image_reader::config::DEFAULT_CONFIG_NAME,
					) {
					match hermit_image_reader::config::parse(i.value) {
						Ok(config) => println!("parsed config ::\n{:#?}\n", config),
						Err(e) => eprintln!("failed to parse config :: {}", e),
					}
				}
			}
		}
	}
}
