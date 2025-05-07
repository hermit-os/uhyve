use std::{
	fs::{self, File},
	io::Write,
};

#[cfg(target_os = "hermit")]
use hermit as _;

fn main() {
    println!("Hello from write_to_same_file!");

    {
        println!("Creating /root/foo.txt...");
        let mut created_file = File::create_new("/root/foo.txt").unwrap();
        created_file.write_all(b"Good morning!\n\n").unwrap();
        println!("Removing /root/foo.txt...");
        fs::remove_file("/root/foo.txt").unwrap();
    }

    {
        println!("Creating /root/foo.txt again...");
        let mut created_file = File::create_new("/root/foo.txt").unwrap();
        created_file.write_all(b"Good morning!\n\n").unwrap();
    }

    // For good measure: Testing whether the file definitely exists.
    File::create_new("/root/foo.txt").expect_err("File already exists.");
    
    let mut file1 = File::create("/root/foo.txt").unwrap();
    println!("Writing to first object...");
	file1.write_all(b"Hello, ").unwrap();

    let mut file2 = File::open("/root/foo.txt").unwrap();
    println!("Writing to second object...");
    file2.write_all(b"wonderful ").unwrap();

    let mut file3 = File::open("/root/foo.txt").unwrap();

    println!("Removing /root/foo.txt...");
    fs::remove_file("/root/foo.txt").unwrap();

    println!("Writing to third object...");
    file3.write_all(b"world!").unwrap();
}
