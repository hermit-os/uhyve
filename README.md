# uhyve - A minimal hypervisor for RustyHermit

## Introduction

uhyve is small hypervisor to boot the library operating systems [RustyHermit](https://github.com/hermitcore/libhermit-rs), which  is a unikernel operating system targeting a scalable and predictable runtime behavior for HPC and cloud environments. 

## Requirements

It is required to install the Rust toolchain.
Please visit the [Rust website](https://www.rust-lang.org/) and follow the installation instructions for your operating system.

## Building
The final step is to create a copy of the repository and to build the kernel:

```sh
$ # Get our source code.
$ git clone git@github.com:hermitcore/uhyve.git
$ cd uhyve

$ # Get a copy of the Rust source code so we can rebuild core
$ # for a bare-metal target.
$ cargo build
```

Use the hypervisor to start the unikernel.

```sh
$ ./uhyve /path_to_the_unikernel/hello_world
```

There are two environment variables to modify the virtual machine:
The variable `HERMIT_CPUS` specifies the number of cores the virtual machine may use.
The variable `HERMIT_MEM` defines the memory size of the virtual machine. The suffixes *M* and *G* can be used to specify a value in megabytes or gigabytes, respectively.
By default, the loader initializes a system with one core and 512 MiB RAM.
For instance, the following command starts the demo application in a virtual machine, which has 4 cores and 8GiB memory:

```bash
$ HERMIT_CPUS=4 HERMIT_MEM=8G uhyve /path_to_the_unikernel/hello_world
```

Setting the environment variable `HERMIT_VERBOSE` to `1` makes the hypervisor print kernel log messages to the terminal.

```bash
$ HERMIT_VERBOSE=1 uhyve /path_to_the_unikernel/hello_world
```

## Licensing

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
