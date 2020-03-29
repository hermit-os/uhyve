# uhyve - A minimal hypervisor for RustyHermit

[![crates.io](https://img.shields.io/crates/v/uhyve.svg)](https://crates.io/crates/uhyve)
![Actions Status](https://github.com/hermitcore/uhyve/workflows/Build/badge.svg)
[![Slack Status](https://radiant-ridge-95061.herokuapp.com/badge.svg)](https://radiant-ridge-95061.herokuapp.com)

## Introduction

uhyve is small hypervisor to boot the library operating systems [RustyHermit](https://github.com/hermitcore/libhermit-rs), which  is a unikernel operating system targeting a scalable and predictable runtime behavior for HPC and cloud environments. 

## Requirements

To build uhyve, it is required to install the **nightly version** of the Rust toolchain on your system.
Please visit the [Rust website](https://www.rust-lang.org/) and follow the installation instructions.

Currently, uhyve is mainly developed for Linux.
The current version works also on macOS, but it has not been tested extensively and does not support all features of the Linux version.

### Linux

On Linux, uhyve depends on the virtualization solution [KVM](https://www.linux-kvm.org/page/Main_Page) (Kernel-based Virtual Machine).
Please check, if the processor supports hardware virtualization like Intel VT-x (code name Vanderpool) and AMD-V (code name Pacifica).
To check if your system supports one of these virtualization techniques, you can use the following command.
The result greater than `0` shows that your processor supports hardware virtualization.

```sh
egrep -c '(vmx|svm)' /proc/cpuinfo
```

In addition, make sure that virtualization is enabled in the BIOS.

### macOS
Apple's *Command Line Tools* must be installed.
The Command Line Tool package gives macOS terminal users many commonly used tools and compilers, that are usually found in default Linux installations.
Following terminal command installs these tools without Apple's IDE Xcode:

```sh
$ xcode-select --install
```

Additionally, the included hypervisor bases on the [Hypervisor Framework](https://developer.apple.com/documentation/hypervisor) depending on OS X Yosemite (10.10) or newer.
To verify if your processor is able to support this framework, run and expect the following in your Terminal:

```sh
$ sysctl kern.hv_support
kern.hv_support: 1
```

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

## Running RustyHermit apps within uhyve

Use the hypervisor to start the unikernel.

```sh
$ uhyve /path_to_the_unikernel/hello_world
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

## Debugging of RustyHermit apps (unstable)

Basic support of (single-core) applications is already integrated into uhyve.
By specifying variable `HERMIT_GDB_PORT=port`, uhyve is working as gdbserver and is waiting on port `port` for a connection to a gdb.
For instance, with the following command uhyve is waiting on port `6677` for a connection.

```bash
HERMIT_GDB_PORT=6677 uhyve /path_to_the_unikernel/hello_world
```

The repository [rusty-hermit](https://github.com/hermitcore/rusty-hermit) provides [example configuration files](https://github.com/hermitcore/rusty-hermit/tree/master/.vscode) to debug a RustyHermit application with Visual Code.
In principle, if the IDE supports remote debugging with gdb, every IDE should be able to debug RustyHermit applications.

![Debugging RustyHermit apps](img/vs_code.png)

## Licensing

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
