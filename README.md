# uhyve - A minimal hypervisor for RustyHermit

[![crates.io](https://img.shields.io/crates/v/uhyve.svg)](https://crates.io/crates/uhyve)
![Actions Status](https://github.com/hermitcore/uhyve/workflows/Build/badge.svg)
[![Slack Status](https://radiant-ridge-95061.herokuapp.com/badge.svg)](https://radiant-ridge-95061.herokuapp.com)

## Introduction

uhyve is small hypervisor to boot the library operating systems [RustyHermit](https://github.com/hermitcore/libhermit-rs), which  is a unikernel operating system targeting a scalable and predictable runtime behavior for HPC and cloud environments.

## Installation

To build uhyve, it is required to install the **nightly version** of the Rust toolchain on your system.
Please visit the [Rust website](https://www.rust-lang.org/) and follow the installation instructions.

```sh
rustup default nightly #change the Rust Compiler Toolchain to 'nightly'
cargo install uhyve # Install latest published version from crates.io
```

## Requirements

### Linux

To check if your system supports virtualization, you can use the following command:

```sh
if egrep -c '(vmx|svm)' /proc/cpuinfo > /dev/null; then echo "Virualization support found"; fi
```

On Linux, uhyve depends on the virtualization solution [KVM](https://www.linux-kvm.org/page/Main_Page) (Kernel-based Virtual Machine).
If the following command gives you some output, you are ready to go!

```sh
lsmod | grep kvm
```

### macOS

**Disclaimer:** Currently, uhyve is mainly developed for Linux.
The macOS version has not been tested extensively and does not support all features of the Linux version.

Apple's *Command Line Tools* must be installed.
The following terminal command installs these tools *without* Apple's IDE Xcode:

```sh
xcode-select --install
```

Additionally, the included hypervisor bases on the [Hypervisor Framework](https://developer.apple.com/documentation/hypervisor) depending on OS X Yosemite (10.10) or newer.
To verify if your processor is able to support this framework, run the following in your Terminal:

```sh
sysctl kern.hv_support
```

The output `kern.hv_support: 1` indicates virtualization support.

## Building from source

To build from souce, simply checkout the code and use `cargo build`.

```sh
git clone https://github.com/hermitcore/uhyve.git
cd uhyve
cargo build --release
```

## Running RustyHermit apps within uhyve

Use the hypervisor to start the unikernel.
```sh
uhyve /path/to/the/unikernel/binary
```

### Configuration

uhyve can be configured via environment variables.
The following variables are supported.

- `HERMIT_CPUS`: specifies the number of cores the virtual machine may use.
- `HERMIT_MEM`: defines the memory size of the virtual machine. The suffixes *M* and *G* can be used to specify a value in megabytes or gigabytes, respectively.
- setting `HERMIT_VERBOSE` to `1` makes the hypervisor print kernel log messages to the terminal.
- `HERMIT_GDB_PORT=port` activate a gdb server for the application running inside uhyve. _See below_

By default, the loader initializes a system with one core and 512 MiB RAM.

**Example:** the following command starts the demo application in a virtual machine, which has 4 cores and 8GiB memory:

```bash
HERMIT_CPUS=4 HERMIT_MEM=8G uhyve /path/to/the/unikernel/binary
```

## Debugging of RustyHermit apps (unstable)

Basic support of (single-core) applications is already integrated into uhyve.
By specifying variable `HERMIT_GDB_PORT=port`, uhyve is working as gdbserver and is waiting on port `port` for a connection to a gdb.
For instance, with the following command uhyve is waiting on port `6677` for a connection.

```bash
HERMIT_GDB_PORT=6677 uhyve /path_to_the_unikernel/hello_world
```

In principle, every gdb-capable IDE should be able to debug RustyHermit applications. (Eclipse, VSCode, ...)

The repository [rusty-hermit](https://github.com/hermitcore/rusty-hermit) provides [example configuration files](https://github.com/hermitcore/rusty-hermit/tree/master/.vscode) to debug a RustyHermit application with Visual Code.

![Debugging RustyHermit apps](img/vs_code.png)

## Licensing

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
