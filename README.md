# uhyve - A minimal hypervisor for RustyHermit

[![crates.io](https://img.shields.io/crates/v/uhyve.svg)](https://crates.io/crates/uhyve)
[![Slack Status](https://matrix.osbyexample.com:3008/badge.svg)](https://matrix.osbyexample.com:3008)

## Introduction

uhyve is small hypervisor to boot the library operating systems [RustyHermit](https://github.com/hermitcore/libhermit-rs), which  is a unikernel operating system targeting a scalable and predictable runtime behavior for HPC and cloud environments.

## Installation

An installation of the Rust toolchain is required.
Please visit the [Rust website](https://www.rust-lang.org/) and follow the installation instructions.
The project can then be installed with the following command:

```sh
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

**NOTE:** If in case the above steps don't work, make sure to check in your BIOS settings that virtualization is enabled there.

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

Startinhg with Big Sur, all processes using the Hypervisor API must have the [com.apple.security.hypervisor](https://developer.apple.com/documentation/Hypervisor) entitlement and therefor must be signed.

## Building from source

To build from souce, simply checkout the code and use `cargo build`.

```sh
git clone https://github.com/hermitcore/uhyve.git
cd uhyve
cargo build --release
```

## Signing uhyve to run on macOS Big Sur

`uhyve` can be self-signed with the following command.

```sh
codesign -s - --entitlements app.entitlements --force path_to_uhyve/uhyve
```

The file `app.entitlements` must have following content:

```sh
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.hypervisor</key>
    <true/>
</dict>
</plist>
```

For further details have a look at [Apple's documentation](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_hypervisor).

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

## Known issues

 * Uhyve isn't able to pass more than 128 environment variables to the unikernel

## Licensing

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
