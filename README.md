<img width="200" align="right" src="img/uhyve.svg" />

# Uhyve

[![crates.io](https://img.shields.io/crates/v/uhyve.svg)](https://crates.io/crates/uhyve)
[![Zulip Badge](https://img.shields.io/badge/chat-hermit-57A37C?logo=zulip)](https://hermit.zulipchat.com/)

Uhyve is a minimal, special-purpose hypervisor for the [Hermit kernel](https://github.com/hermit-os/kernel).

## Installation

1. Install the Rust toolchain. The Rust Foundation provides [installation instructions](https://www.rust-lang.org/tools/install).
2. Install Uhyve:

```sh
cargo install --locked uhyve
```

## Requirements

### Linux

To check if your system supports virtualization, you can use the following command:

```sh
if egrep -c '(vmx|svm)' /proc/cpuinfo > /dev/null; then echo "Virtualization support found"; fi
```

Uhyve on Linux depends on the virtualization solution [KVM (Kernel-based Virtual Machine)](https://www.linux-kvm.org/page/Main_Page).
If the following command gives you some output, you are ready to go!

```sh
lsmod | grep kvm
```

> [!NOTE]
> If the above steps don't work, make sure that you have enabled virtualization in your UEFI/BIOS settings.

### macOS

> [!WARNING]
> Currently, Uhyve is mainly developed for Linux.
> The macOS version has not been tested extensively and does not support all features of the Linux version.

You can install Apple's [Xcode Command Line Tools](https://developer.apple.com/xcode/resources) using the following command:

```sh
xcode-select --install
```

Additionally, the included hypervisor bases on the [Hypervisor Framework](https://developer.apple.com/documentation/hypervisor) depending on OS X Yosemite (10.10) or newer.

To verify if your processor is able to support this framework, run the following in your Terminal:

```sh
sysctl kern.hv_support
```

The output `kern.hv_support: 1` indicates virtualization support.

Starting with Big Sur, all processes using the Hypervisor API must have the [com.apple.security.hypervisor](https://developer.apple.com/documentation/Hypervisor) entitlement and therefore must be signed.

## Building from source

To build from source, simply checkout the code and use `cargo build`:

```sh
git clone https://github.com/hermit-os/uhyve.git
cd uhyve
cargo build --release
```

### macOS Big Sur: Signing Uhyve

`uhyve` can be self-signed using the following command:

```sh
codesign -s - --entitlements app.entitlements --force path_to_uhyve/uhyve
```

The file `app.entitlements` must have following content:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.hypervisor</key>
    <true/>
</dict>
</plist>
```

For further information, please consult [Apple's Documentation](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_hypervisor).

## Usage

Assuming that you have **installed** Uhyve, run the hypervisor to start the unikernel:

```sh
uhyve /path/to/the/unikernel/binary
```

> [!NOTE]
> This repository ships a few binaries that can be used for testing.
>
> If you want to compile Hermit binaries yourself (or create your own), take a look at the following repositories:
> - [hermit-os/hermit-rs](https://github.com/hermit-os/hermit-rs)
> - [hermit-os/hermit-rs-template](https://github.com/hermit-os/hermit-rs-template)
> - [hermit-os/hermit-playground](https://github.com/hermit-os/hermit-playground)

### Configuration

Uhyve can be configured using command line arguments and environment variables.
This example launches a virtual machine with 4 GiB of memory and 4 cores:

```bash
uhyve -m 4GiB -c 4 path/to/unikernel
```

For more options, the default values, and the corresponding environment variables run:

```bash
uhyve --help
```

### Contributing

If you are interested in contributing to Uhyve, make sure to check out the [Uhyve wiki][uhyve-wiki]!

Our wiki contains instructions on working with Uhyve's source code, including setting up a suitable
development environment, as well as profiling, testing and debugging Uhyve.

[uhyve-wiki]: https://github.com/hermit-os/uhyve/wiki

### Known issues

 * Uhyve isn't able to pass more than 128 environment variables to the unikernel.

## Licensing

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

