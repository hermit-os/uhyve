# uhyve - A minimal hypervisor for HermitCore

## Introduction

uhyve is small hypervisor to boot the library operating systems [HermitCore](https://hermitcore.org), which  is a novel unikernel operating system targeting a scalable and predictable runtime behavior for HPC and cloud environments. uhyve is tested under Linux, and Windows. The macOS is currently not finalized and currently under development.

## Requirements

### macOS
Apple's *Command Line Tools* must be installed.
The Command Line Tool package gives macOS terminal users many commonly used tools and compilers, that are usually found in default Linux installations.
Following terminal command installs these tools without Apple's IDE Xcode:

```sh
$ xcode-select --install
```

Additionally, the included hypervisor bases on the [Hypervisor Framework](https://developer.apple.com/documentation/hypervisor) depending on OS X Yosemite (10.10) or newer.
Please activate this feature as *root* by using the following command on your system:

```sh
$ sysctl kern.hv_support=1
```

### Windows

On Windows, *uhyve* bases on the [Windows Hypervisor Platform](https://docs.microsoft.com/en-us/virtualization/api/) depending on Windows 10 (build 17134 or above) or Windows Server (1803 or above).
Please activate this feature as *root* by using the following command on your system:

```sh
Dism /Online /Enable-Feature /FeatureName:HypervisorPlatform
```

### Linux
Linux users should install common developer tools.
For instance, on Ubuntu 18.04 the following command installs the required tools:

```sh
$ apt-get install -y curl wget make autotools-dev gcc g++ build-essential
```

### Common for macOS, Windows and Linux
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
$ git submodule update --init
$ make
```

## Licensing

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
