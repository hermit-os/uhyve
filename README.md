# ehyve - A minimal hypervisor for eduOS-rs

[![Build Status](https://travis-ci.org/RWTH-OS/ehyve.svg?branch=master)](https://travis-ci.org/RWTH-OS/ehyve)

## Introduction

ehyve is small hypervisor to boot the operating systems [eduOS-rs](https://github.com/RWTH-OS/eduOS-rs), which is a Unix-like operating system based on a monolithic architecture for educational purposes. ehyve is tested under Linux, and Windows. The macOS is currently not finalized and currently under development.

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
To build eduOS-rs you have to install a linker, [make](http://gnuwin32.sourceforge.net/packages/make.htm) and a [git client](https://git-scm.com/downloads).
We tested the eduOS-rs with the linker from Visual Studio.
Consequently, we suggest installing Visual Studio in addition to [make](http://gnuwin32.sourceforge.net/packages/make.htm) and [git](https://git-scm.com/downloads).

Furthermore, the included hypervisor bases on the [Windows Hypervisor Platform](https://docs.microsoft.com/en-us/virtualization/api/) depending on Windows 10 (build 17134 or above) or Windows Server (1803 or above).
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
It is important that the *nightly channel* is used to install the toolchain.
This is queried during installation and should be answered as appropriate.

Afterwards the installation of *cargo-xbuild* and the source code of Rust runtime are required to build the kernel:

```sh
$ cargo install cargo-xbuild
$ rustup component add rust-src
```

## Building
The final step is to create a copy of the repository and to build the kernel:

```sh
$ # Get our source code.
$ git clone git@github.com:RWTH-OS/ehyve.git
$ cd ehyve

$ # Get a copy of the Rust source code so we can rebuild core
$ # for a bare-metal target.
$ git submodule update --init
$ make
```

## Licensing

ehyve is licensed under the [MIT license][LICENSE-MIT].

[LICENSE-MIT]: http://opensource.org/licenses/MIT
