# Uhyve `data/` directory

This directory contains example unikernels and configurations that can be used with Uhyve.

- `uhyve.toml`: Example configuration file for Uhyve, also used in unit tests.
- `x86_64`: Sample unikernel images compiled for `x86_64`.
- `aarch64`: Sample unikernel images compiled for `aarch64`.

The `x86_64` unikernel images are used for CI tests.

## Sample unikernels

The unikernels under `tests/test-kernels` are continuously compiled against the latest release of the [Hermit kernel]. They aim to provide test coverage for how the kernel "reacts" to the behavior of unikernels.

In contrast, the unikernels under `data` are prebuilt binaries that are intended as "demos". The CI uses them to test runtime parameters such as `--stats` or `--file-isolation`. They are "older" on purpose; only to be updated only if a major, backwards incompatible change in the kernel takes place. Implicitly, they also test Uhyve's backwards compatibility with older versions of the kernel (that may, in turn, rely upon an older version of `uhyve-interface` as well).

### Updating the sample unikernels

The images are built from the examples of the [hermit-rs repository].

<insert concrete steps here>

For reproducibility reasons, we include the **permalink** to the source code used to compile the binary, as well as the toolchain version that we used.

### Unikernel image list

| File                      | Link                                                                                                      | Toolchain version                                                                           |
| ------------------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `data/x86_64/hello_world` | https://github.com/hermit-os/hermit-rs/tree/996086ee72178d0d463be20a5ce22a6daf81666f/examples/hello_world | rust version 1.93.0-nightly (2286e5d22 2025-11-13) (`nightly-x86_64-unknown-linux-gnu`)     |
| `data/x86_64/rusty_demo`  | https://github.com/hermit-os/hermit-rs/tree/996086ee72178d0d463be20a5ce22a6daf81666f/examples/demo        | rust version 1.93.0-nightly (2286e5d22 2025-11-13) (`nightly-x86_64-unknown-linux-gnu`)     |
| `data/x86_64/hello_c`     |                                                                                                           |                                                                                             |
| `data/aarch64/hello_world`| https://github.com/hermit-os/hermit-rs/tree/996086ee72178d0d463be20a5ce22a6daf81666f/examples/demo        | rust version 1.93.0-nightly (2286e5d22 2025-11-13) (`nightly-x86_64-unknown-linux-gnu`)     |

[Hermit kernel]: https://github.com/hermit-os/kernel
[hermit-rs repository]: https://github.com/hermit-os/hermit-rs

