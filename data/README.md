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

The images are built from the examples of the [hermit-rs repository] (`hello_world`, `rusty_demo` in the `examples` folder)
and [hermit-c repository] (`src/hello_world.c`).

1. Adjust `uhyve-interface` and push to a remote tree, modify local `kernel` tree's `Cargo.toml` to use updated `uhyve-interface` version, adjust the kernel and implement all the necessary changes (to `uhyve-interface` and Uhyve itself). Some further modifications might be required to:
   - Hypercall-handling functions called by `r#continue`/creating a new function
   - Serial port
   - `src/stats.rs` (so that we can maintain statistics of how many hypercalls were called for a given run)
   - Pay attention to memory range-related changes and ASLR.

   It is standard practice to maintain backwards compatibility with older versions, primarily by "translating" 'old structs' into 'new structs'.
   Such an example can be found here: https://github.com/hermit-os/uhyve/blob/c5d573701e479e4ae1c8974bec80742ee928cff0/src/hypercall.rs#L425-L448

   If the integration tests pass, assuming that a kernel version that does not contain your `uhyve-interface`-related modifications is used, you're most likely good to go.
   Normally, Uhyve's CI pipelines should be a sufficient indicator that everything's working as it's supposed to.

2. If necessary, e.g. due to a backwards incompatible change, modify `tests/test-kernels/Cargo.toml` to use a local tree of `hermit-rs`.

3.
   ```
   cd tests/test-kernels
   HERMIT_MANIFEST_DIR=/path/to/modified/kernel cargo build -Zbuild-std=std,panic_abort --target=$(uname -m)-unknown-hermit
   ```
   Draft pull requests can use the draft `uhyve-interface` changes by [overriding dependencies](https://doc.rust-lang.org/cargo/reference/overriding-dependencies.html) (e.g. `[patch.crates-io]`).

4. Repeat the previous steps as necessary until all of Uhyve's test cases pass.

5. Build new test cases that accommodate potentially new hypercalls, confirm that they work.

6. Merge `uhyve-interface` changes to Uhyve tree, publish a new version of the crate on `crates.io`.

7. If you have submitted any draft pull requests to the `kernel` tree, remove the `override`s from `Cargo.toml` and update `Cargo.lock`.
   Your `kernel` PR should be nearly ready.

8. Confirm, again, that Uhyve's tests pass locally; such tests are not run when submitting PRs to the `kernel`.
   For good measure, confirm that this is the case on other targets as well.
   Share results on the pull request to the `kernel`.

9. Your `kernel` pull request should be ready to merge (as long as all tests pass).
   If feasible, wait for a new release after it is merged.

10. Adjust `test-kernels` to use a version of Hermit that bundles a kernel with the newly merged `uhyve-interface` modifications.

11. Build new Hermit unikernel images from the examples of the [hermit-rs repository] (`hello_world`, `rusty_demo` in the `examples` folder)
and [hermit-c repository] (`src/hello_world.c`), as described in step 3 above.
   Then, copy the resulting binaries into `data/${HERMIT_KERNEL_VERSION}/$(uname -m)`, whereas
   `HERMIT_KERNEL_VERSION="$(cargo metadata -m "$HERMIT_MANIFEST_DIR/Cargo.toml" --format-version 1 | jq -r '.workspace_members | map(select(contains("hermit-kernel@")) | split("@")[1])[0]')"`

For reproducibility reasons, we include the **permalink** to the source code used to compile the binary, as well as the toolchain version that we used.

### Unikernel image list

| File                              | Link                                                                                                           | Toolchain version                                                                          |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `data/0.6.0/x86_64/hello_world`   | https://github.com/hermit-os/hermit-rs/tree/996086ee72178d0d463be20a5ce22a6daf81666f/examples/hello_world      | rust version 1.93.0-nightly (2286e5d22 2025-11-13) (`nightly-x86_64-unknown-linux-gnu`)    |
| `data/0.6.0/x86_64/rusty_demo`    | https://github.com/hermit-os/hermit-rs/tree/996086ee72178d0d463be20a5ce22a6daf81666f/examples/demo             | rust version 1.93.0-nightly (2286e5d22 2025-11-13) (`nightly-x86_64-unknown-linux-gnu`)    |
| `data/0.6.0/x86_64/hello_c`       | https://github.com/hermit-os/hermit-playground/blob/b9ce9ae534972b014ad04d32349656c6c47b642b/usr/tests/hello.c |                                                                                            |
| `data/0.11.0/aarch64/hello_world` | https://github.com/hermit-os/hermit-rs/tree/996086ee72178d0d463be20a5ce22a6daf81666f/examples/demo             | rust version 1.93.0-nightly (2286e5d22 2025-11-13) (`nightly-x86_64-unknown-linux-gnu`)    |

[Hermit kernel]: https://github.com/hermit-os/kernel
[hermit-c repository]: https://github.com/hermit-os/hermit-c
[hermit-rs repository]: https://github.com/hermit-os/hermit-rs
