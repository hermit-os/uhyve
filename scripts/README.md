# Uhyve scripts

This folder contains a selection of scripts that are invoked directly
by the CI, to make local "CI-like" testing easier and reduce the time
required to make adjustments, as well as reduce vendor lock-in on particular CI
solutions (such as GitHub Actions).

The scripts are intended to be invoked from the top-level directory of the
repository and assume that a Rust toolchain is installed.

---

- [run_images.sh](./run_images.sh) runs `cargo run` for all images present under
  `data/` for the architecture of the currently running system (`uname -m`).
  When running the script in a Linux environment, we test against every possible
  `--file-isolation` parameter separately.
