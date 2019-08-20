#!/bin/bash

apt-get -qq update || exit 1
apt-get install -y --no-install-recommends binutils bsdmainutils ca-certificates cmake curl gcc git libc-dev make  rpm || exit 1
apt-get install -y --no-install-recommends libssl-dev pkg-config cmake zlib1g-dev

cargo --version # dump version of the Rust toolchain
cargo build
cargo test
