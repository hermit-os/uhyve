<img width="200" align="right" src="https://raw.githubusercontent.com/hermit-os/uhyve/f4070692729c5f1fa1dbf6df67004acbfef39104/img/uhyve.svg" />

# Uhyve Hypercall Interface
[![crates.io](https://img.shields.io/crates/v/uhyve.svg)](https://crates.io/crates/uhyve)

This crate specifies the interface between the [Hermit Unikernel](https://github.com/hermit-os/kernel) and the hypervisor [Uhyve](https://github.com/hermit-os/uhyve).
It includes the definition of the hypercalls and hypercall parameters and is intended to be used in both projects to ensure a coherent and well defined interface.
