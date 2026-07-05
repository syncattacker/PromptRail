//! Build script: compile the `promptrail-ebpf` crate into a BPF object and make
//! it available for `include_bytes_aligned!` in the daemon.
//!
//! `promptrail-ebpf` is excluded from the workspace precisely so it is NOT built
//! by the normal stable-toolchain pass. Here we drive `aya-build`, which shells
//! out to the pinned nightly (`EBPF_TOOLCHAIN`) with the correct target and
//! `-Z build-std=core`, then copies the resulting object to `OUT_DIR`.
use aya_build::{build_ebpf, Package, Toolchain};

/// MUST match the `channel` in promptrail-ebpf/rust-toolchain.toml. Kept as a
/// single constant so there is exactly one place to change the pin. If these
/// drift, the eBPF object is built with a different compiler than intended and
/// the bpf-linker/LLVM pairing guarantee is void.
const EBPF_TOOLCHAIN: &str = "nightly-2026-06-15";

fn main() -> anyhow::Result<()> {
    // Rebuild the object whenever the eBPF sources or the shared ABI change.
    println!("cargo:rerun-if-changed=../promptrail-ebpf/src");
    println!("cargo:rerun-if-changed=../promptrail-common/src");

    build_ebpf(
        [Package {
            name: "promptrail-ebpf",
            root_dir: "../promptrail-ebpf",
            no_default_features: false,
            features: &[],
        }],
        Toolchain::Custom(EBPF_TOOLCHAIN),
    )?;

    Ok(())
}
