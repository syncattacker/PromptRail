use std::path::PathBuf;
use aya_build::{build_ebpf, Package, Toolchain};

const EBPF_TOOLCHAIN: &str = "nightly-2026-06-15";

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=../promptrail-ebpf/src");
    println!("cargo:rerun-if-changed=../promptrail-common/src");

    // Resolve the eBPF crate's manifest relative to THIS build script, so the
    // path is correct regardless of where cargo is invoked from.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ebpf_manifest = manifest_dir.join("../promptrail-ebpf/Cargo.toml");

    build_ebpf(
        [Package {
            name: "promptrail-ebpf",
            manifest_path: ebpf_manifest,        // ← anchor to the crate's own workspace
            root_dir: "../promptrail-ebpf".into(),
            no_default_features: false,
            features: &[],
        }],
        Toolchain::Custom(EBPF_TOOLCHAIN),
    )?;

    Ok(())
}