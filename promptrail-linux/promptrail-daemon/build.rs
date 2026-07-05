use std::{
    env,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const EBPF_TOOLCHAIN: &str = "nightly-2026-06-15";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../promptrail-ebpf");
    println!("cargo:rerun-if-changed=../promptrail-common");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let workspace = manifest_dir.parent().unwrap();

    let ebpf_dir = workspace.join("promptrail-ebpf");
    let manifest = ebpf_dir.join("Cargo.toml");

    let status = Command::new("rustup")
        .current_dir(workspace)
        .args([
            "run",
            EBPF_TOOLCHAIN,
            "cargo",
            "build",
            "--manifest-path",
        ])
        .arg(&manifest)
        .args([
            "--release",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
        ])
        .status()?;

    if !status.success() {
        panic!("Failed to build promptrail-ebpf");
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

    let src = ebpf_dir
        .join("target")
        .join("bpfel-unknown-none")
        .join("release")
        .join("promptrail-ebpf");

    let dst = out_dir.join("promptrail-ebpf");

    if !src.exists() {
        panic!("eBPF artifact not found: {}", src.display());
    }

    fs::copy(&src, &dst)?;

    println!("cargo:warning=Copied {} -> {}", src.display(), dst.display());

    Ok(())
}