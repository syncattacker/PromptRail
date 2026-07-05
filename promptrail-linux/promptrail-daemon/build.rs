use std::{
    env,
    fs,
    path::PathBuf,
    process::Command,
};

const EBPF_TOOLCHAIN: &str = "nightly-2026-06-15";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../promptrail-ebpf/src");
    println!("cargo:rerun-if-changed=../promptrail-common/src");

    let status = Command::new("rustup")
        .args([
            "run",
            EBPF_TOOLCHAIN,
            "cargo",
            "build",
            "--manifest-path",
            "../promptrail-ebpf/Cargo.toml",
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

    let src = PathBuf::from("../promptrail-ebpf")
        .join("target")
        .join("bpfel-unknown-none")
        .join("release")
        .join("promptrail-ebpf");

    let dst = out_dir.join("promptrail-ebpf");

    fs::copy(&src, &dst)?;

    println!("cargo:warning=Copied {:?} -> {:?}", src, dst);

    Ok(())
}