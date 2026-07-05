# PromptRail Linux Agent — Workstream 1

Rust/Aya eBPF agent that intercepts OpenSSL TLS plaintext by hooking
`SSL_write`/`SSL_read` with uprobes and streaming captured bytes to a userspace
daemon over a BPF ring buffer.

**Scope of this workstream:** load the eBPF object, attach the probes, drain the
ring buffer, and print attributed plaintext (`pid`, `comm`, direction, length,
bytes) to stdout. Everything downstream — classification, gRPC transport, policy
— is later-phase and intentionally absent.

## Layout

| Crate | Role |
|-------|------|
| `promptrail-common` | `no_std` shared ABI (the `Event` struct + stat indices). Linked by both sides. |
| `promptrail-ebpf` | The eBPF programs. **Excluded** from the workspace; built by the daemon's `build.rs` on a pinned nightly. |
| `promptrail-daemon` | Userspace loader/attacher, ring buffer consumer, `/proc` TLS-backend watcher. |
| `promptrail-test-harness` | Runtime HTTPS load generator + soak mode for capture verification. |

## Prerequisites

Userspace builds on **stable**; the eBPF object needs a **pinned nightly** plus
`bpf-linker`. Before the first build, reconcile the nightly pin with what you
have installed (see `promptrail-ebpf/rust-toolchain.toml`):

```bash
rustc +nightly --version --verbose        # note the commit-date
# ensure the pinned date is installed, with rust-src and the bpf target:
rustup toolchain install nightly-2026-06-15
rustup component add rust-src --toolchain nightly-2026-06-15
cargo install bpf-linker --version 0.10.3 --locked
```

The pinned nightly string appears in exactly three places that must agree:
`promptrail-ebpf/rust-toolchain.toml`, `promptrail-daemon/build.rs`
(`EBPF_TOOLCHAIN`), and `.github/workflows/ci.yml` (`EBPF_NIGHTLY`).

## Build & run

```bash
cargo build --workspace                   # compiles the eBPF object via build.rs
sudo RUST_LOG=info ./target/debug/promptrail-daemon
```

In another terminal, drive traffic and verify capture:

```bash
./target/debug/promptrail-test-harness --duration 60 --rate 5
# then confirm the daemon printed a `plaintext:` line containing the canary,
# attributed to comm=curl, and that its stats line stays "clean" (no drops).
```

Loading/attaching requires `CAP_BPF` + `CAP_PERFMON` (root is fine for the
prototype; the capability split is a later step).

## WS1 exit gate

1. `curl` over HTTPS → daemon prints the decrypted plaintext with `comm=curl`.
2. 60s soak at a steady rate → daemon reports **no drops**.
3. eBPF object **loads and runs on a 5.15 kernel** (the forgiving 7.x dev kernel
   can mask portability bugs). See the commented `ebpf-portability-5_15` CI job.

See `REVIEW.md` for per-file limitations and the specialist review checklist.
