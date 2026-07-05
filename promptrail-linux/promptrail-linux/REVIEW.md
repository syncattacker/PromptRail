# Review & Limitations (Step 5 blocks)

Each block: (a) what can't be verified from the build chat, (b) the three most
likely real-machine failure modes, (c) a bounded specialist review checklist.

The blocks are ordered by risk. **`promptrail-ebpf/src/main.rs` is the highest
risk and is flagged first** — it is where the pinned-nightly/bpf-linker coupling
and every verifier interaction live.

---

## `promptrail-ebpf/src/main.rs`  ⚠️ FLAGGED — read this one first

**(a) Not verifiable from the chat.** This container has no `bpfel-unknown-none`
cross toolchain, so the object was never compiled or run through the verifier
here. That means: whether the variable-length user read passes the verifier on a
given kernel; whether cross-crate inlining of `clamp_payload_len` preserves the
length bound (mitigated by a local re-mask, but unconfirmed); whether
`reserve::<Event>` with a ~16 KiB `T` is accepted; whether the pinned nightly is
even installed on the target — all unverified. CI (`ebpf-build`) is the real gate.

**(b) Three most likely real-machine failure modes.**
1. **Nightly/bpf-linker mismatch.** If the installed nightly differs from the
   pin, `-Z build-std` can miscompile silently or the link fails with opaque
   errors. This is the single most probable failure and the reason for the pin.
2. **Verifier rejection of the payload copy.** If the `len & (MAX_PAYLOAD-1)`
   bound is optimized away or the kernel is older/stricter than assumed, the
   variable-length `bpf_probe_read_user_buf` is rejected. The 7.x dev kernel is
   lenient and may accept code that a 5.15 verifier rejects — exactly what the
   portability gate exists to catch.
3. **`SSL*`/`buf` are not in the first two arg registers on this target.** The
   probe assumes the SysV AMD64 arg order (`rdi`, `rsi`). On a differently-built
   OpenSSL (LTO, non-standard calling convention) the stashed pointers are wrong
   and reads fault (counted as `USER_READ_FAULT`).

**(c) Specialist review checklist.**
- [ ] Pinned nightly matches the installed nightly; `rust-src` present; bpf-linker 0.10.3.
- [ ] Object verifies **and attaches** on kernel 5.15, not just 7.x.
- [ ] `align_of::<Event>() == 8` still holds if `Event` changes (breaks `reserve`).
- [ ] Confirm the length bound survives to the read site in the compiled bytecode.
- [ ] Payload bytes beyond `payload_len` are uninitialized ring buffer memory —
      accept as prototype behavior or zero-fill before submit (info-leak hardening).
- [ ] `_ex` variants (`SSL_write_ex`/`SSL_read_ex`) are **not** hooked yet.
- [ ] Confirm capture at exactly `MAX_PAYLOAD` is acceptable (masked to `MAX-1`).
- [ ] Verify per-CPU non-atomic `incr` is acceptable under your concurrency model.

---

## `promptrail-daemon/src/main.rs`

**(a) Not verifiable from the chat.** The attach path, `AsyncFd` polling of the
ring buffer, and `include_bytes_aligned!` of the build.rs output were not run.
Whether `"ssl"` resolves via the target's ld.so cache is environment-specific.

**(b) Three most likely failure modes.**
1. **Attach target does not resolve.** If `libssl` isn't in the ld.so cache under
   a name the basename lookup matches, attach fails; pass an absolute path.
2. **Permissions.** Without `CAP_BPF`+`CAP_PERFMON`/root, load or attach fails.
3. **Consumer falls behind under load** → `RINGBUF_FULL` climbs. Tune ring size
   or the drain loop; the stats reporter surfaces this.

**(c) Checklist.**
- [ ] Run as root (or with the two caps) for the prototype.
- [ ] Confirm `program_mut` names exactly match the eBPF fn names.
- [ ] Confirm both entry and ret programs load (both are `UProbe`).
- [ ] Validate `read_unaligned` parse against the on-wire record size.
- [ ] Check stats reporter deltas look sane during a soak.
- [ ] Confirm Ctrl-C detaches cleanly (probes gone from `bpftool perf list`).

---

## `promptrail-daemon/build.rs`

**(a)** aya-build was not executed here. **(b)** Toolchain-not-installed;
`OUT_DIR` object name mismatch with the daemon's `include_bytes_aligned!`; a
stale object not rebuilt because `rerun-if-changed` missed a path. **(c)** Verify
`EBPF_TOOLCHAIN` matches the pin; verify the emitted object is named
`promptrail-ebpf`; test an incremental rebuild after touching an eBPF source.

---

## `promptrail-common/src/lib.rs`

**(a)** The compile-time layout asserts run at build time, not here. **(b)** A
field reordering silently changing layout; padding assumptions wrong on a
non-x86_64 target; `MAX_PAYLOAD` changed to a non-power-of-two (breaks the mask).
**(c)** Keep the size/align asserts; keep `MAX_PAYLOAD` a power of two; treat any
field change as an ABI break requiring a rebuild of both sides.

---

## `promptrail-daemon/src/proc_watch.rs`

**(a)** `/proc` scanning wasn't run against a real process table here. **(b)**
Substring matching misclassifying a path; scan cost on hosts with thousands of
pids; TOCTOU races (handled by skipping vanished pids). **(c)** Confirm OpenSSL
processes log as covered; confirm GnuTLS/NSS log as warnings; confirm the scan
interval is acceptable overhead.

---

## `promptrail-test-harness/src/main.rs`

**(a)** No `curl` run here. **(b)** curl not OpenSSL-linked (probes never fire);
canary not appearing if the request is redirected/failed before write; rate
pacing drift under load. **(c)** Confirm `curl --version` shows OpenSSL; confirm
the canary header reaches `SSL_write`; confirm soak duration/rate match the gate.

---

## `.github/workflows/ci.yml` + `setup-ebpf-toolchain`

**(a)** Not executed. **(b)** `bpf-linker` install failing without the right
LLVM on the runner; every daemon-compiling job needing the full eBPF toolchain
(easy to under-provision); the 5.15 job needing a real 5.15 **host** kernel, not
a container. **(c)** Confirm LLVM version suits bpf-linker 0.10.3; confirm caching
doesn't mask a clean-build failure; wire and enable `ebpf-portability-5_15`
before declaring the WS1 gate met.
