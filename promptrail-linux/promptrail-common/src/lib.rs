//! PromptRail shared ABI types.
//!
//! This crate is the single source of truth for the binary layout of every
//! value that crosses the eBPF <-> userspace boundary. It is compiled into
//! BOTH the `no_std` eBPF program and the `std` userspace daemon, so it must:
//!
//!   * be `#![no_std]` (the eBPF target has no `std`), and
//!   * contain only `#[repr(C)]`, `Copy` "plain old data" — no pointers that
//!     mean anything across an address-space boundary, no enums with niche
//!     optimizations, no `String`/`Vec`.
//!
//! WHY a dedicated crate rather than duplicating the struct on each side:
//! the ring buffer transports raw bytes. If the kernel writer and the
//! userspace reader disagree by even one byte of padding, every field after
//! the mismatch is silently garbage. Sharing one definition makes the
//! compiler enforce that they agree.
#![no_std]

/// Length of the kernel `comm` (thread/process name), fixed by the kernel's
/// `TASK_COMM_LEN`. `bpf_get_current_comm()` always returns exactly this many
/// bytes, NUL-padded.
pub const TASK_COMM_LEN: usize = 16;

/// Maximum plaintext bytes captured per `SSL_read`/`SSL_write` call.
///
/// 16 KiB == 2^14 == the TLS 1.2/1.3 maximum record size, so a single record
/// never needs more than one event. This is deliberately a power of two: the
/// eBPF program masks the copy length with `MAX_PAYLOAD - 1` to give the
/// verifier a provable upper bound (see `promptrail-ebpf`). One consequence of
/// that masking is that a call of *exactly* 16 KiB is captured as 16 KiB - 1
/// (see `clamp_payload_len`); this is documented, intentional, and revisited
/// when chunked capture lands (later workstream).
pub const MAX_PAYLOAD: usize = 16 * 1024;

/// Direction of an intercepted call. Kept as `u8` constants rather than a Rust
/// `enum` on purpose: a `#[repr(u8)]` enum with only two variants invites the
/// compiler to treat other bit patterns as niches, which is undefined behavior
/// if the kernel ever writes an unexpected value. Plain constants have no
/// invalid bit patterns.
pub mod direction {
    /// Plaintext handed to `SSL_write` (egress: what the process is sending).
    pub const WRITE: u8 = 0;
    /// Plaintext produced by `SSL_read` (ingress: what the process received).
    pub const READ: u8 = 1;
}

/// Indices into the per-CPU statistics counter array (`PerCpuArray<u64>`).
///
/// WHY a counter map instead of logging from the probe: emitting a log line per
/// dropped/faulted call on the hot `SSL_*` datapath is expensive and can itself
/// cause drops. A per-CPU counter is a single lock-free increment; the daemon
/// reads and sums the per-CPU values periodically and reports them via tracing.
/// This is the datapath-appropriate substitute for kernel-side `aya-log`, which
/// is deferred to an opt-in debug role.
pub mod stat {
    /// Events successfully submitted to the ring buffer.
    pub const EVENTS_SUBMITTED: u32 = 0;
    /// Calls dropped because the ring buffer was full (userspace fell behind).
    pub const RINGBUF_FULL: u32 = 1;
    /// Calls dropped because the user-space plaintext page could not be read
    /// (swapped out, or a bogus pointer).
    pub const USER_READ_FAULT: u32 = 2;
    /// Entry calls dropped because the correlation stash map was full.
    pub const STASH_FULL: u32 = 3;
    /// Number of distinct counters == length of the `PerCpuArray`.
    pub const COUNT: u32 = 4;
}

/// One intercepted TLS plaintext event.
///
/// Field ordering is chosen so that every field lands on its natural alignment
/// with NO compiler-inserted padding: two `u64`s, then four `u32`s, then the
/// 1-byte direction followed by explicit padding, then the byte arrays. This
/// makes the layout identical and predictable on both sides and keeps
/// `align_of::<Event>() == 8`, which the Aya ring buffer requires (it asserts
/// `8 % align_of::<T>() == 0`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    /// Nanosecond monotonic timestamp (`bpf_ktime_get_ns`) at capture.
    pub timestamp_ns: u64,
    /// The `SSL*` pointer, used to correlate multiple reads/writes belonging to
    /// the same TLS session. Opaque to userspace; only its identity matters.
    pub ssl_ptr: u64,
    /// Thread-group id == the PID as seen by `ps`/userspace.
    pub tgid: u32,
    /// Kernel thread id (the "pid" in kernel terminology). Distinct from `tgid`
    /// in multithreaded programs; correlation of read/write entry/exit is keyed
    /// on the full `pid_tgid`, so both halves are preserved here for attribution.
    pub tid: u32,
    /// Effective UID of the calling task (low 32 bits of `uid_gid`).
    pub uid: u32,
    /// Number of valid bytes in `payload`. Always `<= MAX_PAYLOAD`.
    pub payload_len: u32,
    /// `direction::WRITE` or `direction::READ`.
    pub direction: u8,
    /// Explicit padding so `comm` starts 8-aligned and the struct has no
    /// implicit padding. Never read; present only to make layout deterministic.
    pub _pad: [u8; 7],
    /// Kernel `comm` (short process name), NUL-padded. Full command line is
    /// resolved userspace-side from `/proc/<tgid>/cmdline` — it is not available
    /// cheaply in-kernel.
    pub comm: [u8; TASK_COMM_LEN],
    /// Captured plaintext. Only the first `payload_len` bytes are valid; bytes
    /// beyond that are unspecified and MUST NOT be read by userspace.
    pub payload: [u8; MAX_PAYLOAD],
}

impl Event {
    /// The valid plaintext slice. Safe because `payload_len` is clamped in the
    /// kernel to `<= MAX_PAYLOAD` before the event is submitted.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        let len = core::cmp::min(self.payload_len as usize, MAX_PAYLOAD);
        &self.payload[..len]
    }

    /// The `comm` as a byte slice trimmed at the first NUL.
    #[inline]
    pub fn comm_bytes(&self) -> &[u8] {
        let end = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(TASK_COMM_LEN);
        &self.comm[..end]
    }
}

/// Clamp a raw return length (bytes reported by `SSL_read`/`SSL_write`) to a
/// value the eBPF verifier can prove is in-bounds for `payload`.
///
/// Returns a length in `0..MAX_PAYLOAD` (note: strictly less than `MAX_PAYLOAD`
/// because of the power-of-two mask; see `MAX_PAYLOAD` docs). Shared here so the
/// kernel and any test asserting on lengths use identical arithmetic.
#[inline]
pub fn clamp_payload_len(reported: i64) -> usize {
    if reported <= 0 {
        return 0;
    }
    let reported = reported as usize;
    // Cap first, then mask. The mask is what actually convinces the verifier of
    // the bound; the cap keeps the value meaningful for the common case.
    let capped = core::cmp::min(reported, MAX_PAYLOAD - 1);
    capped & (MAX_PAYLOAD - 1)
}

/// Compile-time guarantees about the ABI. If any of these fail to hold the
/// build breaks here rather than producing silent cross-boundary corruption.
const _: () = {
    // 8-byte alignment is mandatory for Aya ring buffer reservation.
    assert!(core::mem::align_of::<Event>() == 8);
    // No implicit padding: the sum of field sizes must equal the struct size.
    // 8 + 8 + 4 + 4 + 4 + 4 + 1 + 7 + 16 + MAX_PAYLOAD
    assert!(core::mem::size_of::<Event>() == 56 + MAX_PAYLOAD);
};
