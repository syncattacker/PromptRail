//! PromptRail eBPF programs: OpenSSL `SSL_write` / `SSL_read` plaintext capture.
//!
//! ## The core correctness problem this solves
//!
//! `SSL_write(ssl, buf, num)` has the plaintext in `buf` *on entry*.
//! `SSL_read(ssl, buf, num)` receives an *empty* `buf` on entry and only fills
//! it by the time it *returns*. A naive hook that reads `buf` in the entry
//! probe captures uninitialized memory for every read.
//!
//! The correct, uniform pattern (used by mature agents like Pixie) is:
//!   * ENTRY probe: stash `(ssl, buf)` keyed by the full `pid_tgid`.
//!   * RETURN probe: recover the stash, and copy exactly `ret` bytes (the
//!     return value is the number of bytes actually read/written — this also
//!     handles OpenSSL partial writes, where fewer than `num` bytes move).
//!
//! Keying on `pid_tgid` (not `tgid`) is mandatory: in a multithreaded process
//! several threads can be inside `SSL_read` concurrently, and only the full
//! 64-bit id identifies the thread. A single stash map is safe because on any
//! one thread the call is synchronous: entry and its matching return bracket
//! the real function, and the thread cannot begin another SSL_* call in between.
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns, bpf_probe_read_user_buf,
    },
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::{ProbeContext, RetProbeContext},
};
use core::ffi::c_void;
use promptrail_common::{clamp_payload_len, direction, stat, Event, MAX_PAYLOAD, TASK_COMM_LEN};

/// Arguments stashed on the entry probe, recovered on the return probe.
///
/// `#[repr(C)]` so its layout is stable; stored by value in a `HashMap`.
#[repr(C)]
#[derive(Clone, Copy)]
struct SslArgs {
    /// The `SSL*` pointer (arg 0), for session correlation.
    ssl: u64,
    /// The user-space `buf` pointer (arg 1) to read plaintext from on return.
    buf: u64,
    count_ptr: u64,
}

/// Ring buffer carrying `Event`s to userspace.
///
/// Size: 16 MiB. It must be a power-of-two multiple of the page size. Each
/// `Event` is ~16 KiB, so this holds ~1000 in-flight events — headroom for the
/// userspace consumer to fall behind briefly under load without dropping. The
/// exact figure needs load validation on real hardware (see Review block); 16
/// MiB is a defensible starting point, not a measured optimum.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

/// Per-thread stash of entry arguments, keyed by `pid_tgid`.
///
/// 10240 entries bounds worst-case concurrent in-flight SSL_* calls. If it ever
/// fills, `insert` fails and that single call is skipped (counted via STATS),
/// rather than corrupting another thread's data.
#[map]
static ACTIVE_CALLS: HashMap<u64, SslArgs> = HashMap::with_max_entries(10240, 0);

/// Per-CPU statistics counters, indexed by `promptrail_common::stat::*`.
///
/// Per-CPU so increments are lock-free (each CPU owns its slot); the daemon
/// sums the per-CPU values when reporting. This replaces datapath logging.
#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(stat::COUNT, 0);

/// Increment a statistics counter. Never faults: a missing slot (impossible for
/// a fixed-size array with in-range index) is simply ignored.
#[inline(always)]
fn incr(index: u32) {
    if let Some(slot) = STATS.get_ptr_mut(index) {
        // Safe: `slot` points at this CPU's private counter; no other context on
        // this CPU runs concurrently, so a non-atomic increment is sound.
        unsafe { *slot += 1 };
    }
}

// ---------------------------------------------------------------------------
// Entry probes: stash (ssl, buf). Identical for read and write.
// ---------------------------------------------------------------------------

#[uprobe]
pub fn ssl_write_entry(ctx: ProbeContext) -> u32 {
    // A stash failure (map full / malformed context) is non-fatal: we simply
    // won't emit this one call. It is counted so the drop is observable.
    if stash_entry(&ctx).is_err() {
        incr(stat::STASH_FULL);
    }
    0
}

#[uprobe]
pub fn ssl_read_entry(ctx: ProbeContext) -> u32 {
    if stash_entry(&ctx).is_err() {
        incr(stat::STASH_FULL);
    }
    0
}

#[uretprobe]
pub fn ssl_write_ex_ret(ctx: RetProbeContext) -> u32 { on_return_ex(&ctx, direction::WRITE); 0 }
#[uretprobe]
pub fn ssl_read_ex_ret(ctx: RetProbeContext)  -> u32 { on_return_ex(&ctx, direction::READ);  0 }

// ---------------------------------------------------------------------------
// Return probes: recover the stash, copy `ret` bytes, submit an Event.
// ---------------------------------------------------------------------------

#[uretprobe]
pub fn ssl_write_ret(ctx: RetProbeContext) -> u32 {
    on_return(&ctx, direction::WRITE);
    0
}

#[uretprobe]
pub fn ssl_read_ret(ctx: RetProbeContext) -> u32 {
    on_return(&ctx, direction::READ);
    0
}

/// Read `(ssl, buf)` from the probe context and stash them for this thread.
#[inline(always)]
fn stash_entry(ctx: &ProbeContext) -> Result<(), i64> {
    // arg 0 = SSL*, arg 1 = const void *buf. Missing args => malformed probe
    // context; bail. `ok_or` converts the Option into an error we can `?`.
    let ssl: *const c_void = ctx.arg(0).ok_or(-1_i64)?;
    let buf: *const c_void = ctx.arg(1).ok_or(-1_i64)?;

    let key = bpf_get_current_pid_tgid();
    let args = SslArgs {
        ssl: ssl as u64,
        buf: buf as u64,
    };
    // `insert` can fail if the map is full; propagate so the caller can log.
    ACTIVE_CALLS.insert(&key, &args, 0).map_err(|e| e as i64)
}

#[inline(always)]
fn stash_entry_ex(ctx: &ProbeContext) -> Result<(), i64> {
    let ssl:   *const c_void = ctx.arg(0).ok_or(-1_i64)?;
    let buf:   *const c_void = ctx.arg(1).ok_or(-1_i64)?;
    // arg 2 is size_t num (ignored); arg 3 is size_t *written / *readbytes.
    let count: *const c_void = ctx.arg(3).ok_or(-1_i64)?;
    let key = bpf_get_current_pid_tgid();
    let args = SslArgs { ssl: ssl as u64, buf: buf as u64, count_ptr: count as u64 };
    ACTIVE_CALLS.insert(&key, &args, 0).map_err(|e| e as i64)
}

/// Recover the stashed args, capture plaintext, and submit an event.
///
/// Never panics and never leaves a stale stash entry: the entry is removed
/// regardless of whether capture succeeds.
#[inline(always)]
fn on_return(ctx: &RetProbeContext, dir: u8) {
    let key = bpf_get_current_pid_tgid();

    // Look up this thread's stashed entry. If absent, the entry probe didn't
    // fire (e.g. attach happened mid-call) — nothing to do.
    let args = match unsafe { ACTIVE_CALLS.get(&key) } {
        Some(a) => *a,
        None => return,
    };
    // Remove eagerly so a failure below can't leak the entry. Ignore the result:
    // the key is guaranteed present here, and a spurious remove error must not
    // abort capture.
    let _ = ACTIVE_CALLS.remove(&key);

    // Return value = bytes actually read/written. SSL_read/SSL_write return a C
    // `int`, so read exactly 32 bits and widen; reading 64 bits would depend on
    // unspecified upper-register contents. <= 0 means EOF/error/want-retry with
    // no plaintext to capture.
    let ret: i32 = ctx.ret::<i32>();
    if ret <= 0 {
        return;
    }

    // emit_event increments the specific failure counter itself, so there is
    // nothing to do with the error here beyond letting it drop.
    let _ = emit_event(args, dir, ret as i64);
}

#[inline(always)]
fn on_return_ex(ctx: &RetProbeContext, dir: u8) {
    let key = bpf_get_current_pid_tgid();
    let args = match unsafe { ACTIVE_CALLS.get(&key) } { Some(a) => *a, None => return };
    let _ = ACTIVE_CALLS.remove(&key);

    // _ex returns 1 = success, 0 = failure. NOT a byte count.
    let ok: i32 = ctx.ret::<i32>();
    if ok != 1 { return; }

    // The real length lives behind the stashed size_t* (arg 3). Read it from user memory.
    let mut written: u64 = 0;
    if unsafe { bpf_probe_read_user(args.count_ptr as *const u64) }
        .map(|v| { written = v; }).is_err()
    {
        incr(stat::USER_READ_FAULT);
        return;
    }
    let _ = emit_event(args, dir, written as i64);
}

/// Build and submit one `Event` into the ring buffer.
#[inline(always)]
fn emit_event(args: SslArgs, dir: u8, ret: i64) -> Result<(), i64> {
    // Reserve space for a whole Event directly in the ring buffer. This is the
    // key to satisfying the verifier's 512-byte stack limit: a ~16 KiB Event
    // can never live on the eBPF stack, but ring buffer memory is unbounded by
    // that rule. `reserve` returns None when the buffer is full -> treated as a
    // drop.
    let mut entry = match EVENTS.reserve::<Event>(0) {
        Some(e) => e,
        None => {
            incr(stat::RINGBUF_FULL);
            return Err(-1_i64);
        }
    };
    let ptr = entry.as_mut_ptr();

    // Length clamped+masked to a verifier-provable bound in [0, MAX_PAYLOAD).
    // Identical arithmetic to userspace via the shared helper.
    let len = clamp_payload_len(ret);
    // Re-apply the mask locally. `clamp_payload_len` lives in another crate; if
    // cross-crate inlining does not preserve the mask, the verifier could lose
    // the bound at the read site below and reject the program. Masking here with
    // a compile-time power-of-two constant makes the `< MAX_PAYLOAD` bound
    // syntactically visible exactly where the variable-length read happens.
    let len = len & (MAX_PAYLOAD - 1);

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0_u8; TASK_COMM_LEN]);
    // ktime is a raw (generated) helper and therefore unsafe to call.
    let ts = unsafe { bpf_ktime_get_ns() };

    // Write each header field through the raw pointer. We intentionally do NOT
    // construct an `Event` on the stack and copy it in — that 16 KiB stack
    // object is exactly what the verifier forbids. `addr_of_mut!` avoids
    // creating an intermediate reference to uninitialized memory.
    unsafe {
        use core::ptr::addr_of_mut;
        addr_of_mut!((*ptr).timestamp_ns).write(ts);
        addr_of_mut!((*ptr).ssl_ptr).write(args.ssl);
        addr_of_mut!((*ptr).tgid).write((pid_tgid >> 32) as u32);
        addr_of_mut!((*ptr).tid).write(pid_tgid as u32);
        addr_of_mut!((*ptr).uid).write(uid_gid as u32);
        addr_of_mut!((*ptr).payload_len).write(len as u32);
        addr_of_mut!((*ptr).direction).write(dir);
        addr_of_mut!((*ptr)._pad).write([0_u8; 7]);
        addr_of_mut!((*ptr).comm).write(comm);

        // Copy plaintext from userspace directly into the reserved payload.
        // `len` is provably < MAX_PAYLOAD, so this sub-slice is in-bounds — the
        // property the verifier needs to accept a variable-length user read.
        let dst = core::slice::from_raw_parts_mut(addr_of_mut!((*ptr).payload) as *mut u8, len);
        if bpf_probe_read_user_buf(args.buf as *const u8, dst).is_err() {
            // The user page may be swapped out or the pointer bogus. Discard the
            // reservation so userspace never sees a half-filled event.
            entry.discard(0);
            incr(stat::USER_READ_FAULT);
            return Err(-2_i64);
        }
    }

    entry.submit(0);
    incr(stat::EVENTS_SUBMITTED);
    Ok(())
}

/// eBPF panic handler. Required for `#![no_std]` + `#![no_main]`. It is
/// unreachable in practice — the verifier rejects any program with a reachable
/// panic — so the body only needs to satisfy the `-> !` signature.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Deliberately empty infinite loop: never executed, never verified as
    // reachable. `unreachable!()` would itself panic, so we cannot use it.
    loop {}
}
