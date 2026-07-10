//! PromptRail userspace daemon.
//!
//! Responsibilities for Workstream 1:
//!   1. Load the embedded eBPF object into the kernel.
//!   2. Attach entry+return uprobes to `SSL_write`/`SSL_read` in `libssl`.
//!   3. Drain the ring buffer and print attributed plaintext to stdout.
//!   4. Periodically report per-CPU drop/fault counters.
//!   5. Watch `/proc` to report which processes use which TLS backend.
//!
//! Everything downstream of "attributed plaintext to stdout" (classification,
//! gRPC transport, policy) is later-phase scope and deliberately absent.

use std::time::Duration;

use aya::{
    include_bytes_aligned,
    maps::{PerCpuArray, RingBuf},
    programs::{uprobe::UProbeScope, UProbe},
    Ebpf,
};
use tokio::io::unix::AsyncFd;
use tokio::signal;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use promptrail_common::{direction, stat, Event};

mod error;
mod proc_watch;
mod offset_discovery; 

#![allow(dead_code)]
use std::path::Path;
use error::AgentError;

/// (eBPF program function name, exported symbol to attach to). Entry and return
/// probes are distinct programs; both are `UProbe` in userspace terms.
const PROBES: &[(&str, &str)] = &[
    ("ssl_write_entry",    "SSL_write"),
    ("ssl_write_ret",      "SSL_write"),
    ("ssl_read_entry",     "SSL_read"),
    ("ssl_read_ret",       "SSL_read"),
    ("ssl_write_ex_entry", "SSL_write_ex"),   // ← new
    ("ssl_write_ex_ret",   "SSL_write_ex"),   // ← new
    ("ssl_read_ex_entry",  "SSL_read_ex"),    // ← new
    ("ssl_read_ex_ret",    "SSL_read_ex"),    // ← new
];


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Structured logging to stdout. Level controlled by RUST_LOG (default info).
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(false)
        .init();

    // Loading and attaching require CAP_BPF+CAP_PERFMON (or root). Surface a
    // clear message rather than a raw errno if we lack privilege.
    if let Err(e) = run().await {
        error!(error = %e, "fatal");
        // Print the full source chain so the operator sees the root cause.
        for cause in e.chain().skip(1) {
            error!(cause = %cause);
        }
        std::process::exit(1);
    }
    Ok(())
}

async fn run() -> anyhow::Result<()> {
    // The eBPF object is compiled by build.rs (aya-build) and embedded here.
    // `include_bytes_aligned!` guarantees the 8-byte alignment the loader needs.
    let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/promptrail-ebpf"
    )))
    .map_err(AgentError::LoadObject)?;

    attach_probes(&mut ebpf)?;

    // Move the maps out of `ebpf`. The programs (and their attach links) remain
    // owned by `ebpf`, which we keep alive until shutdown below.
    let events_map = ebpf
        .take_map("EVENTS")
        .ok_or(AgentError::RingBufMissing("EVENTS"))?;
    let ring = RingBuf::try_from(events_map).map_err(|source| AgentError::RingBufOpen {
        name: "EVENTS",
        source,
    })?;

    let stats_map = ebpf
        .take_map("STATS")
        .ok_or(AgentError::RingBufMissing("STATS"))?;
    let stats = PerCpuArray::<_, u64>::try_from(stats_map).map_err(|source| {
        AgentError::StatsOpen {
            name: "STATS",
            source,
        }
    })?;

    let libssl_target = proc_watch::resolve_libssl_target();
    match proc_watch::resolve_libssl_path() {
        Some(path) => info!(libssl = %path.display(), target = %libssl_target, "resolved libssl for diagnostics and attach"),
        None => info!(target = %libssl_target, "no process currently maps libssl; using discovered target for attach"),
    }

    // Background: /proc backend discovery and periodic stats reporting. These
    // are aborted automatically when the process exits.
    tokio::spawn(proc_watch::watch(Duration::from_secs(5)));
    tokio::spawn(report_stats(stats, Duration::from_secs(10)));

    info!("PromptRail daemon running — capturing SSL_write/SSL_read plaintext. Ctrl-C to stop.");

    // Run the consumer until Ctrl-C. `ebpf` stays in scope for the whole select,
    // so the probes remain attached until we intentionally shut down.
    tokio::select! {
        res = consume_events(ring) => {
            // The consumer only returns on an unrecoverable async-fd error.
            res?;
        }
        _ = signal::ctrl_c() => {
            info!("received Ctrl-C, detaching probes and exiting");
        }
    }

    // Dropping `ebpf` here detaches all uprobes. Explicit for clarity.
    drop(ebpf);
    Ok(())
}


/// Load and attach all four uprobe programs. Any failure is fatal and typed.
#[allow(clippy::result_large_err)]
fn attach_probes(ebpf: &mut Ebpf) -> Result<(), AgentError> {
    let libssl_target = proc_watch::resolve_libssl_target();
    info!(target = %libssl_target, "attaching uprobes to libssl target");

    for &(prog_name, symbol) in PROBES {
        let program: &mut UProbe = ebpf
            .program_mut(prog_name)
            .ok_or(AgentError::ProgramMissing(prog_name))?
            .try_into()
            .map_err(|source| AgentError::ProgramWrongType {
                program: prog_name,
                source,
            })?;

        program.load().map_err(|source| AgentError::ProgramLoad {
            program: prog_name,
            source,
        })?;

        program
            .attach(symbol, &libssl_target, UProbeScope::AllProcesses)
            .map_err(|source| AgentError::Attach {
                program: prog_name,
                symbol,
                target: libssl_target.clone(),
                source,
            })?;

        info!(program = prog_name, symbol, target = %libssl_target, "attached uprobe");
    }
    Ok(())
}

/// Drain the ring buffer forever, printing each captured plaintext event.
///
/// Returns only if registering/using the async fd fails unrecoverably.
async fn consume_events(ring: RingBuf<aya::maps::MapData>) -> Result<(), AgentError> {
    // Wrap the ring buffer fd so tokio wakes us when the kernel signals data.
    let mut async_fd = AsyncFd::new(ring).map_err(AgentError::AsyncRegister)?;

    loop {
        // Wait for readiness, then drain every currently-available record before
        // clearing readiness — otherwise we'd wake once per record.
        let mut guard = async_fd.readable_mut().await.map_err(AgentError::AsyncRegister)?;
        let ring = guard.get_inner_mut();
        while let Some(item) = ring.next() {
            handle_record(item.as_ref());
        }
        guard.clear_ready();
    }
}

/// Parse one ring buffer record into an `Event` and report it.
fn handle_record(bytes: &[u8]) {
    if bytes.len() < core::mem::size_of::<Event>() {
        // A short record means an ABI mismatch between the kernel object and
        // this binary — never expected, but we refuse to read out of bounds.
        warn!(
            got = bytes.len(),
            want = core::mem::size_of::<Event>(),
            "dropping undersized ring buffer record (ebpf/daemon ABI mismatch?)"
        );
        return;
    }

    // The record is a byte-for-byte `Event`. Read it unaligned: the ring buffer
    // guarantees 8-byte record alignment, but `read_unaligned` is correct
    // regardless and costs one memcpy of an already-owned buffer.
    let event: Event = unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const Event) };

    let dir = match event.direction {
        direction::WRITE => "write",
        direction::READ => "read",
        other => {
            warn!(direction = other, "unknown direction byte");
            "?"
        }
    };
    let comm = String::from_utf8_lossy(event.comm_bytes());
    let preview = render_preview(event.payload());

    // This is the WS1 "done" output: attributed plaintext to stdout. `ssl` is
    // the raw session pointer (u64) — a stable per-session identifier for
    // correlating multiple reads/writes; its numeric value is not meaningful.
    info!(
        pid = event.tgid,
        tid = event.tid,
        uid = event.uid,
        comm = %comm,
        dir,
        len = event.payload_len,
        ssl = event.ssl_ptr,
        "plaintext: {preview}"
    );
}

/// Render a bounded, printable preview of captured plaintext. The full payload
/// is available in `event.payload()`; this only exists to keep stdout legible.
fn render_preview(payload: &[u8]) -> String {
    const MAX_PREVIEW: usize = 256;
    let shown = &payload[..payload.len().min(MAX_PREVIEW)];
    let mut out = String::with_capacity(shown.len());
    for &b in shown {
        if b == b'\n' || b == b'\r' || b == b'\t' || (0x20..0x7f).contains(&b) {
            out.push(b as char);
        } else {
            out.push('.');
        }
    }
    if payload.len() > MAX_PREVIEW {
        out.push_str(&format!(" …(+{} bytes)", payload.len() - MAX_PREVIEW));
    }
    out
}

/// Periodically read the per-CPU counters, sum across CPUs, and report deltas.
async fn report_stats(stats: PerCpuArray<aya::maps::MapData, u64>, interval: Duration) {
    // Read a single counter by summing its per-CPU values. On error we report 0
    // for that counter rather than aborting the reporter.
    let sum = |stats: &PerCpuArray<aya::maps::MapData, u64>, idx: u32| -> u64 {
        match stats.get(&idx, 0) {
            Ok(values) => values.iter().copied().sum(),
            Err(e) => {
                warn!(index = idx, error = %e, "failed to read stat counter");
                0
            }
        }
    };

    let mut last_submitted = 0_u64;
    loop {
        tokio::time::sleep(interval).await;

        let submitted = sum(&stats, stat::EVENTS_SUBMITTED);
        let ringbuf_full = sum(&stats, stat::RINGBUF_FULL);
        let read_fault = sum(&stats, stat::USER_READ_FAULT);
        let stash_full = sum(&stats, stat::STASH_FULL);

        let delta = submitted.saturating_sub(last_submitted);
        last_submitted = submitted;

        // Drops are the number that matters for the WS1 exit gate ("no drops in
        // a 60s run"): a nonzero ringbuf_full means the consumer fell behind.
        if ringbuf_full > 0 || read_fault > 0 || stash_full > 0 {
            warn!(
                submitted,
                submitted_delta = delta,
                ringbuf_full,
                read_fault,
                stash_full,
                "capture stats (DROPS PRESENT)"
            );
        } else {
            info!(
                submitted,
                submitted_delta = delta,
                ringbuf_full,
                read_fault,
                stash_full,
                "capture stats (clean)"
            );
        }
    }
}
