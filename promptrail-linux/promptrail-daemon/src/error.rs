//! Typed errors for the daemon.
//!
//! Every fallible boundary — eBPF load, program lookup, uprobe attach, map
//! extraction, ring buffer setup — maps to a specific variant here rather than
//! a stringly-typed `anyhow` at the point of failure. This makes failures
//! actionable (the message names the exact program/symbol/map) and lets the
//! top level decide what is fatal.

use thiserror::Error;

/// Errors raised while loading and attaching the eBPF programs.
#[derive(Debug, Error)]
pub enum AgentError {
    /// The embedded eBPF object failed to load into the kernel. Almost always a
    /// verifier rejection or a missing kernel feature; the inner error carries
    /// the verifier log when available.
    #[error("failed to load eBPF object into the kernel")]
    LoadObject(#[source] aya::EbpfError),

    /// A program named in the object could not be found. Indicates the eBPF and
    /// daemon builds are out of sync (renamed function).
    #[error("eBPF program `{0}` not found in loaded object (ebpf/daemon build mismatch?)")]
    ProgramMissing(&'static str),

    /// A program was found but is not the expected type (e.g. not a UProbe).
    #[error("eBPF program `{program}` is not a uprobe")]
    ProgramWrongType {
        program: &'static str,
        #[source]
        source: aya::programs::ProgramError,
    },

    /// The verifier accepted the program but it could not be loaded onto the
    /// kernel program slot.
    #[error("failed to load uprobe program `{program}` (needs CAP_BPF/CAP_PERFMON or root)")]
    ProgramLoad {
        program: &'static str,
        #[source]
        source: aya::programs::ProgramError,
    },

    /// Attaching the uprobe to the target symbol failed. The most common causes
    /// are a missing/renamed symbol or the target library not being resolvable
    /// via the ld.so cache.
    #[error("failed to attach `{program}` to symbol `{symbol}` in `{target}`")]
    Attach {
        program: &'static str,
        symbol: &'static str,
        target: String,
        #[source]
        source: aya::programs::ProgramError,
    },

    /// The `EVENTS` ring buffer map was not present in the loaded object.
    #[error("ring buffer map `{0}` missing from loaded object")]
    RingBufMissing(&'static str),

    /// The extracted map could not be turned into a typed `RingBuf`.
    #[error("failed to open ring buffer map `{name}`")]
    RingBufOpen {
        name: &'static str,
        #[source]
        source: aya::maps::MapError,
    },

    /// Registering the ring buffer fd with the async reactor failed.
    #[error("failed to register ring buffer with the async runtime")]
    AsyncRegister(#[source] std::io::Error),

    /// The `STATS` per-CPU counter map was missing or of the wrong type.
    #[error("failed to open stats map `{name}`")]
    StatsOpen {
        name: &'static str,
        #[source]
        source: aya::maps::MapError,
    },
}
