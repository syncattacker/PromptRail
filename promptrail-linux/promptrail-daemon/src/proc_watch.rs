//! Runtime TLS-backend discovery by scanning `/proc/<pid>/maps`.
//!
//! ## What this does and does not do (scope boundary)
//!
//! The OpenSSL uprobe attaches to the `libssl` shared object with
//! `UProbeScope::AllProcesses`, so a single attach already fans out to every
//! process that maps that library — we do NOT need per-PID attach for the
//! OpenSSL case. What this watcher provides for Workstream 1 is *visibility*:
//! it classifies each process by which TLS library it has mapped, so the
//! operator can see, e.g., that `curl` resolved to OpenSSL and would know when
//! a target instead uses GnuTLS/NSS (invisible to an OpenSSL-shaped hook) or is
//! statically linked (candidate BoringSSL/rustls).
//!
//! Reading `/proc/<pid>/maps` reflects libraries actually *loaded* at runtime,
//! which is exactly what matters for interception and sidesteps ELF/DWARF
//! parsing. The harder problem — resolving `SSL_write` offsets inside a
//! *stripped, statically linked* BoringSSL binary — is explicitly Workstream 2
//! and is only *flagged* here, never attempted.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use tracing::{debug, info, warn};

/// TLS backend a process appears to use, inferred from its memory maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsBackend {
    /// Maps `libssl`/`libcrypto` — our uprobe covers this.
    OpenSsl,
    /// Maps `libgnutls` — Firefox and some utilities. Not covered by an OpenSSL
    /// hook; would need a separate GnuTLS uprobe (later phase).
    GnuTls,
    /// Maps `libnss3`/`libnspr4` — NSS. Same caveat as GnuTLS.
    Nss,
    /// No known TLS library mapped. If the process does TLS at all, it is
    /// statically linked (BoringSSL/rustls) — opaque to symbol-based hooks and
    /// the subject of Workstream 2.
    Opaque,
}

impl TlsBackend {
    /// Whether the current OpenSSL uprobe can see this process's TLS plaintext.
    fn covered_by_openssl_hook(self) -> bool {
        matches!(self, TlsBackend::OpenSsl)
    }
}

/// Classify a single pid by reading its maps. Returns `None` if the process is
/// gone or unreadable (races are normal: processes exit mid-scan).
fn classify_pid(pid: u32) -> Option<TlsBackend> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    let mut backend = TlsBackend::Opaque;
    for line in maps.lines() {
        // maps lines end in a pathname for file-backed regions; substring match
        // is sufficient and avoids parsing the address/permission columns.
        if line.contains("libssl.so") || line.contains("libcrypto.so") {
            // OpenSSL wins outright: it's what we hook. Return early.
            return Some(TlsBackend::OpenSsl);
        } else if line.contains("libgnutls.so") {
            backend = TlsBackend::GnuTls;
        } else if line.contains("libnss3.so") || line.contains("libnspr4.so") {
            backend = TlsBackend::Nss;
        }
    }
    Some(backend)
}

/// Read a process's `comm` for friendlier logging. Best-effort.
fn read_comm(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim_end().to_owned())
        .unwrap_or_else(|_| "<unknown>".to_owned())
}

/// Enumerate numeric pids currently under `/proc`.
fn list_pids() -> Vec<u32> {
    let mut pids = Vec::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if let Ok(pid) = name.parse::<u32>() {
                    pids.push(pid);
                }
            }
        }
    }
    pids
}

/// Best-effort resolution of a concrete `libssl` path from any process that has
/// it mapped. Returned purely for logging/diagnostics — the actual attach uses
/// the `"ssl"` basename and lets the kernel/ld.so cache resolve it, so a `None`
/// here does not block attachment.
pub fn resolve_libssl_path() -> Option<PathBuf> {
    for pid in list_pids() {
        let Ok(maps) = fs::read_to_string(format!("/proc/{pid}/maps")) else {
            continue;
        };
        for line in maps.lines() {
            if let Some(idx) = line.find('/') {
                let path = &line[idx..];
                if path.contains("libssl.so") {
                    return Some(PathBuf::from(path.trim()));
                }
            }
        }
    }
    None
}

/// Periodically scan `/proc` and log newly observed processes and their TLS
/// backend. Runs until the task is cancelled (dropped) by the caller.
///
/// This never returns an error: a scan failure for one pid is a normal race and
/// is skipped. The loop only ends when the surrounding task is aborted.
pub async fn watch(interval: Duration) {
    // Remember what we've already reported so each process is logged once, and
    // so a backend change (rare, e.g. dlopen of libssl later) is noticed.
    let mut seen: HashMap<u32, TlsBackend> = HashMap::new();

    loop {
        let pids = list_pids();
        // Drop exited pids so a recycled pid is treated as new.
        seen.retain(|pid, _| pids.contains(pid));

        for pid in pids {
            let Some(backend) = classify_pid(pid) else {
                continue;
            };
            let previously = seen.insert(pid, backend);
            if previously == Some(backend) {
                continue; // already reported, unchanged
            }

            let comm = read_comm(pid);
            match backend {
                TlsBackend::OpenSsl => {
                    info!(pid, comm, backend = "openssl", "process uses OpenSSL — covered by hook");
                }
                TlsBackend::GnuTls => {
                    warn!(pid, comm, backend = "gnutls", "process uses GnuTLS — NOT covered by OpenSSL hook");
                }
                TlsBackend::Nss => {
                    warn!(pid, comm, backend = "nss", "process uses NSS — NOT covered by OpenSSL hook");
                }
                TlsBackend::Opaque => {
                    // Very common and mostly uninteresting (processes that do no
                    // TLS). Log at debug so it doesn't drown the output; only
                    // Workstream 2 will care about distinguishing static-TLS
                    // binaries from non-TLS ones.
                    debug!(pid, comm, backend = "opaque", "no known TLS library mapped");
                }
            }
            let _ = backend.covered_by_openssl_hook(); // documents intent; see WS2
        }

        tokio::time::sleep(interval).await;
    }
}
