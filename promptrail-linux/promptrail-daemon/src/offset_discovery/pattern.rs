//! Stage 1 of the offset-discovery funnel: localize BoringSSL's `ssl_lib.cc`
//! translation unit inside the stripped 200 MiB VS Code blob, reducing ~500k
//! generic prologue candidates to ~12 per-function reference clusters.
//!
//! ## Why this works (and what it deliberately does NOT decide)
//!
//! Every `OPENSSL_PUT_ERROR(...)` in BoringSSL expands to
//! `ERR_put_error(..., __FILE__, __LINE__)`, so every error path in `ssl_lib.cc`
//! emits a `lea reg,[rip+disp32]` loading the address of the *same* rodata
//! string — its source path, embedded verbatim as
//! `../../third_party/boringssl/src/ssl/ssl_lib.cc`. Finding that string and
//! counting the `lea` sites that point at it localizes us to the functions of
//! that one translation unit.
//!
//! Under Chromium's LTO/PGO layout those functions are flung megabytes apart in
//! `.text`, but each *function's* error-path `lea`s stay within a few hundred
//! bytes of each other. So proximity-clustering the reference sites yields one
//! cluster per function, and the cluster's *reference count* is a signature:
//!   * `SSL_write` has exactly 4 `OPENSSL_PUT_ERROR` sites (QUIC / uninitialized
//!     / handshake-failure / bad-length) → a 4-ref cluster.
//!   * `SSL_read` has NONE (it is a thin `SSL_peek` wrapper), so it is NOT a
//!     cluster. It is reached in Stage 2 via `SSL_peek`, which DOES have one
//!     error site → a 1-ref cluster; `SSL_read` calls `SSL_peek` first.
//! Both facts were verified against the pinned source (commit
//! `d8be2b4a71155bf82da092ef543176351eeb59ff`).
//!
//! ## Scope boundary
//! This stage produces *candidate clusters*, NOT confirmed function offsets. A
//! cluster's addresses are `lea` *reference sites* inside a function, not its
//! entry, and the ref-count → role mapping is a PROVISIONAL guess. Stage 2
//! (`disasm`/predicate) back-walks each candidate to the function entry and
//! confirms it structurally before any `OffsetCandidate` is produced. Nothing
//! here disassembles, and nothing here is fed to a uprobe.
//!
//! Validated end-to-end against `ws2_xref.py` on the real target: 39 references,
//! 12 clusters at the default gap, exactly one 4-ref cluster (SSL_write).

use super::ElfImage;

/// The BoringSSL `ssl_lib.cc` source-path substring embedded via `__FILE__`.
/// We search for this short, distinctive tail and expand to the full embedded
/// C string (Chromium embeds the whole build-relative path).
const ANCHOR_NEEDLE: &[u8] = b"ssl_lib.cc";

/// Default maximum byte gap between two reference sites for them to be in the
/// same cluster. Chromium places distinct functions megabytes apart while a
/// single function's error-path `lea`s sit within hundreds of bytes, so any
/// value from a few hundred bytes to tens of KiB gives the same clustering —
/// 4 KiB sits squarely in that safe band (confirmed stable across a 16x change
/// in `ws2_xref.py`).
pub const DEFAULT_CLUSTER_GAP: u64 = 4096;

/// Reference-count signatures from the pinned BoringSSL source. These are the
/// number of `OPENSSL_PUT_ERROR` sites the compiler is *expected* to emit; LTO
/// inlining/dedup can drop some, which is why Stage 2 confirms structurally
/// rather than trusting the count alone.
const SSL_WRITE_REF_COUNT: usize = 4;
const SSL_PEEK_REF_COUNT: usize = 1;

/// What a cluster's reference count *suggests* it is. Provisional only —
/// confirmed or rejected by the Stage-2 disassembly predicate. Deliberately not
/// [`super::TargetFn`]: `SSL_read` is anchored indirectly (via `SSL_peek`), so
/// there is no direct "SSL_read cluster".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterRole {
    /// 4 refs — matches `SSL_write`'s four error sites. The primary anchor.
    SslWriteCandidate,
    /// 1 ref — matches `SSL_peek`'s single error site. Leads to `SSL_read`,
    /// which calls `SSL_peek` as its first action (Stage 2 reverse-call scan).
    SslPeekCandidate,
    /// Any other ref count — a different `ssl_lib.cc` function, not a target.
    Other,
}

impl ClusterRole {
    fn from_ref_count(n: usize) -> Self {
        match n {
            SSL_WRITE_REF_COUNT => ClusterRole::SslWriteCandidate,
            SSL_PEEK_REF_COUNT => ClusterRole::SslPeekCandidate,
            _ => ClusterRole::Other,
        }
    }
}

/// A proximity cluster of RIP-relative reference sites that all point at the
/// `ssl_lib.cc` anchor string. Under LTO, one cluster ≈ one function of that
/// translation unit.
#[derive(Debug, Clone)]
pub struct RefCluster {
    /// Virtual addresses of the referencing `lea` instructions, ascending.
    /// NOTE: these are reference sites *inside* the function body, NOT the
    /// function entry — Stage 2 back-walks to the prologue.
    pub ref_vaddrs: Vec<u64>,
    /// Lowest reference vaddr (a convenient handle for the cluster).
    pub first_vaddr: u64,
    /// Byte span from first to last reference (0 for a single-ref cluster).
    pub span: u64,
    /// Provisional role from ref-count alone.
    pub role: ClusterRole,
}

impl RefCluster {
    pub fn ref_count(&self) -> usize {
        self.ref_vaddrs.len()
    }
}

/// Result of the Stage-1 anchor scan.
#[derive(Debug, Clone)]
pub struct XrefResult {
    /// The exact embedded string as found (e.g.
    /// `../../third_party/boringssl/src/ssl/ssl_lib.cc`), for logging.
    pub anchor_string: String,
    /// File offset of the anchor string's first byte.
    pub anchor_file_offset: u64,
    /// Virtual address of the anchor string's first byte (what `lea`s target).
    pub anchor_vaddr: u64,
    /// Total reference sites across all clusters.
    pub total_refs: usize,
    /// Per-function clusters, ascending by `first_vaddr`.
    pub clusters: Vec<RefCluster>,
}

impl XrefResult {
    /// Clusters whose ref-count matches `SSL_write` (4 error sites). Expected to
    /// be exactly one on a clean target; more than one means Stage 2 must
    /// disambiguate structurally.
    pub fn ssl_write_candidates(&self) -> impl Iterator<Item = &RefCluster> {
        self.clusters
            .iter()
            .filter(|c| c.role == ClusterRole::SslWriteCandidate)
    }

    /// Clusters whose ref-count matches `SSL_peek` (1 error site). Each is a
    /// candidate for the `SSL_read` two-hop (find `SSL_peek`, then the short
    /// function that calls it first).
    pub fn ssl_peek_candidates(&self) -> impl Iterator<Item = &RefCluster> {
        self.clusters
            .iter()
            .filter(|c| c.role == ClusterRole::SslPeekCandidate)
    }
}

/// Run Stage 1 against a parsed image: find the `ssl_lib.cc` anchor string,
/// scan the executable segment(s) for RIP-relative `lea`s that target it, and
/// proximity-cluster the results.
///
/// Returns `None` if the anchor string is absent (i.e. this binary is not a
/// BoringSSL-in-blob target) or not located in a loadable segment — both are
/// legitimate "nothing to do here" outcomes, not errors.
pub fn find_ssl_lib_clusters(img: &ElfImage, gap: u64) -> Option<XrefResult> {
    let (anchor_file_offset, anchor_string) = find_anchor(img.data())?;
    let anchor_vaddr = img.file_offset_to_vaddr(anchor_file_offset as u64)?;

    // Collect reference sites across all executable segments.
    let mut hits = Vec::new();
    for seg in img.executable_segments() {
        scan_lea_rip_into(seg.bytes, seg.vaddr, anchor_vaddr, &mut hits);
    }
    hits.sort_unstable();
    let total_refs = hits.len();

    let clusters = cluster_refs(&hits, gap)
        .into_iter()
        .map(|refs| {
            let first_vaddr = refs[0];
            let span = refs[refs.len() - 1] - first_vaddr;
            let role = ClusterRole::from_ref_count(refs.len());
            RefCluster {
                ref_vaddrs: refs,
                first_vaddr,
                span,
                role,
            }
        })
        .collect();

    Some(XrefResult {
        anchor_string,
        anchor_file_offset: anchor_file_offset as u64,
        anchor_vaddr,
        total_refs,
        clusters,
    })
}

/// Find the `ssl_lib.cc` anchor and expand it to the full NUL-delimited C
/// string. Returns `(file_offset_of_string_start, string)`. Skips a match whose
/// containing bytes are not a plausible printable C string (guards against the
/// needle appearing inside code or non-string data).
fn find_anchor(data: &[u8]) -> Option<(usize, String)> {
    let mut from = 0usize;
    while from + ANCHOR_NEEDLE.len() <= data.len() {
        let rel = data[from..]
            .windows(ANCHOR_NEEDLE.len())
            .position(|w| w == ANCHOR_NEEDLE)?;
        let pos = from + rel;

        // Expand to the containing C string: [after previous NUL, next NUL).
        let start = data[..pos]
            .iter()
            .rposition(|&b| b == 0)
            .map(|i| i + 1)
            .unwrap_or(0);
        let end = data[pos..]
            .iter()
            .position(|&b| b == 0)
            .map(|i| pos + i)
            .unwrap_or(data.len());

        let s = &data[start..end];
        // Plausible source-path string: bounded length, all printable (tab..~).
        if s.len() <= 512 && s.iter().all(|&b| (0x09..=0x7e).contains(&b)) {
            return Some((start, String::from_utf8_lossy(s).into_owned()));
        }
        from = pos + 1;
    }
    None
}

/// Scan one segment's bytes for `lea reg,[rip+disp32]` instructions whose
/// computed target equals `target_vaddr`, appending each referencing
/// instruction's virtual address to `out`.
///
/// This is a targeted encoding scan, not a full disassembler: it matches the
/// two `lea rip` encodings and checks the resolved target. A run of bytes that
/// both decodes as `lea rip` AND resolves to the exact anchor address by
/// coincidence is astronomically unlikely, so the count is a sound estimate of
/// real reference sites (matches `ws2_xref.py` against objdump ground truth).
fn scan_lea_rip_into(bytes: &[u8], base_vaddr: u64, target_vaddr: u64, out: &mut Vec<u64>) {
    let n = bytes.len();
    if n < 7 {
        return;
    }
    let mut k = 0usize;
    while k + 7 <= n {
        let b0 = bytes[k];

        // REX.W form: 0x48..=0x4f, 0x8d, modrm(mod=00, r/m=101), disp32 — len 7.
        if (0x48..=0x4f).contains(&b0) && bytes[k + 1] == 0x8d && (bytes[k + 2] & 0xc7) == 0x05 {
            let disp = i32::from_le_bytes([bytes[k + 3], bytes[k + 4], bytes[k + 5], bytes[k + 6]]);
            let instr_vaddr = base_vaddr.wrapping_add(k as u64);
            let target = instr_vaddr.wrapping_add(7).wrapping_add(disp as i64 as u64);
            if target == target_vaddr {
                out.push(instr_vaddr);
            }
            k += 1;
            continue;
        }

        // Non-REX form: 0x8d, modrm(mod=00, r/m=101), disp32 — len 6. Guard
        // against double-counting the 0x8d that is the second byte of a
        // REX-prefixed lea (its preceding byte would be a REX prefix).
        let prev_is_rex = k > 0 && (0x40..=0x4f).contains(&bytes[k - 1]);
        if b0 == 0x8d && (bytes[k + 1] & 0xc7) == 0x05 && !prev_is_rex {
            let disp = i32::from_le_bytes([bytes[k + 2], bytes[k + 3], bytes[k + 4], bytes[k + 5]]);
            let instr_vaddr = base_vaddr.wrapping_add(k as u64);
            let target = instr_vaddr.wrapping_add(6).wrapping_add(disp as i64 as u64);
            if target == target_vaddr {
                out.push(instr_vaddr);
            }
        }
        k += 1;
    }
}

/// Split ascending reference addresses into clusters, breaking wherever the gap
/// between consecutive references exceeds `gap`. Input must be sorted ascending.
fn cluster_refs(sorted_hits: &[u64], gap: u64) -> Vec<Vec<u64>> {
    let mut clusters: Vec<Vec<u64>> = Vec::new();
    let mut cur: Vec<u64> = Vec::new();
    for &h in sorted_hits {
        if let Some(&last) = cur.last() {
            if h.saturating_sub(last) > gap {
                clusters.push(std::mem::take(&mut cur));
            }
        }
        cur.push(h);
    }
    if !cur.is_empty() {
        clusters.push(cur);
    }
    clusters
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One REX.W `lea rip` pointing at 0x2000, one at 0x3000, back to back.
    /// (Bytes verified against objdump-equivalent arithmetic.)
    fn two_lea_blob() -> Vec<u8> {
        // 48 8d 05 f9 0f 00 00  -> ref @0x1000, target 0x2000
        // 48 8d 05 f2 1f 00 00  -> ref @0x1007, target 0x3000
        vec![
            0x48, 0x8d, 0x05, 0xf9, 0x0f, 0x00, 0x00, 0x48, 0x8d, 0x05, 0xf2, 0x1f, 0x00, 0x00,
        ]
    }

    #[test]
    fn scan_finds_correct_lea_and_target() {
        let blob = two_lea_blob();
        let mut hits = Vec::new();
        scan_lea_rip_into(&blob, 0x1000, 0x2000, &mut hits);
        assert_eq!(hits, vec![0x1000], "only the 0x2000-targeting lea");

        let mut hits2 = Vec::new();
        scan_lea_rip_into(&blob, 0x1000, 0x3000, &mut hits2);
        assert_eq!(hits2, vec![0x1007], "only the 0x3000-targeting lea");
    }

    #[test]
    fn scan_does_not_double_count_rex_lea() {
        // The 0x8d at offset+1 of a REX.W lea must not be counted as a separate
        // non-REX lea (the guard keys on the preceding REX byte).
        let blob = two_lea_blob();
        let mut hits = Vec::new();
        scan_lea_rip_into(&blob, 0x1000, 0x2000, &mut hits);
        assert_eq!(hits.len(), 1, "no phantom non-REX match one byte in");
    }

    #[test]
    fn clustering_splits_on_gap() {
        let hits = [0x100u64, 0x110, 0x5000, 0x5008, 0x5010];
        let clusters = cluster_refs(&hits, 0x1000);
        assert_eq!(clusters.len(), 2);
        assert_eq!(clusters[0], vec![0x100, 0x110]);
        assert_eq!(clusters[1], vec![0x5000, 0x5008, 0x5010]);
    }

    #[test]
    fn role_from_ref_count() {
        assert_eq!(ClusterRole::from_ref_count(4), ClusterRole::SslWriteCandidate);
        assert_eq!(ClusterRole::from_ref_count(1), ClusterRole::SslPeekCandidate);
        assert_eq!(ClusterRole::from_ref_count(2), ClusterRole::Other);
        assert_eq!(ClusterRole::from_ref_count(13), ClusterRole::Other);
    }

    #[test]
    fn find_anchor_expands_to_full_cstring() {
        // NUL, full path, NUL — find_anchor should return the path start + text.
        let mut data = vec![0u8];
        let path = b"../../third_party/boringssl/src/ssl/ssl_lib.cc";
        data.extend_from_slice(path);
        data.push(0);
        let (start, s) = find_anchor(&data).expect("anchor found");
        assert_eq!(start, 1, "string starts right after the leading NUL");
        assert_eq!(s.as_bytes(), path);
    }

    /// Real-target Stage-1 run. Ignored by default; reproduces ws2_xref.py:
    ///   WS2_TARGET=/usr/share/code/code cargo test -p promptrail-daemon \
    ///       offset_discovery::pattern -- --ignored --nocapture
    /// Expect: 39 total refs, 12 clusters (default gap), exactly one 4-ref
    /// (SSL_write) cluster, and a small set of 1-ref (SSL_peek) clusters.
    #[test]
    #[ignore]
    fn probe_real_clusters() {
        let Ok(path) = std::env::var("WS2_TARGET") else {
            return;
        };
        let img = ElfImage::parse(std::path::Path::new(&path)).expect("parse target");
        let res = find_ssl_lib_clusters(&img, DEFAULT_CLUSTER_GAP).expect("anchor found");
        eprintln!("anchor       = {:?}", res.anchor_string);
        eprintln!(
            "anchor vaddr = 0x{:x}  file_offset = 0x{:x}",
            res.anchor_vaddr, res.anchor_file_offset
        );
        eprintln!("total refs   = {}", res.total_refs);
        eprintln!("clusters     = {}", res.clusters.len());
        for (i, c) in res.clusters.iter().enumerate() {
            eprintln!(
                "  [{i:2}] first=0x{:x} refs={} span={}B role={:?}",
                c.first_vaddr,
                c.ref_count(),
                c.span,
                c.role
            );
        }
        let writes = res.ssl_write_candidates().count();
        let peeks = res.ssl_peek_candidates().count();
        eprintln!("SSL_write candidates = {writes}  (expect 1)");
        eprintln!("SSL_peek  candidates = {peeks}");
        assert!(writes >= 1, "expected at least one 4-ref SSL_write cluster");
    }
}