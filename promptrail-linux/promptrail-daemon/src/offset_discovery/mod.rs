//! Dynamic offset discovery for stripped, statically-linked BoringSSL
//! (Workstream 2). This module resolves the file offsets of `SSL_write` /
//! `SSL_read` inside a stripped Electron/VS Code binary so the existing eBPF
//! capture path can attach uprobes to them by offset — the symbol table is
//! absent, so attach-by-name is impossible (confirmed on VS Code 1.128.0:
//! `/usr/share/code/code`, 200 MiB, PIE, stripped, no `SSL_*` symbols).
//!
//! ## Module layout (built one stage at a time)
//!   * `mod` (this file) — version-independent ELF/PIE primitives + the shared
//!     `OffsetCandidate` type. Nothing here knows about BoringSSL specifics; it
//!     is pure ELF machinery every later stage builds on.
//!   * `pattern`  (Stage 2, later) — the three-stage discovery funnel:
//!       1. rodata-string xref (`ssl_lib.cc`) → localize to BoringSSL's ssl_lib
//!          translation unit as a small set of per-function reference clusters,
//!       2. structural/disassembly predicate per candidate function,
//!       3. confidence scoring on survivors.
//!   * `attach`   (Stage 3, later) — uprobe attach by `AbsoluteOffset`, plus
//!     inotify-driven re-discovery on binary change.
//!   * `cache`    (Stage 4, later) — build-id-keyed `OffsetCandidate` cache.
//!
//! ## THE ATTACH QUANTITY IS A FILE OFFSET — NOT A RUNTIME ADDRESS
//!
//! aya 0.14.0's `UProbeAttachLocation::AbsoluteOffset(u64)` is documented in
//! crate source as "The offset in the target object file, in bytes", and the
//! kernel uprobe contract attaches by (inode, file_offset); it resolves the VMA
//! and handles ASLR/PIE itself. So every offset this module produces is a FILE
//! OFFSET into the ELF on disk. We deliberately do NOT compute runtime virtual
//! addresses for attachment and do NOT read `/proc/<pid>/maps` at attach time.
//! (The Step-3 brief's `file_offset + (maps_start - load_vaddr)` formula was
//! struck: it computes a runtime VA, the wrong quantity for `AbsoluteOffset`.)
//!
//! The one place virtual addresses appear is *internally*: the Stage-1 xref
//! yields reference *virtual addresses* (from RIP-relative `lea` targets), which
//! we convert to file offsets via [`ElfImage::vaddr_to_file_offset`] before they
//! ever leave this module as an [`OffsetCandidate`].
//!
//! ## Robustness note
//! This parser reads an untrusted, third-party 200 MiB binary that updates
//! silently (VS Code auto-update). Every field access is bounds-checked; the
//! parser must never panic on a malformed or hostile file — it returns
//! `DiscoveryError` instead. See the module review notes for the threat-model
//! discussion of a deliberately adversarial binary.

use std::path::Path;

use thiserror::Error;

// ---------------------------------------------------------------------------
// ELF64 constants (only what this module needs; x86-64 little-endian only).
// ---------------------------------------------------------------------------

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_DYN: u16 = 3; // PIE / shared object
const EM_X86_64: u16 = 0x3e;

const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const PF_X: u32 = 0x1;

const NT_GNU_BUILD_ID: u32 = 3;

// ELF64 header field offsets.
const EH_TYPE: usize = 16;
const EH_MACHINE: usize = 18;
const EH_PHOFF: usize = 32;
const EH_PHENTSIZE: usize = 54;
const EH_PHNUM: usize = 56;
const EH_MIN_SIZE: usize = 64;

// ELF64 program-header field offsets (within one 56-byte entry).
const PH_TYPE: usize = 0;
const PH_FLAGS: usize = 4;
const PH_OFFSET: usize = 8;
const PH_VADDR: usize = 16;
const PH_FILESZ: usize = 32;
const PH_MEMSZ: usize = 40;
const PH_ENTSIZE_MIN: usize = 56;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failures parsing or reasoning about a target ELF image. All are non-fatal to
/// the daemon: a target we cannot parse is simply not hooked (and reported),
/// exactly as an Opaque process with no discoverable offset would be.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("failed to read target binary `{path}`")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// The file is not an ELF we can process. Carries a short reason for logs.
    #[error("`{path}` is not a supported ELF ({reason})")]
    NotSupportedElf { path: String, reason: &'static str },

    /// A structural field pointed outside the file. Indicates truncation or a
    /// crafted header; we refuse to read out of bounds.
    #[error("malformed ELF `{path}`: {reason}")]
    Malformed { path: String, reason: &'static str },

    /// No executable `PT_LOAD` segment — nothing to scan or attach into.
    #[error("`{path}` has no executable PT_LOAD segment")]
    NoExecutableSegment { path: String },
}

// ---------------------------------------------------------------------------
// Shared output type
// ---------------------------------------------------------------------------

/// Which BoringSSL entry point a candidate resolves. Only the classic API is
/// relevant for VS Code: the pinned BoringSSL commit
/// (`d8be2b4a71155bf82da092ef543176351eeb59ff`, from Chromium 148.0.7778.271)
/// has NO `SSL_write_ex`/`SSL_read_ex` — verified in `ssl/ssl_lib.cc`. So the
/// classic entry/return capture path (return value == byte count,
/// `count_ptr == 0`) is correct and the `_ex` programs are never attached here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetFn {
    SslWrite,
    SslRead,
}

impl TargetFn {
    pub fn as_str(self) -> &'static str {
        match self {
            TargetFn::SslWrite => "SSL_write",
            TargetFn::SslRead => "SSL_read",
        }
    }
}

/// A ranked candidate location for a target function.
///
/// `offset` is a FILE OFFSET into the target ELF — the exact value handed to
/// aya's `UProbeAttachLocation::AbsoluteOffset` (see module docs). It is NEVER a
/// runtime virtual address; no ASLR correction is applied because the kernel
/// performs VMA/ASLR resolution itself given (inode, file_offset).
///
/// `confidence` is produced by Stage-3 scoring in `[0.0, 1.0]`; higher means
/// more of the structural predicate matched. `pattern_id` names the specific
/// rule/heuristic that produced the candidate, so a low-confidence attach can be
/// traced back to which reasoning fired (and so a bad rule can be disabled
/// without touching the others).
#[derive(Debug, Clone)]
pub struct OffsetCandidate {
    pub target: TargetFn,
    pub offset: u64,
    pub confidence: f32,
    pub pattern_id: &'static str,
}

// ---------------------------------------------------------------------------
// Parsed ELF image
// ---------------------------------------------------------------------------

/// One `PT_LOAD` segment, reduced to the fields this module needs.
#[derive(Debug, Clone, Copy)]
struct LoadSegment {
    file_offset: u64,
    vaddr: u64,
    file_size: u64,
    executable: bool,
}

impl LoadSegment {
    #[inline]
    fn contains_vaddr(&self, va: u64) -> bool {
        va >= self.vaddr && va < self.vaddr.saturating_add(self.file_size)
    }
    #[inline]
    fn contains_file_offset(&self, fo: u64) -> bool {
        fo >= self.file_offset && fo < self.file_offset.saturating_add(self.file_size)
    }
}

/// A parsed ELF64 image held wholly in memory.
///
/// We read the whole file rather than mmap it: the daemon parses on discovery
/// (a rare event, not the datapath), 200 MiB is affordable, and owning the bytes
/// avoids a live mapping that could change under us mid-parse if the file is
/// replaced by VS Code auto-update (TOCTOU). The bytes are a snapshot of one
/// inode; Stage 3 binds the attach to that same inode.
pub struct ElfImage {
    path: String,
    data: Vec<u8>,
    is_pie: bool,
    loads: Vec<LoadSegment>,
    /// Raw `NT_GNU_BUILD_ID` bytes, if present. This is the cache key in Stage 4
    /// and the "did the binary really change" discriminator in Stage 3. May be
    /// `None`: not all builds embed one, so callers must have a fallback (e.g.
    /// content hash) rather than assuming it exists.
    build_id: Option<Vec<u8>>,
}

impl ElfImage {
    /// Parse the ELF at `path`. Reads the whole file. Rejects anything that is
    /// not a little-endian ELF64 x86-64 object with at least one executable
    /// `PT_LOAD`. Never panics on malformed input.
    pub fn parse(path: &Path) -> Result<Self, DiscoveryError> {
        let path_str = path.display().to_string();
        let data = std::fs::read(path).map_err(|source| DiscoveryError::Read {
            path: path_str.clone(),
            source,
        })?;

        if data.len() < EH_MIN_SIZE || &data[..4] != ELF_MAGIC {
            return Err(DiscoveryError::NotSupportedElf {
                path: path_str,
                reason: "not an ELF file",
            });
        }
        if data[4] != ELFCLASS64 || data[5] != ELFDATA2LSB {
            return Err(DiscoveryError::NotSupportedElf {
                path: path_str,
                reason: "not ELF64 little-endian",
            });
        }
        let e_type = read_u16(&data, EH_TYPE);
        let e_machine = read_u16(&data, EH_MACHINE);
        if e_machine != EM_X86_64 {
            return Err(DiscoveryError::NotSupportedElf {
                path: path_str,
                reason: "not x86-64",
            });
        }
        let is_pie = e_type == ET_DYN;

        let e_phoff = read_u64(&data, EH_PHOFF);
        let e_phentsize = read_u16(&data, EH_PHENTSIZE) as usize;
        let e_phnum = read_u16(&data, EH_PHNUM) as usize;
        if e_phentsize < PH_ENTSIZE_MIN {
            return Err(DiscoveryError::Malformed {
                path: path_str,
                reason: "program-header entry smaller than ELF64 spec",
            });
        }

        let mut loads = Vec::new();
        let mut note_ranges = Vec::new();
        for i in 0..e_phnum {
            // Bounds-check the whole entry before touching any field.
            let base = match e_phoff
                .checked_add((i as u64).saturating_mul(e_phentsize as u64))
            {
                Some(b) => b as usize,
                None => break,
            };
            if base
                .checked_add(PH_ENTSIZE_MIN)
                .is_none_or(|end| end > data.len())
            {
                return Err(DiscoveryError::Malformed {
                    path: path_str,
                    reason: "program header extends past end of file",
                });
            }
            let p_type = read_u32(&data, base + PH_TYPE);
            let p_flags = read_u32(&data, base + PH_FLAGS);
            let p_offset = read_u64(&data, base + PH_OFFSET);
            let p_vaddr = read_u64(&data, base + PH_VADDR);
            let p_filesz = read_u64(&data, base + PH_FILESZ);
            let _p_memsz = read_u64(&data, base + PH_MEMSZ);

            match p_type {
                PT_LOAD => loads.push(LoadSegment {
                    file_offset: p_offset,
                    vaddr: p_vaddr,
                    file_size: p_filesz,
                    executable: (p_flags & PF_X) != 0,
                }),
                PT_NOTE => note_ranges.push((p_offset, p_filesz)),
                _ => {}
            }
        }

        if !loads.iter().any(|l| l.executable) {
            return Err(DiscoveryError::NoExecutableSegment { path: path_str });
        }

        // Validate every PT_LOAD's file range lies within the file, so later
        // slicing on these segments is guaranteed in-bounds.
        for l in &loads {
            let end = l.file_offset.saturating_add(l.file_size);
            if end > data.len() as u64 {
                return Err(DiscoveryError::Malformed {
                    path: path_str,
                    reason: "PT_LOAD file range extends past end of file",
                });
            }
        }

        let build_id = parse_build_id(&data, &note_ranges);

        Ok(ElfImage {
            path: path_str,
            data,
            is_pie,
            loads,
            build_id,
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn is_pie(&self) -> bool {
        self.is_pie
    }

    /// Raw build-id bytes if the binary embeds `NT_GNU_BUILD_ID`.
    pub fn build_id(&self) -> Option<&[u8]> {
        self.build_id.as_deref()
    }

    /// Lowercase hex of the build-id, for logging and as the Stage-4 cache key.
    pub fn build_id_hex(&self) -> Option<String> {
        self.build_id.as_ref().map(|b| {
            let mut s = String::with_capacity(b.len() * 2);
            for byte in b {
                s.push_str(&format!("{byte:02x}"));
            }
            s
        })
    }

    /// Map a runtime virtual address to a file offset via the containing
    /// `PT_LOAD`. This is the ONLY correct VA→file-offset conversion (it uses
    /// each segment's own `p_vaddr`/`p_offset`, NOT `/proc/maps` runtime bases).
    /// Used to turn Stage-1 xref reference VAs into the file offsets that become
    /// `OffsetCandidate::offset`. Returns `None` if `va` is not in any segment.
    pub fn vaddr_to_file_offset(&self, va: u64) -> Option<u64> {
        self.loads
            .iter()
            .find(|l| l.contains_vaddr(va))
            .map(|l| l.file_offset + (va - l.vaddr))
    }

    /// Inverse of [`vaddr_to_file_offset`], for reporting/diagnostics only —
    /// never used to produce an attach offset.
    pub fn file_offset_to_vaddr(&self, fo: u64) -> Option<u64> {
        self.loads
            .iter()
            .find(|l| l.contains_file_offset(fo))
            .map(|l| l.vaddr + (fo - l.file_offset))
    }

    /// Byte slices of the executable `PT_LOAD` segment(s), paired with the file
    /// offset each slice starts at. Stage 2 scans these for candidate prologues
    /// and instruction structure. Slicing is safe: every segment's file range
    /// was validated in-bounds during `parse`.
    pub fn executable_segments(&self) -> Vec<ExecSegment<'_>> {
        self.loads
            .iter()
            .filter(|l| l.executable)
            .map(|l| ExecSegment {
                file_offset: l.file_offset,
                vaddr: l.vaddr,
                bytes: &self.data[l.file_offset as usize
                    ..(l.file_offset + l.file_size) as usize],
            })
            .collect()
    }

    /// Whole-file byte view (for rodata string search in Stage 1, which is not
    /// confined to executable segments).
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// A borrowed view of one executable segment: its bytes plus the file offset and
/// virtual address the bytes begin at, so a match index `i` maps to file offset
/// `file_offset + i` (the attach quantity) and vaddr `vaddr + i`.
pub struct ExecSegment<'a> {
    pub file_offset: u64,
    pub vaddr: u64,
    pub bytes: &'a [u8],
}

// ---------------------------------------------------------------------------
// Build-id note parsing (walks PT_NOTE; robust to a stripped section table)
// ---------------------------------------------------------------------------

/// Walk each `PT_NOTE` region for an `NT_GNU_BUILD_ID` note with name "GNU".
/// Note layout (ELF64): namesz(u32) descsz(u32) type(u32), then name padded to
/// 4 bytes, then desc padded to 4 bytes. We read from PT_NOTE (a program
/// header) rather than `.note.gnu.build-id` (a section) so it works on a
/// stripped binary whose section table may be absent. All arithmetic is
/// checked; a malformed note simply ends the walk rather than panicking.
fn parse_build_id(data: &[u8], note_ranges: &[(u64, u64)]) -> Option<Vec<u8>> {
    for &(off, sz) in note_ranges {
        let start = off as usize;
        let end = (off.checked_add(sz)? as usize).min(data.len());
        let mut p = start;
        while p + 12 <= end {
            let namesz = read_u32(data, p) as usize;
            let descsz = read_u32(data, p + 4) as usize;
            let ntype = read_u32(data, p + 8);
            p += 12;

            let name_end = p.checked_add(namesz)?;
            let name_padded = p.checked_add((namesz + 3) & !3)?;
            let desc_start = name_padded;
            let desc_end = desc_start.checked_add(descsz)?;
            let desc_padded = desc_start.checked_add((descsz + 3) & !3)?;
            if name_end > end || desc_end > end {
                break;
            }

            // A GNU build-id note: type is NT_GNU_BUILD_ID and the name field
            // is "GNU" (namesz is 4, counting the trailing NUL). Match on the
            // first three bytes so a namesz of 3 or 4 both work.
            if ntype == NT_GNU_BUILD_ID && namesz >= 3 && &data[p..p + 3] == b"GNU" {
                return Some(data[desc_start..desc_end].to_vec());
            }
            p = desc_padded;
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Bounds-checked little-endian readers. Callers guarantee the offset is in
// range (validated during parse); these use fixed-size slices and cannot panic
// for in-range offsets. For defense in depth against an arithmetic slip they
// saturate to 0 rather than panic on a short/out-of-range read.
// ---------------------------------------------------------------------------

#[inline]
fn read_u16(data: &[u8], off: usize) -> u16 {
    match data.get(off..off + 2) {
        Some(b) => u16::from_le_bytes([b[0], b[1]]),
        None => 0,
    }
}

#[inline]
fn read_u32(data: &[u8], off: usize) -> u32 {
    match data.get(off..off + 4) {
        Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        None => 0,
    }
}

#[inline]
fn read_u64(data: &[u8], off: usize) -> u64 {
    match data.get(off..off + 8) {
        Some(b) => u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse the test runner's own executable — a real PIE ELF64 — and assert
    /// the primitives hold. This needs no fixture file and runs anywhere the
    /// daemon builds.
    #[test]
    fn parses_own_executable() {
        let exe = std::env::current_exe().expect("current_exe");
        let img = ElfImage::parse(&exe).expect("parse self");
        assert!(img.is_pie(), "test binaries are normally PIE");
        assert!(
            !img.executable_segments().is_empty(),
            "must have an executable segment"
        );
        // Round-trip the exec segment start through both mappings.
        let seg = &img.executable_segments()[0];
        let fo = seg.file_offset;
        let va = img.file_offset_to_vaddr(fo).expect("fo->va");
        assert_eq!(img.vaddr_to_file_offset(va), Some(fo), "mapping round-trip");
    }

    #[test]
    fn rejects_non_elf() {
        let dir = std::env::temp_dir().join("promptrail_notelf_test");
        std::fs::write(&dir, b"not an elf at all, just some bytes........").unwrap();
        let err = ElfImage::parse(&dir).unwrap_err();
        assert!(matches!(err, DiscoveryError::NotSupportedElf { .. }));
        let _ = std::fs::remove_file(&dir);
    }
}