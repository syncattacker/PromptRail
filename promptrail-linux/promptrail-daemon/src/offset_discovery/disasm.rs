//! Stage 2, part A: disassembly primitives and a real-target *structure
//! diagnostic*. This file deliberately makes NO discovery decision and produces
//! NO [`super::OffsetCandidate`]. Its job is to reveal, from the real binary,
//! the actual instruction structure of the Stage-1 candidate functions so the
//! Stage-2 *predicate* (next file) can be written against ground truth rather
//! than against a different toolchain's output.
//!
//! ## Why a diagnostic first
//! The structural signatures we expect for `SSL_write`/`SSL_read` (e.g. two
//! calls near entry, `cmp [reg+0xNN],0` null-checks of `SSL`/`BIO` pointer
//! fields, `SSL_read` calling `SSL_peek` first) were derived from BoringSSL
//! compiled with g++, which does NOT reliably match Chromium's clang + LTO +
//! PGO layout at the instruction level. So we treat those as a *reference
//! structure the predicate will encode*, NOT as a hard-coded constant — and we
//! confirm the real structure empirically here before encoding anything.
//!
//! ## What Stage 1 handed us (validated on the real target)
//!   * exactly one 4-ref `SSL_write` candidate cluster at ref-site `0x331e00a`,
//!   * five 1-ref `SSL_peek` candidate clusters (only ~3 stable across gap
//!     changes; the predicate disambiguates to the real `SSL_peek`).
//! A cluster address is a `lea` *reference site inside* a function, not its
//! entry, so this file back-walks each to the function entry before decoding.
//!
//! ## Entry back-walk
//! This Electron build has NO `endbr64` (CET disabled) but IS built with frame
//! pointers, so functions begin `push rbp; mov rbp,rsp` (`55 48 89 e5`). We
//! back-scan from a reference site to the nearest preceding such prologue and
//! report the byte before it (a `ret`/`int3`/`nop` padding boundary is the
//! confirmation that it is a real function entry, not a mid-function frame
//! setup). The diagnostic prints these so a human verifies the back-walk.

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};

use super::ElfImage;

/// x86-64 frame-pointer prologue: `push rbp; mov rbp,rsp`. The entry anchor for
/// this CET-less, frame-pointer-full build.
const PROLOGUE: [u8; 4] = [0x55, 0x48, 0x89, 0xe5];

/// How far back from a reference site to look for the function entry. `SSL_write`
/// and `SSL_peek` are small; 16 KiB is comfortably more than their body size.
const ENTRY_BACKSCAN_WINDOW: usize = 16 * 1024;

/// A decoded instruction reduced to the structural facts the predicate cares
/// about. Positional data (`ip`, `len`) is kept so the diagnostic can print
/// offsets from the function entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsnCat {
    /// Direct near `call rel32` (target resolved) or indirect call (`None`).
    Call { target: Option<u64> },
    /// `jmp`/`jcc`. `conditional` distinguishes `jcc` from `jmp`; indirect → `None`.
    Jmp { target: Option<u64>, conditional: bool },
    /// A `ret`.
    Ret,
    /// `cmp`/`test` of a memory operand against an immediate — the shape of a
    /// struct-field null/flag check (`cmp qword [reg+disp], imm`). Captures the
    /// base register and displacement, which is exactly the fingerprint that
    /// distinguishes `SSL_write`'s pointer-field checks.
    CmpMemImm { base: Register, disp: u64, imm: u64 },
    /// `cmp`/`test` of two registers (e.g. `test rax,rax` null-check).
    CmpReg,
    /// `lea` — RIP-relative target captured when present (this is how the
    /// Stage-1 `ssl_lib.cc` references appear at the instruction level).
    Lea { ip_rel_target: Option<u64> },
    /// Anything else (mov, arithmetic, prologue pieces, …).
    Other,
}

/// One decoded instruction: its virtual address, byte length, and category.
#[derive(Debug, Clone)]
pub struct Decoded {
    pub ip: u64,
    pub len: usize,
    pub cat: InsnCat,
}

/// Compact structural summary of a decoded function body, for logging and (in
/// the next file) for scoring.
#[derive(Debug, Clone, Default)]
pub struct FnFingerprint {
    pub insn_count: usize,
    pub direct_call_targets: Vec<u64>,
    pub indirect_calls: usize,
    /// `(base_register, displacement)` of each `cmp/test [reg+disp], imm`.
    pub cmp_mem_fields: Vec<(Register, u64)>,
    pub cmp_reg_count: usize,
    pub cond_branches: usize,
    pub rets: usize,
}

impl FnFingerprint {
    fn from_decoded(insns: &[Decoded]) -> Self {
        let mut f = FnFingerprint {
            insn_count: insns.len(),
            ..Default::default()
        };
        for d in insns {
            match d.cat {
                InsnCat::Call { target: Some(t) } => f.direct_call_targets.push(t),
                InsnCat::Call { target: None } => f.indirect_calls += 1,
                InsnCat::Jmp {
                    conditional: true, ..
                } => f.cond_branches += 1,
                InsnCat::Ret => f.rets += 1,
                InsnCat::CmpMemImm { base, disp, .. } => f.cmp_mem_fields.push((base, disp)),
                InsnCat::CmpReg => f.cmp_reg_count += 1,
                _ => {}
            }
        }
        f
    }
}

/// Locate the executable segment containing `vaddr`, returning `(bytes, base_vaddr)`.
fn exec_segment_for<'a>(img: &'a ElfImage, vaddr: u64) -> Option<(&'a [u8], u64)> {
    img.executable_segments().into_iter().find_map(|s| {
        let end = s.vaddr + s.bytes.len() as u64;
        if vaddr >= s.vaddr && vaddr < end {
            Some((s.bytes, s.vaddr))
        } else {
            None
        }
    })
}

/// Back-walk from a reference site to the nearest preceding frame-pointer
/// prologue (`55 48 89 e5`) — the function entry for this build. Returns
/// `(entry_vaddr, preceding_byte)`; the preceding byte lets a caller sanity-check
/// that the entry follows a padding/terminator boundary.
pub fn find_prologue_entry(
    seg_bytes: &[u8],
    base_vaddr: u64,
    ref_vaddr: u64,
    window: usize,
) -> Option<(u64, u8)> {
    let ref_off = ref_vaddr.checked_sub(base_vaddr)? as usize;
    if ref_off >= seg_bytes.len() {
        return None;
    }
    let lo = ref_off.saturating_sub(window);
    // Scan downward for the highest offset <= ref_off whose 4 bytes are the
    // prologue. `p` can reach ref_off itself (a ref site could be right at a
    // tiny function's entry, though not expected here).
    let mut p = ref_off.min(seg_bytes.len().saturating_sub(PROLOGUE.len()));
    loop {
        if seg_bytes[p..p + PROLOGUE.len()] == PROLOGUE {
            let prev = if p > 0 { seg_bytes[p - 1] } else { 0 };
            return Some((base_vaddr + p as u64, prev));
        }
        if p <= lo {
            return None;
        }
        p -= 1;
    }
}

/// Decode forward from `entry`, classifying each instruction, stopping at
/// `max_insns` or after the 2nd `ret` (enough to capture a small function's
/// shape without running into the next function).
pub fn decode_function(
    seg_bytes: &[u8],
    base_vaddr: u64,
    entry: u64,
    max_insns: usize,
) -> Vec<Decoded> {
    let Some(off) = entry.checked_sub(base_vaddr) else {
        return Vec::new();
    };
    let off = off as usize;
    if off >= seg_bytes.len() {
        return Vec::new();
    }
    let data = &seg_bytes[off..];
    let mut dec = Decoder::with_ip(64, data, entry, DecoderOptions::NONE);
    let mut out = Vec::new();
    let mut rets = 0usize;
    while dec.can_decode() && out.len() < max_insns {
        let insn = dec.decode();
        let cat = classify(&insn);
        let is_ret = matches!(cat, InsnCat::Ret);
        out.push(Decoded {
            ip: insn.ip(),
            len: insn.len(),
            cat,
        });
        if is_ret {
            rets += 1;
            if rets >= 2 {
                break;
            }
        }
    }
    out
}

/// Classify one decoded instruction into an [`InsnCat`].
fn classify(insn: &Instruction) -> InsnCat {
    match insn.flow_control() {
        FlowControl::Call => InsnCat::Call {
            target: Some(insn.near_branch_target()),
        },
        FlowControl::IndirectCall => InsnCat::Call { target: None },
        FlowControl::UnconditionalBranch => InsnCat::Jmp {
            target: Some(insn.near_branch_target()),
            conditional: false,
        },
        FlowControl::ConditionalBranch => InsnCat::Jmp {
            target: Some(insn.near_branch_target()),
            conditional: true,
        },
        FlowControl::IndirectBranch => InsnCat::Jmp {
            target: None,
            conditional: false,
        },
        FlowControl::Return => InsnCat::Ret,
        _ => classify_data(insn),
    }
}

/// Classify a non-flow instruction (the `lea`/`cmp`/`test` shapes we care about).
fn classify_data(insn: &Instruction) -> InsnCat {
    let m = insn.mnemonic();
    if m == Mnemonic::Lea {
        return if insn.is_ip_rel_memory_operand() {
            InsnCat::Lea {
                ip_rel_target: Some(insn.ip_rel_memory_address()),
            }
        } else {
            InsnCat::Lea {
                ip_rel_target: None,
            }
        };
    }
    if m == Mnemonic::Cmp || m == Mnemonic::Test {
        if insn.op_count() >= 2
            && insn.op_kind(0) == OpKind::Memory
            && is_immediate_opkind(insn.op_kind(1))
        {
            return InsnCat::CmpMemImm {
                base: insn.memory_base(),
                disp: insn.memory_displacement64(),
                imm: insn.immediate(1),
            };
        }
        if insn.op_count() >= 2
            && insn.op_kind(0) == OpKind::Register
            && insn.op_kind(1) == OpKind::Register
        {
            return InsnCat::CmpReg;
        }
    }
    InsnCat::Other
}

fn is_immediate_opkind(k: OpKind) -> bool {
    matches!(
        k,
        OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

/// Human-readable register name for the GPRs and RIP we might print. Falls back
/// to `"reg"` for anything outside that set (we only need base-register identity
/// for the struct-field-check fingerprint).
pub fn reg_name(r: Register) -> &'static str {
    match r {
        Register::RAX => "rax",
        Register::RCX => "rcx",
        Register::RDX => "rdx",
        Register::RBX => "rbx",
        Register::RSP => "rsp",
        Register::RBP => "rbp",
        Register::RSI => "rsi",
        Register::RDI => "rdi",
        Register::R8 => "r8",
        Register::R9 => "r9",
        Register::R10 => "r10",
        Register::R11 => "r11",
        Register::R12 => "r12",
        Register::R13 => "r13",
        Register::R14 => "r14",
        Register::R15 => "r15",
        Register::RIP => "rip",
        Register::None => "none",
        _ => "reg",
    }
}

/// Render one instruction's category compactly for the diagnostic dump.
fn cat_str(cat: &InsnCat) -> String {
    match cat {
        InsnCat::Call { target: Some(t) } => format!("call    -> 0x{t:x}"),
        InsnCat::Call { target: None } => "call    (indirect)".to_string(),
        InsnCat::Jmp {
            target: Some(t),
            conditional: true,
        } => format!("jcc     -> 0x{t:x}"),
        InsnCat::Jmp {
            target: Some(t),
            conditional: false,
        } => format!("jmp     -> 0x{t:x}"),
        InsnCat::Jmp { target: None, .. } => "jmp     (indirect)".to_string(),
        InsnCat::Ret => "ret".to_string(),
        InsnCat::CmpMemImm { base, disp, imm } => {
            format!("cmp/test [{}+0x{:x}], 0x{:x}", reg_name(*base), disp, imm)
        }
        InsnCat::CmpReg => "cmp/test reg,reg".to_string(),
        InsnCat::Lea {
            ip_rel_target: Some(t),
        } => format!("lea     [rip] -> 0x{t:x}"),
        InsnCat::Lea {
            ip_rel_target: None,
        } => "lea".to_string(),
        InsnCat::Other => "..".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_one(bytes: &[u8], ip: u64) -> InsnCat {
        let mut dec = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
        let insn = dec.decode();
        classify(&insn)
    }

    #[test]
    fn classify_ret() {
        assert_eq!(decode_one(&[0xc3], 0x1000), InsnCat::Ret);
    }

    #[test]
    fn classify_call_rel32() {
        // e8 00000000 at 0x1000 -> target 0x1000 + 5 + 0 = 0x1005
        let cat = decode_one(&[0xe8, 0x00, 0x00, 0x00, 0x00], 0x1000);
        assert_eq!(
            cat,
            InsnCat::Call {
                target: Some(0x1005)
            }
        );
    }

    #[test]
    fn classify_cmp_mem_imm() {
        // 48 83 bf 98 00 00 00 00 = cmp qword ptr [rdi+0x98], 0
        let cat = decode_one(&[0x48, 0x83, 0xbf, 0x98, 0x00, 0x00, 0x00, 0x00], 0x1000);
        assert_eq!(
            cat,
            InsnCat::CmpMemImm {
                base: Register::RDI,
                disp: 0x98,
                imm: 0
            }
        );
    }

    #[test]
    fn classify_test_reg() {
        // 48 85 c0 = test rax, rax
        assert_eq!(decode_one(&[0x48, 0x85, 0xc0], 0x1000), InsnCat::CmpReg);
    }

    #[test]
    fn classify_lea_iprel() {
        // 48 8d 35 34 12 00 00 = lea rsi,[rip+0x1234] at 0x1000
        // target = 0x1000 + 7 + 0x1234 = 0x223b
        let cat = decode_one(&[0x48, 0x8d, 0x35, 0x34, 0x12, 0x00, 0x00], 0x1000);
        assert_eq!(
            cat,
            InsnCat::Lea {
                ip_rel_target: Some(0x223b)
            }
        );
    }

    #[test]
    fn prologue_entry_backwalk() {
        // padding(int3 x2) | prologue | body...   ref points into the body.
        let seg = [
            0xcc, 0xcc, // padding
            0x55, 0x48, 0x89, 0xe5, // prologue @ off 2
            0x48, 0x83, 0xec, 0x20, // sub rsp,0x20 (body)
        ];
        let base = 0x2000u64;
        let ref_vaddr = 0x2008; // inside the body
        let (entry, prev) = find_prologue_entry(&seg, base, ref_vaddr, 4096).expect("entry");
        assert_eq!(entry, 0x2002, "entry at the prologue");
        assert_eq!(prev, 0xcc, "preceding byte is int3 padding");
    }

    /// Real-target STRUCTURE DIAGNOSTIC. Ignored by default. Dumps the actual
    /// instruction shape of the Stage-1 candidates so the Stage-2 predicate can
    /// be written against ground truth. Run:
    ///   WS2_TARGET=/usr/share/code/code cargo test -p promptrail-daemon \
    ///       offset_discovery::disasm -- --ignored --nocapture
    #[test]
    #[ignore]
    fn probe_real_structure() {
        use super::super::pattern::{find_ssl_lib_clusters, ClusterRole, DEFAULT_CLUSTER_GAP};

        let Ok(path) = std::env::var("WS2_TARGET") else {
            return;
        };
        let img = ElfImage::parse(std::path::Path::new(&path)).expect("parse target");
        let xref = find_ssl_lib_clusters(&img, DEFAULT_CLUSTER_GAP).expect("anchor");

        let mut targets: Vec<(&'static str, u64)> = Vec::new();
        for c in &xref.clusters {
            match c.role {
                ClusterRole::SslWriteCandidate => targets.push(("SSL_write", c.first_vaddr)),
                ClusterRole::SslPeekCandidate => targets.push(("SSL_peek? ", c.first_vaddr)),
                ClusterRole::Other => {}
            }
        }

        for (label, ref_vaddr) in targets {
            eprintln!("\n=== {label} candidate: ref-site 0x{ref_vaddr:x} ===");
            let Some((seg, base)) = exec_segment_for(&img, ref_vaddr) else {
                eprintln!("  (no exec segment?!)");
                continue;
            };
            let Some((entry, prev)) =
                find_prologue_entry(seg, base, ref_vaddr, ENTRY_BACKSCAN_WINDOW)
            else {
                eprintln!("  entry: NOT FOUND within {ENTRY_BACKSCAN_WINDOW}B back-scan");
                continue;
            };
            let eoff = (entry - base) as usize;
            let first16: Vec<String> = seg[eoff..(eoff + 16).min(seg.len())]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            eprintln!(
                "  entry = 0x{entry:x}  (prec byte 0x{prev:02x}, back {}B)  first16: {}",
                ref_vaddr - entry,
                first16.join(" ")
            );

            let insns = decode_function(seg, base, entry, 80);
            for d in &insns {
                eprintln!("    +0x{:<4x} {}", d.ip - entry, cat_str(&d.cat));
            }
            let fp = FnFingerprint::from_decoded(&insns);
            let fields: Vec<String> = fp
                .cmp_mem_fields
                .iter()
                .map(|(r, d)| format!("[{}+0x{:x}]", reg_name(*r), d))
                .collect();
            let calls: Vec<String> = fp
                .direct_call_targets
                .iter()
                .map(|t| format!("0x{t:x}"))
                .collect();
            eprintln!(
                "  fp: insns={} direct_calls={:?} indirect={} cmp_mem={:?} cmp_reg={} jcc={} rets={}",
                fp.insn_count, calls, fp.indirect_calls, fields, fp.cmp_reg_count, fp.cond_branches, fp.rets
            );
        }
    }
}