#!/usr/bin/env python3
"""
PromptRail Workstream 2 — Stage-1 anchor confirmation.

Confirms (before any engine code) that the `ssl_lib.cc` __FILE__ rodata string
exists in the target binary and is referenced by a SMALL, CLUSTERED set of
`lea reg,[rip+disp32]` sites — the anchor the discovery engine's Stage 1 uses to
localize to BoringSSL's ssl_lib translation unit instead of scanning ~500k
generic prologues.

It reports exactly the four things being decided:
  1. Is an `ssl_lib.cc`-family string present in rodata?
  2. The EXACT embedded form (Chromium often embeds a full build path).
  3. How many `lea rip+disp32` references point at it.
  4. Whether those references cluster in a localized code region or scatter.

This is a magnitude estimator, not a disassembler: it scans the executable
segment(s) for the lea-rip encoding whose computed target equals the string's
virtual address. A mid-instruction byte run that both decodes as lea-rip AND
resolves EXACTLY to the string address is astronomically unlikely, so the count
is a sound estimate of real reference sites. Full instruction decoding is a
Stage-2 (engine) concern, not needed here.

Pure Python 3 stdlib. Linux/x86-64. Throwaway diagnostic — outside the workspace.

Usage:
    python3 ws2_xref.py                         # defaults to /usr/share/code/code
    python3 ws2_xref.py --binary /path/to/elf
    python3 ws2_xref.py --binary ELF --needle ssl_lib.cc [--needle other.cc]
"""

import os
import struct
import sys

PT_LOAD = 1
PF_X = 0x1

DEFAULT_BINARY = "/usr/share/code/code"
DEFAULT_NEEDLES = [b"ssl_lib.cc"]  # substring; full embedded path is reported


class Elf:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        if d[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        if d[4] != 2 or d[5] != 1:
            raise ValueError("only ELF64 little-endian supported")
        (self.e_type, self.e_machine) = struct.unpack_from("<HH", d, 16)
        (self.e_phoff,) = struct.unpack_from("<Q", d, 32)
        (self.e_phentsize, self.e_phnum) = struct.unpack_from("<HH", d, 54)

    def program_headers(self):
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            p_type, p_flags = struct.unpack_from("<II", self.data, off)
            p_offset, p_vaddr, _pa, p_filesz, _pm, _al = \
                struct.unpack_from("<QQQQQQ", self.data, off + 8)
            yield {"type": p_type, "flags": p_flags, "offset": p_offset,
                   "vaddr": p_vaddr, "filesz": p_filesz}

    def loads(self):
        return [p for p in self.program_headers() if p["type"] == PT_LOAD]

    def exec_segments(self):
        return [p for p in self.loads() if p["flags"] & PF_X]

    def file_offset_to_vaddr(self, fo):
        for p in self.loads():
            if p["offset"] <= fo < p["offset"] + p["filesz"]:
                return p["vaddr"] + (fo - p["offset"])
        return None


def full_cstring(data, pos):
    """Return the NUL-delimited C string that CONTAINS position `pos`."""
    start = data.rfind(b"\x00", 0, pos) + 1
    end = data.find(b"\x00", pos)
    if end < 0:
        end = pos + 200
    return data[start:end], start


def find_string_occurrences(data, needle):
    out = []
    i = data.find(needle)
    while i != -1:
        s, start = full_cstring(data, i)
        # only accept printable-ish strings (avoid matching inside code/data)
        if all(0x09 <= b <= 0x7e for b in s) and len(s) < 512:
            out.append((start, s))
        i = data.find(needle, i + 1)
    # dedupe by string start offset
    seen, uniq = set(), []
    for start, s in out:
        if start in seen:
            continue
        seen.add(start)
        uniq.append((start, s))
    return uniq


def scan_lea_rip_to(elf, target_vaddr):
    """Find all `lea reg,[rip+disp32]` whose target == target_vaddr.
    Returns list of referencing instruction virtual addresses."""
    hits = []
    for seg in elf.exec_segments():
        blob = elf.data[seg["offset"]:seg["offset"] + seg["filesz"]]
        base_vaddr = seg["vaddr"]
        n = len(blob)
        k = 0
        while k < n - 7:
            b0 = blob[k]
            # REX.W form: 48-4F, 8D, modrm(mod=00,rm=101), disp32   (len 7)
            if 0x48 <= b0 <= 0x4f and blob[k + 1] == 0x8d and \
               (blob[k + 2] & 0xc7) == 0x05:
                disp = struct.unpack_from("<i", blob, k + 3)[0]
                instr_vaddr = base_vaddr + k
                target = instr_vaddr + 7 + disp
                if target == target_vaddr:
                    hits.append(instr_vaddr)
                k += 1
                continue
            # non-REX form: 8D, modrm(mod=00,rm=101), disp32        (len 6)
            # Guard against double-counting the disp of a REX-prefixed lea:
            # if the previous byte is a REX prefix, this 8D is the second byte
            # of that instruction, not a standalone lea.
            prev_is_rex = k > 0 and 0x40 <= blob[k - 1] <= 0x4f
            if b0 == 0x8d and (blob[k + 1] & 0xc7) == 0x05 and not prev_is_rex:
                disp = struct.unpack_from("<i", blob, k + 2)[0]
                instr_vaddr = base_vaddr + k
                target = instr_vaddr + 6 + disp
                if target == target_vaddr:
                    hits.append(instr_vaddr)
            k += 1
    return hits


def cluster_refs(hits, gap):
    """Group sorted reference addresses into clusters, splitting wherever the
    gap between consecutive refs exceeds `gap` bytes. Each cluster ~ one
    function's error-path references (LTO co-locates a function's body, so its
    OPENSSL_PUT_ERROR lea sites stay within a few hundred bytes, while distinct
    functions are separated by MB under LTO layout)."""
    clusters = []
    cur = []
    for h in sorted(hits):
        if cur and h - cur[-1] > gap:
            clusters.append(cur)
            cur = []
        cur.append(h)
    if cur:
        clusters.append(cur)
    return clusters


def cluster_report(hits, gap):
    if not hits:
        print("      (no references)")
        return
    lo, hi = min(hits), max(hits)
    print(f"      references: {len(hits)}")
    print(f"      overall addr range: 0x{lo:x} .. 0x{hi:x}   "
          f"span={hi-lo:,} bytes")
    clusters = cluster_refs(hits, gap)
    print(f"      proximity clusters (gap>{gap}B splits): {len(clusters)}")
    print(f"      => ~{len(clusters)} candidate functions in this TU\n")
    # Distribution of cluster sizes — the signature selector.
    from collections import Counter
    dist = Counter(len(c) for c in clusters)
    print("      cluster-size distribution (refs_per_fn: count):")
    for size in sorted(dist, reverse=True):
        tag = ""
        if size == 4:
            tag = "  <-- SSL_write candidate(s) (4 OPENSSL_PUT_ERROR sites)"
        elif size == 1:
            tag = "  <-- SSL_peek candidate(s) (1 site; SSL_read calls it first)"
        print(f"        {size} ref(s): {dist[size]} cluster(s){tag}")
    print()
    # Per-cluster detail: address + count + internal span.
    print("      per-cluster (addr of first ref / count / internal span):")
    for i, c in enumerate(clusters):
        span = c[-1] - c[0]
        note = ""
        if len(c) == 4:
            note = "  *** SSL_write candidate ***"
        elif len(c) == 1:
            note = "  (SSL_peek candidate)"
        print(f"        [{i:2}] 0x{c[0]:x}  refs={len(c)}  span={span}B{note}")


def main():
    args = sys.argv[1:]
    path = DEFAULT_BINARY
    needles = []
    gap = 4096  # max intra-function byte gap between error-path lea sites
    i = 0
    while i < len(args):
        if args[i] == "--binary" and i + 1 < len(args):
            path = args[i + 1]; i += 2; continue
        if args[i] == "--needle" and i + 1 < len(args):
            needles.append(args[i + 1].encode()); i += 2; continue
        if args[i] == "--gap" and i + 1 < len(args):
            gap = int(args[i + 1], 0); i += 2; continue
        i += 1
    if not needles:
        needles = DEFAULT_NEEDLES

    print("=" * 72)
    print(f"WS2 Stage-1 anchor check: {path}")
    print("=" * 72)
    try:
        elf = Elf(path)
    except (OSError, ValueError) as e:
        print(f"cannot open/parse: {e}")
        return 2

    execs = elf.exec_segments()
    print(f"executable segments: " +
          ", ".join(f"[file 0x{s['offset']:x} vaddr 0x{s['vaddr']:x} "
                    f"size {s['filesz']:,}]" for s in execs))
    print()

    any_found = False
    for needle in needles:
        print(f"--- needle: {needle.decode()} ---")
        occ = find_string_occurrences(elf.data, needle)
        if not occ:
            print("  NOT FOUND in file.")
            print()
            continue
        any_found = True
        for fo, s in occ:
            vaddr = elf.file_offset_to_vaddr(fo)
            print(f"  found string @ file 0x{fo:x} "
                  f"(vaddr {'0x%x' % vaddr if vaddr else 'n/a (not in PT_LOAD)'})")
            print(f"    exact form: {s.decode('utf-8', 'replace')!r}")
            if vaddr is None:
                print("    (string not in a loadable segment; cannot xref)")
                continue
            hits = scan_lea_rip_to(elf, vaddr)
            cluster_report(hits, gap)
        print()

    if not any_found:
        print("No ssl_lib.cc-family string found. Try alternate needles, e.g.:")
        print("  --needle ssl_lib.cc  --needle third_party/boringssl")
        print("Or list candidate embedded source paths:")
        print("  (strings-like scan of '.cc' paths would go here on the real run)")
    return 0


if __name__ == "__main__":
    sys.exit(main())