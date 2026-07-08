#!/usr/bin/env python3
"""
PromptRail Workstream 2 — Step 2 diagnostic.

Purpose (validate the problem statement on the real machine BEFORE any engine
code is written):

  2a) Find every Opaque-classified process (same classification the daemon's
      proc_watch uses: libssl.so -> OpenSSL, libgnutls -> GnuTLS,
      libnss3/libnspr4 -> NSS, else Opaque), highlight VS Code / Electron ones,
      and for the ELF binary backing them confirm:
        - it appears in the Opaque list (no libssl.so mapped),
        - it is a statically-linked TLS blob (no libssl.so in ANY of its maps),
        - it is stripped (no .symtab; no SSL_write/SSL_read symbol resolvable).
      Reports exact binary path, size, ELF type (PIE?), stripped state.

  2b) Baseline prologue scan: count candidate function prologues in the binary's
      executable segment(s) using DELIBERATELY GENERIC x86-64 patterns. This is
      NOT the Step 3 signature — it exists to quantify the false-positive
      baseline from the pre-mortem. A huge count is the expected, informative
      result: it shows why Step 3 needs disassembly-consistency verification and
      ranking, not a blind byte match.

This tool is intentionally OUTSIDE the Rust workspace: it is throwaway
diagnostic tooling. Step 3's production engine reimplements ELF parsing in Rust
with build-id-keyed caching. Nothing here touches the settled 4-crate layout.

Pure Python 3 stdlib. No external tools, no dependencies. Linux/x86-64 only.

Usage:
    python3 ws2_diag.py                 # auto-discover VS Code Opaque processes
    python3 ws2_diag.py --binary PATH   # analyze a specific ELF file directly
    python3 ws2_diag.py --all-opaque    # also list non-VS-Code Opaque processes
"""

import os
import struct
import sys

# ---- ELF constants -------------------------------------------------------
ET_DYN = 3          # PIE / shared object
EM_X86_64 = 0x3E
PT_LOAD = 1
PF_X = 0x1
SHT_SYMTAB = 2
SHT_DYNSYM = 11

# Symbols we care about for attach-by-name. If any of these resolve, discovery
# is unnecessary for that function.
TARGET_SYMS = {b"SSL_write", b"SSL_read", b"SSL_write_ex", b"SSL_read_ex"}

# Baseline prologue patterns (2b). Generic on purpose — see module docstring.
PROLOGUE_PATTERNS = [
    ("endbr64                 (f3 0f 1e fa)", b"\xf3\x0f\x1e\xfa"),
    ("push rbp; mov rbp,rsp   (55 48 89 e5)", b"\x55\x48\x89\xe5"),
    ("endbr64 + frame setup   (f3 0f 1e fa 55 48 89 e5)",
     b"\xf3\x0f\x1e\xfa\x55\x48\x89\xe5"),
]
SAMPLE_OFFSETS = 12  # how many example offsets to print per pattern


# ---- small output helpers ------------------------------------------------
def hr(title):
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def kv(k, v):
    print(f"  {k:<26} {v}")


# ---- /proc scanning (mirrors daemon proc_watch::classify_pid) ------------
def read_maps(pid):
    try:
        with open(f"/proc/{pid}/maps", "r") as f:
            return f.read()
    except OSError:
        return None


def classify(maps_text):
    """Exact precedence match to proc_watch::classify_pid."""
    openssl = "libssl.so" in maps_text
    gnutls = "libgnutls.so" in maps_text
    nss = ("libnss3.so" in maps_text) or ("libnspr4.so" in maps_text)
    if gnutls:
        return "GnuTls"
    if nss:
        return "Nss"
    if openssl:
        return "OpenSsl"
    return "Opaque"


def read_cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            parts = f.read().split(b"\x00")
        return [p.decode("utf-8", "replace") for p in parts if p]
    except OSError:
        return []


def proc_type(cmdline):
    for a in cmdline:
        if a.startswith("--type="):
            t = a[len("--type="):]
            for a2 in cmdline:
                if a2.startswith("--utility-sub-type="):
                    return f"{t}/{a2.split('=',1)[1]}"
            return t
    return "main"  # no --type= => the main/browser process


def read_exe(pid):
    try:
        return os.path.realpath(f"/proc/{pid}/exe")
    except OSError:
        return None


def looks_like_vscode(exe, cmdline):
    hay = ((exe or "") + " " + " ".join(cmdline)).lower()
    for needle in ("vscode", "code-insiders", "code - insiders",
                   "visual-studio-code", "/code", "electron"):
        if needle in hay:
            return True
    # fallback: exe basename is exactly 'code' or 'electron'
    base = os.path.basename(exe or "")
    return base in ("code", "electron")


def exec_file_mappings(maps_text):
    """Distinct file-backed executable mappings (path only)."""
    files = []
    for line in maps_text.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        perms = parts[1]
        path = parts[5]
        if "x" in perms and path.startswith("/"):
            if path not in files:
                files.append(path)
    return files


# ---- ELF parsing ---------------------------------------------------------
class Elf:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        if d[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        self.is64 = d[4] == 2
        self.le = d[5] == 1
        if not (self.is64 and self.le):
            raise ValueError("only ELF64 little-endian supported")
        (self.e_type, self.e_machine) = struct.unpack_from("<HH", d, 16)
        (self.e_phoff,) = struct.unpack_from("<Q", d, 32)
        (self.e_shoff,) = struct.unpack_from("<Q", d, 40)
        (self.e_phentsize, self.e_phnum) = struct.unpack_from("<HH", d, 54)
        (self.e_shentsize, self.e_shnum) = struct.unpack_from("<HH", d, 58)

    def program_headers(self):
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            p_type, p_flags = struct.unpack_from("<II", self.data, off)
            p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, _p_align = \
                struct.unpack_from("<QQQQQQ", self.data, off + 8)
            yield {"type": p_type, "flags": p_flags, "offset": p_offset,
                   "vaddr": p_vaddr, "filesz": p_filesz}

    def exec_segments(self):
        return [ph for ph in self.program_headers()
                if ph["type"] == PT_LOAD and (ph["flags"] & PF_X)]

    def section_headers(self):
        if self.e_shoff == 0 or self.e_shnum == 0:
            return []
        out = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            sh_name, sh_type = struct.unpack_from("<II", self.data, off)
            (_sh_flags, _sh_addr, sh_offset, sh_size) = \
                struct.unpack_from("<QQQQ", self.data, off + 8)
            (sh_link, _sh_info) = struct.unpack_from("<II", self.data, off + 40)
            (_align, sh_entsize) = struct.unpack_from("<QQ", self.data, off + 48)
            out.append({"type": sh_type, "offset": sh_offset, "size": sh_size,
                        "link": sh_link, "entsize": sh_entsize})
        return out

    def symbol_tables(self):
        return [(i, sh) for i, sh in enumerate(self.section_headers())
                if sh["type"] in (SHT_SYMTAB, SHT_DYNSYM)]

    def find_symbols(self, wanted):
        """Return list of (table_name, symbol_name, value) matches."""
        secs = self.section_headers()
        matches = []
        tables_seen = []
        for idx, sh in enumerate(secs):
            if sh["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
                continue
            tname = ".symtab" if sh["type"] == SHT_SYMTAB else ".dynsym"
            entsize = sh["entsize"] or 24
            count = sh["size"] // entsize if entsize else 0
            tables_seen.append((tname, count))
            strtab = secs[sh["link"]] if sh["link"] < len(secs) else None
            if strtab is None:
                continue
            str_base = strtab["offset"]
            str_end = str_base + strtab["size"]
            for n in range(count):
                symoff = sh["offset"] + n * entsize
                if symoff + 24 > len(self.data):
                    break
                st_name = struct.unpack_from("<I", self.data, symoff)[0]
                st_value = struct.unpack_from("<Q", self.data, symoff + 8)[0]
                if st_name == 0:
                    continue
                p = str_base + st_name
                if p >= str_end:
                    continue
                z = self.data.find(b"\x00", p, str_end)
                if z < 0:
                    continue
                name = self.data[p:z]
                if name in wanted:
                    matches.append((tname, name.decode("ascii", "replace"),
                                    st_value))
        return matches, tables_seen

    def has_symtab(self):
        return any(sh["type"] == SHT_SYMTAB for sh in self.section_headers())


# ---- 2b prologue scan ----------------------------------------------------
def count_and_sample(hay, pat, base_file_offset):
    """Total occurrences plus up to SAMPLE_OFFSETS file offsets."""
    total = hay.count(pat)
    samples = []
    i = hay.find(pat)
    while i != -1 and len(samples) < SAMPLE_OFFSETS:
        samples.append(base_file_offset + i)
        i = hay.find(pat, i + 1)
    return total, samples


# ---- per-binary analysis -------------------------------------------------
def analyze_binary(path, libssl_in_maps=None):
    hr(f"ELF ANALYSIS: {path}")
    try:
        st = os.stat(path)
    except OSError as e:
        print(f"  cannot stat: {e}")
        return
    kv("size", f"{st.st_size:,} bytes  ({st.st_size/1024/1024:.1f} MiB)")

    try:
        elf = Elf(path)
    except (OSError, ValueError) as e:
        print(f"  cannot parse ELF: {e}")
        return

    kv("machine", "x86-64" if elf.e_machine == EM_X86_64
       else f"0x{elf.e_machine:x} (UNEXPECTED)")
    kv("type", "ET_DYN (PIE / shared object)" if elf.e_type == ET_DYN
       else f"e_type={elf.e_type} (non-PIE)")

    # --- stripped? symbols? (2a) ---
    stripped = not elf.has_symtab()
    kv("stripped (.symtab)", "STRIPPED — no .symtab" if stripped
       else "NOT stripped — .symtab present")
    matches, tables = elf.find_symbols(TARGET_SYMS)
    if tables:
        kv("symbol tables", ", ".join(f"{t} ({c} syms)" for t, c in tables))
    else:
        kv("symbol tables", "none present")
    if matches:
        print("  SSL_* symbols resolvable BY NAME (attach-by-symbol possible!):")
        for tname, name, val in matches:
            print(f"      {tname:<9} {name:<16} value=0x{val:x}")
    else:
        print("  SSL_write / SSL_read / SSL_write_ex / SSL_read_ex: "
              "NONE resolvable by name")
        print("      -> attach-by-symbol impossible; offset discovery required")
        print("      -> NOTE: on a stripped binary this does NOT reveal whether")
        print("         BoringSSL implements _ex variants. That is answered from")
        print("         BoringSSL source at the pinned commit (Step 4 CI).")

    if libssl_in_maps is not None:
        kv("libssl.so in its maps",
           "PRESENT (unexpected — not opaque!)" if libssl_in_maps
           else "absent (confirms statically-linked TLS)")

    # --- executable segments + 2b scan ---
    segs = elf.exec_segments()
    if not segs:
        print("  no PT_LOAD executable segment found (?)")
        return
    hr(f"2b BASELINE PROLOGUE SCAN: {os.path.basename(path)}")
    print("  Generic patterns — NOT the Step 3 signature. Offsets are FILE")
    print("  offsets (the quantity a uprobe attaches at). Large counts are the")
    print("  expected finding: they quantify the false-positive baseline.\n")
    for seg in segs:
        fo, fs = seg["offset"], seg["filesz"]
        blob = elf.data[fo:fo + fs]
        print(f"  exec segment: file_offset=0x{fo:x} size={fs:,} bytes "
              f"vaddr=0x{seg['vaddr']:x}")
        for label, pat in PROLOGUE_PATTERNS:
            total, samples = count_and_sample(blob, pat, fo)
            shown = " ".join(f"0x{o:x}" for o in samples)
            more = "" if total <= len(samples) else f"  …(+{total-len(samples)} more)"
            print(f"    {label}")
            print(f"        count={total:<8} sample file offsets: {shown}{more}")
        print()


# ---- discovery mode ------------------------------------------------------
def discover(show_all_opaque):
    hr("2a  /proc SCAN — TLS backend classification")
    pids = []
    for name in os.listdir("/proc"):
        if name.isdigit():
            pids.append(int(name))

    opaque = []       # (pid, backend, exe, cmdline, ptype, maps_text)
    unreadable = 0
    for pid in sorted(pids):
        maps = read_maps(pid)
        if maps is None:
            unreadable += 1
            continue
        backend = classify(maps)
        if backend != "Opaque":
            continue
        exe = read_exe(pid)
        cmd = read_cmdline(pid)
        opaque.append((pid, exe, cmd, proc_type(cmd), maps))

    vscode = [o for o in opaque if looks_like_vscode(o[1], o[2])]

    kv("total processes seen", len(pids))
    kv("unreadable (perm/race)", unreadable)
    kv("Opaque processes", len(opaque))
    kv("VS Code / Electron", len(vscode))

    if unreadable:
        print("\n  NOTE: some /proc entries were unreadable. If VS Code runs as")
        print("  another user or under a sandbox, re-run with sudo, or pass")
        print("  --binary <path-to-code-binary> directly.")

    if not vscode:
        print("\n  No VS Code / Electron process detected in the Opaque set.")
        if opaque:
            print("  Opaque processes present (exe — type):")
            for pid, exe, cmd, pt, _ in opaque[:40]:
                print(f"    pid={pid:<7} {pt:<28} {exe}")
        print("\n  ACTION: launch VS Code, make it do HTTPS (open the Extensions")
        print("  marketplace), then re-run this script. Or point it at the")
        print("  binary directly:  python3 ws2_diag.py --binary /usr/share/code/code")
        return

    hr("VS CODE OPAQUE PROCESSES")
    print(f"  {'pid':<8}{'process type':<30}{'exe'}")
    binaries = {}   # realpath -> libssl_seen_in_any_map
    for pid, exe, cmd, pt, maps in vscode:
        print(f"  {pid:<8}{pt:<30}{exe}")
        if exe:
            binaries.setdefault(exe, False)
            if "libssl.so" in maps:
                binaries[exe] = True

    # Show the distinct executable file-backed mappings across VS Code procs,
    # so a separately-bundled TLS .so (if any) would be visible.
    all_exec_files = []
    for _, _, _, _, maps in vscode:
        for f in exec_file_mappings(maps):
            if f not in all_exec_files:
                all_exec_files.append(f)
    hr("DISTINCT FILE-BACKED EXECUTABLE MAPPINGS (VS Code procs)")
    print("  (main binary is the primary scan target; a bundled TLS .so would")
    print("   show up here as a separate suspicious file)\n")
    for f in all_exec_files:
        note = "  <-- backing exe" if f in binaries else ""
        print(f"    {f}{note}")

    for path, libssl_seen in binaries.items():
        analyze_binary(path, libssl_in_maps=libssl_seen)

    if show_all_opaque and opaque:
        hr("ALL OPAQUE PROCESSES (context)")
        for pid, exe, cmd, pt, _ in opaque:
            print(f"    pid={pid:<7} {pt:<28} {exe}")


# ---- entry ---------------------------------------------------------------
def main():
    if not sys.platform.startswith("linux"):
        print("Linux only.")
        return 2

    args = sys.argv[1:]
    if "--binary" in args:
        i = args.index("--binary")
        try:
            path = args[i + 1]
        except IndexError:
            print("--binary requires a path")
            return 2
        analyze_binary(os.path.realpath(path))
        return 0

    discover(show_all_opaque=("--all-opaque" in args))
    return 0


if __name__ == "__main__":
    sys.exit(main())