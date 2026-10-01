"""Loaders for the scene's offset-table dialects + anchor-convention normalization.

Dialects:
- UMTX / Specter JS   : const OFFSET_X = 0x...;  + syscall_map {num: off}
                        kernel_* names are TEXT-anchored (kernel VA base).
- Relapse JS          : same const style (7.00-13.60 corpus), text-anchored.
- kld-sdk C headers   : #define name_403 OFFSET(0xVA) | plain offset (text-anchored).
- kstuff DEF tables   : DEF(name, 0xoff) inside START_FW(nnn) — DATA-anchored:
                        values are relative to the kernel data segment, which
                        starts OFFSET_KERNEL_DATA (0xC00000 on 4.x) above the
                        text base. Normalized to text-anchored canonical form.

The normalization is mechanical, not assumed: a source's value is shifted only
when value + anchor_delta matches an independent source's value for the same
name+FW, and never when the raw value already agrees.
"""
from __future__ import annotations

import re
from pathlib import Path

from .model import Offset

_CONST_RE = re.compile(
    r"^\s*(?:const|let|var)\s+(?:OFFSET_)?([A-Za-z0-9_]+)\s*=\s*"
    r"(0x[0-9A-Fa-f]+|\d+)(?:\s*([+-])\s*(0x[0-9A-Fa-f]+|\d+))?\s*;?")
_SYSCALL_RE = re.compile(
    r"^\s*(0x[0-9A-Fa-f]+)\s*:\s*(0x[0-9A-Fa-f]+)\s*,?\s*(?://\s*(\S+))?")
_DEFINE_RE = re.compile(
    r"^\s*#define\s+([A-Za-z0-9_]+?)_(?:\d{3})\s+(?:OFFSET\()?("
    r"0x[0-9A-Fa-f]+|\d+)\)?\s*$")
_DEF_RE = re.compile(r"^\s*\+?\s*DEF\(\s*([A-Za-z0-9_]+)\s*,\s*([^)]*?)(?:\s*/\*.*?\*/)?\s*\)")
_START_FW_RE = re.compile(r"^\s*\+?\s*START_FW\(\s*(\w+)\s*\)")

KERNEL_VA_BASE = 0xFFFFFFFF80210000

_PREFIXES = ("OFFSET_KERNEL_", "OFFSET_LK_", "OFFSET_WK_", "OFFSET_LC_",
             "OFFSET_", "LK_", "WK_", "LC_", "KERNEL_")


def _canon(name: str) -> str:
    n = name.strip()
    changed = True
    while changed:
        changed = False
        for p in _PREFIXES:
            if n.upper().startswith(p):
                n = n[len(p):]
                changed = True
    return n.lower()


def load_js(path: str, fw: str, source_tag: str) -> dict:
    """UMTX- and Relapse-style JS offset files."""
    out: dict = {}
    text = Path(path).read_text()
    in_syscall_map = False
    for line in text.splitlines():
        low = line.strip()
        if low.startswith(("let syscall_map", "const syscall_map")):
            in_syscall_map = True
            continue
        if in_syscall_map and low.startswith("};"):
            in_syscall_map = False
            continue
        if in_syscall_map:
            m = _SYSCALL_RE.match(line)
            if m:
                num, off, cmt = int(m.group(1), 16), int(m.group(2), 16), m.group(3)
                nm = f"syscall_{cmt}" if cmt else f"syscall_{num:#x}"
                out[nm] = Offset(nm, off, fw, f"{source_tag}:{Path(path).name}",
                                 kind="syscall")
                continue
        m = _CONST_RE.match(line)
        if m:
            name = m.group(1)
            val = int(m.group(2), 0)
            expr_note = ""
            if m.group(3):  # expression form: base ± delta (Relapse flag fields)
                d = int(m.group(4), 0)
                val = val + d if m.group(3) == "+" else val - d
                expr_note = " (evaluated base+delta expression)"
            nm = _canon(name)
            kind = "data" if any(k in nm for k in (
                "allproc", "prison0", "rootvnode", "data", "idt", "gdt", "tss",
                "pcpu", "sysent", "pmap", "apic", "flags", "utoken", "qa_",
                "targetid", "stack")) else "text"
            out[nm] = Offset(nm, val, fw, f"{source_tag}:{Path(path).name}",
                             kind=kind, note=expr_note)
    return out


def load_kld_header(path: str, fw: str) -> dict:
    """kld-sdk C header: #define name_403 [OFFSET(](0xVA | off))"""
    out: dict = {}
    for line in Path(path).read_text().splitlines():
        m = _DEFINE_RE.match(line)
        if not m:
            continue
        name, val_s = m.group(1), m.group(2)
        val = int(val_s, 0)
        if val > KERNEL_VA_BASE:  # absolute VA -> normalize to base-relative
            val -= KERNEL_VA_BASE
        nm = _canon(name).replace("_offset", "").rstrip("_")
        out[nm] = Offset(nm, val, fw, f"kld-sdk:{Path(path).name}", kind="data")
    return out


def load_kstuff_patch(path: str) -> dict:
    """kstuff DEF patch -> {fw: {name: Offset}} for every START_FW block.

    Matches added (+DEF) and context ( DEF) lines so pre-existing FW tables
    visible in the patch context are captured too.
    """
    tables: dict = {}
    fw = None
    for line in Path(path).read_text().splitlines():
        m = _START_FW_RE.match(line)
        if m:
            s = m.group(1)
            if re.fullmatch(r"\d{3,4}", s):
                fw = normalize_fw(s)     # 320 -> 3.20, 1300 -> 13.00
                tables.setdefault(fw, {})
            continue
        m = _DEF_RE.match(line)
        if m and fw:
            name = m.group(1)
            raw = m.group(2).strip()
            try:
                val = int(raw, 0)
            except ValueError:
                mm = re.match(r"^(\w+)\s*-\s*(0x[0-9a-fA-F]+|\d+)$", raw)
                if mm and mm.group(1) in tables.get(fw, {}):
                    val = tables[fw][mm.group(1)].value - int(mm.group(2), 0)
                else:
                    continue  # symbolic expression we can't resolve yet
            tables[fw][name] = Offset(name, val, fw, "kstuff-patch", kind="data")
    return tables


def _anchor_delta(tbl: dict) -> int | None:
    """This FW's kernel-data anchor (OFFSET_KERNEL_DATA) from the umtx source."""
    ds = {o.value for o in tbl.get("data", []) if o.source.startswith("umtx")}
    return ds.pop() if len(ds) == 1 else None


def _normalize_anchors(refs: dict) -> dict:
    """Shift data-anchored source values to text-anchored canonical form.

    Pass 1 (per-name, precise): value+delta matches an independent source and
    the raw value does not -> shift, with provenance note.
    Pass 2 (per-family inference): if a family showed >=1 pass-1 hit and zero
    raw agreements, apply the same shift to its unconfirmed kernel-data names.
    """
    for fw, tbl in refs.items():
        delta = _anchor_delta(tbl)
        if not delta:
            continue
        fams: dict = {}
        for name, offs in tbl.items():
            if name == "data":
                continue
            for o in offs:
                fams.setdefault(o.source.split(":")[0], {})[name] = o
        shifted = {f: 0 for f in fams}
        for fam, entries in fams.items():
            for name, o in entries.items():
                others = {x.value for x in tbl.get(name, [])
                          if x.source.split(":")[0] != fam}
                if not others:
                    continue
                if o.value + delta in others and o.value not in others:
                    o.note = ((o.note + "; ") if o.note else "") + \
                        f"normalized +{delta:#x} (source was data-anchored)"
                    o.value += delta
                    shifted[fam] += 1
                elif o.value in others:
                    shifted[fam] = -1  # marker: family has a raw agreement
        for fam, entries in fams.items():
            if shifted.get(fam, 0) > 0 and fam == "kstuff-patch":
                for name, o in entries.items():
                    others = {x.value for x in tbl.get(name, [])
                              if x.source.split(":")[0] != fam}
                    if others:
                        continue  # pass 1 already decided
                    o.note = ((o.note + "; ") if o.note else "") + \
                        f"normalized +{delta:#x} (family data-anchored, inferred)"
                    o.value += delta
    return refs


def load_all_refs(refs_dir: str) -> dict:
    """Load every reference source under refs/ -> {fw: {name: [Offset, ...]}}."""
    refs: dict = {}
    root = Path(refs_dir)

    def put(fw, nm, off):
        refs.setdefault(fw, {}).setdefault(nm, [])
        if not any(o.source == off.source and o.value == off.value
                   for o in refs[fw][nm]):
            refs[fw][nm].append(off)

    umtx_dir = root / "umtx" / "document" / "en" / "ps5" / "offsets"
    if umtx_dir.is_dir():
        for f in sorted(umtx_dir.glob("*.js")):
            for nm, off in load_js(str(f), f.stem, "umtx").items():
                put(normalize_fw(f.stem), nm, off)
    relapse_dirs = [root / "relapse" / "offsets", root / "relapse-sonic" / "offsets"]
    relapse_dirs += list(Path("~/slopervisor_hunt").expanduser().glob("*/offsets")) + \
        list(Path("~/slopervisor_hunt/tools").expanduser().glob("*/offsets"))
    seen_dirs = set()
    for d in relapse_dirs:
        if not d.is_dir() or str(d.resolve()) in seen_dirs:
            continue
        seen_dirs.add(str(d.resolve()))
        for f in sorted(d.glob("*.js")):
            if f.stem == "TEMPLATE":
                continue
            # tag by the corpus directory (parent), not d.name — both repos
            # have an "offsets/" leaf dir and must NOT share one tag
            src_tag = ("relapse-sonic" if "sonic" in str(d)
                       else "relapse")
            for nm, off in load_js(str(f), f.stem, src_tag).items():
                put(normalize_fw(f.stem), nm, off)
    for f in sorted((root / "kld-sdk" / "include" / "ps5kld" / "offsets").glob("*.h")):
        if f.stem == "offsets":
            continue
        for nm, off in load_kld_header(str(f), f.stem).items():
            put(normalize_fw(f.stem), nm, off)
    for kc in [root / "kstuff_offsets.c", root / "kstuff" / "kstuff_offsets.c"]:
        if kc.is_file():
            for fw, tbl in load_kstuff_c(str(kc)).items():
                for nm, off in tbl.items():
                    put(normalize_fw(fw), nm, off)
            break
    kp = root / "kstuff_320321.patch"
    if kp.is_file():
        for fw, tbl in load_kstuff_patch(str(kp)).items():
            for nm, off in tbl.items():
                put(normalize_fw(fw), nm, off)
    return _normalize_anchors(refs)


def load_kstuff_c(path: str) -> dict:
    """Full kstuff/prosper0gdb offsets.c -> {fw: {name: Offset}} for all
    START_FW blocks. Handles expression values and trailing /*comments*/."""
    tables: dict = {}
    fw = None
    for line in Path(path).read_text().splitlines():
        m = _START_FW_RE.match(line)
        if m:
            s = m.group(1)
            if re.fullmatch(r"\d{3,4}", s):
                fw = normalize_fw(s)
                tables.setdefault(fw, {})
            continue
        m = _DEF_RE.match(line)
        if m and fw:
            name, raw = m.group(1), m.group(2).strip()
            try:
                val = int(raw, 0)
            except ValueError:
                mm = re.match(r"^(\w+)\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)$", raw)
                if not mm:
                    continue  # unresolvable symbolic expression
                base = tables[fw].get(mm.group(1))
                if base is None:
                    continue
                val = (base.value + int(mm.group(3), 0)
                       if mm.group(2) == "+" else
                       base.value - int(mm.group(3), 0))
            tables[fw][name] = Offset(name, val, fw, "kstuff", kind="data")
    return tables


def _absorb_kstuff_c(path: str, refs: dict, put) -> None:
    """Parse DEF tables from a full kstuff checkout's offsets.c/main.c."""
    import re as _re
    text = Path(path).read_text()
    fw = None
    for line in text.splitlines():
        m = _re.match(r"\s*START_FW\(\s*(\w+)\s*\)", line)
        if m:
            s = m.group(1)
            fw = f"{s[0]}.{s[1:]}" if _re.fullmatch(r"\d{3,4}", s) else s
            continue
        m = _re.match(r"\s*DEF\(\s*([A-Za-z0-9_]+)\s*,\s*([^)]+)\)", line)
        if m and fw:
            name, raw = m.group(1), m.group(2).strip()
            try:
                val = int(raw, 0)
            except ValueError:
                mm = _re.match(r"^(\w+)\s*-\s*(0x[0-9a-fA-F]+|\d+)$", raw)
                if not mm:
                    continue
                prev = refs.get(fw, {}).get(mm.group(1))
                if not prev:
                    continue
                val = prev[0].value - int(mm.group(2), 0)
            put(fw, name, Offset(name, val, fw, "kstuff", kind="data"))


def normalize_fw(fw: str) -> str:
    """'4.03', '403', '1300', '13.00.00' -> '4.03' / '13.00'."""
    f = fw.strip().lower()
    if re.fullmatch(r"\d{3}", f):
        return f"{f[0]}.{f[1:]}"
    if re.fullmatch(r"\d{4}", f):
        return f"{f[:-2]}.{f[-2:]}"
    if f.endswith(".00") is False and re.fullmatch(r"\d+\.\d", f):
        return f + "0"
    return f