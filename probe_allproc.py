#!/usr/bin/env python3
"""Probe: resolve the allproc base-convention conflict with captured bytes.

kstuff 4.03 allproc = 0x27edcb8 (kernel-text-base relative)
UMTX   4.03 allproc = 0x33edcb8 (anchor unknown — delta is exactly 0xC00000)

Kernel layout facts from our captures:
  region_0x60000000.bin            (12 MB) kernel text+early data, PA 0x60000000
  freebsd_kernel_region_0x60c00000.bin (29 MB) kernel data, PA 0x60C00000
  kernel VA base = 0xFFFFFFFF80210000 (kld-sdk) <-> PA 0x60000000
"""
import struct, sys, os, re

CAP = os.path.expanduser("~/ps5_re/deploy/captures")
TEXT = open(os.path.join(CAP, "region_0x60000000.bin"), "rb").read()       # PA 0x60000000
DATA = open(os.path.join(CAP, "freebsd_kernel_region_0x60c00000.bin"), "rb").read()  # PA 0x60C00000
TEXT_PA, DATA_PA = 0x60000000, 0x60C00000
KVA = 0xFFFFFFFF80210000

def mem(pa, n=8):
    if TEXT_PA <= pa < TEXT_PA + len(TEXT):
        o = pa - TEXT_PA; return TEXT[o:o+n]
    if DATA_PA <= pa < DATA_PA + len(DATA):
        o = pa - DATA_PA; return DATA[o:o+n]
    return None

def q(pa):
    b = mem(pa, 8)
    return struct.unpack("<Q", b)[0] if b else None

def kptr(v):
    return v is not None and 0xFFFF800000000000 <= v <= 0xFFFFFFFFFFFFFFFF

print("=== UMTX 4.03.js kernel constants (anchor evidence) ===")
txt = open(os.path.expanduser(
    "~/scene_contrib/ps5-koff/refs/umtx/document/en/ps5/offsets/4.03.js")).read()
for line in txt.splitlines():
    if re.match(r"\s*const OFFSET_(KERNEL|GADGET)", line):
        print("  ", line.strip())

print("\n=== candidate allproc checks (live-capture TAILQ semantics) ===")
def check_allproc(pa, label):
    q0, q1 = q(pa), q(pa + 8)
    va_head = KVA + (pa - TEXT_PA)
    print(f"-- {label}: PA {pa:#x}  q0={q0 and hex(q0)}  q1={q1 and hex(q1)}")
    if q0 is None or q1 is None:
        print("     not in captures"); return
    if q0 == 0 and q1 == va_head:
        print(f"     EMPTY-TAILQ MATCH: q1 == &head ({va_head:#x})  ==> THIS IS allproc")
        return
    if kptr(q0) and kptr(q1):
        # live list: first proc's le_prev must point back at the head
        pa0 = q0 - KVA + TEXT_PA
        prev = q(pa0 + 8)
        if prev == va_head:
            print(f"     LIVE-TAILQ MATCH: first proc le_prev == &head  ==> THIS IS allproc")
        else:
            print(f"     both kernel ptrs, but le_prev={prev and hex(prev)} != &head {va_head:#x} (maybe not in capture)")
    else:
        print("     not a TAILQ head (ptrs not kernel-canonical)")

# kstuff: text-base-relative
check_allproc(TEXT_PA + 0x27edcb8, "kstuff text-base-rel 0x27edcb8")
# UMTX hypothesis A: data-base-relative
check_allproc(DATA_PA + 0x33edcb8, "umtx data-base-rel 0x33edcb8")
# UMTX hypothesis B: text-base-relative (would be outside captures)
check_allproc(TEXT_PA + 0x33edcb8, "umtx text-base-rel 0x33edcb8")

print("\n=== also verify kstuff's other 4.03 data anchors ===")
for name, off in [("idt", 0x64cdc80), ("allproc", 0x27edcb8), ("sysentvec", 0xca0cd8)]:
    va = KVA + off
    pa = TEXT_PA + off
    print(f"  {name:<10} off={off:#x} VA={va:#x} PA={pa:#x}", end=" ")
    v = q(pa)
    print(f"val={v and hex(v)}", end=" ")
    print("(in captures)" if v is not None else "(OUTSIDE captures)")

print("\n=== prison0 (UMTX 0x2934d00, kstuff none) ===")
for base, lbl in [(TEXT_PA, "text-base"), (DATA_PA, "data-base")]:
    pa = base + 0x2934d00
    v = q(pa)
    print(f"  {lbl}: PA {pa:#x} val={v and hex(v)} kernel-ptr={kptr(v)}")