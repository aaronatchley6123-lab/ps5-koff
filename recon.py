#!/usr/bin/env python3
"""Recon: capture layout + reference offset formats, before building the koff engine."""
import json, os, re, struct, sys, glob

ROOT = os.path.expanduser("~/scene_contrib/ps5-koff")
CAP = os.path.expanduser("~/ps5_re/deploy/captures")

def sz(p):
    try: return os.path.getsize(p)
    except OSError: return -1

print("=== CAPTURES ===")
for f in sorted(os.listdir(CAP)):
    p = os.path.join(CAP, f)
    if os.path.isfile(p):
        with open(p, "rb") as fh:
            head = fh.read(32)
        print(f"{sz(p):>12}  {f}  head={head[:24].hex()}")

print()
print("=== STRING SCAN (kernel text candidates) ===")
needles = [b"Native SELF", b"PS4 SELF", b"FreeBSD", b"sysctl", b"__FreeBSD", b"sys-revision", b"USER_CONFIG", b"prospero"]
for name in ["region_0x60000000.bin", "freebsd_kernel_region_0x60c00000.bin"]:
    p = os.path.join(CAP, name)
    if not os.path.isfile(p):
        print(f"{name}: MISSING"); continue
    data = open(p, "rb").read()
    print(f"-- {name} ({len(data)} bytes) --")
    for n in needles:
        i = data.find(n)
        cnt = data.count(n)
        if i >= 0:
            print(f"   {n.decode():<16} first@0x{i:x} count={cnt}")
        else:
            print(f"   {n.decode():<16} not found")

print()
print("=== KLD-SDK 403.h (format sample) ===")
for p in glob.glob(f"{ROOT}/refs/kld-sdk/include/ps5kld/offsets/*.h"):
    print(f"-- {os.path.basename(p)} ({sz(p)}B) --")
    txt = open(p).read()
    for line in txt.splitlines()[:40]:
        print("  ", line)

print()
print("=== UMTX offsets files ===")
umtx_off = glob.glob(f"{ROOT}/refs/umtx/document/**/offset*", recursive=True)
for d in umtx_off:
    print(f"-- dir {d}")
    for f in sorted(os.listdir(d)):
        print(f"   {f} ({sz(os.path.join(d,f))}B)")

print()
print("=== UMTX 4.03 offsets (sample) ===")
for f in glob.glob(f"{ROOT}/refs/umtx/document/**/offset*/*403*", recursive=True) + \
         glob.glob(f"{ROOT}/refs/umtx/document/**/offset*/*4.03*", recursive=True):
    print(f"-- {f}")
    txt = open(f).read()
    for line in txt.splitlines()[:50]:
        print("  ", line)
    break

print()
print("=== KSTUFF PATCH: 403 DEF table (existing context lines) ===")
patch = open(f"{ROOT}/refs/kstuff_320321.patch").read()
m = re.search(r"START_FW\(403\)(.*?)END_FW", patch, re.S)
if m:
    for line in m.group(1).strip().splitlines()[:45]:
        print("  ", line)

print()
print("=== RELAPSE 13.00.js (format sample) ===")
p = os.path.expanduser("~/slopervisor_hunt/Relapse-Exploit/offsets/13.00.js")
txt = open(p).read()
print(f"({len(txt)} chars)")
for line in txt.splitlines()[:60]:
    print("  ", line)

print()
print("=== fw_13.00 decrypted artifacts? ===")
for pat in ["~/slopervisor_hunt/fw_13.00/**/*", "~/slopervisor_hunt/fw_staged/**/*dec*"]:
    for f in glob.glob(os.path.expanduser(pat), recursive=True):
        if os.path.isfile(f) and sz(f) > 1_000_000:
            print(f"   {sz(f):>12}  {f}")