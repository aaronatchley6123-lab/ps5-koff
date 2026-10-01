#!/usr/bin/env python3
"""koff CLI — verify, cross-firm, and diff PS5 kernel offsets.

Usage:
  koff verify --fw 4.03 [--image PATH] [--pa-base 0x60C00000] [table.json]
  koff crossfirm --name allproc
  koff diff --a 4.03 --b 5.00
  koff refs [--fw 4.03]

table.json: {"name": value, ...} — e.g. an LLM-proposed offset table.
Without a table, the candidate is the merged public reference for that FW
(catch: public tables disagreeing with each other is the finding).
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from koff import KERNEL_VA_BASE  # noqa: E402
from koff.kernel import KernelImage  # noqa: E402
from koff.model import Offset  # noqa: E402
from koff.loaders import load_all_refs, normalize_fw  # noqa: E402
from koff.verify import verify_table, diff_tables, cross_firm_all  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _image(args) -> KernelImage | None:
    if not args.image:
        return None
    kw = {}
    if args.pa_base:
        kw = dict(pa_base=int(args.pa_base, 0), kernel_phys_base=0x60000000)
    return KernelImage(args.image, **kw)


def _candidate_table(args, refs) -> dict:
    """Candidate table: file, or merged public refs for the FW."""
    fw = normalize_fw(args.fw)
    if args.table:
        raw = json.load(open(args.table))
        cand = {}
        for name, val in raw.items():
            if name.startswith("_"):
                continue  # metadata keys (_comment etc.) are not offsets
            v = int(val, 0) if isinstance(val, str) else int(val)
            cand[name.lower()] = Offset(name.lower(), v, fw, "candidate")
        return cand
    merged: dict = {}
    for name, offs in refs.get(fw, {}).items():
        vals = {o.value for o in offs}
        merged[name] = Offset(name, sorted(vals)[0], fw, "merged-public",
                              note=("; ".join(
                                  f"{o.source}={o.value:#x}" for o in offs
                                  if o.value != sorted(vals)[0])
                              ) if len(vals) > 1 else "")
    return merged


def _print_results(results, fw) -> None:
    counts = {}
    print(f"\n=== koff verify — firmware {fw} ===")
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
        flag = {"VERIFIED": "OK ", "VERIFIED*": "!! ", "PLAUSIBLE": "~  ",
                "MISMATCH": "XX ", "UNVERIFIABLE": "?  ",
                "CONFLICT": "!! "}[r.status]
        print(f"{flag} {r.name:<28} {r.value:#12x}  [{r.status}] {r.detail}")
    print(f"\n  {sum(counts.values())} offsets: " +
          ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="koff")
    sub = p.add_subparsers(dest="cmd", required=True)

    pv = sub.add_parser("verify")
    pv.add_argument("--fw", required=True)
    pv.add_argument("--image", help="raw capture or decrypted kernel image")
    pv.add_argument("--pa-base", help="PA of image file offset 0 (e.g. 0x60C00000)")
    pv.add_argument("--table", help="candidate offset table JSON {name: value}")

    pf = sub.add_parser("fetch")
    pf.add_argument("--force", action="store_true",
                    help="re-fetch even if refs/ entries exist")

    pc = sub.add_parser("crossfirm")
    pc.add_argument("--name", required=True)

    pd = sub.add_parser("diff")
    pd.add_argument("--a", required=True)
    pd.add_argument("--b", required=True)

    pr = sub.add_parser("refs")
    pr.add_argument("--fw")

    args = p.parse_args(argv)

    if args.cmd == "fetch":
        from .fetch import fetch_all
        res = fetch_all(os.path.join(ROOT, "refs"), force=args.force)
        return 0 if all(ok for _, ok, _ in res) else 1

    refs = load_all_refs(os.path.join(ROOT, "refs"))

    if args.cmd == "verify":
        fw = normalize_fw(args.fw)
        img = _image(args)
        cand = _candidate_table(args, refs)
        if not cand:
            print(f"no candidate offsets for FW {fw}", file=sys.stderr)
            return 1
        results = verify_table(img, cand, refs, fw)
        _print_results(results, fw)
        bad = [r for r in results if r.status in ("MISMATCH", "CONFLICT")]
        return 1 if bad else 0

    if args.cmd == "crossfirm":
        vals = cross_firm_all(refs, args.name.lower())
        if not vals:
            print(f"offset '{args.name}' not in any public table", file=sys.stderr)
            return 1
        print(f"\n=== {args.name} across public tables ===")
        for fw, vv in vals.items():
            for v in vv:
                print(f"  {fw:<8} {v:#x}")
        if len({v[0] for v in vals.values() if v}) == 1:
            print("  (single value across all firmwares)")
        return 0

    if args.cmd == "diff":
        fa, fb = normalize_fw(args.a), normalize_fw(args.b)
        if fa not in refs or fb not in refs:
            print(f"need both FWs in refs; have {sorted(refs)}", file=sys.stderr)
            return 1
        ta = {n: Offset(n, sorted({o.value for o in offs})[0], fa, "pub")
              for n, offs in refs[fa].items()}
        tb = {n: Offset(n, sorted({o.value for o in offs})[0], fb, "pub")
              for n, offs in refs[fb].items()}
        rows = diff_tables(ta, tb, fa, fb)
        print(f"\n=== diff {fa} -> {fb} ===")
        for name, va, vb, note in rows:
            print(f"  {name:<28} {va and hex(va) or '-':>12} -> "
                  f"{vb and hex(vb) or '-':>12}  {note}")
        print(f"  {len(rows)} rows ({sum(1 for r in rows if r[3].startswith('moved'))} moved)")
        return 0

    if args.cmd == "refs":
        if args.fw:
            fw = normalize_fw(args.fw)
            tbl = refs.get(fw, {})
            print(f"\n=== public refs for {fw} ===")
            for name, offs in sorted(tbl.items()):
                vals = sorted({o.value for o in offs})
                mark = " !CONFLICT" if len(vals) > 1 else ""
                print(f"  {name:<28} " +
                      ", ".join(hex(v) for v in vals) + mark)
            print(f"  {len(tbl)} entries")
        else:
            print("\n=== reference coverage ===")
            for fw in sorted(refs, key=lambda s: (len(s), s)):
                total = sum(len(v) for v in refs[fw].values())
                confl = sum(1 for v in refs[fw].values()
                            if len({o.value for o in v}) > 1)
                print(f"  {fw:<8} {total:>4} entries, {confl} conflicted names")
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())