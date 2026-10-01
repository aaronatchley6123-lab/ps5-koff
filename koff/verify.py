"""Three-tier verification: byte-verify against an image, cross-firm against
public tables, and convention-check against source anchoring.

Statuses:
  VERIFIED     — byte-level signature passed against a real image
  PLAUSIBLE    — mapped & consistent with structure class, no specific sig
  MISMATCH     — bytes at that offset contradict the expected structure
  UNVERIFIABLE — offset VA not present in the image / no image given
  CONFLICT     — candidate disagrees with public tables (incl. convention mix)
  VERIFIED*    — bytes pass but public tables disagree (worth publishing)
"""
from __future__ import annotations

from typing import Optional

from .kernel import KernelImage
from .model import Offset, VerifyResult
from .signatures import check
from .loaders import normalize_fw


def _fw_delta(refs: dict, fw: str) -> Optional[int]:
    tbl = refs.get(fw, {})
    ds = {o.value for o in tbl.get("data", []) if o.source.startswith("umtx")}
    return ds.pop() if len(ds) == 1 else None


def _ref_values(ref_tbl: dict, name: str) -> list:
    return sorted({o.value for o in ref_tbl.get(name, [])})


def verify_table(img: Optional[KernelImage], table: dict,
                 refs: dict, fw: str) -> list:
    fw = normalize_fw(fw)
    results = []
    ref_tbl = refs.get(fw, {})
    delta = _fw_delta(refs, fw)
    for name, cand in sorted(table.items()):
        vr = VerifyResult(name=name, value=cand.value)
        # ---- tier 1: byte-level against the image ----
        if img is not None:
            ok, detail = check(img, name, cand.value)
            if ok:
                vr.status = "VERIFIED"
                vr.detail = detail
            elif "not mapped" in detail or "unreadable" in detail:
                vr.status = "UNVERIFIABLE"
                vr.detail = detail
            else:
                vr.status = "MISMATCH"
                vr.detail = detail
        else:
            vr.status = "UNVERIFIABLE"
            vr.detail = "no image given"
        # ---- tier 2: cross-firm against public tables ----
        vals = _ref_values(ref_tbl, name)
        vr.sources = {o.source: o.value for o in ref_tbl.get(name, [])}
        if not vals:
            vr.detail += " | no public reference for this name on this FW"
        elif len(vals) > 1:
            vr.status = "CONFLICT"
            vr.detail += " | public sources disagree: " + ", ".join(
                f"{o.source}={o.value:#x}" for o in ref_tbl[name])
        elif cand.value not in vals:
            # candidate disagrees with the (unanimous) public value
            if delta is not None and cand.value + delta in vals:
                vr.status = "CONFLICT"
                vr.detail += (f" | CONVENTION MIXUP: candidate {cand.value:#x} is "
                              f"DATA-anchored (kstuff-style); canonical TEXT-anchored "
                              f"value is {cand.value + delta:#x} (= candidate + "
                              f"{delta:#x}). LLM blended source conventions.")
            elif delta is not None and cand.value - delta in vals:
                vr.status = "CONFLICT"
                vr.detail += (f" | CONVENTION MIXUP: candidate {cand.value:#x} "
                              f"over-shifted; canonical is {cand.value - delta:#x}.")
            else:
                if vr.status == "VERIFIED":
                    # bytes confirm the candidate; public tables disagree ->
                    # worth publishing, not silently trusting either side
                    vr.status = "VERIFIED*"
                    vr.detail += (" | image bytes confirm candidate BUT public "
                                  f"tables say {vals[0]:#x} — investigate before shipping")
                elif vr.status != "MISMATCH":
                    vr.status = "CONFLICT"
                vr.detail += f" | public tables say {vals[0]:#x}"
        else:
            vr.detail += f" | matches public tables ({vals[0]:#x})"
        results.append(vr)
    order = {"MISMATCH": 0, "CONFLICT": 1, "UNVERIFIABLE": 2,
             "VERIFIED*": 3, "PLAUSIBLE": 4, "VERIFIED": 5}
    results.sort(key=lambda r: (order.get(r.status, 9), r.name))
    return results


def diff_tables(a: dict, b: dict, fw_a: str, fw_b: str) -> list:
    """Diff two candidate tables: added/removed/changed, with per-entry notes."""
    out = []
    for n in sorted(set(a) | set(b)):
        if n not in a:
            out.append((n, None, b[n].value, f"new in {fw_b}"))
        elif n not in b:
            out.append((n, a[n].value, None, f"dropped in {fw_b}"))
        elif a[n].value != b[n].value:
            d = b[n].value - a[n].value
            out.append((n, a[n].value, b[n].value,
                        f"moved {'+' if d >= 0 else ''}{d:#x}"))
    return out


def cross_firm_all(refs: dict, name: str) -> dict:
    """One offset's values across every public firmware table."""
    out = {}
    for fw, tbl in sorted(refs.items()):
        if name in tbl:
            out[fw] = sorted({o.value for o in tbl[name]})
    return out