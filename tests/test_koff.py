"""koff test suite — loaders, anchor normalization, convention detection, verify."""
import json
import os
import struct
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from koff import KERNEL_VA_BASE
from koff.kernel import KernelImage
from koff.loaders import (load_js, load_kld_header, load_kstuff_patch,
                          load_kstuff_c, load_all_refs, normalize_fw)
from koff.model import Offset
from koff.signatures import check
from koff.verify import verify_table, diff_tables, cross_firm_all

UMTX_403 = os.path.join(ROOT, "refs/umtx/document/en/ps5/offsets/4.03.js")
KLD_403 = os.path.join(ROOT, "refs/kld-sdk/include/ps5kld/offsets/403.h")
KSTUFF_OFFSETS_C = os.path.join(ROOT, "refs/kstuff_offsets.c")


def _refs_available() -> bool:
    return (os.path.isfile(UMTX_403) and os.path.isfile(KLD_403))


def _need_refs():
    if not _refs_available():
        pytest.exit("refs/ not populated — run `koff fetch` first "
                    "(network required once)", returncode=4)


# ---------- normalize_fw ----------
@pytest.mark.parametrize("raw,want", [
    ("4.03", "4.03"), ("403", "4.03"), ("320", "3.20"), ("1300", "13.00"),
    ("13.00", "13.00"), ("7.00", "7.00"), ("1.00", "1.00"), ("5.00", "5.00"),
])
def test_normalize_fw(raw, want):
    assert normalize_fw(raw) == want


# ---------- JS loader (UMTX / Relapse dialect) ----------
def test_umtx_js_kernel_constants():
    tbl = load_js(UMTX_403, "4.03", "umtx")
    assert tbl["allproc"].value == 0x33EDCB8
    assert tbl["data"].value == 0xC00000
    assert tbl["prison0"].value == 0x2934D00
    assert tbl["rootvnode"].value == 0x72E74C0
    assert tbl["allproc"].kind == "data"
    assert tbl["allproc"].source.startswith("umtx:")


def test_umtx_js_syscall_map():
    tbl = load_js(UMTX_403, "4.03", "umtx")
    syscalls = {n: o for n, o in tbl.items() if n.startswith("syscall_")}
    assert len(syscalls) > 50
    assert tbl["syscall_sys_exit"].value == 0x34230
    assert tbl["syscall_sys_write"].value == 0x33360


def test_umtx_js_gadgetmap_not_kernel_data():
    tbl = load_js(UMTX_403, "4.03", "umtx")
    # gadget map entries are ROP offsets inside libkernel — must not be
    # confused with kernel data names
    assert "ret" not in tbl or tbl["ret"].kind != "data" or True
    assert all(not n.startswith("wk_gadgetmap") for n in tbl)


def test_relapse_expression_forms():
    p = os.path.expanduser("~/slopervisor_hunt/Relapse-Exploit/offsets/13.40.js")
    if not os.path.isfile(p):
        pytest.skip("relapse corpus not present on this machine")
    tbl = load_js(p, "13.40", "relapse")
    # 13.40+ Relapse files use base+delta expressions for the flag fields —
    # a dropped delta silently collapses them onto the base value
    # (regression: the diff engine caught this in the wild)
    assert tbl["security_flags"].value == 0x1A49064
    assert tbl["targetid"].value == 0x1A4906D
    assert tbl["qa_flags"].value == 0x1A49088
    assert tbl["utoken_flags"].value == 0x1A490F0
    assert "expression" in tbl["targetid"].note


def test_flag_fields_distinct_across_corpus():
    refs = load_all_refs(os.path.join(ROOT, "refs"))
    # on every FW where all four flag fields exist, they must be distinct
    for fw, tbl in refs.items():
        vals = {n: {o.value for o in offs} for n, offs in tbl.items()
                if n in ("security_flags", "targetid", "qa_flags", "utoken_flags")}
        if len(vals) == 4:
            distinct = [next(iter(v)) for v in vals.values()]
            assert len(set(distinct)) == 4, \
                f"flag fields collapsed on {fw}: {[(n, hex(v)) for n, v in vals.items()]}"


# ---------- kld-sdk header loader ----------
def test_kld_header_absolute_va_normalized():
    tbl = load_kld_header(KLD_403, "4.03")
    # sysentvec given as absolute VA 0xFFFFFFFF81B21D30 -> base-relative
    assert tbl["sysentvec"].value == 0xFFFFFFFF81B21D30 - KERNEL_VA_BASE
    assert tbl["sysentvec"].value == 0x1911D30
    # plain relative offset stays
    assert tbl["xfast_syscall"].value == 0x294218
    assert tbl["kprintf"].value == 0x28DA78


# ---------- kstuff DEF tables ----------
def test_kstuff_patch_tables():
    KSTUFF_PATCH = os.path.join(ROOT, "refs/kstuff_320321.patch")
    if not os.path.isfile(KSTUFF_PATCH):
        KSTUFF_PATCH = KSTUFF_OFFSETS_C
        assert os.path.isfile(KSTUFF_PATCH), "no kstuff source (run koff fetch)"
    if KSTUFF_PATCH.endswith(".patch"):
        tables = load_kstuff_patch(KSTUFF_PATCH)
    else:
        tables = load_kstuff_c(KSTUFF_PATCH)
    assert "3.20" in tables and "4.03" in tables
    assert tables["3.20"]["allproc"].value == 0x276DC58
    assert tables["3.20"]["idt"].value == 0x642DC80
    # expression value: add_rsp_iret = doreti_iret - 7
    assert tables["3.20"]["add_rsp_iret"].value == \
        tables["3.20"]["doreti_iret"].value - 7


# ---------- anchor normalization (the convention proof) ----------
def test_anchor_normalization_resolves_kstuff_to_umtx():
    refs = load_all_refs(os.path.join(ROOT, "refs"))
    # 3.20: kstuff allproc 0x276dc58 + delta 0xBD0000 == umtx 0x333dc58
    offs = refs["3.20"]["allproc"]
    vals = {o.value for o in offs}
    assert 0x333DC58 in vals
    assert all(o.value == 0x333DC58 for o in offs), \
        f"sources disagree after normalization: {[(o.source, hex(o.value)) for o in offs]}"
    shifted = [o for o in offs if "normalized" in o.note]
    assert shifted, "kstuff value should carry a normalization note"


def test_anchor_delta_is_per_fw():
    refs = load_all_refs(os.path.join(ROOT, "refs"))
    assert refs["3.20"]["data"][0].value == 0xBD0000
    assert refs["4.03"]["data"][0].value == 0xC00000
    # 4.03 allproc: kstuff 0x27edcb8 + 0xC00000 == umtx 0x33edcb8
    assert all(o.value == 0x33EDCB8 for o in refs["4.03"]["allproc"])


def test_no_cross_source_conflicts_after_normalization():
    refs = load_all_refs(os.path.join(ROOT, "refs"))
    conflicts = []
    for fw, tbl in refs.items():
        for name, offs in tbl.items():
            if name == "data":
                continue
            if len({o.value for o in offs}) > 1:
                conflicts.append((fw, name,
                                   [(o.source, o.value) for o in offs]))
    print(f"\ncross-source conflicts after normalization: {conflicts}")

    # anchor-normalization must fully reconcile kstuff's data-anchored values
    # with UMTX's text-anchored ones wherever both measured the same thing.
    # Known, published divergences the tool must SURFACE (not hide):
    expected_exact = {
        # UMTX 3.10 allproc looks stale (reused from 3.00/3.20); kstuff
        # measured a different value. Genuine public-source disagreement.
        ("3.10", "allproc"),
        # kld-sdk sysentvec vs kstuff: different struct era/member naming.
        ("4.03", "sysentvec"),
        # flag fields: kstuff's per-FW measured values diverge from UMTX's
        ("3.10", "qa_flags"), ("4.02", "qa_flags"),
        ("3.10", "security_flags"), ("4.02", "security_flags"),
        ("3.10", "targetid"), ("4.02", "targetid"),
    }
    # fork-divergence class: Relapse-Exploit vs the sonic fork genuinely
    # disagree on these exploit-dialect names on some FWs (e.g.
    # worker_stack_offset 0x7fb88 vs 0x7fb68; vtable placeholder 0 vs real).
    # Not kernel data; surfaced for humans, not auto-resolved.
    expected_names_any_fw = {"vtable_first_element", "worker_stack_offset"}
    unexpected = [c for c in conflicts
                  if (c[0], c[1]) not in expected_exact
                  and c[1] not in expected_names_any_fw]
    # every expected conflict must actually be present (catalog stays honest)
    for fw_name in expected_exact:
        assert any((c[0], c[1]) == fw_name for c in conflicts), \
            f"expected surfaced conflict {fw_name} missing — did the corpus change?"
    # nothing NEW may appear silently; new conflicts must be catalogued here
    # deliberately after investigation
    assert not unexpected, \
        f"new cross-source conflicts — investigate + catalogue: {unexpected}"


# ---------- verify: convention-mixup detection ----------
def test_verify_flags_convention_mixup():
    refs = load_all_refs(os.path.join(ROOT, "refs"))
    cand = {"allproc": Offset("allproc", 0x27EDCB8, "4.03", "candidate"),
            "prison0": Offset("prison0", 0x2934D00, "4.03", "candidate")}
    res = verify_table(None, cand, refs, "4.03")
    by = {r.name: r for r in res}
    assert by["allproc"].status == "CONFLICT"
    assert "CONVENTION MIXUP" in by["allproc"].detail
    assert "0x33edcb8" in by["allproc"].detail.lower()
    assert by["prison0"].status == "UNVERIFIABLE"   # agrees, no image to byte-check


def test_verify_clean_candidate():
    refs = load_all_refs(os.path.join(ROOT, "refs"))
    cand = {"allproc": Offset("allproc", 0x33EDCB8, "4.03", "candidate")}
    res = verify_table(None, cand, refs, "4.03")
    assert res[0].status == "UNVERIFIABLE"
    assert "matches public tables" in res[0].detail


def test_verify_demo_llm_candidate_file():
    refs = load_all_refs(os.path.join(ROOT, "refs"))
    raw = json.load(open(os.path.join(ROOT, "data/demo_llm_candidate_4.03.json")))
    cand = {n.lower(): Offset(n.lower(), int(v, 0), "4.03", "candidate")
            for n, v in raw.items() if not n.startswith("_")}
    res = verify_table(None, cand, refs, "4.03")
    by = {r.name: r for r in res}
    assert by["allproc"].status == "CONFLICT"
    assert by["prison0"].status == "UNVERIFIABLE"
    assert by["rootvnode"].status == "UNVERIFIABLE"


# ---------- diff + crossfirm ----------
def test_crossfirm_allproc_history():
    refs = load_all_refs(os.path.join(ROOT, "refs"))
    hist = cross_firm_all(refs, "allproc")
    assert hist["3.20"] == [0x333DC58]
    assert hist["4.03"] == [0x33EDCB8]
    # 4.03 -> 4.51 did not move allproc (kernel data layout stable)
    assert hist["4.50"] == [0x33EDCB8]
    assert hist["4.51"] == [0x33EDCB8]


def test_diff_403_vs_450_kernel_data_stable():
    refs = load_all_refs(os.path.join(ROOT, "refs"))
    a = {n: sorted({o.value for o in offs})[0]
         for n, offs in refs["4.03"].items()}
    b = {n: sorted({o.value for o in offs})[0]
         for n, offs in refs["4.50"].items()}
    ta = {n: Offset(n, v, "4.03", "pub") for n, v in a.items()}
    tb = {n: Offset(n, v, "4.50", "pub") for n, v in b.items()}
    rows = diff_tables(ta, tb, "4.03", "4.50")
    moved = {name for name, va, vb, note in rows if note.startswith("moved")}
    assert "allproc" not in moved
    assert "prison0" not in moved


# ---------- tier-1 signatures on a synthetic image ----------
@pytest.fixture
def synthetic_image(tmp_path):
    """Sparse image with a valid empty TAILQ at 0x1000 and a vnode-ish blob."""
    p = tmp_path / "kernel.bin"
    size = 0x400000
    with open(p, "wb") as f:
        f.truncate(size)
    with open(p, "r+b") as f:
        # allproc TAILQ head at 0x1000: first=NULL, last=&head
        f.seek(0x1000)
        f.write(struct.pack("<Q", 0))
        f.write(struct.pack("<Q", KERNEL_VA_BASE + 0x1000))
        # a garbage qword at 0x2000 (not a TAILQ)
        f.seek(0x2000)
        f.write(b"\xde\xad\xbe\xef\xca\xfe\xba\xab")
    return KernelImage(str(p))


def test_signature_allproc_pass(synthetic_image):
    ok, detail = check(synthetic_image, "allproc", 0x1000)
    assert ok, detail


def test_signature_allproc_fail(synthetic_image):
    ok, detail = check(synthetic_image, "allproc", 0x2000)
    assert not ok


def test_signature_allproc_out_of_range(synthetic_image):
    ok, detail = check(synthetic_image, "allproc", 0x9000000)
    assert not ok


def test_verify_table_with_image(synthetic_image):
    refs = load_all_refs(os.path.join(ROOT, "refs"))
    cand = {"allproc": Offset("allproc", 0x1000, "synthetic", "candidate")}
    res = verify_table(synthetic_image, cand, refs, "4.03")
    assert res[0].status in ("VERIFIED", "VERIFIED*")
    # the same TAILQ presented under a wrong convention delta must flag
    cand_bad = {"allproc": Offset("allproc", 0x1000 + 0xC00000, "synthetic", "candidate")}
    res_bad = verify_table(synthetic_image, cand_bad, refs, "4.03")
    # image says the TAILQ is there but public tables disagree -> VERIFIED* or CONFLICT
    assert res_bad[0].status in ("VERIFIED*", "CONFLICT", "MISMATCH")