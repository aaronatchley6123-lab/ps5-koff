"""Byte-level signatures for PS5 kernel data offsets (FreeBSD 11 derived).

Each signature knows how to check "is the qword(s) at this offset consistent
with what this structure should contain, given this image?" — the ground
truth that catches hallucinated offsets before they reach a console.
"""
from __future__ import annotations

from .kernel import KernelImage
from . import KERNEL_VA_BASE


def _tailq_selfptr(img: KernelImage, off: int) -> tuple[bool, str]:
    """TAILQ_HEAD: qword[1] (tqh_last) points back at &head->tqh_first."""
    q0 = img.qword(KERNEL_VA_BASE + off)
    q1 = img.qword(KERNEL_VA_BASE + off + 8)
    if q0 is None or q1 is None:
        return False, "not mapped in image"
    if q1 != KERNEL_VA_BASE + off:
        return False, f"tqh_last={q1:#x} != &allproc+off={KERNEL_VA_BASE + off:#x}"
    if q0 != 0 and not img.is_kernel_ptr(q0):
        return False, f"tqh_first={q0:#x} is not a kernel pointer or NULL"
    return True, f"TAILQ ok (first={q0:#x}, self-ptr ok)"


def _kptr(img: KernelImage, off: int, null_ok: bool = True) -> tuple[bool, str]:
    v = img.qword(KERNEL_VA_BASE + off)
    if v is None:
        return False, "not mapped in image"
    if null_ok and v == 0:
        return True, "NULL (allowed)"
    if not img.is_kernel_ptr(v):
        return False, f"{v:#x} is not a kernel pointer"
    return True, f"kernel ptr {v:#x}"


def _rootvnode(img: KernelImage, off: int) -> tuple[bool, str]:
    """rootvnode: pointer to a vnode; vnode's v_type field is a small enum."""
    v = img.qword(KERNEL_VA_BASE + off)
    if v is None:
        return False, "not mapped in image"
    if not img.is_kernel_ptr(v):
        return False, f"{v:#x} not a kernel ptr"
    # v_data/v_type near the vnode start; v_type is a small int (< 0x100)
    # FreeBSD vnode: v_type at offset 0x38 (11-derived layout varies) — scan
    # the first 0x40 bytes for a plausible small enum + kernel pointers.
    head = img.read(v, 0x40)
    if head is None:
        return True, f"ptr ok {v:#x} (vnode not in capture)"
    kptrs = sum(1 for i in range(0, 0x40, 8)
                if img.is_kernel_ptr(int.from_bytes(head[i:i + 8], "little")))
    if kptrs >= 2:
        return True, f"ptr ok {v:#x}, vnode-shaped ({kptrs} kernel ptrs in first 0x40)"
    return False, f"ptr ok {v:#x} but target doesn't look like a vnode"


def _idt(img: KernelImage, off: int) -> tuple[bool, str]:
    """IDT: 16-byte gates; the divide-error gate is present in any kernel."""
    b = img.read(KERNEL_VA_BASE + off, 16)
    if b is None:
        return False, "idt region unreadable"
    if not any(b):
        return False, "first gate all zero"
    return True, "idt gate bytes present"


# name -> checker(img, off) -> (ok, detail)
SIGNATURES = {
    "allproc": _tailq_selfptr,
    "zombproc": _tailq_selfptr,
    "prison0": lambda img, off: _kptr(img, off, null_ok=False),
    "rootvnode": _rootvnode,
    "rootvnode_ptr": _rootvnode,
    "kernel_pmap": lambda img, off: _kptr(img, off, null_ok=False),
    "idt": _idt,
}
POINTER_CLASS = (
    "prison0", "rootvnode", "kernel_pmap", "apic_ops", "cpu_apic_ids",
    "allproc", "idt", "gdt_array", "tss_array", "pcpu_array", "sysentvec",
    "sysents", "kernel_pmap_store", "crypt_singleton_array",
)


def check(img: KernelImage, name: str, off: int) -> tuple[bool, str]:
    """Byte-verify one offset against the image. Returns (ok, detail)."""
    if name in SIGNATURES:
        return SIGNATURES[name](img, off)
    if not img.is_mapped(KERNEL_VA_BASE + off):
        return False, f"VA {KERNEL_VA_BASE + off:#x} not mapped in image"
    if name in POINTER_CLASS or any(k in name for k in
                                   ("ptr", "proc", "vnode", "pmap", "array")):
        return _kptr(img, off)
    # generic: mapped is all we can claim
    return True, "mapped (no specific signature — generic pass)"