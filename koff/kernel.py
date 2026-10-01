"""KernelImage: byte access into a raw kernel memory capture or decrypted image.

Two kinds of image are supported:
  - raw PA capture: dumped from a live console at a known physical base
    (e.g. ~/ps5_re captures at PA 0x60C00000). VA = KERNEL_VA_BASE maps to
    PA kernel_phys_base; we translate VA -> file offset via the delta.
  - decrypted image: a plain kernel image whose offset 0 == kernel VA base
    (kernel_phys_base irrelevant; text may be readable).
"""
from __future__ import annotations

import struct

from . import KERNEL_VA_BASE


class KernelImage:
    def __init__(self, path: str, pa_base: int | None = None,
                 kernel_phys_base: int = 0x60000000,
                 va_base: int = KERNEL_VA_BASE,
                 text_readable: bool | None = None):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        self.pa_base = pa_base          # physical address of file offset 0
        self.kernel_phys_base = kernel_phys_base
        self.va_base = va_base
        self.text_readable = text_readable
        # PA of kernel VA base:
        #   va -> pa: pa = va - va_base + kernel_phys_base
        #   pa -> file offset: off = pa - pa_base
        if pa_base is not None:
            self._file_off_of_va = lambda va: (va - va_base + kernel_phys_base) - pa_base
        else:
            self._file_off_of_va = lambda va: va - va_base

    # ---- addressing ----
    def off(self, va_or_off: int) -> int:
        """File offset for a kernel VA (or pass an already-relative offset)."""
        off = self._file_off_of_va(va_or_off)
        if 0 <= off < len(self.data):
            return off
        # caller may have passed a base-relative offset for a va_base-mapped image
        off2 = va_or_off
        if 0 <= off2 < len(self.data):
            return off2
        return -1

    def read(self, va_or_off: int, n: int) -> bytes | None:
        off = self.off(va_or_off)
        if off < 0:
            return None
        return self.data[off:off + n]

    def qword(self, va_or_off: int) -> int | None:
        b = self.read(va_or_off, 8)
        return struct.unpack("<Q", b)[0] if b and len(b) == 8 else None

    def dword(self, va_or_off: int) -> int | None:
        b = self.read(va_or_off, 4)
        return struct.unpack("<I", b)[0] if b and len(b) == 4 else None

    def is_mapped(self, va_or_off: int) -> bool:
        return self.off(va_or_off) >= 0

    # ---- plausibility helpers (PS5 kernel address-space facts) ----
    @staticmethod
    def is_kernel_ptr(v: int) -> bool:
        return 0xFFFF800000000000 <= v <= 0xFFFFFFFFFFFFFFFF

    @staticmethod
    def is_kernel_text_ptr(v: int) -> bool:
        # text lives near the kernel base
        return 0xFFFFFFFF80210000 <= v < 0xFFFFFFFF90000000

    @staticmethod
    def is_ptr_or_null(v: int) -> bool:
        return v == 0 or KernelImage.is_kernel_ptr(v)

    def text_sample(self, va_or_off: int, n: int = 16) -> bytes | None:
        """Return text bytes if the text region is readable; else None.

        XOM-protected captures return high-entropy bytes for text; we detect
        that heuristically: readable x86 text has a sane distribution of
        common opcode bytes; XOM garbage does not.
        """
        b = self.read(va_or_off, n)
        if b is None or len(b) < n:
            return None
        if self.text_readable is False:
            return None
        # heuristic: count very common x86 text bytes; also 0x00/0xCC runs.
        common = sum(b.count(c) for c in (0x00, 0x48, 0x89, 0x8B, 0xE8, 0xFF, 0x55, 0x90))
        if self.text_readable is None and common < n // 8:
            return None  # looks like XOM garbage
        return b