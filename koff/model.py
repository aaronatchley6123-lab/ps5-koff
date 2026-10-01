"""Core data model: offsets, tables, verification results."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Offset:
    name: str            # canonical name, e.g. "allproc"
    value: int           # offset (usually relative to kernel VA base)
    fw: str              # firmware label, e.g. "4.03"
    source: str          # provenance, e.g. "umtx:document/en/ps5/offsets/4.03.js"
    kind: str = "unknown"     # data | text | sysent | syscall | flag | ...
    abs_va: Optional[int] = None   # set when the source gave an absolute VA
    note: str = ""

    def key(self) -> str:
        return f"{self.fw}:{self.name}"


@dataclass
class OffsetTable:
    fw: str
    offsets: dict = field(default_factory=dict)  # name -> Offset

    def add(self, off: Offset) -> None:
        if off.name in self.offsets:
            existing = self.offsets[off.name]
            if existing.value != off.value:
                off.note = (off.note + "; " if off.note else "") + \
                    f"conflict with {existing.source}={existing.value:#x}"
        self.offsets[off.name] = off

    def names(self):
        return sorted(self.offsets)

    def __len__(self):
        return len(self.offsets)


@dataclass
class VerifyResult:
    name: str
    value: int
    status: str = "UNVERIFIABLE"      # VERIFIED | PLAUSIBLE | MISMATCH | UNVERIFIABLE | CONFLICT | VERIFIED*
    detail: str = ""
    sources: dict = field(default_factory=dict)   # source -> value (cross-firm)

    @property
    def ok(self) -> bool:
        return self.status in ("VERIFIED", "PLAUSIBLE")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()