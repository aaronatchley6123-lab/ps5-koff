"""Fetch public offset sources into refs/ at install/run time.

koff ships NO offset data. Everything under refs/ is fetched from the
scene's public repositories:

  Specter/UMTX jailbreak   github.com/PS5Dev/PS5-UMTX-Jailbreak      (Unlicense)
  Relapse exploit          github.com/ntfargo/Relapse-Exploit        (MIT)
  Relapse (sonic fork)      github.com/soniciso1/relapse              (MIT)
  kld-sdk                  github.com/buzzer-re/ps5-kld-sdk          (MIT)
  kstuff offsets.c         sleirsgoevy/ps4jb-payloads @ bd-jb         (MIT)

Only stdlib: urllib + tarfile. `koff fetch` is idempotent; pass --force to
re-fetch even if targets exist.
"""
from __future__ import annotations

import io
import os
import shutil
import sys
import tarfile
import urllib.request
from pathlib import Path

CODELOAD = "https://codeload.github.com/{repo}/tar.gz/refs/heads/{branch}"
RAW = "https://raw.githubusercontent.com/{repo}/{branch}/{path}"

SOURCES = [
    # (name, kind, url, dest subdir, strip top-level tar dir?)
    ("umtx", "tar", CODELOAD.format(repo="PS5Dev/PS5-UMTX-Jailbreak",
                                    branch="main"),
     "umtx", True),
    ("relapse", "tar", CODELOAD.format(repo="ntfargo/Relapse-Exploit",
                                       branch="main"),
     "relapse", True),
    ("relapse-sonic", "tar", CODELOAD.format(repo="soniciso1/relapse",
                                              branch="main"),
     "relapse-sonic", True),
    ("kld-sdk", "tar", CODELOAD.format(repo="buzzer-re/ps5-kld-sdk",
                                       branch="main"),
     "kld-sdk", True),
    ("kstuff", "raw", RAW.format(
        repo="sleirsgoevy/ps4jb-payloads", branch="bd-jb",
        path="prosper0gdb/offsets.c"),
     "kstuff_offsets.c", False),
]

# some repos use master as default branch; try in order
_BRANCH_FALLBACKS = {"main", "master"}


def _fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "koff/0.1"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def _download_tar(url: str, dest: Path, strip_top: bool) -> None:
    data = _fetch(url)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.parent / (dest.name + ".tmp")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        members = tf.getmembers()
        if strip_top and members:
            top = members[0].name.split("/")[0]
            for m in members:
                parts = m.name.split("/", 1)
                if len(parts) < 2 or parts[0] != top:
                    continue
                m.name = parts[1]
                tf.extract(m, tmp)
    if tmp.exists():
        if dest.exists():
            shutil.rmtree(dest)
        tmp.rename(dest)
    else:
        raise RuntimeError(f"tarball unpack produced nothing for {url}")


def _download_raw(url: str, dest: Path) -> None:
    data = _fetch(url)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)


def _probe_branch(repo: str) -> str:
    """Try main, then master; return whichever yields a tarball."""
    last = None
    for br in _BRANCH_FALLBACKS:
        url = CODELOAD.format(repo=repo, branch=br)
        try:
            _fetch(url)
            return br
        except Exception as e:      # noqa: BLE001
            last = e
    raise RuntimeError(f"cannot reach {repo} on main or master: {last}")


def fetch_all(refs_dir: str, force: bool = False, verbose: bool = True) -> list:
    """Fetch every source. Returns list of (name, ok, detail)."""
    root = Path(refs_dir)
    root.mkdir(parents=True, exist_ok=True)
    results = []
    for name, kind, url, dest_s, strip in SOURCES:
        dest = root / dest_s
        if dest.exists() and not force:
            results.append((name, True, "present (use --force to re-fetch)"))
            continue
        try:
            if kind == "tar":
                branch = _probe_branch("/".join(url.split("/")[3:5]))
                url = CODELOAD.format(repo="/".join(url.split("/")[3:5]),
                                      branch=branch)
                _download_tar(url, dest, strip)
            else:
                _download_raw(url, dest)
            results.append((name, True, f"fetched -> {dest}"))
        except Exception as e:      # noqa: BLE001
            results.append((name, False, f"{type(e).__name__}: {e}"))
        if verbose:
            ok, detail = results[-1][1], results[-1][2]
            print(f"  [{'ok' if ok else 'FAIL'}] {name:<13} {detail}",
                  file=sys.stderr)
    return results


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(prog="koff.fetch")
    p.add_argument("refs_dir", nargs="?", default="refs")
    p.add_argument("--force", action="store_true")
    a = p.parse_args()
    res = fetch_all(a.refs_dir, force=a.force)
    sys.exit(0 if all(ok for _, ok, _ in res) else 1)