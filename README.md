# koff — PS5 kernel offset verifier

The missing half of the scene's LLM-assisted offset workflow:
**your LLM proposes offsets; koff verifies them.**

The PS5 scene now does offset work with LLMs. LLMs are fluent in the scene's
dialects but hallucinate values, and the public sources they learned from use
**incompatible anchor conventions** — a table that mixes them compiles, links,
and patches the wrong bytes into a kernel. koff byte-verifies candidate offset
tables against ground truth (kernel images) and cross-firms them against every
public offset table, mechanically.

## What it does

1. **Cross-firm verification** (`koff verify`) — a candidate table
   `{name: value}` is checked against every public source for that firmware:
   - `CONVENTION MIXUP` — the value is off by exactly the kernel-data anchor
     (`OFFSET_KERNEL_DATA`, per-FW: 0xBD0000 on 3.20, 0xC00000 on 4.x …):
     the classic LLM failure of blending kstuff (data-anchored) with
     Specter/UMTX (text-anchored) sources. koff names the corrected value.
   - `CONFLICT` — public sources genuinely disagree (surfaced for a human).
   - `VERIFIED*` — image bytes confirm the candidate but public tables
     disagree: a finding worth publishing, never silently resolved.
2. **Byte verification** (`--image`) — against a raw capture or decrypted
   kernel image, using structure signatures (allproc must be a valid TAILQ
   head whose `tqh_last` self-points; rootvnode must point at a vnode-shaped
   kernel object; IDT gates must be present; …). Tier-1 ready; activates
   wherever a decrypted image exists for the target FW.
3. **Firmware diff** (`koff diff --a 4.03 --b 5.00`) — which anchors moved
   between firmwares, with deltas.
4. **Offset history** (`koff crossfirm --name allproc`) — one offset's value
   across every public firmware table.

## Proven on real scene data

During development koff caught two live defect classes:

- **The anchor-convention split.** kstuff's `DEF(allproc, 0x27edcb8)` (4.03)
  and Specter/UMTX's `OFFSET_KERNEL_ALLPROC = 0x033EDCB8` differ by exactly
  `OFFSET_KERNEL_DATA` — both are right in their own frame, and any table
  mixing them is silently wrong. koff derives the per-FW delta from the
  sources themselves and normalizes before comparing.
- **Expression-form collapse.** Relapse 13.40+ writes the QA/security flag
  fields as `= 0x01A49064 + 0x24`. A lazy parser silently collapses
  `targetid`, `qa_flags` and `utoken_flags` onto the `security_flags` base
  value — plausible-looking, wrong, unflagged. koff evaluates the expression
  and tags the provenance.

## Usage

```bash
uv venv .venv && uv pip install --python .venv/bin/python pytest
.venv/bin/python -m koff.cli fetch                       # one-time: pull public refs
.venv/bin/python -m koff.cli refs                        # coverage: 64 FW tables
.venv/bin/python -m koff.cli verify --fw 4.03 \
    --table my_candidate_table.json                      # LLM output in
# -> CONVENTION MIXUP: candidate 0x27edcb8 is DATA-anchored (kstuff-style);
#    canonical TEXT-anchored value is 0x33edcb8 (= candidate + 0xc00000).
.venv/bin/python -m koff.cli diff --a 13.40 --b 13.60   # which anchors moved
.venv/bin/python -m koff.cli crossfirm --name allproc
```

`verify` exits non-zero on any MISMATCH/CONFLICT — CI-friendly.

## Sources ingested (koff fetch pulls all of these live — nothing is vendored)

- Specter/UMTX jailbreak offsets (1.00–5.50) — text-anchored (Unlicense)
- Relapse + sonic-fork offsets (7.00–13.60) — text-anchored, expression forms (MIT)
- buzzer-re/ps5-kld-sdk headers (4.03, 5.00) — absolute-VA normalized (MIT)
- kstuff/prosper0gdb offsets.c (3.00–4.51, sleirsgoevy's archived repo) —
  data-anchored, normalized per-FW (MIT)

## Status

- Cross-firm tier: **complete** — 64 firmware tables, 350+ entries each,
  zero kernel-data conflicts after normalization (the remaining conflict
  names are genuine public-source divergences, surfaced not hidden).
- Byte-verify tier: engine + synthetic-image tests green; awaiting a decrypted
  kernel image on this bench (our 4.03 capture is fSELF-encrypted at rest).
- Planned: signature sweep of a decrypted image to emit a fully VERIFIED pack.

## Tests

```bash
.venv/bin/python -m pytest tests/ -q    # 27 passed
```