# Agent Trust Border Phase 2 roadmap

This roadmap is ordered by risk removed, not visual polish. A later slice does
not begin until the earlier slice has a behavior-level receipt.

## P2.1 — Executable request lab

Status: complete. The executable slice, tests and audit are published on
`main`. The frozen audit preserves three historical pre-fix accessibility
failures; the corrective source is deployed and byte-verified, while the
post-fix interactive recheck remains blocked by the disconnected Browser
backend.

Browser controls call the real synthetic kernel and receive an independently
verified signed result. State is intentionally fresh per HTTP evaluation and
no requested action executes.

Exit proof: the five-scenario contract in `PHASE-2-SLICE.md`, fail-closed HTTP
tests, independent browser matrix, current checksum manifest and public source.

## P2.2 — Durable one-use admission state

Persist grant consumption, idempotency and receipt commit atomically across
process restarts. Keep the store receiver-owned and outside model control.

Exit proof:

- two independent HTTP requests cannot consume one grant twice;
- crash at every commit boundary yields either the original receipt or a
  non-admit result, never a second capability;
- concurrent requests have exactly one winner and no orphaned lease;
- state schema/version migration is explicit and rollback-tested.

## P2.3 — One live protocol ingress adapter

Select one official, version-pinned source representation and translate it into
the existing closed request model. The adapter reports every lost, weaker,
conflicting or unsupported field; it never creates authority.

Exit proof: official conformance fixtures plus adversarial mutations produce
the same receiver verdicts as direct canonical requests. No claim of broad
protocol or GB/Z conformance is allowed from one adapter.

## P2.4 — Contained action handoff

Add a separate sandbox broker that accepts only an independently verified,
unexpired `ADMIT` receipt and its exact effective scope. The broker produces a
separate action receipt; the admission kernel remains unable to execute tools.

Exit proof: `UNKNOWN`, `DENY`, edited, expired, replayed and scope-expanded
receipts result in zero broker calls. The positive path can affect only a
disposable sandbox fixture and is reversible.

## P2.5 — Cross-system border adapter

Add the first directional trust crosswalk between two independently verified
identity/authority systems. Preserve `UNKNOWN` for semantic non-equivalence and
sign a mapping/policy receipt.

Exit proof: published field-level crosswalk, loss fixtures, receiver policy,
offline verifier and external interoperability run. This is the first slice
that may support a trust-border product claim beyond the local lab.
