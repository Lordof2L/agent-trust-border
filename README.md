# Agent Trust Border

**A loss-aware admission layer for AI agents crossing trust systems.**

Agent protocols can carry signed identity and capability claims, but a valid
signature does not prove that the receiver authorised the requested action.
Agent Trust Border keeps integrity, identity, authority, evidence and world
truth separate. Missing trust semantics remain explicit `UNKNOWN` instead of
being silently upgraded into permission.

> **STATIC SYNTHETIC EVIDENCE — NO ACTION EXECUTION.** This repository is a
> bounded NTU InnovateX 2026 Stage-1 prototype, not a production gateway.

## Recorded proof

```text
capability only                         -> UNKNOWN:MISSING_AUTHORIZATION
exact trusted one-use sandbox grant     -> ADMIT:ALL_MANDATORY_CHECKS_PASS
production scope mutation               -> DENY:SCOPE_EXCEEDED
consumed grant replay                    -> DENY:REPLAY_DETECTED
```

- 20/20 named security cases pass.
- The matrix ran 100 times from fresh state: 2,000 deterministic case executions.
- Grants and receipts use real DSSE/Ed25519 operations.
- Independent verification recomputes every receipt binding offline.
- Every result preserves `action_executed:false`.

[Explore the static evidence viewer](https://lordof2l.github.io/agent-trust-border/)
or inspect the committed [proof report](PROOF-REPORT.md),
[trace](artifacts/trace.json), and [signed receipts](artifacts/).

[Watch the 2-minute narrated demo](https://lordof2l.github.io/agent-trust-border/#video)
or download the reproducible [MP4](video/Agent-Trust-Border-Stage1.mp4).
The English narration uses [ElevenLabs](https://elevenlabs.io/)' premade Eric voice. Generation details
and the accepted Free-plan licence risk are recorded in the
[narration rights ledger](video/RIGHTS-LEDGER.md).

## How it works

```text
external agent claim
        |
        v
strict ingress + pinned adapter result
        |
        v
directional semantic-loss ledger
        |
        v
receiver policy + exact authority challenge
        |
        v
ADMIT | DENY | UNKNOWN + signed BorderReceipt
```

The effective scope is never broader than:

```text
request ∩ trusted grant ∩ receiver policy
```

`ADMIT` is a decision only. This prototype has no requested-action execution
path, network fetcher, model client, tool client, registry or production trust
root.

## Reproduce locally

Prerequisites: Python 3.12 and `uv` 0.11.15 or a compatible newer release.

```bash
uv sync --frozen
./verify
```

`./verify` runs Ruff, 25 tests including the fixed 20 × 100 determinism gate,
the four-step demo, and evidence export. To view the exported trace directly:

```bash
open artifacts/trace.html
```

All identities and deterministically derived keys use a `demo:` namespace and
carry no external authority. Never reuse them outside this synthetic fixture.

## Truth boundary

This prototype demonstrates receiver-owned, loss-aware admission for one
static synthetic profile. It does **not** prove:

- world truth, benign intent, or future agent behaviour;
- production key security, durability, or distributed atomicity;
- live A2A, Pramana, ACPs, GB/Z, or authorization-network conformance;
- production security, users, revenue, adoption, or first-of-kind novelty.

The source-agent integrity, identity and evidence outcomes are pinned synthetic
adapter results. Canonical bytes and valid signatures prove exact-byte
integrity and key control—not authorization or truth.

See [DISCLOSURE.md](DISCLOSURE.md) for prior art and reused standards,
[THIRD_PARTY-NOTICES.md](THIRD_PARTY-NOTICES.md) for dependency licences, and
[SECURITY.md](SECURITY.md) for the security boundary.

## Licence

Original project code is source-available and all rights reserved. NTU
InnovateX organisers and judges receive the narrow evaluation permission stated
in [LICENSE](LICENSE). Dependencies retain their own licences. No upstream
source code is vendored.
