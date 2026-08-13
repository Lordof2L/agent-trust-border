# Stage-1 proof report

Executed: 2026-08-14 CEST
Runtime: local CPython 3.12 / macOS arm64
Mode: offline kernel; sequential test worker; synthetic fixtures

## Verdict

The narrow competition claim passes its behavioral gate:

```text
capability only                         -> UNKNOWN:MISSING_AUTHORIZATION
exact trusted one-use sandbox grant     -> ADMIT:ALL_MANDATORY_CHECKS_PASS
production scope mutation               -> DENY:SCOPE_EXCEEDED
consumed grant replay                    -> DENY:REPLAY_DETECTED
```

The exact challenge emitted by the first transition is hash/nonce-bound into
the grant used by the second transition. Every result carries
`action_executed:false`, and world truth remains `OUT_OF_SCOPE`.

## Executed evidence

- 20 named behavioral cases K01-K20 passed.
- 25 tests passed, including a public-fixture namespace gate.
- The complete matrix ran 100 times from fresh deterministic fixture state:
  2,000 case executions with byte-identical observations.
- Independent receipt verification recomputed the request subject digest,
  policy/mapping/trust hashes, receipt ID, DSSE payload type, signer purpose and
  Ed25519 signature.
- Grant and receipt payload mutation, context mutation, replay, wrong key
  purpose, untrusted issuer, expiry, revocation, unknown schema/predicate,
  semantic loss/conflict, prompt text and loopback URI cases remained
  non-admit.
- Static import gate found no model, network, subprocess or tool-client import
  in `src/agent_trust_border`.
- Ruff passed with no findings.
- Runtime lock resolved ten dependencies. `pip-audit` reported zero known
  vulnerabilities for the hash-pinned runtime set. This is an advisory lookup,
  not a security audit or guarantee.
- CycloneDX 1.5 SBOM exported with uv 0.11.15. uv labels this export path
  experimental.

Run all local proof:

```bash
./verify
```

## Truth boundary

What this proves:

- deterministic, receiver-owned, loss-aware admission for one static synthetic
  profile;
- real DSSE/Ed25519 operations for grants and receipts;
- exact scope intersection and one-use/idempotency behavior;
- offline replayable receipts and a deterministic self-contained trace.

What it does not prove:

- world truth, benign intent or future agent behavior;
- production key protection, durability, distributed atomicity or revocation;
- live A2A, Pramana, ACPs or GB/Z conformance;
- official GB/Z identity roots or certification;
- a production gateway, tool broker or action executor;
- novelty of generic agent identity, authorization, attestation or DSSE.

The source integrity/identity pass in V0 is a receiver-owned pinned synthetic
adapter result. It is labelled as such in code, output and submission material.
No runtime path fetches a source, key, URI or evidence object.

Every synthetic identity and deterministically derived key is namespaced
`demo:` and the exported key set and trace carry `demo_only:true`. These keys
are intentionally reproducible from public source and are not credentials.
