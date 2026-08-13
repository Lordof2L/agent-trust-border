# Security boundary

Agent Trust Border is a synthetic, offline competition prototype. It is not a
production security product and has not received an external cryptographic,
penetration, conformance, or deployment review.

## Never provide real secrets

Do not submit production credentials, private keys, tokens, identity documents,
agent traffic, or confidential data. The repository accepts no network input
and contains only deterministic `demo:` identities and keys that anyone can
reproduce from source.

## In scope for review

- an input that produces a false `ADMIT` under the frozen synthetic policy;
- receipt or grant mutation that passes independent verification;
- replay, context, issuer, key-purpose, scope, or semantic-loss bypass;
- a repository secret or non-demo private key accidentally committed.

## Explicitly unsupported

- live A2A, ACPs, GB/Z, Pramana, registry, wallet, or tool integration;
- production key storage, revocation, distributed state, or action execution;
- claims that a valid signature proves truth, intent, or future safe behaviour.

Report issues through GitHub private vulnerability reporting when available.
Do not include real secrets in any report.
