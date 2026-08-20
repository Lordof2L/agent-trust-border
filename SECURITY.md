# Security boundary

Agent Trust Border is a synthetic, offline competition prototype. It is not a
production security product and has not received an external cryptographic,
penetration, conformance, or deployment review.

## Never provide real secrets

Do not submit production credentials, private keys, tokens, identity documents,
agent traffic, or confidential data. The trusted kernel performs no network
I/O and contains only deterministic `demo:` identities and keys that anyone
can reproduce from source.

The Phase-2 request lab adds an explicitly untrusted loopback HTTP adapter. It
binds only to `127.0.0.1`, accepts a closed synthetic command of at most 8 KiB,
and has no endpoint for arbitrary keys, claims, actions or external resources.
Do not expose this development server to another interface or the public
internet.

Each lab evaluation starts from fresh deterministic fixture state. The replay
preset consumes and reuses a grant inside one request; replay state is not
durable across independent HTTP requests.

## In scope for review

- an input that produces a false `ADMIT` under the frozen synthetic policy;
- receipt or grant mutation that passes independent verification;
- replay, context, issuer, key-purpose, scope, or semantic-loss bypass;
- local-lab input that escapes the closed command schema, reaches an arbitrary
  file, or causes a verdict without the kernel;
- a repository secret or non-demo private key accidentally committed.

## Explicitly unsupported

- live A2A, ACPs, GB/Z, Pramana, registry, wallet, or tool integration;
- production key storage, revocation, distributed state, or action execution;
- public or multi-tenant hosting of the Phase-2 development adapter;
- claims that a valid signature proves truth, intent, or future safe behaviour.

Report issues through GitHub private vulnerability reporting when available.
Do not include real secrets in any report.
