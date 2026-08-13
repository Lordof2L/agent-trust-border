# Prior work and reuse disclosure

Agent Trust Border is a competition-specific composition and synthetic offline
prototype built from pre-existing internal trust/receipt research and public
prior art. The claimed contribution is narrow: a receiver-side flow that keeps
integrity, identity, authority, evidence, and world truth separate; records
directional semantic loss; requests missing authority with a context-bound
challenge; intersects scope with receiver policy; and emits a signed decision
receipt.

## Prior work and public foundations

| Foundation | Use in this prototype | Boundary |
|---|---|---|
| [Pramana Attestation](https://github.com/Pramana-Research/pramana-attestation) | Typed claim vocabulary and explicit unverifiable state informed static fixtures | Not our invention; no runtime fetcher or world-truth claim |
| [A2A](https://github.com/a2aproject/A2A) | Agent-card and capability vocabulary informed a synthetic fixture | No SDK integration or conformance claim; capability is not permission |
| [ACPs Community](https://github.com/AIP-PUB/ACPs-community) | Public AIC/ACS concepts informed fixture vocabulary | No production root, ARSP verification, GB/Z certification, or conformance claim |
| [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) | Canonical JSON bytes | Canonical bytes prove neither semantics nor truth |
| [DSSE](https://github.com/secure-systems-lab/dsse) and [securesystemslib](https://github.com/secure-systems-lab/securesystemslib) | Grant and receipt envelopes with Ed25519 operations | A signature proves exact bytes and key control only |
| [in-toto Statement v1](https://github.com/in-toto/attestation) | Receipt wrapper and request-subject digest shape | No full in-toto framework or supply-chain claim |
| IETF Agent Operation Authorization work and [open-agent-auth](https://github.com/alibaba/open-agent-auth) | Authorization vocabulary and negative cases | Generic agent authorization is prior art; this demo is not AOAT/JWT conformant |

No upstream source code is vendored. Direct runtime packages are pinned in
`uv.lock` and retain their own licences.

## New Stage-1 work

- a closed Python admission kernel and five separate trust axes;
- directional semantic-loss checks and a prohibition on generic `VERIFIED`;
- exact challenge, least-authority reducer, one-use state, and signed receipt;
- 20 named security cases and a 2,000-execution determinism gate;
- a four-step synthetic demo, static evidence viewer, deck, and proof artifacts.

The internal research predates this submission. The competition-period work is
the bounded composition, implementation, tests, evidence package, and demo.

## Claims not made

No world-first claim. No proof of benign agent intent, issuer honesty, world
truth, production security, live protocol conformance, users, revenue, or
adoption. Source-agent integrity, identity, and evidence results are pinned
synthetic adapter outcomes. All generated identities and keys use `demo:` and
have no external authority.
