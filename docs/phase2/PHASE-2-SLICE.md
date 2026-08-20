# Agent Trust Border Phase 2 — executable request lab

Status: acceptance contract frozen before implementation; P2.1 complete

## Target

Turn the Stage-1 recorded evidence into one real, browser-operated vertical
slice. A user changes a bounded synthetic request, submits it to the actual
Python admission kernel, and receives a newly computed signed result.

This slice proves interactive admission behavior. It still performs no
requested deployment, wallet, tool, model, registry, remote-key or network
resolution action.

## Highest-leverage boundary

The first Phase-2 slice is not a generic gateway or production API. It is a
local executable lab with three layers:

1. the unchanged offline `agent_trust_border` kernel;
2. a small untrusted HTTP adapter outside the trusted package;
3. an accessible browser UI that sends only a closed synthetic command.

The adapter may translate and transport data. It may never select a verdict,
expand scope, construct authority from free text, or execute the requested
action.

## Closed user inputs

- requested resource: `sandbox:demo` or `production:demo`;
- authority mode: `missing`, `exact_trusted_grant`, or
  `consumed_grant_replay`;
- evidence mode: `verified` or `unavailable`.

`consumed_grant_replay` is valid only for `sandbox:demo` with verified
evidence. Any unsupported field, value, combination, duplicate JSON key,
non-finite number, wrong content type or oversized body fails visibly.

## Required behavior

| Request | Expected result |
|---|---|
| sandbox + missing + verified | `UNKNOWN:MISSING_AUTHORIZATION` |
| sandbox + exact grant + verified | `ADMIT:ALL_MANDATORY_CHECKS_PASS` |
| production + exact grant + verified | `DENY:SCOPE_EXCEEDED` |
| sandbox + consumed grant + verified | `DENY:REPLAY_DETECTED` |
| sandbox + missing + unavailable evidence | `UNKNOWN:MISSING_AUTHORIZATION,EVIDENCE_UNAVAILABLE` |

Every response must contain a DSSE/Ed25519 `BorderReceipt` that the server
independently verifies before returning. Every response keeps
`action_executed:false` and `world_truth:OUT_OF_SCOPE`.

Each HTTP evaluation uses fresh deterministic fixture state. The consumed
replay preset proves one-use behavior inside one bounded evaluation; it does
not claim replay durability across independent HTTP requests.

## Acceptance test

The slice is complete only when all of the following are true:

1. the five behaviors above pass through the public lab function and HTTP API;
2. malformed, unsupported and incompatible input is rejected without a stack
   trace or fallback allow;
3. the browser operator can run every valid scenario and observes the same
   verdict, reason, effective scope and no-action boundary as the API;
4. keyboard operation, mobile layout, local links, video/static Stage-1 paths
   and browser console are checked in a bounded pass;
5. all original Stage-1 tests and deterministic receipt gates remain green;
6. any public description says `local executable synthetic lab`, not
   `production gateway`, `live protocol conformance` or `action execution`.

## Deferred

- arbitrary external agent requests or keys;
- production trust roots, key storage, revocation network or persistent state;
- AgentTeams, A2A, ACPs, Pramana or GB/Z live adapters;
- real deployment/tool execution and rollback;
- multi-tenant authentication, rate limiting and public hosting.
