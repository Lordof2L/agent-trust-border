# Phase 2 Web-Operator Audit

Date: 2026-08-20 (Europe/Bratislava)

Surfaces:

- Public evidence explorer: <https://lordof2l.github.io/agent-trust-border/>
- Public submission: <https://devpost.com/software/agent-trust-border>
- Local Phase-2 lab: <http://127.0.0.1:8877/>

Mode: one bounded, read-only browser pass. Targeted recapture was used only where an unsupported browser selector or client-side block invalidated the first observation. No login, like, comment, follow, form submission, publication, deployment or source mutation was performed.

## Verdict

Core security semantics passed. No tested path executed the requested action, widened authority, admitted a replay, or admitted unavailable evidence.

| Result | Count |
|---|---:|
| PASS | 53 |
| FAIL | 3 |
| WARN | 1 |
| BLOCKED by operator tooling | 3 |
| Pending | 0 |
| Total | 60 |

P0 findings: **0**.

P1 findings recorded in the frozen pass: **2**:

1. The pre-fix public decision tablist did not implement the WAI-ARIA tabs pattern or Arrow/Home/End operation. A source fix is now deployed, but a post-deploy interactive recheck is blocked as recorded below.
2. The Devpost YouTube iframe was unavailable inside the Codex in-app browser; the failure may be environment-specific.

This report preserves the three observed pre-fix public FAIL results. A deployed
source match is evidence that the fix reached production; it is not silently
substituted for the missing interactive operator recheck.

## Post-deploy source verification

GitHub Pages successfully deployed main commit
`7e36084a4cd59cb6819b1f9d3913d4add6d9f0da`. Fresh HTTP GETs after that build
proved that the public files are byte-identical to the locally tested fix:

- `docs/index.html`: `42f71fca0b6cc20c6de412d0762009cb02f5fe6069d5d4c491d9a6ef697659fe`;
- `docs/app.js`: `49f7e171ab42d04c41c6475bbd02d2140929d93f1ef7b44f14f6b530a6995e23`.

The deployed HTML contains four `aria-controls="decisionPanel"` relationships,
one labelled `role="tabpanel"`, one initial `tabindex="0"` and three initial
`tabindex="-1"` values. The deployed JavaScript contains the
ArrowLeft/ArrowRight/Home/End handlers and roving-tabstop update.

The retained Codex Browser binding disconnected before the bounded interactive
recheck. Explicit reconnect was unavailable and `browsers.list()` returned an
empty list. No replacement tab was created. Therefore the source/deployment fix
is proved, while KEYBOARD-003, KEYBOARD-004 and SEMANTIC-ARIA-001 remain the
historical pre-fix observations rather than being relabelled PASS without a
working browser operator.

## Highest-impact evidence

### Local executable kernel

All five visible presets were clicked and returned independently verified signed results:

| Preset | Verdict | Reasons | Effective scope | Receipt verified | Action executed |
|---|---|---|---|---:|---:|
| Missing authority | UNKNOWN | MISSING_AUTHORIZATION | none | true | false |
| Exact grant | ADMIT | ALL_MANDATORY_CHECKS_PASS | sandbox:demo / deploy / max_runs=1 | true | false |
| Production mutation | DENY | SCOPE_EXCEEDED | none | true | false |
| Consumed replay | DENY | REPLAY_DETECTED | none | true | false |
| Evidence unavailable | UNKNOWN | MISSING_AUTHORIZATION, EVIDENCE_UNAVAILABLE | none | true | false |

Manual sandbox:demo + exact_trusted_grant + verified produced the same ADMIT contract as the preset.

The conflicting manual combination exact_trusted_grant + unavailable was coerced by the UI to missing + unavailable and returned a fail-closed UNKNOWN. A direct server request for the forbidden combination returned:

    {"http":422,"error":"invalid_command","action_executed":false}

GET /api/v1/health returned:

    {"action_execution":false,"kernel":"agent-trust-border/0.1","profile":"synthetic-local-lab","status":"ok"}

Five valid preset POSTs returned HTTP 200 with the exact contracts above. The conflict returned bounded HTTP 422. The browser captured zero error-level console entries.

### Public explorer

- UNKNOWN, ADMIT, SCOPE_EXCEEDED DENY and REPLAY_DETECTED DENY were clicked and matched the committed receipt links.
- Every visible result retained action_executed false.
- Public CSS, JS, poster, captions and PDF returned HTTP 200.
- MP4 byte range returned HTTP 206.
- Public and local MP4 SHA-256 matched:

  0cafc1e540d313c66394a5e0dab2fe16a5d328fd4e2934745b7b22af99dcf8bd

- Media proof: 122.76 seconds, H.264 1920×1080, AAC 48 kHz mono, mov_text subtitles.
- English captions were present and showing by default.
- All internal anchors worked.
- GitHub Source and ElevenLabs attribution reached the intended destinations.
- 1440×900, 768×1024 and 390×844 had no horizontal overflow or off-screen interactive controls.
- Zero error-level console entries were captured.

The Browser client refused direct JSON navigation with ERR_BLOCKED_BY_CLIENT. This was not classified as a product failure because all four raw targets independently returned HTTP 200, parsed as DSSE JSON, carried one signature, and decoded to the exact full receipt IDs displayed by the application:

- UNKNOWN: br_886de803bb354350420ef1eff04c38c9ae074bd2268af8e9bea30eff99e00392
- ADMIT: br_8ce58bd9ca390aab2afab145d86a1d03d79d0213483a0af43df5f95c2b9730cc
- SCOPE DENY: br_c8dcb446b475a9a19b1f6b90f200316f292b57fea1811e2af630e96d906b59cc
- REPLAY DENY: br_b8051445ad5162eab32e792cf1e4241c346206a3fcb2cd67382800f614704abb

### Devpost

- Public page returned HTTP 200 without authentication.
- Exact title, tagline, story, proof claims, limitations, Built With section, creator, competition and Try it out links were visible.
- Pages, repository and release URLs were correct and live.
- 390×844 had no horizontal overflow.
- Zero error-level console entries were captured.

The embedded frame visibly reported that www.youtube.com refused the connection. The same environment also could not establish a direct connection to youtube.com, so this is a P1 presentation risk with environment-specific confidence, not proof that every judge browser fails. The public MP4 fallback itself is healthy and AV-valid.

## Confirmed pre-fix accessibility failure

The public decision UI used role=tab, but the live DOM had:

- all four tabs at tabindex=0;
- no tab IDs;
- no aria-controls;
- no role=tabpanel / aria-labelledby relationship;
- no ArrowLeft/ArrowRight/Home/End selection or focus behavior.

Cases:

- KEYBOARD-003 — FAIL
- KEYBOARD-004 — FAIL
- SEMANTIC-ARIA-001 — FAIL

Visible focus itself passed through the browser's native outline.

## Tool-blocked keyboard cases

Synthetic key injection through both browser keyboard surfaces failed to dispatch native button/summary activation on the public and local pages. The elements are native button, select, summary and anchor controls with tabindex=0, but the requested activation could not be distinguished from a browser-operator limitation.

Therefore these are BLOCKED, not product FAIL:

- KEYBOARD-001
- KEYBOARD-002
- LOCAL-KEYBOARD-001

## Local responsive and disclosure evidence

- 390×844: scrollWidth equals clientWidth; zero clipped/off-screen interactive controls.
- Lab, Boundary, home and Source navigation passed.
- Raw-details disclosure opened.
- Its 4,577-byte JSON parsed and matched the visible verdict, reasons, scope, receipt ID, receipt_verified and action_executed.
- All interactive controls were native and enabled.

## Case-level record

The authoritative 60-case matrix, expected result, final status, evidence, limitations and hashes are in [WEB-OPERATOR-AUDIT.json](./WEB-OPERATOR-AUDIT.json).
