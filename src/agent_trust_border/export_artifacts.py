"""Export reviewable Stage-1 evidence outside the trusted kernel."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from .fixtures import (
    CHALLENGE_NONCE,
    IDEMPOTENCY_KEY,
    NOW,
    make_adapter,
    make_authority_bundle,
    make_request,
    make_world,
)
from .models import ReasonCode, Verdict
from .projection import render_trace_html


def _pretty(value: Any) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json", by_alias=True)
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _row(step: str, result) -> dict[str, Any]:
    return {
        "step": step,
        "verdict": result.verdict.value,
        "reason_codes": [item.value for item in result.reason_codes],
        "receipt_id": result.receipt.receipt_id,
        "challenge_id": result.challenge.challenge_id if result.challenge else None,
        "effective_scope": result.receipt.effective_scope.model_dump(mode="json"),
        "world_truth": result.receipt.world_truth.value,
        "action_executed": result.action_executed,
    }


def export(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    world = make_world()
    adapter = make_adapter(world)
    request = make_request(world)
    kernel = world.kernel()

    unknown = kernel.evaluate(
        request,
        adapter=adapter,
        now=NOW,
        challenge_nonce=CHALLENGE_NONCE,
    )
    assert unknown.challenge is not None
    bundle = make_authority_bundle(world, request, challenge=unknown.challenge)
    admitted = kernel.evaluate(
        request,
        adapter=adapter,
        now=NOW,
        challenge_nonce=CHALLENGE_NONCE,
        challenge=bundle.challenge,
        response=bundle.response,
        idempotency_key=IDEMPOTENCY_KEY,
    )
    production_request = make_request(
        world,
        resource="production:*",
        message_id="demo:msg:production",
    )
    production_bundle = make_authority_bundle(
        world,
        production_request,
        grant_resource="sandbox:demo",
        grant_key_id="demo:grant:production",
    )
    denied = world.kernel().evaluate(
        production_request,
        adapter=adapter,
        now=NOW,
        challenge_nonce=CHALLENGE_NONCE,
        challenge=production_bundle.challenge,
        response=production_bundle.response,
    )
    replay = kernel.evaluate(
        request,
        adapter=adapter,
        now=NOW,
        challenge_nonce=CHALLENGE_NONCE,
        challenge=bundle.challenge,
        response=bundle.response,
    )

    assert unknown.verdict is Verdict.UNKNOWN
    assert admitted.verdict is Verdict.ADMIT
    assert denied.reason_codes == (ReasonCode.SCOPE_EXCEEDED,)
    assert replay.reason_codes == (ReasonCode.REPLAY_DETECTED,)
    rows = [
        _row("capability-only", unknown),
        _row("exact-trusted-grant", admitted),
        _row("production-scope-mutation", denied),
        _row("consumed-grant-replay", replay),
    ]
    files = {
        "trace.json": _pretty(
            {
                "proof_boundary": {
                    "demo_only": True,
                    "fixtures": "synthetic-offline",
                    "source_integrity": "receiver-owned pinned adapter result",
                    "grant_and_receipt_crypto": "DSSE/Ed25519",
                    "live_protocol_conformance": False,
                    "world_truth_proven": False,
                    "action_execution_path": False,
                },
                "rows": rows,
            }
        ),
        "trace.html": render_trace_html(rows),
        "request.json": _pretty(request),
        "challenge.json": _pretty(unknown.challenge),
        "grant.dsse.json": _pretty(bundle.response.grant_envelope),
        "unknown-receipt.dsse.json": _pretty(unknown.receipt_envelope),
        "admit-receipt.dsse.json": _pretty(admitted.receipt_envelope),
        "deny-receipt.dsse.json": _pretty(denied.receipt_envelope),
        "replay-receipt.dsse.json": _pretty(replay.receipt_envelope),
        "public-keys.json": _pretty(
            {
                "demo_only": True,
                "keys": {
                    keyid: key.to_dict()
                    for keyid, key in sorted(world.keys.public_keys.items())
                },
            }
        ),
    }
    for name, content in files.items():
        (output_dir / name).write_text(content, encoding="utf-8")
    manifest = {
        name: hashlib.sha256((output_dir / name).read_bytes()).hexdigest() for name in sorted(files)
    }
    (output_dir / "manifest-sha256.json").write_text(_pretty(manifest), encoding="utf-8")
    print(f"Exported {len(files)} evidence files + manifest to {output_dir}")


def main() -> None:
    output_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("artifacts")
    export(output_dir.resolve())


if __name__ == "__main__":
    main()
