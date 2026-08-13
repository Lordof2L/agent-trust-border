"""One-command bounded acceptance demo for the competition artifact."""

from __future__ import annotations

import json

from .canonical import canonical_bytes
from .fixtures import (
    CHALLENGE_NONCE,
    IDEMPOTENCY_KEY,
    NOW,
    make_adapter,
    make_authority_bundle,
    make_request,
    make_world,
)
from .kernel import verify_receipt
from .models import ReasonCode, Verdict


def _summary(label: str, result) -> dict:
    return {
        "step": label,
        "verdict": result.verdict.value,
        "reason_codes": [code.value for code in result.reason_codes],
        "receipt_id": result.receipt.receipt_id,
        "effective_scope": result.receipt.effective_scope.model_dump(mode="json"),
        "challenge_id": result.challenge.challenge_id if result.challenge else None,
        "world_truth": result.receipt.world_truth.value,
        "action_executed": result.action_executed,
    }


def main() -> None:
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
    assert unknown.verdict is Verdict.UNKNOWN
    assert unknown.reason_codes == (ReasonCode.MISSING_AUTHORIZATION,)
    assert unknown.challenge is not None
    assert unknown.action_executed is False

    authority = make_authority_bundle(world, request, challenge=unknown.challenge)
    admitted = kernel.evaluate(
        request,
        adapter=adapter,
        now=NOW,
        challenge_nonce=CHALLENGE_NONCE,
        challenge=authority.challenge,
        response=authority.response,
        idempotency_key=IDEMPOTENCY_KEY,
    )
    assert admitted.verdict is Verdict.ADMIT
    assert admitted.receipt.effective_scope.resources == ("sandbox:demo",)
    assert admitted.receipt.effective_scope.constraints.max_runs == 1
    assert admitted.action_executed is False
    verify_receipt(
        admitted.receipt_envelope,
        request=request,
        receipt_key=world.keys.receipt.public_key,
        expected_policy_hash=kernel.policy_hash,
        expected_mapping_hash=kernel.mapping_hash,
        expected_trust_profile_hash=kernel.trust_profile_hash,
    )

    production_request = make_request(
        world,
        resource="production:*",
        message_id="demo:msg:production",
    )
    production_authority = make_authority_bundle(
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
        challenge=production_authority.challenge,
        response=production_authority.response,
    )
    assert denied.verdict is Verdict.DENY
    assert denied.reason_codes == (ReasonCode.SCOPE_EXCEEDED,)
    assert denied.action_executed is False

    replay = kernel.evaluate(
        request,
        adapter=adapter,
        now=NOW,
        challenge_nonce=CHALLENGE_NONCE,
        challenge=authority.challenge,
        response=authority.response,
    )
    assert replay.verdict is Verdict.DENY
    assert replay.reason_codes == (ReasonCode.REPLAY_DETECTED,)
    assert replay.action_executed is False

    summaries = [
        _summary("capability-only", unknown),
        _summary("exact-trusted-grant", admitted),
        _summary("production-scope-mutation", denied),
        _summary("consumed-grant-replay", replay),
    ]
    print(json.dumps(summaries, indent=2, sort_keys=True))
    print("\nACCEPTANCE DEMO: PASS")
    print("PROOF BOUNDARY: synthetic offline fixtures; no action executed; world truth not proven")
    print("TRACE SHA256:", __import__("hashlib").sha256(canonical_bytes(summaries)).hexdigest())


if __name__ == "__main__":
    main()
