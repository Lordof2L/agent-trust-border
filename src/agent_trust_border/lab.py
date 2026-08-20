"""Bounded executable lab over the real synthetic admission kernel."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import Field, model_validator

from .fixtures import (
    CHALLENGE_NONCE,
    NOW,
    make_adapter,
    make_authority_bundle,
    make_request,
    make_world,
)
from .kernel import verify_receipt
from .models import (
    BorderChallenge,
    CheckOutcome,
    CheckResult,
    EffectiveScope,
    ReasonCode,
    StrictModel,
    Verdict,
    WorldTruth,
)


class AuthorityMode(StrEnum):
    MISSING = "missing"
    EXACT_TRUSTED_GRANT = "exact_trusted_grant"
    CONSUMED_GRANT_REPLAY = "consumed_grant_replay"


class EvidenceMode(StrEnum):
    VERIFIED = "verified"
    UNAVAILABLE = "unavailable"


class LabCommand(StrictModel):
    resource: Literal["sandbox:demo", "production:demo"]
    authority_mode: AuthorityMode
    evidence_mode: EvidenceMode

    @model_validator(mode="after")
    def validate_combination(self) -> LabCommand:
        if (
            self.authority_mode is AuthorityMode.CONSUMED_GRANT_REPLAY
            and self.resource != "sandbox:demo"
        ):
            raise ValueError("consumed replay is defined only for sandbox:demo")
        if (
            self.evidence_mode is EvidenceMode.UNAVAILABLE
            and self.authority_mode is not AuthorityMode.MISSING
        ):
            raise ValueError("unavailable evidence cannot be upgraded by a lab authority preset")
        return self


class LabResult(StrictModel):
    schema_id: Literal["agent-trust-border-lab-result/0.1"] = Field(
        default="agent-trust-border-lab-result/0.1", alias="schema"
    )
    command: LabCommand
    verdict: Verdict
    reason_codes: tuple[ReasonCode, ...]
    effective_scope: EffectiveScope
    checks: tuple[CheckResult, ...]
    challenge: BorderChallenge | None
    receipt_id: str
    receipt_envelope: dict[str, Any]
    receipt_verified: Literal[True] = True
    world_truth: WorldTruth
    action_executed: Literal[False] = False
    state_counts: dict[str, int]
    proof_boundary: dict[str, bool]


def _message_id(command: LabCommand) -> str:
    resource = command.resource.replace(":", "-")
    return f"demo:lab:{resource}:{command.authority_mode.value}:{command.evidence_mode.value}"


def evaluate_lab(command: LabCommand) -> LabResult:
    """Evaluate one closed synthetic command and independently verify its receipt."""

    world = make_world()
    request = make_request(world, resource=command.resource, message_id=_message_id(command))
    adapter = make_adapter(
        world,
        evidence=(
            CheckOutcome.PASS
            if command.evidence_mode is EvidenceMode.VERIFIED
            else CheckOutcome.UNKNOWN
        ),
        evidence_reason=(
            None
            if command.evidence_mode is EvidenceMode.VERIFIED
            else ReasonCode.EVIDENCE_UNAVAILABLE
        ),
    )
    kernel = world.kernel()

    missing = kernel.evaluate(
        request,
        adapter=adapter,
        now=NOW,
        challenge_nonce=CHALLENGE_NONCE,
    )
    result = missing

    if command.authority_mode is not AuthorityMode.MISSING:
        if missing.challenge is None:
            raise RuntimeError("lab authority flow requires an exact receiver challenge")
        bundle = make_authority_bundle(
            world,
            request,
            challenge=missing.challenge,
            grant_key_id=f"demo:grant:{_message_id(command)}",
        )
        result = kernel.evaluate(
            request,
            adapter=adapter,
            now=NOW,
            challenge_nonce=CHALLENGE_NONCE,
            challenge=bundle.challenge,
            response=bundle.response,
        )
        if command.authority_mode is AuthorityMode.CONSUMED_GRANT_REPLAY:
            if result.verdict is not Verdict.ADMIT:
                raise RuntimeError("replay preset could not establish its consumed baseline")
            result = kernel.evaluate(
                request,
                adapter=adapter,
                now=NOW,
                challenge_nonce=CHALLENGE_NONCE,
                challenge=bundle.challenge,
                response=bundle.response,
            )

    verified = verify_receipt(
        result.receipt_envelope,
        request=request,
        receipt_key=world.keys.receipt.public_key,
        expected_policy_hash=kernel.policy_hash,
        expected_mapping_hash=kernel.mapping_hash,
        expected_trust_profile_hash=kernel.trust_profile_hash,
    )
    if verified != result.receipt:
        raise RuntimeError("independent receipt verification changed the result")

    return LabResult(
        command=command,
        verdict=result.verdict,
        reason_codes=result.reason_codes,
        effective_scope=result.receipt.effective_scope,
        checks=result.receipt.checks,
        challenge=result.challenge,
        receipt_id=result.receipt.receipt_id,
        receipt_envelope=result.receipt_envelope,
        world_truth=result.receipt.world_truth,
        state_counts=kernel.state.public_counts(),
        proof_boundary={
            "synthetic_fixture": True,
            "live_kernel_evaluation": True,
            "requested_action_execution": False,
            "network_resolution": False,
            "production_trust_roots": False,
            "cross_request_replay_state": False,
        },
    )
