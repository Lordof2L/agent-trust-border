from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from agent_trust_border.canonical import canonical_bytes
from agent_trust_border.lab import (
    AuthorityMode,
    EvidenceMode,
    LabCommand,
    evaluate_lab,
)


@pytest.mark.parametrize(
    ("command", "verdict", "reasons", "resources"),
    (
        (
            LabCommand(
                resource="sandbox:demo",
                authority_mode=AuthorityMode.MISSING,
                evidence_mode=EvidenceMode.VERIFIED,
            ),
            "UNKNOWN",
            ("MISSING_AUTHORIZATION",),
            (),
        ),
        (
            LabCommand(
                resource="sandbox:demo",
                authority_mode=AuthorityMode.EXACT_TRUSTED_GRANT,
                evidence_mode=EvidenceMode.VERIFIED,
            ),
            "ADMIT",
            ("ALL_MANDATORY_CHECKS_PASS",),
            ("sandbox:demo",),
        ),
        (
            LabCommand(
                resource="production:demo",
                authority_mode=AuthorityMode.EXACT_TRUSTED_GRANT,
                evidence_mode=EvidenceMode.VERIFIED,
            ),
            "DENY",
            ("SCOPE_EXCEEDED",),
            (),
        ),
        (
            LabCommand(
                resource="sandbox:demo",
                authority_mode=AuthorityMode.CONSUMED_GRANT_REPLAY,
                evidence_mode=EvidenceMode.VERIFIED,
            ),
            "DENY",
            ("REPLAY_DETECTED",),
            (),
        ),
        (
            LabCommand(
                resource="sandbox:demo",
                authority_mode=AuthorityMode.MISSING,
                evidence_mode=EvidenceMode.UNAVAILABLE,
            ),
            "UNKNOWN",
            ("MISSING_AUTHORIZATION", "EVIDENCE_UNAVAILABLE"),
            (),
        ),
    ),
)
def test_phase2_lab_behavior(command, verdict, reasons, resources) -> None:
    result = evaluate_lab(command)

    assert result.verdict.value == verdict
    assert tuple(reason.value for reason in result.reason_codes) == reasons
    assert result.effective_scope.resources == resources
    assert result.receipt_verified is True
    assert result.action_executed is False
    assert result.world_truth.value == "OUT_OF_SCOPE"
    assert result.proof_boundary["synthetic_fixture"] is True
    assert result.proof_boundary["requested_action_execution"] is False
    assert result.proof_boundary["cross_request_replay_state"] is False


def test_phase2_lab_is_byte_stable_for_fixed_command() -> None:
    command = LabCommand(
        resource="sandbox:demo",
        authority_mode=AuthorityMode.EXACT_TRUSTED_GRANT,
        evidence_mode=EvidenceMode.VERIFIED,
    )

    first = canonical_bytes(evaluate_lab(command))
    second = canonical_bytes(evaluate_lab(command))

    assert first == second


def test_phase2_lab_rejects_unknown_and_incompatible_inputs() -> None:
    with pytest.raises(ValidationError):
        LabCommand.model_validate(
            {
                "resource": "sandbox:demo",
                "authority_mode": "missing",
                "evidence_mode": "verified",
                "verdict": "ADMIT",
            }
        )

    with pytest.raises(ValidationError):
        LabCommand(
            resource="production:demo",
            authority_mode=AuthorityMode.CONSUMED_GRANT_REPLAY,
            evidence_mode=EvidenceMode.VERIFIED,
        )

    with pytest.raises(ValidationError):
        LabCommand(
            resource="sandbox:demo",
            authority_mode=AuthorityMode.EXACT_TRUSTED_GRANT,
            evidence_mode=EvidenceMode.UNAVAILABLE,
        )


def test_phase2_result_can_be_rendered_as_strict_json() -> None:
    result = evaluate_lab(
        LabCommand(
            resource="sandbox:demo",
            authority_mode=AuthorityMode.MISSING,
            evidence_mode=EvidenceMode.VERIFIED,
        )
    )

    encoded = result.model_dump_json(by_alias=True)
    decoded = json.loads(encoded)

    assert decoded["schema"] == "agent-trust-border-lab-result/0.1"
    assert decoded["action_executed"] is False
    assert decoded["receipt_envelope"]["payloadType"] == "application/vnd.in-toto+json"
