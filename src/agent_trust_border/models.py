"""Closed Stage-1 data model. No caller-selected verdicts or algorithms."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
UtcSecond = Annotated[str, Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")]


def _json_array_to_tuple(value):
    """Accept JSON's one array type while preserving immutable kernel fields."""

    if isinstance(value, list):
        return tuple(value)
    return value


class StrictModel(BaseModel):
    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        populate_by_name=True,
    )


class CheckOutcome(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class Verdict(StrEnum):
    ADMIT = "ADMIT"
    DENY = "DENY"
    UNKNOWN = "UNKNOWN"
    QUARANTINE = "QUARANTINE"


class TrustAxis(StrEnum):
    INTEGRITY = "INTEGRITY"
    IDENTITY = "IDENTITY"
    AUTHORIZATION = "AUTHORIZATION"
    EVIDENCE = "EVIDENCE"
    WORLD_TRUTH = "WORLD_TRUTH"


class WorldTruth(StrEnum):
    NOT_PROVEN = "NOT_PROVEN"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"


class MappingStatus(StrEnum):
    EQUIVALENT = "EQUIVALENT"
    NARROWER = "NARROWER"
    WEAKER = "WEAKER"
    STRONGER = "STRONGER"
    UNSUPPORTED = "UNSUPPORTED"
    CONFLICTING = "CONFLICTING"
    UNKNOWN = "UNKNOWN"
    REQUIRES_EXTERNAL_ROOT = "REQUIRES_EXTERNAL_ROOT"


class ReasonCode(StrEnum):
    MALFORMED_INPUT = "MALFORMED_INPUT"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
    CONTEXT_MISMATCH = "CONTEXT_MISMATCH"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    UNTRUSTED_ISSUER = "UNTRUSTED_ISSUER"
    WRONG_KEY_PURPOSE = "WRONG_KEY_PURPOSE"
    EXPIRED_GRANT = "EXPIRED_GRANT"
    REVOKED_CREDENTIAL = "REVOKED_CREDENTIAL"
    SCOPE_EXCEEDED = "SCOPE_EXCEEDED"
    MAPPING_CONFLICT = "MAPPING_CONFLICT"
    MAPPING_REQUIRED_CLAIM_LOST = "MAPPING_REQUIRED_CLAIM_LOST"
    POLICY_DENY = "POLICY_DENY"
    MISSING_AUTHORIZATION = "MISSING_AUTHORIZATION"
    MISSING_TRUST_ROOT = "MISSING_TRUST_ROOT"
    UNKNOWN_PREDICATE = "UNKNOWN_PREDICATE"
    UNKNOWN_SCHEMA_VERSION = "UNKNOWN_SCHEMA_VERSION"
    UNKNOWN_MAPPING_VERSION = "UNKNOWN_MAPPING_VERSION"
    UNVERIFIABLE_CLAIM = "UNVERIFIABLE_CLAIM"
    EVIDENCE_UNAVAILABLE = "EVIDENCE_UNAVAILABLE"
    INTERNAL_EVALUATION_ERROR = "INTERNAL_EVALUATION_ERROR"
    ALL_MANDATORY_CHECKS_PASS = "ALL_MANDATORY_CHECKS_PASS"


class SourceRef(StrictModel):
    standard: str
    version: str
    document_hash: Digest


class PartyRef(StrictModel):
    id: str
    key_id: str


class SubjectRef(StrictModel):
    id: str
    id_kind: str


class ActionConstraints(StrictModel):
    max_runs: Annotated[int, Field(ge=1, le=1000)]


class RequestedAction(StrictModel):
    verb: str
    resource: str
    constraints: ActionConstraints


class MappingRef(StrictModel):
    id: str
    hash: Digest


class Claim(StrictModel):
    id: str
    kind: str
    predicate: str
    subject: str
    object: dict[str, Any]
    evidence_refs: Annotated[tuple[str, ...], BeforeValidator(_json_array_to_tuple)]


class BorderRequest(StrictModel):
    schema_id: str = Field(alias="schema")
    message_id: str
    source: SourceRef
    issuer: PartyRef
    subject: SubjectRef
    audience: str
    issued_at: UtcSecond
    expires_at: UtcSecond
    nonce: str
    claims: Annotated[tuple[Claim, ...], BeforeValidator(_json_array_to_tuple)]
    requested_action: RequestedAction
    mapping: MappingRef


class SemanticLoss(StrictModel):
    source_path: str
    target_path: str
    status: MappingStatus
    detail: str


class AdapterAssessment(StrictModel):
    """Receiver-owned output of a frozen static adapter, never claimant input."""

    source_document_hash: Digest
    integrity: CheckOutcome
    identity: CheckOutcome
    evidence: CheckOutcome
    evidence_reason: ReasonCode | None = None
    semantic_loss: Annotated[tuple[SemanticLoss, ...], BeforeValidator(_json_array_to_tuple)] = ()
    unknown_predicates: Annotated[tuple[str, ...], BeforeValidator(_json_array_to_tuple)] = ()
    world_truth: WorldTruth = WorldTruth.OUT_OF_SCOPE


class ReceiverPolicy(StrictModel):
    version: str
    audience: str
    subject: str
    action: str
    resource: str
    max_runs: Annotated[int, Field(ge=1, le=1000)]


class MappingProfile(StrictModel):
    version: str
    source_standard: str
    target_profile: str


class TrustProfile(StrictModel):
    version: str
    subject: str
    source_key_id: str
    grant_issuer_id: str
    grant_key_id: str
    receipt_key_id: str


class ChallengeRequirement(StrictModel):
    reason: Literal["MISSING_AUTHORIZATION"]
    proof_kind: Literal["AUTHORIZATION"]
    subject: str
    action: str
    resource: str
    acceptable_issuers: Annotated[tuple[str, ...], BeforeValidator(_json_array_to_tuple)]
    max_age_seconds: Annotated[int, Field(ge=1, le=3600)]


class BorderChallenge(StrictModel):
    schema_id: Literal["border-challenge/0.1"] = Field(
        default="border-challenge/0.1", alias="schema"
    )
    challenge_id: str
    request_hash: Digest
    policy_hash: Digest
    mapping_hash: Digest
    audience: str
    subject: str
    nonce: str
    issued_at: UtcSecond
    expires_at: UtcSecond
    requirements: Annotated[tuple[ChallengeRequirement, ...], BeforeValidator(_json_array_to_tuple)]


class BorderGrant(StrictModel):
    iss: str
    sub: str
    aud: str
    iat: UtcSecond
    nbf: UtcSecond
    exp: UtcSecond
    jti: str
    challenge_hash: Digest
    nonce: str
    request_hash: Digest
    policy_hash: Digest
    action: str
    resource: str
    max_runs: Annotated[int, Field(ge=1, le=1000)]
    can_delegate: Literal[False]


class BorderResponse(StrictModel):
    schema_id: Literal["border-response/0.1"] = Field(default="border-response/0.1", alias="schema")
    challenge_hash: Digest
    nonce: str
    status: Literal["SUPPLIED", "UNAVAILABLE", "DECLINED"]
    grant_envelope: dict[str, Any] | None = None


class CheckResult(StrictModel):
    axis: TrustAxis
    outcome: CheckOutcome
    finding: str
    path: str


class ScopeConstraints(StrictModel):
    max_runs: int | None = None


class EffectiveScope(StrictModel):
    actions: Annotated[tuple[str, ...], BeforeValidator(_json_array_to_tuple)] = ()
    resources: Annotated[tuple[str, ...], BeforeValidator(_json_array_to_tuple)] = ()
    constraints: ScopeConstraints = ScopeConstraints()


class BorderReceipt(StrictModel):
    schema_id: Literal["border-receipt/0.1"] = Field(default="border-receipt/0.1", alias="schema")
    receipt_id: str
    request_hash: Digest
    challenge_hash: Digest
    response_hash: Digest
    trust_profile_hash: Digest
    mapping_hash: Digest
    policy_hash: Digest
    checks: Annotated[tuple[CheckResult, ...], BeforeValidator(_json_array_to_tuple)]
    semantic_loss: Annotated[tuple[SemanticLoss, ...], BeforeValidator(_json_array_to_tuple)]
    verdict: Verdict
    reason_codes: Annotated[tuple[ReasonCode, ...], BeforeValidator(_json_array_to_tuple)]
    effective_scope: EffectiveScope
    world_truth: WorldTruth
    issued_at: UtcSecond
    expires_at: UtcSecond
    signer_key_id: str
    action_executed: Literal[False] = False


class StatementSubject(StrictModel):
    name: str
    digest: dict[str, str]


class ReceiptStatement(StrictModel):
    statement_type: Literal["https://in-toto.io/Statement/v1"] = Field(alias="_type")
    subject: Annotated[tuple[StatementSubject, ...], BeforeValidator(_json_array_to_tuple)]
    predicate_type: Literal["https://agent-trust-border.local/BorderReceipt/v0.1"] = Field(
        alias="predicateType"
    )
    predicate: BorderReceipt


class DecisionResult(StrictModel):
    verdict: Verdict
    reason_codes: Annotated[tuple[ReasonCode, ...], BeforeValidator(_json_array_to_tuple)]
    receipt: BorderReceipt
    receipt_envelope: dict[str, Any]
    challenge: BorderChallenge | None = None
    idempotent_replay: bool = False
    action_executed: Literal[False] = False
