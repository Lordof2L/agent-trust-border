"""Pure admission semantics plus bounded in-memory one-use state.

The reducer never calls a model, network, filesystem mutator, wallet, or tool.
An ADMIT receipt describes an exact candidate capability; it does not execute it.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import ValidationError
from securesystemslib.signer import CryptoSigner, SSlibKey

from .canonical import EMPTY_DIGEST, canonical_bytes, digest, load_json_strict
from .envelopes import (
    GRANT_PAYLOAD_TYPE,
    RECEIPT_PAYLOAD_TYPE,
    EnvelopeError,
    UnknownEnvelopeKey,
    sign_payload,
    verify_payload,
)
from .models import (
    AdapterAssessment,
    BorderChallenge,
    BorderGrant,
    BorderReceipt,
    BorderRequest,
    BorderResponse,
    CheckOutcome,
    CheckResult,
    DecisionResult,
    EffectiveScope,
    MappingProfile,
    MappingStatus,
    ReasonCode,
    ReceiptStatement,
    ReceiverPolicy,
    ScopeConstraints,
    StatementSubject,
    TrustAxis,
    TrustProfile,
    Verdict,
    WorldTruth,
)

SUPPORTED_REQUEST_SCHEMA = "border-envelope/0.1"
SUPPORTED_MAPPING = "a2a-to-strict-receiver/0.1"
KNOWN_PREDICATES = frozenset({"agent.can_propose"})


class KernelError(ValueError):
    pass


def _parse_time(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _check(axis: TrustAxis, outcome: CheckOutcome, finding: str, path: str) -> CheckResult:
    return CheckResult(axis=axis, outcome=outcome, finding=finding, path=path)


@dataclass
class BorderState:
    """Demo-only atomic replay/idempotency store."""

    revoked_grant_ids: set[str] = field(default_factory=set)
    consumed_grants: dict[str, str] = field(default_factory=dict)
    idempotency: dict[str, tuple[str, str]] = field(default_factory=dict)
    receipt_envelopes: dict[str, dict[str, Any]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def public_counts(self) -> dict[str, int]:
        with self._lock:
            return {
                "consumed_grants": len(self.consumed_grants),
                "idempotency_records": len(self.idempotency),
                "receipts": len(self.receipt_envelopes),
            }


def make_challenge(
    request: BorderRequest,
    *,
    policy_hash: str,
    mapping_hash: str,
    grant_issuer: str,
    nonce: str,
    issued_at: str,
    expires_at: str,
) -> BorderChallenge:
    base = {
        "schema": "border-challenge/0.1",
        "request_hash": digest(request),
        "policy_hash": policy_hash,
        "mapping_hash": mapping_hash,
        "audience": request.subject.id,
        "subject": request.subject.id,
        "nonce": nonce,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "requirements": [
            {
                "reason": "MISSING_AUTHORIZATION",
                "proof_kind": "AUTHORIZATION",
                "subject": request.subject.id,
                "action": request.requested_action.verb,
                "resource": request.requested_action.resource,
                "acceptable_issuers": [grant_issuer],
                "max_age_seconds": 300,
            }
        ],
    }
    challenge_id = "ch_" + digest(base).removeprefix("sha256:")[:24]
    return BorderChallenge(challenge_id=challenge_id, **base)


def _receipt_without_id(
    *,
    request_hash: str,
    challenge_hash: str,
    response_hash: str,
    trust_profile_hash: str,
    mapping_hash: str,
    policy_hash: str,
    checks: tuple[CheckResult, ...],
    semantic_loss: tuple,
    verdict: Verdict,
    reasons: tuple[ReasonCode, ...],
    scope: EffectiveScope,
    world_truth: WorldTruth,
    issued_at: str,
    expires_at: str,
    signer_key_id: str,
) -> dict[str, Any]:
    return {
        "schema": "border-receipt/0.1",
        "request_hash": request_hash,
        "challenge_hash": challenge_hash,
        "response_hash": response_hash,
        "trust_profile_hash": trust_profile_hash,
        "mapping_hash": mapping_hash,
        "policy_hash": policy_hash,
        "checks": [item.model_dump(mode="json") for item in checks],
        "semantic_loss": [item.model_dump(mode="json") for item in semantic_loss],
        "verdict": verdict.value,
        "reason_codes": [item.value for item in reasons],
        "effective_scope": scope.model_dump(mode="json"),
        "world_truth": world_truth.value,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "signer_key_id": signer_key_id,
        "action_executed": False,
    }


def make_signed_receipt(
    *,
    request: BorderRequest,
    challenge_hash: str,
    response_hash: str,
    trust_profile_hash: str,
    mapping_hash: str,
    policy_hash: str,
    checks: tuple[CheckResult, ...],
    semantic_loss: tuple,
    verdict: Verdict,
    reasons: tuple[ReasonCode, ...],
    scope: EffectiveScope,
    world_truth: WorldTruth,
    issued_at: str,
    expires_at: str,
    signer: CryptoSigner,
) -> tuple[BorderReceipt, dict[str, Any]]:
    request_hash = digest(request)
    predicate = _receipt_without_id(
        request_hash=request_hash,
        challenge_hash=challenge_hash,
        response_hash=response_hash,
        trust_profile_hash=trust_profile_hash,
        mapping_hash=mapping_hash,
        policy_hash=policy_hash,
        checks=checks,
        semantic_loss=semantic_loss,
        verdict=verdict,
        reasons=reasons,
        scope=scope,
        world_truth=world_truth,
        issued_at=issued_at,
        expires_at=expires_at,
        signer_key_id=signer.public_key.keyid,
    )
    predicate["receipt_id"] = "br_" + digest(predicate).removeprefix("sha256:")
    receipt = BorderReceipt.model_validate_json(canonical_bytes(predicate))
    statement = ReceiptStatement(
        statement_type="https://in-toto.io/Statement/v1",
        subject=(
            StatementSubject(
                name="agent-trust-border/request",
                digest={"sha256": request_hash.removeprefix("sha256:")},
            ),
        ),
        predicate_type="https://agent-trust-border.local/BorderReceipt/v0.1",
        predicate=receipt,
    )
    return receipt, sign_payload(RECEIPT_PAYLOAD_TYPE, statement, signer)


def verify_receipt(
    envelope_data: dict[str, Any],
    *,
    request: BorderRequest,
    receipt_key: SSlibKey,
    expected_policy_hash: str,
    expected_mapping_hash: str,
    expected_trust_profile_hash: str,
) -> BorderReceipt:
    payload, keyid = verify_payload(
        envelope_data,
        expected_payload_type=RECEIPT_PAYLOAD_TYPE,
        keys={receipt_key.keyid: receipt_key},
    )
    try:
        statement = ReceiptStatement.model_validate_json(payload)
    except ValidationError as exc:
        raise KernelError("invalid receipt statement") from exc
    receipt = statement.predicate
    request_hash = digest(request)
    if len(statement.subject) != 1:
        raise KernelError("receipt must bind exactly one request subject")
    if statement.subject[0].digest != {"sha256": request_hash.removeprefix("sha256:")}:
        raise KernelError("receipt subject digest mismatch")
    if receipt.request_hash != request_hash:
        raise KernelError("receipt request hash mismatch")
    if receipt.policy_hash != expected_policy_hash:
        raise KernelError("receipt policy hash mismatch")
    if receipt.mapping_hash != expected_mapping_hash:
        raise KernelError("receipt mapping hash mismatch")
    if receipt.trust_profile_hash != expected_trust_profile_hash:
        raise KernelError("receipt trust profile hash mismatch")
    if receipt.signer_key_id != keyid:
        raise KernelError("receipt signer key purpose mismatch")
    raw = receipt.model_dump(mode="json", by_alias=True)
    claimed_id = raw.pop("receipt_id")
    expected_id = "br_" + digest(raw).removeprefix("sha256:")
    if claimed_id != expected_id:
        raise KernelError("receipt ID mismatch")
    return receipt


class BorderKernel:
    def __init__(
        self,
        *,
        policy: ReceiverPolicy,
        mapping: MappingProfile,
        trust: TrustProfile,
        receipt_signer: CryptoSigner,
        public_keys: dict[str, SSlibKey],
        state: BorderState | None = None,
    ) -> None:
        self.policy = policy
        self.mapping = mapping
        self.trust = trust
        self.receipt_signer = receipt_signer
        self.public_keys = dict(public_keys)
        self.state = state or BorderState()
        self.policy_hash = digest(policy)
        self.mapping_hash = digest(mapping)
        self.trust_profile_hash = digest(trust)

    def evaluate(
        self,
        request: BorderRequest,
        *,
        adapter: AdapterAssessment,
        now: str,
        challenge_nonce: str,
        challenge: BorderChallenge | None = None,
        response: BorderResponse | None = None,
        idempotency_key: str | None = None,
    ) -> DecisionResult:
        request_hash = digest(request)
        if idempotency_key is not None:
            with self.state._lock:
                prior = self.state.idempotency.get(idempotency_key)
                if prior is not None:
                    prior_request_hash, prior_receipt_id = prior
                    if prior_request_hash != request_hash:
                        return self._hard_result(
                            request,
                            adapter=adapter,
                            now=now,
                            verdict=Verdict.DENY,
                            reason=ReasonCode.CONTEXT_MISMATCH,
                            finding="idempotency key is bound to another request",
                            path="/idempotency_key",
                            challenge=challenge,
                            response=response,
                        )
                    envelope = self.state.receipt_envelopes[prior_receipt_id]
                    receipt = verify_receipt(
                        envelope,
                        request=request,
                        receipt_key=self.receipt_signer.public_key,
                        expected_policy_hash=self.policy_hash,
                        expected_mapping_hash=self.mapping_hash,
                        expected_trust_profile_hash=self.trust_profile_hash,
                    )
                    return DecisionResult(
                        verdict=receipt.verdict,
                        reason_codes=receipt.reason_codes,
                        receipt=receipt,
                        receipt_envelope=envelope,
                        challenge=challenge,
                        idempotent_replay=True,
                    )

        preflight = self._preflight(request, adapter=adapter)
        if preflight is not None:
            verdict, reasons, checks = preflight
            if (
                verdict is Verdict.UNKNOWN
                and response is None
                and ReasonCode.EVIDENCE_UNAVAILABLE in reasons
                and ReasonCode.MISSING_AUTHORIZATION not in reasons
            ):
                reasons = (ReasonCode.MISSING_AUTHORIZATION, *reasons)
                checks += (
                    _check(
                        TrustAxis.AUTHORIZATION,
                        CheckOutcome.UNKNOWN,
                        ReasonCode.MISSING_AUTHORIZATION.value,
                        "/authorization",
                    ),
                )
            return self._finalize(
                request,
                adapter=adapter,
                now=now,
                verdict=verdict,
                reasons=reasons,
                checks=checks,
                scope=EffectiveScope(),
                challenge=challenge,
                response=response,
            )

        if response is None:
            challenge_expiry = min(
                _parse_time(request.expires_at), _parse_time(now) + timedelta(minutes=3)
            )
            generated = make_challenge(
                request,
                policy_hash=self.policy_hash,
                mapping_hash=self.mapping_hash,
                grant_issuer=self.trust.grant_issuer_id,
                nonce=challenge_nonce,
                issued_at=now,
                expires_at=_format_time(challenge_expiry),
            )
            checks = (
                *self._base_checks(adapter),
                _check(
                    TrustAxis.AUTHORIZATION,
                    CheckOutcome.UNKNOWN,
                    ReasonCode.MISSING_AUTHORIZATION.value,
                    "/authorization",
                ),
            )
            return self._finalize(
                request,
                adapter=adapter,
                now=now,
                verdict=Verdict.UNKNOWN,
                reasons=(ReasonCode.MISSING_AUTHORIZATION,),
                checks=checks,
                scope=EffectiveScope(),
                challenge=generated,
                response=None,
            )

        if challenge is None:
            return self._hard_result(
                request,
                adapter=adapter,
                now=now,
                verdict=Verdict.DENY,
                reason=ReasonCode.CONTEXT_MISMATCH,
                finding="response supplied without receiver challenge",
                path="/response/challenge_hash",
                challenge=None,
                response=response,
            )

        grant_or_result = self._verify_authority(
            request,
            adapter=adapter,
            challenge=challenge,
            response=response,
            now=now,
        )
        if isinstance(grant_or_result, DecisionResult):
            return grant_or_result
        grant = grant_or_result

        scope_ok = (
            request.requested_action.verb == grant.action == self.policy.action
            and request.requested_action.resource == grant.resource == self.policy.resource
        )
        if not scope_ok:
            return self._hard_result(
                request,
                adapter=adapter,
                now=now,
                verdict=Verdict.DENY,
                reason=ReasonCode.SCOPE_EXCEEDED,
                finding=(
                    f"request={request.requested_action.resource}; "
                    f"grant={grant.resource}; policy={self.policy.resource}"
                ),
                path="/requested_action/resource",
                challenge=challenge,
                response=response,
            )
        max_runs = min(
            request.requested_action.constraints.max_runs,
            grant.max_runs,
            self.policy.max_runs,
        )
        if max_runs < 1:
            return self._hard_result(
                request,
                adapter=adapter,
                now=now,
                verdict=Verdict.DENY,
                reason=ReasonCode.SCOPE_EXCEEDED,
                finding="effective max_runs is empty",
                path="/requested_action/constraints/max_runs",
                challenge=challenge,
                response=response,
            )

        with self.state._lock:
            if grant.jti in self.state.consumed_grants:
                return self._hard_result_unlocked(
                    request,
                    adapter=adapter,
                    now=now,
                    verdict=Verdict.DENY,
                    reason=ReasonCode.REPLAY_DETECTED,
                    finding="grant jti was already consumed",
                    path="/response/grant/jti",
                    challenge=challenge,
                    response=response,
                )

            checks = (
                *self._base_checks(adapter),
                _check(
                    TrustAxis.AUTHORIZATION,
                    CheckOutcome.PASS,
                    "AUTHORIZED exact request/grant/policy intersection",
                    "/authorization",
                ),
            )
            scope = EffectiveScope(
                actions=(grant.action,),
                resources=(grant.resource,),
                constraints=ScopeConstraints(max_runs=max_runs),
            )
            result = self._finalize_unlocked(
                request,
                adapter=adapter,
                now=now,
                verdict=Verdict.ADMIT,
                reasons=(ReasonCode.ALL_MANDATORY_CHECKS_PASS,),
                checks=checks,
                scope=scope,
                challenge=challenge,
                response=response,
            )
            self.state.consumed_grants[grant.jti] = result.receipt.receipt_id
            if idempotency_key is not None:
                self.state.idempotency[idempotency_key] = (
                    request_hash,
                    result.receipt.receipt_id,
                )
            return result

    def _base_checks(self, adapter: AdapterAssessment) -> tuple[CheckResult, ...]:
        return (
            _check(
                TrustAxis.INTEGRITY,
                adapter.integrity,
                "SIGNATURE_VALID synthetic pinned source-adapter result",
                "/source",
            ),
            _check(
                TrustAxis.IDENTITY,
                adapter.identity,
                "IDENTITY_BOUND by receiver trust profile",
                "/subject",
            ),
            _check(
                TrustAxis.EVIDENCE,
                adapter.evidence,
                (
                    adapter.evidence_reason.value
                    if adapter.evidence_reason is not None
                    else "ISSUER_ATTESTED; not world truth"
                ),
                "/claims",
            ),
            _check(
                TrustAxis.WORLD_TRUTH,
                CheckOutcome.UNKNOWN,
                adapter.world_truth.value,
                "/world_truth",
            ),
        )

    def _preflight(
        self,
        request: BorderRequest,
        *,
        adapter: AdapterAssessment,
    ) -> tuple[Verdict, tuple[ReasonCode, ...], tuple[CheckResult, ...]] | None:
        base = self._base_checks(adapter)
        failures: list[tuple[ReasonCode, TrustAxis, str, str]] = []
        unknowns: list[tuple[ReasonCode, TrustAxis, str, str]] = []
        if request.schema_id != SUPPORTED_REQUEST_SCHEMA:
            unknowns.append(
                (
                    ReasonCode.UNKNOWN_SCHEMA_VERSION,
                    TrustAxis.INTEGRITY,
                    request.schema_id,
                    "/schema",
                )
            )
        if (
            request.subject.id != self.trust.subject
            or request.issuer.id != request.subject.id
            or request.issuer.key_id != self.trust.source_key_id
        ):
            failures.append(
                (
                    ReasonCode.UNTRUSTED_ISSUER,
                    TrustAxis.IDENTITY,
                    "request identity does not match receiver trust profile",
                    "/issuer",
                )
            )
        if request.audience != self.policy.audience:
            failures.append(
                (
                    ReasonCode.CONTEXT_MISMATCH,
                    TrustAxis.IDENTITY,
                    "request audience does not match receiver policy",
                    "/audience",
                )
            )
        if request.mapping.id != self.mapping.version or request.mapping.hash != self.mapping_hash:
            unknowns.append(
                (
                    ReasonCode.UNKNOWN_MAPPING_VERSION,
                    TrustAxis.EVIDENCE,
                    request.mapping.id,
                    "/mapping",
                )
            )
        if request.source.standard != self.mapping.source_standard:
            unknowns.append(
                (
                    ReasonCode.UNKNOWN_MAPPING_VERSION,
                    TrustAxis.EVIDENCE,
                    request.source.standard,
                    "/source/standard",
                )
            )
        if adapter.source_document_hash != request.source.document_hash:
            failures.append(
                (
                    ReasonCode.CONTEXT_MISMATCH,
                    TrustAxis.INTEGRITY,
                    "adapter source digest mismatch",
                    "/source/document_hash",
                )
            )
        if adapter.integrity is CheckOutcome.FAIL:
            failures.append(
                (
                    ReasonCode.INVALID_SIGNATURE,
                    TrustAxis.INTEGRITY,
                    "source proof failed",
                    "/source",
                )
            )
        elif adapter.integrity is CheckOutcome.UNKNOWN:
            unknowns.append(
                (
                    ReasonCode.UNVERIFIABLE_CLAIM,
                    TrustAxis.INTEGRITY,
                    "source proof unavailable",
                    "/source",
                )
            )
        if adapter.identity is CheckOutcome.UNKNOWN:
            unknowns.append(
                (
                    ReasonCode.MISSING_TRUST_ROOT,
                    TrustAxis.IDENTITY,
                    "receiver cannot bind source identity",
                    "/subject",
                )
            )
        elif adapter.identity is CheckOutcome.FAIL:
            failures.append(
                (
                    ReasonCode.UNTRUSTED_ISSUER,
                    TrustAxis.IDENTITY,
                    "source identity binding failed",
                    "/subject",
                )
            )
        if adapter.evidence is CheckOutcome.UNKNOWN:
            unknowns.append(
                (
                    adapter.evidence_reason or ReasonCode.UNVERIFIABLE_CLAIM,
                    TrustAxis.EVIDENCE,
                    "evidence remains unverifiable",
                    "/claims",
                )
            )
        elif adapter.evidence is CheckOutcome.FAIL:
            failures.append(
                (
                    adapter.evidence_reason or ReasonCode.UNVERIFIABLE_CLAIM,
                    TrustAxis.EVIDENCE,
                    "evidence failed receiver checks",
                    "/claims",
                )
            )
        for predicate in sorted(set(adapter.unknown_predicates)):
            unknowns.append(
                (
                    ReasonCode.UNKNOWN_PREDICATE,
                    TrustAxis.EVIDENCE,
                    predicate,
                    "/claims",
                )
            )
        for index, claim in enumerate(request.claims):
            if claim.predicate not in KNOWN_PREDICATES:
                unknowns.append(
                    (
                        ReasonCode.UNKNOWN_PREDICATE,
                        TrustAxis.EVIDENCE,
                        claim.predicate,
                        f"/claims/{index}/predicate",
                    )
                )
        for loss in adapter.semantic_loss:
            if loss.status is MappingStatus.CONFLICTING:
                failures.append(
                    (
                        ReasonCode.MAPPING_CONFLICT,
                        TrustAxis.EVIDENCE,
                        loss.detail,
                        loss.source_path,
                    )
                )
            elif loss.status is MappingStatus.UNSUPPORTED:
                failures.append(
                    (
                        ReasonCode.MAPPING_REQUIRED_CLAIM_LOST,
                        TrustAxis.AUTHORIZATION,
                        loss.detail,
                        loss.source_path,
                    )
                )
            elif loss.status in {
                MappingStatus.WEAKER,
                MappingStatus.REQUIRES_EXTERNAL_ROOT,
                MappingStatus.UNKNOWN,
            }:
                unknowns.append(
                    (
                        ReasonCode.MISSING_TRUST_ROOT,
                        TrustAxis.IDENTITY,
                        loss.detail,
                        loss.source_path,
                    )
                )
        if not failures and not unknowns:
            return None
        selected = failures if failures else unknowns
        verdict = Verdict.DENY if failures else Verdict.UNKNOWN
        selected.sort(key=lambda item: (item[3], item[0].value))
        checks = base + tuple(
            _check(axis, CheckOutcome.FAIL if failures else CheckOutcome.UNKNOWN, code.value, path)
            for code, axis, _detail, path in selected
        )
        reasons = tuple(dict.fromkeys(code for code, _axis, _detail, _path in selected))
        return verdict, reasons, checks

    def _verify_authority(
        self,
        request: BorderRequest,
        *,
        adapter: AdapterAssessment,
        challenge: BorderChallenge,
        response: BorderResponse,
        now: str,
    ) -> BorderGrant | DecisionResult:
        challenge_hash = digest(challenge)
        if (
            challenge.request_hash != digest(request)
            or challenge.policy_hash != self.policy_hash
            or challenge.mapping_hash != self.mapping_hash
            or response.challenge_hash != challenge_hash
            or response.nonce != challenge.nonce
        ):
            return self._hard_result(
                request,
                adapter=adapter,
                now=now,
                verdict=Verdict.DENY,
                reason=ReasonCode.CONTEXT_MISMATCH,
                finding="challenge/response binding mismatch",
                path="/response/challenge_hash",
                challenge=challenge,
                response=response,
            )
        if response.status != "SUPPLIED" or response.grant_envelope is None:
            return self._finalize(
                request,
                adapter=adapter,
                now=now,
                verdict=Verdict.UNKNOWN,
                reasons=(ReasonCode.MISSING_AUTHORIZATION,),
                checks=(
                    *self._base_checks(adapter),
                    _check(
                        TrustAxis.AUTHORIZATION,
                        CheckOutcome.UNKNOWN,
                        ReasonCode.MISSING_AUTHORIZATION.value,
                        "/response/status",
                    ),
                ),
                scope=EffectiveScope(),
                challenge=challenge,
                response=response,
            )
        try:
            payload, keyid = verify_payload(
                response.grant_envelope,
                expected_payload_type=GRANT_PAYLOAD_TYPE,
                keys=self.public_keys,
            )
            grant = BorderGrant.model_validate(load_json_strict(payload))
        except UnknownEnvelopeKey:
            return self._hard_result(
                request,
                adapter=adapter,
                now=now,
                verdict=Verdict.DENY,
                reason=ReasonCode.UNTRUSTED_ISSUER,
                finding="grant key is not pinned",
                path="/response/grant/signatures/0/keyid",
                challenge=challenge,
                response=response,
            )
        except (EnvelopeError, ValidationError, ValueError):
            return self._hard_result(
                request,
                adapter=adapter,
                now=now,
                verdict=Verdict.DENY,
                reason=ReasonCode.INVALID_SIGNATURE,
                finding="grant DSSE signature or payload is invalid",
                path="/response/grant",
                challenge=challenge,
                response=response,
            )
        if grant.iss != self.trust.grant_issuer_id:
            return self._hard_result(
                request,
                adapter=adapter,
                now=now,
                verdict=Verdict.DENY,
                reason=ReasonCode.UNTRUSTED_ISSUER,
                finding=grant.iss,
                path="/response/grant/iss",
                challenge=challenge,
                response=response,
            )
        if keyid != self.trust.grant_key_id:
            return self._hard_result(
                request,
                adapter=adapter,
                now=now,
                verdict=Verdict.DENY,
                reason=ReasonCode.WRONG_KEY_PURPOSE,
                finding=keyid,
                path="/response/grant/signatures/0/keyid",
                challenge=challenge,
                response=response,
            )
        if grant.jti in self.state.revoked_grant_ids:
            return self._hard_result(
                request,
                adapter=adapter,
                now=now,
                verdict=Verdict.DENY,
                reason=ReasonCode.REVOKED_CREDENTIAL,
                finding=grant.jti,
                path="/response/grant/jti",
                challenge=challenge,
                response=response,
            )
        current = _parse_time(now)
        if current >= _parse_time(challenge.expires_at):
            return self._hard_result(
                request,
                adapter=adapter,
                now=now,
                verdict=Verdict.DENY,
                reason=ReasonCode.CONTEXT_MISMATCH,
                finding="challenge expired",
                path="/challenge/expires_at",
                challenge=challenge,
                response=response,
            )
        if current < _parse_time(grant.nbf) or current >= _parse_time(grant.exp):
            return self._hard_result(
                request,
                adapter=adapter,
                now=now,
                verdict=Verdict.DENY,
                reason=ReasonCode.EXPIRED_GRANT,
                finding=grant.exp,
                path="/response/grant/exp",
                challenge=challenge,
                response=response,
            )
        expected = (
            grant.sub == request.subject.id
            and grant.aud == request.audience
            and grant.challenge_hash == challenge_hash
            and grant.nonce == challenge.nonce
            and grant.request_hash == digest(request)
            and grant.policy_hash == self.policy_hash
            and response.challenge_hash == challenge_hash
        )
        if not expected:
            return self._hard_result(
                request,
                adapter=adapter,
                now=now,
                verdict=Verdict.DENY,
                reason=ReasonCode.CONTEXT_MISMATCH,
                finding="grant does not bind complete receiver context",
                path="/response/grant",
                challenge=challenge,
                response=response,
            )
        return grant

    def _hard_result(
        self,
        request: BorderRequest,
        *,
        adapter: AdapterAssessment,
        now: str,
        verdict: Verdict,
        reason: ReasonCode,
        finding: str,
        path: str,
        challenge: BorderChallenge | None,
        response: BorderResponse | None,
    ) -> DecisionResult:
        with self.state._lock:
            return self._hard_result_unlocked(
                request,
                adapter=adapter,
                now=now,
                verdict=verdict,
                reason=reason,
                finding=finding,
                path=path,
                challenge=challenge,
                response=response,
            )

    def _hard_result_unlocked(
        self,
        request: BorderRequest,
        *,
        adapter: AdapterAssessment,
        now: str,
        verdict: Verdict,
        reason: ReasonCode,
        finding: str,
        path: str,
        challenge: BorderChallenge | None,
        response: BorderResponse | None,
    ) -> DecisionResult:
        checks = (
            *self._base_checks(adapter),
            _check(TrustAxis.AUTHORIZATION, CheckOutcome.FAIL, f"{reason.value}: {finding}", path),
        )
        return self._finalize_unlocked(
            request,
            adapter=adapter,
            now=now,
            verdict=verdict,
            reasons=(reason,),
            checks=checks,
            scope=EffectiveScope(),
            challenge=challenge,
            response=response,
        )

    def _finalize(
        self,
        request: BorderRequest,
        *,
        adapter: AdapterAssessment,
        now: str,
        verdict: Verdict,
        reasons: tuple[ReasonCode, ...],
        checks: tuple[CheckResult, ...],
        scope: EffectiveScope,
        challenge: BorderChallenge | None,
        response: BorderResponse | None,
    ) -> DecisionResult:
        with self.state._lock:
            return self._finalize_unlocked(
                request,
                adapter=adapter,
                now=now,
                verdict=verdict,
                reasons=reasons,
                checks=checks,
                scope=scope,
                challenge=challenge,
                response=response,
            )

    def _finalize_unlocked(
        self,
        request: BorderRequest,
        *,
        adapter: AdapterAssessment,
        now: str,
        verdict: Verdict,
        reasons: tuple[ReasonCode, ...],
        checks: tuple[CheckResult, ...],
        scope: EffectiveScope,
        challenge: BorderChallenge | None,
        response: BorderResponse | None,
    ) -> DecisionResult:
        if verdict is not Verdict.ADMIT and (
            scope.actions or scope.resources or scope.constraints.max_runs is not None
        ):
            raise KernelError("non-admit result cannot carry effective scope")
        if verdict is Verdict.QUARANTINE:
            raise KernelError("QUARANTINE is unreachable in V0")
        challenge_hash = digest(challenge) if challenge is not None else EMPTY_DIGEST
        response_hash = digest(response) if response is not None else EMPTY_DIGEST
        receipt, envelope = make_signed_receipt(
            request=request,
            challenge_hash=challenge_hash,
            response_hash=response_hash,
            trust_profile_hash=self.trust_profile_hash,
            mapping_hash=self.mapping_hash,
            policy_hash=self.policy_hash,
            checks=checks,
            semantic_loss=adapter.semantic_loss,
            verdict=verdict,
            reasons=reasons,
            scope=scope,
            world_truth=adapter.world_truth,
            issued_at=now,
            expires_at=request.expires_at,
            signer=self.receipt_signer,
        )
        existing = self.state.receipt_envelopes.get(receipt.receipt_id)
        if existing is not None and existing != envelope:
            raise KernelError("append-only receipt collision")
        self.state.receipt_envelopes[receipt.receipt_id] = envelope
        verify_receipt(
            envelope,
            request=request,
            receipt_key=self.receipt_signer.public_key,
            expected_policy_hash=self.policy_hash,
            expected_mapping_hash=self.mapping_hash,
            expected_trust_profile_hash=self.trust_profile_hash,
        )
        return DecisionResult(
            verdict=verdict,
            reason_codes=reasons,
            receipt=receipt,
            receipt_envelope=envelope,
            challenge=challenge,
        )
