"""Deterministic synthetic fixtures. Keys and identities have no external authority."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .canonical import digest
from .envelopes import GRANT_PAYLOAD_TYPE, DemoKeyring, make_demo_keyring, sign_payload
from .kernel import BorderKernel, BorderState, make_challenge
from .models import (
    AdapterAssessment,
    BorderGrant,
    BorderRequest,
    BorderResponse,
    CheckOutcome,
    MappingProfile,
    ReceiverPolicy,
    TrustProfile,
    WorldTruth,
)

NOW = "2026-08-13T12:00:00Z"
CHALLENGE_NONCE = "000102030405060708090a0b0c0d0e0f"
IDEMPOTENCY_KEY = "demo:idem:0001"


@dataclass(frozen=True)
class FixtureWorld:
    keys: DemoKeyring
    policy: ReceiverPolicy
    mapping: MappingProfile
    trust: TrustProfile
    source_document: dict[str, Any]

    def kernel(self, *, state: BorderState | None = None) -> BorderKernel:
        return BorderKernel(
            policy=self.policy,
            mapping=self.mapping,
            trust=self.trust,
            receipt_signer=self.keys.receipt,
            public_keys=self.keys.public_keys,
            state=state,
        )


@dataclass(frozen=True)
class AuthorityBundle:
    challenge: Any
    grant: BorderGrant
    response: BorderResponse


def make_world() -> FixtureWorld:
    source_document = {
        "demo_only": True,
        "schema": "synthetic-a2a-agent-card/1.0",
        "agent_id": "demo:agent:deploy-bot",
        "declared_skill": {"action": "deploy", "resource": "sandbox:demo"},
        "proof_boundary": "synthetic-pinned-adapter-result",
    }
    policy = ReceiverPolicy(
        version="receiver-policy/0.1",
        audience="demo:border:receiver-a",
        subject="demo:agent:deploy-bot",
        action="deploy",
        resource="sandbox:demo",
        max_runs=1,
    )
    mapping = MappingProfile(
        version="a2a-to-strict-receiver/0.1",
        source_standard="A2A",
        target_profile="agent-trust-border-dsse/0.1",
    )
    trust = TrustProfile(
        version="receiver-trust/0.1",
        subject="demo:agent:deploy-bot",
        source_key_id="demo:key:deploy-bot-request",
        grant_issuer_id="demo:key:ops-admin",
        grant_key_id="demo:key:ops-admin-grant",
        receipt_key_id="demo:key:border-receiver-a",
    )
    return FixtureWorld(
        keys=make_demo_keyring(),
        policy=policy,
        mapping=mapping,
        trust=trust,
        source_document=source_document,
    )


def make_request(
    world: FixtureWorld,
    *,
    resource: str = "sandbox:demo",
    schema: str = "border-envelope/0.1",
    predicate: str = "agent.can_propose",
    message_id: str = "demo:msg:0001",
) -> BorderRequest:
    return BorderRequest.model_validate(
        {
            "schema": schema,
            "message_id": message_id,
            "source": {
                "standard": "A2A",
                "version": "1.0",
                "document_hash": digest(world.source_document),
            },
            "issuer": {
                "id": "demo:agent:deploy-bot",
                "key_id": "demo:key:deploy-bot-request",
            },
            "subject": {
                "id": "demo:agent:deploy-bot",
                "id_kind": "synthetic-demo-agent",
            },
            "audience": "demo:border:receiver-a",
            "issued_at": "2026-08-13T11:59:00Z",
            "expires_at": "2026-08-13T12:05:00Z",
            "nonce": CHALLENGE_NONCE,
            "claims": [
                {
                    "id": "demo:claim:capability:1",
                    "kind": "CAPABILITY",
                    "predicate": predicate,
                    "subject": "demo:agent:deploy-bot",
                    "object": {"action": "deploy", "resource": resource},
                    "evidence_refs": ["demo:evidence:capability:1"],
                }
            ],
            "requested_action": {
                "verb": "deploy",
                "resource": resource,
                "constraints": {"max_runs": 1},
            },
            "mapping": {
                "id": world.mapping.version,
                "hash": digest(world.mapping),
            },
        }
    )


def make_adapter(
    world: FixtureWorld,
    *,
    integrity: CheckOutcome = CheckOutcome.PASS,
    identity: CheckOutcome = CheckOutcome.PASS,
    evidence: CheckOutcome = CheckOutcome.PASS,
    evidence_reason=None,
    semantic_loss=(),
    unknown_predicates=(),
) -> AdapterAssessment:
    return AdapterAssessment(
        source_document_hash=digest(world.source_document),
        integrity=integrity,
        identity=identity,
        evidence=evidence,
        evidence_reason=evidence_reason,
        semantic_loss=tuple(semantic_loss),
        unknown_predicates=tuple(unknown_predicates),
        world_truth=WorldTruth.OUT_OF_SCOPE,
    )


def make_authority_bundle(
    world: FixtureWorld,
    request: BorderRequest,
    *,
    grant_resource: str | None = None,
    grant_issuer: str = "demo:key:ops-admin",
    grant_signer=None,
    grant_key_id: str = "demo:grant:0001",
    grant_expiry: str = "2026-08-13T12:05:00Z",
    challenge=None,
) -> AuthorityBundle:
    if challenge is None:
        challenge = make_challenge(
            request,
            policy_hash=digest(world.policy),
            mapping_hash=digest(world.mapping),
            grant_issuer=world.trust.grant_issuer_id,
            nonce=CHALLENGE_NONCE,
            issued_at=NOW,
            expires_at="2026-08-13T12:03:00Z",
        )
    grant = BorderGrant(
        iss=grant_issuer,
        sub=request.subject.id,
        aud=request.audience,
        iat="2026-08-13T11:59:00Z",
        nbf="2026-08-13T11:59:00Z",
        exp=grant_expiry,
        jti=grant_key_id,
        challenge_hash=digest(challenge),
        nonce=challenge.nonce,
        request_hash=digest(request),
        policy_hash=digest(world.policy),
        action="deploy",
        resource=grant_resource or request.requested_action.resource,
        max_runs=1,
        can_delegate=False,
    )
    signer = grant_signer or world.keys.ops
    envelope = sign_payload(GRANT_PAYLOAD_TYPE, grant, signer)
    response = BorderResponse(
        challenge_hash=digest(challenge),
        nonce=challenge.nonce,
        status="SUPPLIED",
        grant_envelope=envelope,
    )
    return AuthorityBundle(challenge=challenge, grant=grant, response=response)
