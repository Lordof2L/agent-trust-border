"""Single DSSE/Ed25519 profile with exact payload-type and key closure."""

from __future__ import annotations

import copy
import hashlib
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from securesystemslib.dsse import Envelope
from securesystemslib.signer import CryptoSigner, SSlibKey

from .canonical import canonical_bytes, load_json_strict

GRANT_PAYLOAD_TYPE = "application/vnd.agent-trust-border.grant.v0+json"
RECEIPT_PAYLOAD_TYPE = "application/vnd.in-toto+json"


class EnvelopeError(ValueError):
    pass


class UnknownEnvelopeKey(EnvelopeError):
    pass


@dataclass(frozen=True)
class DemoKeyring:
    agent: CryptoSigner
    ops: CryptoSigner
    receipt: CryptoSigner
    rogue: CryptoSigner

    @property
    def public_keys(self) -> dict[str, SSlibKey]:
        signers = (self.agent, self.ops, self.receipt, self.rogue)
        return {signer.public_key.keyid: signer.public_key for signer in signers}


def _demo_signer(keyid: str) -> CryptoSigner:
    if not keyid.startswith("demo:key:"):
        raise ValueError("deterministic demo key IDs must use the demo:key: namespace")
    seed = hashlib.sha256(f"agent-trust-border-demo-only:{keyid}".encode()).digest()
    private = Ed25519PrivateKey.from_private_bytes(seed)
    public = SSlibKey.from_crypto(private.public_key(), keyid, "ed25519")
    return CryptoSigner(private, public)


def make_demo_keyring() -> DemoKeyring:
    return DemoKeyring(
        agent=_demo_signer("demo:key:deploy-bot-request"),
        ops=_demo_signer("demo:key:ops-admin-grant"),
        receipt=_demo_signer("demo:key:border-receiver-a"),
        rogue=_demo_signer("demo:key:rogue"),
    )


def sign_payload(payload_type: str, payload: Any, signer: CryptoSigner) -> dict[str, Any]:
    envelope = Envelope(canonical_bytes(payload), payload_type, {})
    envelope.sign(signer)
    return envelope.to_dict()


def envelope_hash(envelope: dict[str, Any]) -> str:
    from .canonical import digest

    return digest(envelope)


def verify_payload(
    data: dict[str, Any],
    *,
    expected_payload_type: str,
    keys: dict[str, SSlibKey],
) -> tuple[bytes, str]:
    if set(data) != {"payload", "payloadType", "signatures"}:
        raise EnvelopeError("DSSE envelope fields are not closed")
    if data.get("payloadType") != expected_payload_type:
        raise EnvelopeError("DSSE payload type mismatch")
    signatures = data.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise EnvelopeError("exactly one DSSE signature is required")
    signature = signatures[0]
    if not isinstance(signature, dict) or set(signature) != {"keyid", "sig"}:
        raise EnvelopeError("DSSE signature fields are not closed")
    keyid = signature.get("keyid")
    if not isinstance(keyid, str) or keyid not in keys:
        raise UnknownEnvelopeKey(str(keyid))
    key = keys[keyid]
    if key.keytype != "ed25519" or key.scheme != "ed25519":
        raise EnvelopeError("only pinned Ed25519 keys are accepted")
    try:
        envelope = Envelope.from_dict(copy.deepcopy(data))
        if envelope.payload_type != expected_payload_type:
            raise EnvelopeError("decoded DSSE payload type mismatch")
        envelope.verify([key], 1)
    except EnvelopeError:
        raise
    except Exception as exc:
        raise EnvelopeError(f"DSSE verification failed: {type(exc).__name__}") from exc
    if canonical_bytes(load_json_strict(envelope.payload)) != envelope.payload:
        raise EnvelopeError("DSSE payload is not canonical RFC 8785 JSON")
    return envelope.payload, keyid
