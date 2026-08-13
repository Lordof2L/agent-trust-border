"""Bounded strict JSON ingress and RFC 8785 canonical bytes."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import rfc8785
from pydantic import BaseModel


class IngressError(ValueError):
    pass


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise IngressError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise IngressError(f"non-I-JSON number: {value}")


def load_json_strict(raw: str | bytes, *, max_bytes: int = 65_536) -> Any:
    encoded = raw.encode("utf-8") if isinstance(raw, str) else raw
    if len(encoded) > max_bytes:
        raise IngressError(f"input exceeds {max_bytes} bytes")
    try:
        text = encoded.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IngressError(str(exc)) from exc


def primitive(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True)
    return value


def canonical_bytes(value: Any) -> bytes:
    try:
        return rfc8785.dumps(primitive(value))
    except (rfc8785.CanonicalizationError, UnicodeEncodeError, TypeError) as exc:
        raise IngressError(f"cannot canonicalize value: {exc}") from exc


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


EMPTY_DIGEST = digest_bytes(b"")
