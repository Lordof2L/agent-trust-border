from __future__ import annotations

import ast
from pathlib import Path

import pytest

from agent_trust_border.canonical import IngressError, load_json_strict
from agent_trust_border.fixtures import make_world
from agent_trust_border.projection import render_trace_html

from .matrix_cases import run_case

EXPECTED = {
    "K01": ("UNKNOWN", ("MISSING_AUTHORIZATION",)),
    "K02": ("ADMIT", ("ALL_MANDATORY_CHECKS_PASS",)),
    "K03": ("DENY", ("SCOPE_EXCEEDED",)),
    "K04": ("DENY", ("CONTEXT_MISMATCH",)),
    "K05": ("DENY", ("REPLAY_DETECTED",)),
    "K06": ("ADMIT", ("ALL_MANDATORY_CHECKS_PASS",)),
    "K07": ("DENY", ("UNTRUSTED_ISSUER",)),
    "K08": ("DENY", ("WRONG_KEY_PURPOSE",)),
    "K09": ("DENY", ("EXPIRED_GRANT",)),
    "K10": ("DENY", ("REVOKED_CREDENTIAL",)),
    "K11": ("DENY", ("INVALID_SIGNATURE",)),
    "K12": ("DENY", ("MALFORMED_INPUT",)),
    "K13": ("UNKNOWN", ("UNKNOWN_SCHEMA_VERSION",)),
    "K14": ("UNKNOWN", ("MISSING_TRUST_ROOT",)),
    "K15": ("UNKNOWN", ("UNVERIFIABLE_CLAIM",)),
    "K16": ("DENY", ("MAPPING_REQUIRED_CLAIM_LOST",)),
    "K17": ("DENY", ("MAPPING_CONFLICT",)),
    "K18": ("UNKNOWN", ("UNKNOWN_PREDICATE",)),
    "K19": ("DENY", ("INVALID_SIGNATURE",)),
    "K20": ("UNKNOWN", ("MISSING_AUTHORIZATION", "EVIDENCE_UNAVAILABLE")),
}


@pytest.mark.parametrize("case_id", tuple(EXPECTED))
def test_behavioral_matrix(case_id: str) -> None:
    observation = run_case(case_id)
    assert (observation.verdict, observation.reasons) == EXPECTED[case_id]
    assert observation.action_executed is False
    if case_id == "K02" or case_id == "K06":
        assert observation.scope_resources == ("sandbox:demo",)
    else:
        assert observation.scope_resources == ()


def test_all_twenty_cases_are_byte_stable_for_one_hundred_fresh_runs() -> None:
    baselines = {case_id: run_case(case_id).artifact for case_id in EXPECTED}
    for _ in range(99):
        for case_id, baseline in baselines.items():
            assert run_case(case_id).artifact == baseline, case_id


def test_strict_ingress_rejects_duplicate_keys_and_non_finite_numbers() -> None:
    with pytest.raises(IngressError):
        load_json_strict('{"x":1,"x":2}')
    with pytest.raises(IngressError):
        load_json_strict('{"x":NaN}')


def test_trusted_kernel_has_no_network_model_or_tool_imports() -> None:
    source_root = Path(__file__).parents[1] / "src" / "agent_trust_border"
    banned_roots = {
        "aiohttp",
        "anthropic",
        "httpx",
        "openai",
        "requests",
        "socket",
        "subprocess",
        "urllib",
    }
    for path in sorted(source_root.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                assert name.split(".", 1)[0] not in banned_roots, (path, name)


def test_human_projection_is_deterministic_and_self_contained() -> None:
    rows = [
        {
            "step": "capability-only",
            "verdict": "UNKNOWN",
            "reason_codes": ["MISSING_AUTHORIZATION"],
            "effective_scope": {"resources": []},
        }
    ]
    first = render_trace_html(rows)
    second = render_trace_html(rows)
    assert first == second
    assert "<script" not in first.lower()
    assert "http://" not in first.lower()
    assert "https://" not in first.lower()


def test_public_fixture_identifiers_and_keys_are_unambiguously_demo_only() -> None:
    world = make_world()
    assert world.source_document["demo_only"] is True
    assert world.source_document["agent_id"].startswith("demo:agent:")
    assert world.policy.audience.startswith("demo:border:")
    assert world.trust.subject.startswith("demo:agent:")
    assert all(key_id.startswith("demo:key:") for key_id in world.keys.public_keys)
