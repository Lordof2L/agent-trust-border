from __future__ import annotations

import http.client
import json
import threading

import pytest

from agent_trust_border_web.server import create_server


@pytest.fixture
def lab_server():
    server = create_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


def request(lab_server, method: str, path: str, *, body=None, headers=None):
    host, port = lab_server
    connection = http.client.HTTPConnection(host, port, timeout=3)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def test_health_and_options_are_closed_and_explicit(lab_server) -> None:
    status, headers, body = request(lab_server, "GET", "/api/v1/health")
    payload = json.loads(body)

    assert status == 200
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert payload == {
        "action_execution": False,
        "kernel": "agent-trust-border/0.1",
        "profile": "synthetic-local-lab",
        "status": "ok",
    }

    status, _headers, body = request(lab_server, "GET", "/api/v1/options")
    payload = json.loads(body)
    assert status == 200
    assert payload["resources"] == ["sandbox:demo", "production:demo"]
    assert payload["authority_modes"] == [
        "missing",
        "exact_trusted_grant",
        "consumed_grant_replay",
    ]


def test_http_evaluate_calls_real_kernel(lab_server) -> None:
    body = json.dumps(
        {
            "resource": "sandbox:demo",
            "authority_mode": "exact_trusted_grant",
            "evidence_mode": "verified",
        }
    )
    status, _headers, raw = request(
        lab_server,
        "POST",
        "/api/v1/evaluate",
        body=body,
        headers={"Content-Type": "application/json"},
    )
    payload = json.loads(raw)

    assert status == 200
    assert payload["verdict"] == "ADMIT"
    assert payload["reason_codes"] == ["ALL_MANDATORY_CHECKS_PASS"]
    assert payload["effective_scope"]["resources"] == ["sandbox:demo"]
    assert payload["receipt_verified"] is True
    assert payload["action_executed"] is False


def test_static_lab_shell_is_served_with_closed_security_headers(lab_server) -> None:
    status, headers, body = request(lab_server, "GET", "/")

    assert status == 200
    assert headers["Content-Security-Policy"].startswith("default-src 'self'")
    assert headers["X-Frame-Options"] == "DENY"
    assert b"Executable Request Lab" in body


@pytest.mark.parametrize(
    ("body", "content_type", "expected_status", "expected_error"),
    (
        (
            '{"resource":"sandbox:demo","resource":"production:demo",'
            '"authority_mode":"missing","evidence_mode":"verified"}',
            "application/json",
            400,
            "invalid_json",
        ),
        (
            json.dumps(
                {
                    "resource": "sandbox:demo",
                    "authority_mode": "missing",
                    "evidence_mode": "verified",
                    "verdict": "ADMIT",
                }
            ),
            "application/json",
            422,
            "invalid_command",
        ),
        (
            "{}",
            "text/plain",
            415,
            "unsupported_media_type",
        ),
        (
            json.dumps(
                {
                    "resource": "production:demo",
                    "authority_mode": "consumed_grant_replay",
                    "evidence_mode": "verified",
                }
            ),
            "application/json",
            422,
            "invalid_command",
        ),
        (
            "x" * 8_193,
            "application/json",
            413,
            "body_too_large",
        ),
    ),
)
def test_http_evaluate_fails_closed(
    lab_server, body, content_type, expected_status, expected_error
) -> None:
    status, _headers, raw = request(
        lab_server,
        "POST",
        "/api/v1/evaluate",
        body=body,
        headers={"Content-Type": content_type},
    )
    payload = json.loads(raw)

    assert status == expected_status
    assert payload["error"] == expected_error
    assert payload["action_executed"] is False


def test_server_does_not_expose_arbitrary_paths(lab_server) -> None:
    status, _headers, body = request(lab_server, "GET", "/../pyproject.toml")

    assert status == 404
    assert json.loads(body)["error"] == "not_found"


def test_server_rejects_non_loopback_binding() -> None:
    with pytest.raises(ValueError, match=r"only to 127\.0\.0\.1"):
        create_server("0.0.0.0", 8877)
