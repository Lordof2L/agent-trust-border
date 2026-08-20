"""Local-only HTTP adapter and static UI for the bounded Phase-2 lab."""

from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from agent_trust_border.canonical import IngressError, load_json_strict
from agent_trust_border.lab import AuthorityMode, EvidenceMode, LabCommand, evaluate_lab

MAX_BODY_BYTES = 8_192
STATIC_ROOT = Path(__file__).resolve().parents[2] / "phase2_web"
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
}


class LabHTTPServer(ThreadingHTTPServer):
    daemon_threads = True


class LabHandler(BaseHTTPRequestHandler):
    server_version = "AgentTrustBorderLab/0.1"

    def _security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'self'; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        )

    def _send_bytes(
        self,
        status: HTTPStatus,
        body: bytes,
        content_type: str,
        *,
        cache_control: str,
        head_only: bool = False,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache_control)
        self._security_headers()
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def _send_json(
        self,
        status: HTTPStatus,
        payload: dict[str, Any],
        *,
        head_only: bool = False,
    ) -> None:
        body = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
        self._send_bytes(
            status,
            body,
            "application/json; charset=utf-8",
            cache_control="no-store",
            head_only=head_only,
        )

    def _not_found(self, *, head_only: bool = False) -> None:
        self._send_json(
            HTTPStatus.NOT_FOUND,
            {"action_executed": False, "error": "not_found"},
            head_only=head_only,
        )

    def _serve_get(self, *, head_only: bool = False) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/api/v1/health":
            self._send_json(
                HTTPStatus.OK,
                {
                    "action_execution": False,
                    "kernel": "agent-trust-border/0.1",
                    "profile": "synthetic-local-lab",
                    "status": "ok",
                },
                head_only=head_only,
            )
            return
        if path == "/api/v1/options":
            self._send_json(
                HTTPStatus.OK,
                {
                    "action_execution": False,
                    "authority_modes": [item.value for item in AuthorityMode],
                    "evidence_modes": [item.value for item in EvidenceMode],
                    "resources": ["sandbox:demo", "production:demo"],
                },
                head_only=head_only,
            )
            return
        static = STATIC_FILES.get(path)
        if static is None:
            self._not_found(head_only=head_only)
            return
        filename, content_type = static
        try:
            body = (STATIC_ROOT / filename).read_bytes()
        except OSError as exc:
            self.log_error("static asset unavailable: %s: %s", filename, type(exc).__name__)
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"action_executed": False, "error": "static_asset_unavailable"},
                head_only=head_only,
            )
            return
        self._send_bytes(
            HTTPStatus.OK,
            body,
            content_type,
            cache_control="no-cache",
            head_only=head_only,
        )

    def do_GET(self) -> None:
        self._serve_get()

    def do_HEAD(self) -> None:
        self._serve_get(head_only=True)

    def do_POST(self) -> None:
        if self.path.split("?", 1)[0] != "/api/v1/evaluate":
            self._not_found()
            return
        media_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if media_type != "application/json":
            self._send_json(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                {"action_executed": False, "error": "unsupported_media_type"},
            )
            return
        try:
            content_length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            content_length = -1
        if content_length < 0:
            self._send_json(
                HTTPStatus.LENGTH_REQUIRED,
                {"action_executed": False, "error": "content_length_required"},
            )
            return
        if content_length > MAX_BODY_BYTES:
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"action_executed": False, "error": "body_too_large"},
            )
            return
        raw = self.rfile.read(content_length)
        try:
            load_json_strict(raw, max_bytes=MAX_BODY_BYTES)
        except IngressError as exc:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {
                    "action_executed": False,
                    "detail": str(exc),
                    "error": "invalid_json",
                },
            )
            return
        try:
            command = LabCommand.model_validate_json(raw)
        except ValidationError as exc:
            self._send_json(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                {
                    "action_executed": False,
                    "detail": json.loads(exc.json(include_url=False)),
                    "error": "invalid_command",
                },
            )
            return
        try:
            result = evaluate_lab(command)
        except Exception as exc:
            self.log_error("lab evaluation failed visibly: %s", type(exc).__name__)
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"action_executed": False, "error": "evaluation_failed"},
            )
            return
        self._send_bytes(
            HTTPStatus.OK,
            (result.model_dump_json(by_alias=True) + "\n").encode(),
            "application/json; charset=utf-8",
            cache_control="no-store",
        )


def create_server(host: str, port: int) -> LabHTTPServer:
    if host != "127.0.0.1":
        raise ValueError("the Phase-2 lab may bind only to 127.0.0.1")
    return LabHTTPServer((host, port), LabHandler)


def _port(value: str) -> int:
    parsed = int(value)
    if not 1 <= parsed <= 65_535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local synthetic Agent Trust Border lab")
    parser.add_argument("--host", choices=("127.0.0.1",), default="127.0.0.1")
    parser.add_argument("--port", type=_port, default=8877)
    args = parser.parse_args()
    server = create_server(args.host, args.port)
    print(f"Agent Trust Border lab: http://{args.host}:{server.server_port}", flush=True)
    print("Synthetic local fixtures; requested action execution is disabled", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
