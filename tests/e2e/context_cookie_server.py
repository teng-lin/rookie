#!/usr/bin/env python3
"""HTTPS test origin for browser-produced partitioned cookie contexts."""

from __future__ import annotations

import argparse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import sys
import threading
from urllib.parse import parse_qs, urlparse


ALLOWED_TOP_HOSTS = frozenset({"top.rookie-a.test", "other.rookie-c.test"})
ALLOWED_THIRD_HOST = "third.rookie-b.test"


class ContextCookieServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], event_log: Path | None = None):
        super().__init__(address, ContextCookieHandler)
        self.event_log = event_log
        self._event_lock = threading.Lock()

    def record(self, event: dict[str, object]) -> None:
        if self.event_log is None:
            return
        encoded = json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
        with self._event_lock:
            self.event_log.parent.mkdir(parents=True, exist_ok=True)
            with self.event_log.open("a", encoding="utf-8") as stream:
                stream.write(encoded)


class ContextCookieHandler(BaseHTTPRequestHandler):
    server: ContextCookieServer

    def log_message(self, format: str, *args: object) -> None:
        print(f"context-cookie-server: {format % args}", file=sys.stderr)

    def host(self) -> str:
        return self.headers.get("Host", "").split(":", 1)[0].lower()

    def send_body(
        self,
        status: HTTPStatus,
        body: str,
        *,
        content_type: str = "text/plain; charset=utf-8",
        cookies: tuple[str, ...] = (),
    ) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        for cookie in cookies:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        parsed = urlparse(self.path)
        host = self.host()
        self.server.record(
            {
                "host": host,
                "path": parsed.path,
                "cookie": self.headers.get("Cookie", ""),
            }
        )

        if parsed.path == "/health":
            self.send_body(HTTPStatus.OK, "ok\n")
            return

        if parsed.path == "/top":
            if host not in ALLOWED_TOP_HOSTS:
                self.send_body(HTTPStatus.BAD_REQUEST, "invalid top host\n")
                return
            query = parse_qs(parsed.query)
            third_origin = query.get("third_origin", [""])[0]
            expected_prefix = f"https://{ALLOWED_THIRD_HOST}:"
            if not third_origin.startswith(expected_prefix):
                self.send_body(HTTPStatus.BAD_REQUEST, "invalid third origin\n")
                return
            iframe = f"{third_origin}/set-context"
            body = f"""<!doctype html>
<meta charset="utf-8">
<title>partition-pending</title>
<iframe id="third" src="{iframe}"></iframe>
<script>
addEventListener("message", (event) => {{
  if (event.origin === {json.dumps(third_origin)} && event.data === "rookie-context-set") {{
    document.title = "partition-seeded";
  }}
}});
</script>
"""
            self.send_body(
                HTTPStatus.OK,
                body,
                content_type="text/html; charset=utf-8",
                cookies=(
                    "rookie_top=top; Secure; HttpOnly; SameSite=Lax; Path=/",
                ),
            )
            return

        if parsed.path == "/set-context":
            if host != ALLOWED_THIRD_HOST:
                self.send_body(HTTPStatus.BAD_REQUEST, "invalid third-party host\n")
                return
            body = """<!doctype html>
<meta charset="utf-8">
<title>third-party-set</title>
<script>parent.postMessage("rookie-context-set", "*");</script>
"""
            self.send_body(
                HTTPStatus.OK,
                body,
                content_type="text/html; charset=utf-8",
                cookies=(
                    "rookie_chips=partitioned; Secure; HttpOnly; SameSite=None; Partitioned; Path=/",
                    "rookie_dfpi=partitioned-by-context; Secure; HttpOnly; SameSite=None; Path=/",
                ),
            )
            return

        if parsed.path == "/echo":
            if host != ALLOWED_THIRD_HOST:
                self.send_body(HTTPStatus.BAD_REQUEST, "invalid echo host\n")
                return
            self.send_body(
                HTTPStatus.OK,
                json.dumps({"cookie": self.headers.get("Cookie", "")}),
                content_type="application/json",
            )
            return

        self.send_body(HTTPStatus.NOT_FOUND, "not found\n")


def build_server(
    host: str,
    port: int,
    *,
    event_log: Path | None = None,
    certificate: Path | None = None,
    private_key: Path | None = None,
) -> ContextCookieServer:
    server = ContextCookieServer((host, port), event_log)
    if (certificate is None) != (private_key is None):
        server.server_close()
        raise ValueError("certificate and private key must be supplied together")
    if certificate is not None and private_key is not None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, private_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--event-log", type=Path)
    parser.add_argument("--certificate", type=Path)
    parser.add_argument("--private-key", type=Path)
    args = parser.parse_args()
    try:
        server = build_server(
            args.host,
            args.port,
            event_log=args.event_log,
            certificate=args.certificate,
            private_key=args.private_key,
        )
    except (OSError, ssl.SSLError, ValueError) as error:
        print(f"context cookie server failed: {error}", file=sys.stderr)
        return 1
    scheme = "https" if args.certificate else "http"
    print(f"context cookie server listening on {scheme}://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
