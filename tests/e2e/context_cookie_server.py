#!/usr/bin/env python3
"""HTTPS test origin for browser-produced partitioned cookie contexts."""

from __future__ import annotations

import argparse
from email.utils import formatdate
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import ssl
import sys
import threading
import time
from urllib.parse import parse_qs, urlparse


ALLOWED_TOP_HOSTS = frozenset({"top.rookie-a.test", "other.rookie-c.test"})
ALLOWED_THIRD_HOST = "third.rookie-b.test"
STRESS_HOST_PATTERN = re.compile(r"seed\.rookie-(?P<index>[0-7])\.test\Z")
MAX_STRESS_COOKIES_PER_HOST = 64


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

    def log_message(self, message_format: str, *args: object) -> None:
        if args and "/stress/churn?" in str(args[0]):
            return
        print(f"context-cookie-server: {message_format % args}", file=sys.stderr)

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
        try:
            self.end_headers()
            self.wfile.write(encoded)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            # A browser navigation may replace the churn page immediately
            # after headers are accepted; the Set-Cookie write already landed.
            pass

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
            engine = query.get("engine", [""])[0]
            parsed_third = urlparse(third_origin)
            try:
                third_port = parsed_third.port
            except ValueError:
                third_port = None
            if (
                parsed_third.scheme != "https"
                or parsed_third.hostname != ALLOWED_THIRD_HOST
                or parsed_third.username is not None
                or parsed_third.password is not None
                or third_port is None
                or parsed_third.path
                or parsed_third.params
                or parsed_third.query
                or parsed_third.fragment
            ):
                self.send_body(HTTPStatus.BAD_REQUEST, "invalid third origin\n")
                return
            third_origin = f"https://{ALLOWED_THIRD_HOST}:{third_port}"
            if engine not in {"chromium", "firefox"}:
                self.send_body(HTTPStatus.BAD_REQUEST, "invalid browser engine\n")
                return
            partition = "a" if host == "top.rookie-a.test" else "c"
            iframe = f"{third_origin}/set-context?partition={partition}&engine={engine}"
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
                    f"rookie_top=top-{partition}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600",
                ),
            )
            return

        if parsed.path == "/set-context":
            if host != ALLOWED_THIRD_HOST:
                self.send_body(HTTPStatus.BAD_REQUEST, "invalid third-party host\n")
                return
            query = parse_qs(parsed.query)
            partition = query.get("partition", [""])[0]
            engine = query.get("engine", [""])[0]
            if partition not in {"a", "c"}:
                self.send_body(HTTPStatus.BAD_REQUEST, "invalid partition label\n")
                return
            if engine not in {"chromium", "firefox"}:
                self.send_body(HTTPStatus.BAD_REQUEST, "invalid browser engine\n")
                return
            body = """<!doctype html>
<meta charset="utf-8">
<title>third-party-set</title>
<script>parent.postMessage("rookie-context-set", "*");</script>
"""
            cookies = (
                f"rookie_chips=partition-{partition}; Secure; HttpOnly; SameSite=None; Partitioned; Path=/; Max-Age=3600",
            )
            if engine == "firefox":
                cookies += (
                    f"rookie_dfpi=dfpi-{partition}; Secure; HttpOnly; SameSite=None; Path=/; Max-Age=3600",
                )
            self.send_body(
                HTTPStatus.OK,
                body,
                content_type="text/html; charset=utf-8",
                cookies=cookies,
            )
            return

        if parsed.path == "/set-unpartitioned":
            if host != ALLOWED_THIRD_HOST:
                self.send_body(HTTPStatus.BAD_REQUEST, "invalid third-party host\n")
                return
            engine = parse_qs(parsed.query).get("engine", [""])[0]
            if engine not in {"chromium", "firefox"}:
                self.send_body(HTTPStatus.BAD_REQUEST, "invalid browser engine\n")
                return
            self.send_body(
                HTTPStatus.OK,
                "<!doctype html><title>unpartitioned-seeded</title>\n",
                content_type="text/html; charset=utf-8",
                cookies=(
                    "rookie_chips=unpartitioned; Secure; HttpOnly; SameSite=None; "
                    "Path=/; Max-Age=3600",
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

        stress_match = STRESS_HOST_PATTERN.fullmatch(host)
        if parsed.path == "/stress/seed":
            if stress_match is None:
                self.send_body(HTTPStatus.BAD_REQUEST, "invalid stress host\n")
                return
            query = parse_qs(parsed.query)
            try:
                count = int(query.get("count", ["40"])[0])
            except ValueError:
                count = 0
            if not 1 <= count <= MAX_STRESS_COOKIES_PER_HOST:
                self.send_body(HTTPStatus.BAD_REQUEST, "invalid stress count\n")
                return
            try:
                expiry = int(query.get("expiry", ["0"])[0])
            except ValueError:
                expiry = 0
            if expiry <= 0:
                expiry = int(time.time()) + 1209600
            expires_header = f"Expires={formatdate(expiry, usegmt=True)}"
            host_index = int(stress_match.group("index"))
            cookies = tuple(
                f"{'stress_shared' if cookie_index == count - 1 else f'stress_{host_index}_{cookie_index}'}="
                f"seed-{host_index}-{cookie_index}; "
                f"Secure; HttpOnly; SameSite=Lax; Path=/; {expires_header}"
                for cookie_index in range(count)
            )
            self.send_body(
                HTTPStatus.OK,
                json.dumps(
                    {
                        "host_index": host_index,
                        "seeded": count,
                        "expiry": expiry,
                    }
                ),
                content_type="application/json",
                cookies=cookies,
            )
            return

        if parsed.path == "/stress/mutate":
            if stress_match is None:
                self.send_body(HTTPStatus.BAD_REQUEST, "invalid stress host\n")
                return
            query = parse_qs(parsed.query)
            try:
                round_number = int(query.get("round", [""])[0])
            except ValueError:
                round_number = -1
            if not 0 <= round_number <= 999:
                self.send_body(HTTPStatus.BAD_REQUEST, "invalid mutation round\n")
                return
            try:
                expiry = int(query.get("expiry", ["0"])[0])
            except ValueError:
                expiry = 0
            if expiry <= 0:
                expiry = int(time.time()) + 1209600
            expires_header = f"Expires={formatdate(expiry, usegmt=True)}"
            host_index = int(stress_match.group("index"))
            delete_index = round_number + 1
            cookies = (
                f"stress_{host_index}_0=updated-{round_number}; Secure; HttpOnly; "
                f"SameSite=Lax; Path=/; {expires_header}",
                f"stress_{host_index}_{delete_index}=deleted; Secure; HttpOnly; SameSite=Lax; "
                "Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
                f"stress_{host_index}_round_{round_number}=added-{round_number}; "
                f"Secure; HttpOnly; SameSite=Lax; Path=/; {expires_header}",
            )
            self.send_body(
                HTTPStatus.OK,
                json.dumps(
                    {
                        "host_index": host_index,
                        "round": round_number,
                        "deleted_index": delete_index,
                        "expiry": expiry,
                    }
                ),
                content_type="application/json",
                cookies=cookies,
            )
            return

        if parsed.path == "/stress/churn":
            if stress_match is None:
                self.send_body(HTTPStatus.BAD_REQUEST, "invalid stress host\n")
                return
            query = parse_qs(parsed.query)
            host_index = int(stress_match.group("index"))
            value = query.get("value", [""])[0]
            valid_value = value == f"seed-{host_index}-0" or re.fullmatch(
                r"updated-[0-9]+", value
            )
            try:
                expiry = int(query.get("expiry", [""])[0])
            except ValueError:
                expiry = 0
            if not valid_value or expiry <= 0:
                self.send_body(HTTPStatus.BAD_REQUEST, "invalid stress churn state\n")
                return
            self.send_body(
                HTTPStatus.OK,
                json.dumps({"host_index": host_index, "churned": True}),
                content_type="application/json",
                cookies=(
                    f"stress_{host_index}_0={value}; Secure; HttpOnly; "
                    f"SameSite=Lax; Path=/; Expires={formatdate(expiry, usegmt=True)}",
                ),
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
