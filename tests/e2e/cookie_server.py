"""Minimal local HTTP server used by e2e tests.

Listens on 127.0.0.1:8765. Every GET returns 200 OK with a `Set-Cookie`
that the e2e tests grep for after extracting cookies via rookie-cookies.

Run from the workspace root: `python3 tests/e2e/cookie_server.py`.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header(
            "Set-Cookie",
            "rookie_ci=bar; Path=/; Max-Age=3600; SameSite=Lax",
        )
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_args, **_kwargs) -> None:
        # Quiet the access log; CI doesn't need it.
        return


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8765), Handler).serve_forever()
