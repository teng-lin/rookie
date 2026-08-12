"""Minimal local HTTP server used by e2e tests.

Listens on 127.0.0.1:8765. Every GET returns 200 OK with a `Set-Cookie`
that the e2e tests grep for after extracting cookies via rookie-cookies.

Run from the workspace root: `python3 tests/e2e/cookie_server.py`.
"""

import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_LOG_LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    # Browsers preconnect to origins they have already visited, so they open
    # TCP sockets they may never send a request on. Reap those sockets instead
    # of parking a worker thread on them until the browser exits.
    timeout = 10

    def do_GET(self) -> None:
        request_log = os.environ.get("ROOKIE_E2E_REQUEST_LOG")
        if request_log:
            with _LOG_LOCK, Path(request_log).open("a", encoding="utf-8") as log:
                log.write(f"{self.path}\n")

        self.send_response(200)
        self.send_header(
            "Set-Cookie",
            "rookie_ci=bar; Path=/; Max-Age=3600; SameSite=Lax",
        )
        # The App-Bound canary requests this route while Chrome stays open.
        # Its second cookie should therefore be visible through Chrome's live
        # write-ahead log, rather than only after a browser shutdown/checkpoint.
        if self.path.startswith("/wal"):
            self.send_header(
                "Set-Cookie",
                "rookie_wal=live; Path=/; Max-Age=3600; SameSite=Lax",
            )
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_args, **_kwargs) -> None:
        # Quiet the access log; CI doesn't need it.
        return


if __name__ == "__main__":
    # Threaded: a single-threaded server is wedged permanently by one idle
    # preconnected socket, which silently drops every later request.
    server = ThreadingHTTPServer(("127.0.0.1", 8765), Handler)
    server.daemon_threads = True
    server.serve_forever()
