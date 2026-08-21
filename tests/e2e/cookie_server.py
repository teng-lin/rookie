"""Local HTTP server used by browser E2E tests.

The legacy ``/set`` and ``/wal`` routes retain their focused canaries. Corpus
routes are declarative: ``/corpus/<phase>?engine=<engine>&tiers=<csv>`` emits
the matching operations from :file:`cookie_corpus.json`.

Run from the workspace root: `python3 tests/e2e/cookie_server.py`.
"""

import os
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

_LOG_LOCK = threading.Lock()
_CORPUS_PATH = Path(__file__).with_name("cookie_corpus.json")


def load_corpus() -> dict:
    return json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))


def expanded_value(operation: dict) -> str:
    if "value" in operation:
        return str(operation["value"])
    repeat = operation.get("value_repeat")
    if not isinstance(repeat, dict):
        raise ValueError("cookie operation must define value or value_repeat")
    return str(repeat["text"]) * int(repeat["count"])


def set_cookie_header(operation: dict) -> str:
    header = f"{operation['name']}={expanded_value(operation)}"
    attributes = [f"Path={operation.get('path', '/')}"]
    if "domain" in operation:
        attributes.append(f"Domain={operation['domain']}")
    if "max_age" in operation:
        attributes.append(f"Max-Age={int(operation['max_age'])}")
    if "expires" in operation:
        attributes.append(f"Expires={operation['expires']}")
    if operation.get("secure"):
        attributes.append("Secure")
    if operation.get("http_only"):
        attributes.append("HttpOnly")
    if "same_site" in operation:
        attributes.append(f"SameSite={operation['same_site']}")
    return "; ".join((header, *attributes))


def corpus_headers(path: str, host: str, corpus: dict | None = None) -> list[str]:
    parsed = urlsplit(path)
    if not parsed.path.startswith("/corpus/"):
        return []
    corpus = corpus or load_corpus()
    phase = parsed.path.removeprefix("/corpus/")
    query = parse_qs(parsed.query)
    engine = query.get("engine", [""])[0]
    tiers = {
        tier
        for value in query.get("tiers", corpus["default_tiers"])
        for tier in value.split(",")
        if tier
    }
    hostname = host.rsplit(":", 1)[0].lower()
    headers: list[str] = []
    for scenario in corpus["scenarios"]:
        if engine not in scenario["applicability"]["engines"]:
            continue
        if not tiers.intersection(scenario["tiers"]):
            continue
        origin = corpus["origins"][scenario["origin"]]
        if hostname != origin["hostname"]:
            continue
        for operation in scenario["operations"]:
            if operation["phase"] == phase:
                headers.append(set_cookie_header(operation))
    return headers


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
        corpus_cookie_headers = corpus_headers(self.path, self.headers.get("Host", ""))
        if corpus_cookie_headers:
            for header in corpus_cookie_headers:
                self.send_header("Set-Cookie", header)
        else:
            # Preserve the original focused canary for native-browser and WAL
            # jobs that have not opted into the corpus seeder.
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


def listen_port() -> int:
    return int(os.environ.get("ROOKIE_E2E_COOKIE_PORT", "8765"))


if __name__ == "__main__":
    # Threaded: a single-threaded server is wedged permanently by one idle
    # preconnected socket, which silently drops every later request.
    port = listen_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    print(f"cookie server listening on 127.0.0.1:{port}", flush=True)
    server.serve_forever()
