"""Local HTTP server used by browser E2E tests.

The legacy ``/set`` and ``/wal`` routes retain their focused canaries, while
active-writer routes provide deterministic add/replace/delete transitions.
Corpus routes are declarative: ``/corpus/<phase>?engine=<engine>&tiers=<csv>``
emits the matching operations from :file:`cookie_corpus.json`.

Run from the workspace root: `python3 tests/e2e/cookie_server.py`.
"""

import os
import json
import threading
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

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


def corpus_run_response(
    path: str, host: str, corpus: dict | None = None
) -> tuple[list[str], str | None]:
    """Apply one corpus origin/phase and redirect to the next one."""

    corpus = corpus or load_corpus()
    parsed = urlsplit(path)
    query = parse_qs(parsed.query)
    engine = query.get("engine", [""])[0]
    tiers = query.get("tiers", [",".join(corpus["default_tiers"])])[0]
    try:
        step = int(query.get("step", ["0"])[0])
    except ValueError as error:
        raise ValueError("corpus run step must be an integer") from error
    sequence = [
        (phase, origin_name)
        for phase in corpus["phase_order"]
        for origin_name in corpus["origins"]
    ]
    if step < 0 or step >= len(sequence):
        raise ValueError(f"corpus run step {step} is outside 0..{len(sequence) - 1}")

    phase, origin_name = sequence[step]
    expected_host = corpus["origins"][origin_name]["hostname"]
    actual_host, separator, port = host.rpartition(":")
    if not separator:
        actual_host, port = host, ""

    def run_url(target_step: int, target_host: str) -> str:
        authority = f"{target_host}:{port}" if port else target_host
        encoded = urlencode({"engine": engine, "tiers": tiers, "step": target_step})
        return f"http://{authority}/corpus/run?{encoded}"

    if actual_host.lower() != expected_host.lower():
        return [], run_url(step, expected_host)
    virtual_path = f"/corpus/{phase}?" + urlencode({"engine": engine, "tiers": tiers})
    headers = corpus_headers(virtual_path, host, corpus)
    if step + 1 == len(sequence):
        return headers, None
    next_origin = sequence[step + 1][1]
    next_host = corpus["origins"][next_origin]["hostname"]
    return headers, run_url(step + 1, next_host)


class Handler(BaseHTTPRequestHandler):
    # Browsers preconnect to origins they have already visited, so they open
    # TCP sockets they may never send a request on. Reap those sockets instead
    # of parking a worker thread on them until the browser exits.
    timeout = 10

    @staticmethod
    def cookie_headers(path: str) -> list[str]:
        route = urlsplit(path).path
        attributes = "Path=/; Max-Age=3600; SameSite=Lax"
        if route == "/active-writer/baseline":
            return [
                f"rookie_ci=before; {attributes}",
                f"rookie_remove=present; {attributes}",
                "rookie_added=; Path=/; Max-Age=0; SameSite=Lax",
            ]
        if route == "/active-writer/mutate":
            return [
                f"rookie_ci=after; {attributes}",
                f"rookie_added=present; {attributes}",
                "rookie_remove=; Path=/; Max-Age=0; SameSite=Lax",
            ]
        if route == "/active-writer/churn":
            query = parse_qs(urlsplit(path).query)
            try:
                expiry = int(query.get("expiry", [""])[0])
            except ValueError:
                return []
            fixed = f"Path=/; Expires={formatdate(expiry, usegmt=True)}; SameSite=Lax"
            return [
                f"rookie_ci=after; {fixed}",
                f"rookie_added=present; {fixed}",
            ]

        if route == "/set":
            return [f"rookie_ci=bar; {attributes}"]
        if route == "/wal":
            return [
                f"rookie_ci=bar; {attributes}",
                f"rookie_wal=live; {attributes}",
            ]
        return []

    def do_GET(self) -> None:
        request_log = os.environ.get("ROOKIE_E2E_REQUEST_LOG")
        if request_log:
            with _LOG_LOCK, Path(request_log).open("a", encoding="utf-8") as log:
                log.write(f"{self.path}\n")

        request_path = urlsplit(self.path).path
        is_corpus_route = request_path.startswith("/corpus/")
        corpus = load_corpus() if is_corpus_route else None
        redirect = None
        if request_path == "/corpus/run":
            corpus_cookie_headers, redirect = corpus_run_response(
                self.path, self.headers.get("Host", ""), corpus
            )
        elif is_corpus_route:
            corpus_cookie_headers = corpus_headers(
                self.path, self.headers.get("Host", ""), corpus
            )
        else:
            corpus_cookie_headers = []
        self.send_response(302 if redirect else 200)
        if is_corpus_route:
            for header in corpus_cookie_headers:
                self.send_header("Set-Cookie", header)
        else:
            for header in self.cookie_headers(self.path):
                self.send_header("Set-Cookie", header)
        if redirect:
            self.send_header("Location", redirect)
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
