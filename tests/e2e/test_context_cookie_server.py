"""Tests for the isolated partition-cookie HTTPS origin."""

from __future__ import annotations

import http.client
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest


def load_module(name: str, filename: str):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SERVER = load_module("context_cookie_server", "context_cookie_server.py")


class ContextCookieServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="rookie context server ")
        self.event_log = Path(self.tempdir.name) / "events.jsonl"
        self.server = SERVER.build_server("127.0.0.1", 0, event_log=self.event_log)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tempdir.cleanup()

    def request(self, host: str, target: str) -> tuple[int, list[tuple[str, str]], str]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        try:
            connection.request("GET", target, headers={"Host": host})
            response = connection.getresponse()
            body = response.read().decode("utf-8")
            return response.status, response.getheaders(), body
        finally:
            connection.close()

    def test_top_page_sets_first_party_cookie_and_embeds_only_allowed_origin(self) -> None:
        target = f"/top?third_origin=https://{SERVER.ALLOWED_THIRD_HOST}:8766"
        status, headers, body = self.request("top.rookie-a.test", target)
        self.assertEqual(status, 200)
        cookies = [value for name, value in headers if name.lower() == "set-cookie"]
        self.assertEqual(
            cookies,
            ["rookie_top=top; Secure; HttpOnly; SameSite=Lax; Path=/"],
        )
        self.assertIn("https://third.rookie-b.test:8766/set-context", body)
        self.assertIn("partition-seeded", body)

    def test_third_party_page_sets_chips_and_dfpi_candidates(self) -> None:
        status, headers, body = self.request(
            SERVER.ALLOWED_THIRD_HOST, "/set-context"
        )
        self.assertEqual(status, 200)
        cookies = [value for name, value in headers if name.lower() == "set-cookie"]
        self.assertEqual(len(cookies), 2)
        self.assertIn("Partitioned", cookies[0])
        self.assertNotIn("Partitioned", cookies[1])
        self.assertIn("rookie-context-set", body)

    def test_host_and_third_origin_are_restricted(self) -> None:
        status, _, _ = self.request(
            "attacker.test",
            f"/top?third_origin=https://{SERVER.ALLOWED_THIRD_HOST}:8766",
        )
        self.assertEqual(status, 400)
        status, _, _ = self.request(
            "top.rookie-a.test", "/top?third_origin=https://attacker.test:8766"
        )
        self.assertEqual(status, 400)
        status, _, _ = self.request("attacker.test", "/set-context")
        self.assertEqual(status, 400)

    def test_event_log_records_host_path_and_cookie_header(self) -> None:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        try:
            connection.request(
                "GET",
                "/echo",
                headers={
                    "Host": SERVER.ALLOWED_THIRD_HOST,
                    "Cookie": "rookie_chips=partitioned",
                },
            )
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            response.read()
        finally:
            connection.close()
        events = [
            json.loads(line)
            for line in self.event_log.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(
            events[-1],
            {
                "host": SERVER.ALLOWED_THIRD_HOST,
                "path": "/echo",
                "cookie": "rookie_chips=partitioned",
            },
        )


if __name__ == "__main__":
    unittest.main()
