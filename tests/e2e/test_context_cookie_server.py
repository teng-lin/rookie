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

    def test_top_page_sets_first_party_cookie_and_embeds_only_allowed_origin(
        self,
    ) -> None:
        target = (
            f"/top?third_origin=https://{SERVER.ALLOWED_THIRD_HOST}:8766"
            "&engine=chromium"
        )
        status, headers, body = self.request("top.rookie-a.test", target)
        self.assertEqual(status, 200)
        cookies = [value for name, value in headers if name.lower() == "set-cookie"]
        self.assertEqual(
            cookies,
            ["rookie_top=top-a; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600"],
        )
        self.assertIn(
            "https://third.rookie-b.test:8766/set-context?partition=a&engine=chromium",
            body,
        )
        self.assertIn("partition-seeded", body)

    def test_third_party_page_sets_chips_and_dfpi_candidates(self) -> None:
        status, headers, body = self.request(
            SERVER.ALLOWED_THIRD_HOST, "/set-context?partition=a&engine=firefox"
        )
        self.assertEqual(status, 200)
        cookies = [value for name, value in headers if name.lower() == "set-cookie"]
        self.assertEqual(len(cookies), 2)
        self.assertIn("Partitioned", cookies[0])
        self.assertIn("partition-a", cookies[0])
        self.assertNotIn("Partitioned", cookies[1])
        self.assertIn("rookie-context-set", body)

    def test_host_and_third_origin_are_restricted(self) -> None:
        status, _, _ = self.request(
            "attacker.test",
            f"/top?third_origin=https://{SERVER.ALLOWED_THIRD_HOST}:8766&engine=chromium",
        )
        self.assertEqual(status, 400)
        status, _, _ = self.request(
            "top.rookie-a.test", "/top?third_origin=https://attacker.test:8766"
        )
        self.assertEqual(status, 400)
        status, _, body = self.request(
            "top.rookie-a.test",
            f"/top?third_origin=https://{SERVER.ALLOWED_THIRD_HOST}:8766/"
            "%22%3E%3Cscript%3Ealert(1)%3C/script%3E&engine=chromium",
        )
        self.assertEqual(status, 400)
        self.assertNotIn("<script>alert(1)</script>", body)
        status, _, _ = self.request(
            "attacker.test", "/set-context?partition=a&engine=chromium"
        )
        self.assertEqual(status, 400)
        status, _, _ = self.request(SERVER.ALLOWED_THIRD_HOST, "/set-context")
        self.assertEqual(status, 400)

    def test_chromium_context_route_omits_the_firefox_only_candidate(self) -> None:
        status, headers, _ = self.request(
            SERVER.ALLOWED_THIRD_HOST, "/set-context?partition=c&engine=chromium"
        )
        self.assertEqual(status, 200)
        cookies = [value for name, value in headers if name.lower() == "set-cookie"]
        self.assertEqual(len(cookies), 1)
        self.assertTrue(cookies[0].startswith("rookie_chips=partition-c;"))

    def test_unpartitioned_route_creates_the_same_flat_chips_identity(self) -> None:
        status, headers, body = self.request(
            SERVER.ALLOWED_THIRD_HOST,
            "/set-unpartitioned?engine=chromium",
        )
        self.assertEqual(status, 200)
        cookies = [value for name, value in headers if name.lower() == "set-cookie"]
        self.assertEqual(
            cookies,
            [
                "rookie_chips=unpartitioned; Secure; HttpOnly; SameSite=None; "
                "Path=/; Max-Age=3600"
            ],
        )
        self.assertIn("unpartitioned-seeded", body)

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

    def test_stress_seed_distributes_a_bounded_cookie_batch(self) -> None:
        status, headers, body = self.request(
            "seed.rookie-3.test", "/stress/seed?count=40&expiry=4102444800"
        )
        self.assertEqual(status, 200)
        cookies = [value for name, value in headers if name.lower() == "set-cookie"]
        self.assertEqual(len(cookies), 40)
        self.assertTrue(cookies[0].startswith("stress_3_0=seed-3-0;"))
        self.assertIn("Expires=Fri, 01 Jan 2100 00:00:00 GMT", cookies[0])
        self.assertTrue(cookies[-1].startswith("stress_shared=seed-3-39;"))
        self.assertIn("Expires=Fri, 01 Jan 2100 00:00:00 GMT", cookies[-1])
        self.assertEqual(
            json.loads(body),
            {"host_index": 3, "seeded": 40, "expiry": 4102444800},
        )

    def test_stress_seed_rejects_unbounded_or_wrong_host_requests(self) -> None:
        status, _, _ = self.request(
            "seed.rookie-0.test",
            f"/stress/seed?count={SERVER.MAX_STRESS_COOKIES_PER_HOST + 1}",
        )
        self.assertEqual(status, 400)
        status, _, _ = self.request("top.rookie-a.test", "/stress/seed?count=40")
        self.assertEqual(status, 400)

    def test_stress_mutation_updates_deletes_and_adds(self) -> None:
        status, headers, body = self.request(
            "seed.rookie-5.test", "/stress/mutate?round=7&expiry=4102444800"
        )
        self.assertEqual(status, 200)
        cookies = [value for name, value in headers if name.lower() == "set-cookie"]
        self.assertEqual(len(cookies), 3)
        self.assertIn("stress_5_0=updated-7", cookies[0])
        self.assertIn("Expires=Fri, 01 Jan 2100 00:00:00 GMT", cookies[0])
        self.assertIn("stress_5_8=deleted", cookies[1])
        self.assertIn("Max-Age=0", cookies[1])
        self.assertIn("stress_5_round_7=added-7", cookies[2])
        self.assertIn("Expires=Fri, 01 Jan 2100 00:00:00 GMT", cookies[2])
        self.assertEqual(
            json.loads(body),
            {
                "host_index": 5,
                "round": 7,
                "deleted_index": 8,
                "expiry": 4102444800,
            },
        )

    def test_stress_churn_rewrites_only_the_stable_cookie_state(self) -> None:
        status, headers, body = self.request(
            "seed.rookie-2.test",
            "/stress/churn?value=seed-2-0&expiry=4102444800",
        )
        self.assertEqual(status, 200)
        cookies = [value for name, value in headers if name.lower() == "set-cookie"]
        self.assertEqual(len(cookies), 1)
        self.assertTrue(cookies[0].startswith("stress_2_0=seed-2-0;"))
        self.assertIn("Expires=Fri, 01 Jan 2100 00:00:00 GMT", cookies[0])
        self.assertEqual(json.loads(body), {"host_index": 2, "churned": True})

        status, _, _ = self.request(
            "seed.rookie-2.test",
            "/stress/churn?value=seed-7-0&expiry=4102444800",
        )
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
