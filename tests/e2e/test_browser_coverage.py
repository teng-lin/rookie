"""Every registry browser/OS pair must appear in the claimed-browser matrix."""

from __future__ import annotations

import ast
from contextlib import redirect_stdout
import io
import json
import re
import sys
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
COVERAGE_PATH = Path(__file__).with_name("browser_coverage.json")
REGISTRY_PATH = REPOSITORY_ROOT / "rookie-rs" / "browser_registry.json"
TESTING_MD_PATH = REPOSITORY_ROOT / "docs" / "testing.md"
PYTHON_BINDING_PATH = (
    REPOSITORY_ROOT / "bindings" / "python" / "rookie_cookies" / "__init__.py"
)
NODE_BINDING_PATH = REPOSITORY_ROOT / "bindings" / "node" / "index.js"
CLAIMED_RUNNER_PATH = Path(__file__).with_name("run_hosted_claimed_e2e.py")
sys.path.insert(0, str(Path(__file__).parent))

from browser_coverage_contract import (  # noqa: E402 - local harness path above
    CONVENIENCE_DISPATCHES,
    DEPTH_LEVELS,
    assert_observed_depth,
    convenience_function,
    depth_for,
    emit_representative_depth,
)

# docs/testing.md uses the shorter product names readers already know.
DOC_BROWSER_TITLES = {
    "chrome": "Chrome",
    "coccoc": "Cốc Cốc",
    "edge": "Edge",
}
DOC_LANE_CELLS = {
    "hosted": "nightly_hosted",
    "fixture": "release_fixture",
    "manual": "manual",
    "**manual**": "manual",
    "—": None,
}

KNOWN_LANES = frozenset({"nightly_hosted", "release_fixture", "manual"})
COOKIE_CONTEXT_FIELDS = frozenset(
    {
        "top_frame_site_key",
        "has_cross_site_ancestor",
        "source_scheme",
        "source_port",
        "is_persistent",
        "origin_attributes",
        "user_context_id",
        "partition_key",
        "private_browsing_id",
    }
)
CONTEXT_CLASSIFICATIONS = frozenset({"live", "fixture_only", "non_persistable"})
NIGHTLY_HOSTED = frozenset(
    {
        ("linux", "brave"),
        ("linux", "chrome"),
        ("linux", "chromium"),
        ("linux", "edge"),
        ("linux", "firefox"),
        ("linux", "librewolf"),
        ("linux", "opera"),
        ("linux", "vivaldi"),
        ("linux", "zen"),
        ("macos", "brave"),
        ("macos", "chrome"),
        ("macos", "chromium"),
        ("macos", "edge"),
        ("macos", "firefox"),
        ("macos", "librewolf"),
        ("macos", "opera"),
        ("macos", "opera_gx"),
        ("macos", "safari"),
        ("macos", "vivaldi"),
        ("macos", "yandex"),
        ("macos", "zen"),
        ("windows", "brave"),
        ("windows", "chrome"),
        ("windows", "chromium"),
        ("windows", "edge"),
        ("windows", "firefox"),
        ("windows", "librewolf"),
        ("windows", "opera"),
        ("windows", "opera_gx"),
        ("windows", "vivaldi"),
        ("windows", "yandex"),
        ("windows", "zen"),
    }
)
MANUAL: frozenset[tuple[str, str]] = frozenset()

ALL_PLATFORMS = frozenset({"linux", "macos", "windows"})
# The bindings gate on `sys.platform`; the coverage manifest names the same
# three platforms the way the registry does.
SYS_PLATFORM_IDS = {"win32": "windows", "darwin": "macos", "linux": "linux"}
CONVENIENCE_ENTRY_KEYS = frozenset(
    {"python", "node", "dispatch", "platforms", "aliases"}
)
DISCOVERY_ENV_KEYS = frozenset(
    {"ROOKIE_E2E_CHECK_BROWSER_DISCOVERY", "ROOKIE_E2E_TARGET_BROWSER"}
)
NODE_EXPORT_PATTERN = re.compile(r"^module\.exports\.(\w+) = ", re.MULTILINE)
NODE_PLATFORM_EXPORT_PATTERN = re.compile(
    r"^module\.exports\.(?P<name>\w+) = platformNative\("
    r"\s*\w+,\s*'\w+',\s*(?P<platforms>\[[^\]]*\]|'\w+')",
    re.MULTILINE,
)


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _camel_case(browser_id: str) -> str:
    head, *rest = browser_id.split("_")
    return head + "".join(part.title() for part in rest)


def _is_platform_reference(node: ast.expr) -> bool:
    """True for either `platform` or `sys.platform`; the binding uses both forms."""
    if isinstance(node, ast.Name):
        return node.id == "platform"
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "platform"
        and isinstance(node.value, ast.Name)
        and node.value.id == "sys"
    )


def _guarded_platforms(test: ast.expr) -> frozenset[str]:
    """Resolve one `if platform ...:` guard in the binding onto platform names."""
    if (
        isinstance(test, ast.Compare)
        and _is_platform_reference(test.left)
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.Eq)
        and isinstance(test.comparators[0], ast.Constant)
    ):
        return frozenset({SYS_PLATFORM_IDS[test.comparators[0].value]})
    if (
        isinstance(test, ast.Call)
        and isinstance(test.func, ast.Attribute)
        and test.func.attr == "startswith"
        and _is_platform_reference(test.func.value)
        and isinstance(test.args[0], ast.Constant)
    ):
        return frozenset({SYS_PLATFORM_IDS[test.args[0].value]})
    raise AssertionError(f"unrecognised platform guard at line {test.lineno}")


def _guarded_exports(body: list[ast.stmt]) -> list[str]:
    """Collect every name a guarded block appends to `__all__`."""
    names: list[str] = []
    for node in ast.walk(ast.Module(body=body, type_ignores=[])):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if not isinstance(node.func.value, ast.Name) or node.func.value.id != "__all__":
            continue
        if node.func.attr == "extend":
            names.extend(element.value for element in node.args[0].elts)
        elif node.func.attr == "append":
            names.append(node.args[0].value)
    return names


def _python_export_platforms() -> dict[str, frozenset[str]]:
    """Map every `rookie_cookies` export onto the platforms that define it."""
    module = ast.parse(PYTHON_BINDING_PATH.read_text(encoding="utf-8"))
    exports: dict[str, frozenset[str]] = {}
    for node in module.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "__all__"
            for target in node.targets
        ):
            for element in node.value.elts:
                exports[element.value] = frozenset(ALL_PLATFORMS)
        elif isinstance(node, ast.If):
            platforms = _guarded_platforms(node.test)
            for name in _guarded_exports(node.body):
                # `opera_gx` is re-exported by more than one platform guard.
                exports[name] = exports.get(name, frozenset()) | platforms
    if not exports:
        raise AssertionError(f"no __all__ entries parsed from {PYTHON_BINDING_PATH}")
    return exports


def _node_export_platforms() -> dict[str, frozenset[str]]:
    """Map every `rookie-cookies` export onto the platforms that define it."""
    source = NODE_BINDING_PATH.read_text(encoding="utf-8")
    exports = {
        name: frozenset(ALL_PLATFORMS) for name in NODE_EXPORT_PATTERN.findall(source)
    }
    for match in NODE_PLATFORM_EXPORT_PATTERN.finditer(source):
        tokens = re.findall(r"'(\w+)'", match.group("platforms"))
        exports[match.group("name")] = frozenset(
            SYS_PLATFORM_IDS[token] for token in tokens
        )
    if not exports:
        raise AssertionError(f"no exports parsed from {NODE_BINDING_PATH}")
    return exports


def _doc_title(canonical_id: str, display_name: str) -> str:
    return DOC_BROWSER_TITLES.get(canonical_id, display_name)


def _parse_testing_md_matrix(text: str) -> dict[str, dict[str, str | None]]:
    """Parse the Browser / Linux / macOS / Windows table in docs/testing.md."""
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.startswith("| Browser | Linux | macOS | Windows |"):
            start = index
            break
    if start is None:
        raise AssertionError("docs/testing.md is missing the browser coverage matrix")

    rows: dict[str, dict[str, str | None]] = {}
    for line in lines[start + 2 :]:
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 4:
            raise AssertionError(f"unexpected matrix row: {line!r}")
        title, *platforms = cells
        parsed: dict[str, str | None] = {}
        for platform, cell in zip(
            ("linux", "macos", "windows"), platforms, strict=True
        ):
            if cell not in DOC_LANE_CELLS:
                raise AssertionError(f"unknown lane cell {cell!r} for {title}")
            parsed[platform] = DOC_LANE_CELLS[cell]
        rows[title] = parsed
    return rows


def _registry_platforms(registry: dict) -> dict[str, frozenset[str]]:
    platforms: dict[str, set[str]] = {}
    for platform, browsers in registry["platforms"].items():
        for browser in browsers:
            platforms.setdefault(browser["canonical_id"], set()).add(platform)
    return {browser: frozenset(names) for browser, names in platforms.items()}


def _hosted_platforms(coverage_doc: dict) -> dict[str, frozenset[str]]:
    hosted: dict[str, set[str]] = {}
    for row in coverage_doc["coverage"]:
        if row["lane"] == "nightly_hosted":
            hosted.setdefault(row["browser"], set()).add(row["platform"])
    return {browser: frozenset(names) for browser, names in hosted.items()}


def _expected_lane(platform: str, browser: str) -> str:
    key = (platform, browser)
    if key in NIGHTLY_HOSTED:
        return "nightly_hosted"
    if key in MANUAL:
        return "manual"
    return "release_fixture"


class BrowserCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.coverage_doc = _load_json(COVERAGE_PATH)
        cls.registry = _load_json(REGISTRY_PATH)
        cls.python_exports = _python_export_platforms()
        cls.node_exports = _node_export_platforms()
        cls.registry_platforms = _registry_platforms(cls.registry)
        cls.hosted_platforms = _hosted_platforms(cls.coverage_doc)

    def test_schema_and_lane_docs(self) -> None:
        self.assertEqual(self.coverage_doc["schema_version"], 2)
        self.assertEqual(set(self.coverage_doc["lanes"]), set(KNOWN_LANES))

    def test_depth_profiles_are_complete_and_use_known_levels(self) -> None:
        capabilities = set(self.coverage_doc["depth_capabilities"])
        self.assertEqual(set(self.coverage_doc["depth_levels"]), set(DEPTH_LEVELS))
        self.assertGreaterEqual(len(capabilities), 9)
        used_profiles = {row["depth_profile"] for row in self.coverage_doc["coverage"]}
        self.assertEqual(used_profiles, set(self.coverage_doc["depth_profiles"]))
        for name, profile in self.coverage_doc["depth_profiles"].items():
            self.assertEqual(set(profile), capabilities, name)
            for capability, level in profile.items():
                self.assertIn(level, DEPTH_LEVELS, (name, capability))

    def test_depth_profiles_do_not_overclaim_lane_provenance(self) -> None:
        for row in self.coverage_doc["coverage"]:
            depth = depth_for(row, self.coverage_doc)
            if row["lane"] == "nightly_hosted":
                self.assertNotIn("fixture", set(depth.values()), row)
                self.assertEqual(depth["browser_launch"], "live", row)
            else:
                self.assertNotIn("live", set(depth.values()), row)
                self.assertEqual(depth["browser_launch"], "none", row)

    def test_runner_contract_rejects_unobserved_depth_claims(self) -> None:
        row = next(
            row
            for row in self.coverage_doc["coverage"]
            if row["depth_profile"] == "hosted_chromium"
        )
        declared = depth_for(row, self.coverage_doc)
        observed = {
            capability: level
            for capability, level in declared.items()
            if level != "none"
        }
        assert_observed_depth(row, observed, self.coverage_doc)
        observed.pop("recommended_read")
        with self.assertRaisesRegex(AssertionError, "recommended_read"):
            assert_observed_depth(row, observed, self.coverage_doc)

    def test_every_cookie_context_field_has_an_applicability_classification(
        self,
    ) -> None:
        fields = self.coverage_doc["cookie_context_fields"]
        self.assertEqual(set(fields), set(COOKIE_CONTEXT_FIELDS))
        for field, contract in fields.items():
            self.assertEqual(
                set(contract), {"classification", "engines", "rationale"}, field
            )
            self.assertIn(contract["classification"], CONTEXT_CLASSIFICATIONS, field)
            self.assertTrue(contract["engines"], field)
            self.assertTrue(set(contract["engines"]) <= {"chromium", "gecko"}, field)
            self.assertGreaterEqual(len(contract["rationale"].split()), 8, field)

    def test_private_browsing_is_the_only_non_persistable_context_field(self) -> None:
        fields = self.coverage_doc["cookie_context_fields"]
        non_persistable = {
            field
            for field, contract in fields.items()
            if contract["classification"] == "non_persistable"
        }
        self.assertEqual(non_persistable, {"private_browsing_id"})

    def test_representative_depth_lanes_are_executable_and_complete(self) -> None:
        lanes = self.coverage_doc["representative_depth_lanes"]
        self.assertEqual(
            set(lanes),
            {
                "core_chromium",
                "core_chromium_windows",
                "core_firefox",
                "partition_context",
                "firefox_container",
                "nightly_stress",
                "manual_fixture_capture",
            },
        )
        capabilities = set(self.coverage_doc["depth_capabilities"])
        for name, lane in lanes.items():
            self.assertEqual(
                set(lane),
                {
                    "workflow",
                    "runner",
                    "platforms",
                    "engines",
                    "capabilities",
                    "surfaces",
                },
                name,
            )
            workflow = REPOSITORY_ROOT / lane["workflow"]
            runner = REPOSITORY_ROOT / lane["runner"]
            self.assertTrue(workflow.is_file(), name)
            self.assertTrue(runner.is_file(), name)
            self.assertIn(lane["runner"], workflow.read_text(encoding="utf-8"), name)
            self.assertTrue(set(lane["capabilities"]) <= capabilities, name)
            self.assertTrue(
                set(lane["platforms"]) <= {"linux", "macos", "windows"}, name
            )
            self.assertTrue(set(lane["engines"]) <= {"chromium", "gecko"}, name)
            self.assertTrue(
                set(lane["surfaces"]) <= {"rust", "python", "node", "cli"},
                name,
            )
            self.assertIn(
                "browser_coverage_contract",
                runner.read_text(encoding="utf-8"),
                f"{name} must emit a checked runtime depth receipt",
            )
        for core in ("core_firefox",):
            self.assertEqual(
                set(lanes[core]["platforms"]), {"linux", "macos", "windows"}
            )
            self.assertIn("exact_set", lanes[core]["capabilities"])
            self.assertIn("active_writer", lanes[core]["capabilities"])
            self.assertEqual(
                set(lanes[core]["surfaces"]), {"rust", "python", "node", "cli"}
            )
        self.assertEqual(set(lanes["core_chromium"]["platforms"]), {"linux", "macos"})
        self.assertIn("active_writer", lanes["core_chromium"]["capabilities"])
        self.assertEqual(set(lanes["core_chromium_windows"]["platforms"]), {"windows"})
        self.assertIn(
            "locked_writer_safety",
            lanes["core_chromium_windows"]["capabilities"],
        )
        for core in ("core_chromium", "core_chromium_windows"):
            self.assertIn("exact_set", lanes[core]["capabilities"])
            self.assertEqual(
                set(lanes[core]["surfaces"]), {"rust", "python", "node", "cli"}
            )

    def test_representative_depth_receipt_rejects_missing_capability(self) -> None:
        lane = self.coverage_doc["representative_depth_lanes"]["nightly_stress"]
        with self.assertRaisesRegex(AssertionError, "representative depth mismatch"):
            emit_representative_depth(
                "nightly_stress",
                set(lane["capabilities"]) - {"active_writer"},
                lane["surfaces"],
                self.coverage_doc,
            )

    def test_representative_depth_receipt_is_machine_readable(self) -> None:
        lane = self.coverage_doc["representative_depth_lanes"]["partition_context"]
        output = io.StringIO()
        with redirect_stdout(output):
            emit_representative_depth(
                "partition_context",
                lane["capabilities"],
                lane["surfaces"],
                self.coverage_doc,
            )
        prefix, payload = output.getvalue().strip().split(" ", 1)
        self.assertEqual(prefix, "E2E_DEPTH_RECEIPT")
        receipt = json.loads(payload)
        self.assertEqual(receipt["lane"], "partition_context")
        self.assertEqual(receipt["capabilities"], sorted(lane["capabilities"]))
        self.assertEqual(receipt["surfaces"], sorted(lane["surfaces"]))

    def test_every_registry_cell_has_exactly_one_lane(self) -> None:
        expected = {}
        for platform, browsers in self.registry["platforms"].items():
            for browser in browsers:
                key = (platform, browser["canonical_id"])
                expected[key] = browser["engine"]

        actual = {}
        for row in self.coverage_doc["coverage"]:
            key = (row["platform"], row["browser"])
            self.assertNotIn(key, actual, f"duplicate coverage row for {key}")
            self.assertIn(row["lane"], KNOWN_LANES, key)
            self.assertEqual(row["lane"], _expected_lane(*key), key)
            actual[key] = row["engine"]

        self.assertEqual(set(actual), set(expected))
        for key, engine in expected.items():
            self.assertEqual(actual[key], engine, key)

    def test_hosted_real_browsers_are_on_the_nightly_lane(self) -> None:
        hosted = {
            (row["platform"], row["browser"])
            for row in self.coverage_doc["coverage"]
            if row["lane"] == "nightly_hosted"
        }
        self.assertEqual(hosted, NIGHTLY_HOSTED)

    def test_every_fixture_cell_has_a_concrete_limitation(self) -> None:
        fixtures = {
            f"{row['platform']}/{row['browser']}"
            for row in self.coverage_doc["coverage"]
            if row["lane"] == "release_fixture"
        }
        limitations = self.coverage_doc["fixture_limitations"]
        self.assertEqual(set(limitations), fixtures)
        for cell, reason in limitations.items():
            self.assertIsInstance(reason, str, cell)
            self.assertGreaterEqual(len(reason.split()), 6, cell)

    def test_every_feasible_fixture_cell_requires_exact_corpus_equality(self) -> None:
        for row in self.coverage_doc["coverage"]:
            if row["lane"] != "release_fixture":
                continue
            exact_set = depth_for(row, self.coverage_doc)["exact_set"]
            if row["engine"] in {"chromium", "gecko"}:
                self.assertEqual(exact_set, "fixture", row)
            else:
                self.assertEqual(row["browser"], "internet_explorer", row)
                self.assertEqual(exact_set, "none", row)

    def test_every_registry_browser_declares_or_excuses_a_convenience_function(
        self,
    ) -> None:
        declared = set(self.coverage_doc["convenience_functions"])
        excused = set(self.coverage_doc["convenience_function_exceptions"])
        self.assertEqual(declared & excused, set())
        self.assertEqual(declared | excused, set(self.registry_platforms))

    def test_convenience_function_entries_are_well_formed(self) -> None:
        entries = self.coverage_doc["convenience_functions"]
        seen_aliases: dict[str, str] = {}
        for browser_id, entry in entries.items():
            self.assertEqual(set(entry), set(CONVENIENCE_ENTRY_KEYS), browser_id)
            self.assertIn(entry["dispatch"], CONVENIENCE_DISPATCHES, browser_id)
            self.assertTrue(entry["platforms"], browser_id)
            self.assertEqual(
                entry["platforms"], sorted(set(entry["platforms"])), browser_id
            )
            self.assertTrue(set(entry["platforms"]) <= ALL_PLATFORMS, browser_id)
            for alias in entry["aliases"]:
                self.assertEqual(alias, alias.lower(), (browser_id, alias))
                self.assertNotIn(alias, entries, (browser_id, alias))
                self.assertNotIn(alias, seen_aliases, (browser_id, alias))
                seen_aliases[alias] = browser_id

    def test_convenience_function_platforms_match_binding_gating(self) -> None:
        for browser_id, entry in self.coverage_doc["convenience_functions"].items():
            registry = self.registry_platforms[browser_id]
            self.assertIn(entry["python"], self.python_exports, browser_id)
            self.assertIn(entry["node"], self.node_exports, browser_id)
            self.assertEqual(entry["node"], _camel_case(entry["python"]), browser_id)
            self.assertEqual(
                set(entry["platforms"]),
                self.python_exports[entry["python"]] & registry,
                f"{browser_id} Python gating",
            )
            self.assertEqual(
                set(entry["platforms"]),
                self.node_exports[entry["node"]] & registry,
                f"{browser_id} Node gating",
            )

    def test_every_declared_convenience_function_has_a_hosted_lane(self) -> None:
        for browser_id, entry in self.coverage_doc["convenience_functions"].items():
            self.assertEqual(
                set(entry["platforms"]),
                self.hosted_platforms.get(browser_id, frozenset()),
                f"{browser_id} must be launched on exactly its declared platforms",
            )

    def test_convenience_function_exceptions_document_a_concrete_reason(self) -> None:
        exceptions = self.coverage_doc["convenience_function_exceptions"]
        for browser_id, reason in exceptions.items():
            self.assertIsInstance(reason, str, browser_id)
            self.assertGreaterEqual(len(reason.split()), 6, browser_id)

    def test_convenience_function_exceptions_have_no_hosted_binding_export(
        self,
    ) -> None:
        for browser_id in self.coverage_doc["convenience_function_exceptions"]:
            registry = self.registry_platforms[browser_id]
            exported = (
                self.python_exports.get(browser_id, frozenset())
                | self.node_exports.get(_camel_case(browser_id), frozenset())
            ) & registry
            hosted = self.hosted_platforms.get(browser_id, frozenset())
            self.assertEqual(
                exported & hosted,
                frozenset(),
                f"{browser_id} exposes a convenience function on a hosted platform "
                "and must move into convenience_functions",
            )

    def test_convenience_dispatch_resolves_aliases_and_rejects_unknown_browsers(
        self,
    ) -> None:
        resolved = convenience_function(
            "google-chrome", "chromium", self.coverage_doc, platform="linux"
        )
        self.assertEqual(resolved["browser_id"], "chrome")
        self.assertEqual(resolved["python"], "chrome")
        self.assertEqual(resolved["node"], "chrome")
        with self.assertRaisesRegex(AssertionError, "no convenience function is"):
            convenience_function(
                "yandex", "chromium", self.coverage_doc, platform="linux"
            )
        with self.assertRaisesRegex(AssertionError, "dispatch family"):
            convenience_function(
                "firefox", "chromium", self.coverage_doc, platform="linux"
            )
        with self.assertRaisesRegex(AssertionError, "no convenience function on linux"):
            convenience_function(
                "safari", "native", self.coverage_doc, platform="linux"
            )

    def test_assert_scripts_dispatch_convenience_functions_from_the_contract(
        self,
    ) -> None:
        harness = Path(__file__).parent
        scripts = {
            "assert_chrome_cookie.py": "browser_coverage_contract",
            "assert_firefox_cookie.py": "browser_coverage_contract",
            "assert_chrome_cookie.mjs": "browser_coverage_contract.mjs",
            "assert_firefox_cookie.mjs": "browser_coverage_contract.mjs",
        }
        for name, module in scripts.items():
            source = (harness / name).read_text(encoding="utf-8")
            self.assertIn(module, source, name)
            self.assertIn("ROOKIE_E2E_CHECK_BROWSER_DISCOVERY", source, name)
            self.assertIn("ROOKIE_E2E_TARGET_BROWSER", source, name)
            self.assertNotIn("browser_fns", source, name)
            self.assertNotIn("browserFns", source, name)

    def test_claimed_runner_scopes_browser_discovery_to_the_binding_subprocesses(
        self,
    ) -> None:
        # The discovery flags must never reach the `cargo test` environment.
        # `rookie-rs/tests/e2e_chrome.rs:638` reads the same two variables and
        # matches the target browser against its own hardcoded arm list, so
        # hoisting them onto the shared env dict panics the Rust surface for
        # any claimed browser outside that list.
        source = CLAIMED_RUNNER_PATH.read_text(encoding="utf-8")
        module = ast.parse(source)
        written: set[tuple[str, str]] = set()
        for node in ast.walk(module):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if (
                    isinstance(target, ast.Subscript)
                    and isinstance(target.value, ast.Name)
                    and isinstance(target.slice, ast.Constant)
                    and target.slice.value in DISCOVERY_ENV_KEYS
                ):
                    written.add((target.value.id, target.slice.value))
        self.assertEqual({key for _, key in written}, set(DISCOVERY_ENV_KEYS))
        self.assertEqual(
            {name for name, _ in written},
            {"discovery"},
            "the discovery flags may only be written to a copied env dict, "
            "never to the env handed to cargo test",
        )

        functions = {
            node.name: node for node in module.body if isinstance(node, ast.FunctionDef)
        }
        lanes = (
            (
                "assert_chromium",
                "chromium",
                ("assert_chrome_cookie.py", "assert_chrome_cookie.mjs"),
            ),
            (
                "assert_gecko",
                "gecko",
                ("assert_firefox_cookie.py", "assert_firefox_cookie.mjs"),
            ),
        )
        for name, dispatch, scripts in lanes:
            function = functions[name]
            self.assertIn(
                f'binding_discovery_environment(env, browser_id, "{dispatch}")',
                ast.get_source_segment(source, function),
                name,
            )
            handed: dict[str, str] = {}
            for call in ast.walk(function):
                if not isinstance(call, ast.Call) or not call.args:
                    continue
                if not (
                    isinstance(call.func, ast.Attribute) and call.func.attr == "run"
                ):
                    continue
                environment = next(
                    (
                        keyword.value.id
                        for keyword in call.keywords
                        if keyword.arg == "env" and isinstance(keyword.value, ast.Name)
                    ),
                    None,
                )
                command = ast.get_source_segment(source, call.args[0])
                if '"cargo"' in command:
                    handed["cargo"] = environment
                for script in scripts:
                    if script in command:
                        handed[script] = environment
            self.assertEqual(handed.get("cargo"), "env", f"{name} cargo invocation")
            for script in scripts:
                self.assertEqual(handed.get(script), "discovery", f"{name} {script}")

    def test_testing_md_matrix_matches_coverage(self) -> None:
        titles: dict[str, str] = {}
        for browsers in self.registry["platforms"].values():
            for browser in browsers:
                titles[browser["canonical_id"]] = _doc_title(
                    browser["canonical_id"], browser["display_name"]
                )

        expected: dict[str, dict[str, str | None]] = {
            title: {"linux": None, "macos": None, "windows": None}
            for title in titles.values()
        }
        for row in self.coverage_doc["coverage"]:
            expected[titles[row["browser"]]][row["platform"]] = row["lane"]

        actual = _parse_testing_md_matrix(TESTING_MD_PATH.read_text(encoding="utf-8"))
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
