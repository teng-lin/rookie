"""Drive scripts/check-doc-snippets.py against the shipped docs and public stubs."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPOSITORY_ROOT / "scripts" / "check-doc-snippets.py"


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_doc_snippets", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class CheckDocSnippetsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.checker = _load_checker()

    def test_script_passes_on_repository_docs(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--repo", str(REPOSITORY_ROOT)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            result.returncode,
            0,
            msg=f"stdout={result.stdout!r}\nstderr={result.stderr!r}",
        )
        self.assertIn("check-doc-snippets: ok", result.stdout)

    def test_invented_python_export_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._seed_minimal_surfaces(root)
            (root / "README.md").write_text(
                "# demo\n\n```python\nimport rookie_cookies\n"
                "rookie_cookies.not_a_real_export()\n```\n",
                encoding="utf-8",
            )
            (root / "rookie-rs" / "README.md").write_text(
                "# rust\n\n## Recommended usage (0.6 series)\n\n"
                "## 0.5.6 API\n\n## Migrate 0.5.6 → 0.6.0\n\n"
                "```rust\nfn main() { let _ = rookie_cookies::chrome(None); }\n```\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--repo", str(root)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not_a_real_export", result.stderr)

    def test_top_level_header_import_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._seed_minimal_surfaces(root)
            (root / "README.md").write_text("# demo\n", encoding="utf-8")
            (root / "bindings" / "python" / "README.md").write_text(
                "## Recommended usage (0.6 series)\n## 0.5.6 API\n## Migrate 0.5.6\n\n"
                "```python\nfrom rookie_cookies import header\nheader('https://x')\n```\n",
                encoding="utf-8",
            )
            (root / "bindings" / "node" / "README.md").write_text(
                "## Recommended usage (0.6 series)\n## 0.5.6 API\n## Migrate 0.5.6\n\n"
                "```js\nimport { chrome } from \"rookie-cookies\";\nawait chrome();\n```\n",
                encoding="utf-8",
            )
            (root / "rookie-rs" / "README.md").write_text(
                "## Recommended usage (0.6 series)\n## 0.5.6 API\n## Migrate 0.5.6\n\n"
                "```rust\nfn main() { let _ = rookie_cookies::chrome(None); }\n```\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--repo", str(root)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("header", result.stderr)

    def test_multiline_python_import_of_missing_export_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._seed_minimal_surfaces(root)
            (root / "bindings" / "python" / "README.md").write_text(
                "## Recommended usage (0.6 series)\n## 0.5.6 API\n## Migrate 0.5.6\n\n"
                "```python\nfrom rookie_cookies import (\n    chrome,\n"
                "    not_a_real_export,\n)\n```\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--repo", str(root)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not_a_real_export", result.stderr)

    def test_invented_node_export_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._seed_minimal_surfaces(root)
            (root / "bindings" / "node" / "README.md").write_text(
                "## Recommended usage (0.6 series)\n## 0.5.6 API\n## Migrate 0.5.6\n\n"
                "```js\nimport { notARealExport } from \"rookie-cookies\";\n"
                "await notARealExport();\n```\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--repo", str(root)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("notARealExport", result.stderr)

    def test_invented_rust_export_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._seed_minimal_surfaces(root)
            (root / "rookie-rs" / "README.md").write_text(
                "## Recommended usage (0.6 series)\n## 0.5.6 API\n## Migrate 0.5.6\n\n"
                "```rust\nfn main() { let _ = rookie_cookies::not_a_real_export(); }\n```\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--repo", str(root)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not_a_real_export", result.stderr)

    def test_rust_report_module_path_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._seed_minimal_surfaces(root)
            (root / "rookie-rs" / "README.md").write_text(
                "## Recommended usage (0.6 series)\n## 0.5.6 API\n## Migrate 0.5.6\n\n"
                "```rust\nuse rookie_cookies::report;\n"
                "fn main() { let _ = rookie_cookies::chrome(None); }\n```\n",
                encoding="utf-8",
            )
            (root / "rookie-rs" / "src" / "lib.rs").write_text(
                "pub fn chrome() {}\npub fn read() {}\npub struct ReadRequest;\n"
                "pub mod report;\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--repo", str(root)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                result.returncode,
                0,
                msg=f"stdout={result.stdout!r}\nstderr={result.stderr!r}",
            )

    def test_rust_crate_root_report_call_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._seed_minimal_surfaces(root)
            (root / "rookie-rs" / "README.md").write_text(
                "## Recommended usage (0.6 series)\n## 0.5.6 API\n## Migrate 0.5.6\n\n"
                "```rust\nfn main() { let _ = rookie_cookies::report(\"chrome\"); }\n```\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--repo", str(root)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("report", result.stderr)

    def test_python_export_loader_sees_jar_and_read(self) -> None:
        exports = self.checker.load_python_exports(REPOSITORY_ROOT)
        self.assertIn("jar", exports)
        self.assertIn("read", exports)
        self.assertIn("chrome", exports)
        self.assertNotIn("header", exports)

    def test_node_export_loader_sees_read_and_jar_not_top_level_header(self) -> None:
        exports = self.checker.load_node_exports(REPOSITORY_ROOT)
        self.assertIn("read", exports)
        self.assertIn("jar", exports)
        self.assertIn("chrome", exports)
        self.assertIn("ReadResult", exports)
        self.assertNotIn("header", exports)

    def test_rust_export_loader_sees_read_jar_request(self) -> None:
        exports = self.checker.load_rust_exports(REPOSITORY_ROOT)
        self.assertIn("read", exports)
        self.assertIn("jar", exports)
        self.assertIn("ReadRequest", exports)
        self.assertIn("browser", exports)
        # A `direct_path` re-export, to prove the loader walks the submodule
        # and not just the crate root. `cookies_from_path` was this symbol
        # until 0.6.0 collapsed the three path functions into one.
        self.assertIn("extract_from_path", exports)

    def _seed_minimal_surfaces(self, root: Path) -> None:
        py = root / "bindings" / "python" / "rookie_cookies"
        py.mkdir(parents=True)
        (py / "__init__.py").write_text(
            '__all__ = ["chrome", "jar", "read", "firefox", "brave", "load", "to_cookiejar"]\n',
            encoding="utf-8",
        )
        (py / "rookie_cookies.pyi").write_text(
            "def chrome(): ...\ndef jar(): ...\ndef read(): ...\n"
            "def firefox(): ...\ndef brave(): ...\ndef load(): ...\n"
            "def to_cookiejar(): ...\n",
            encoding="utf-8",
        )
        node = root / "bindings" / "node"
        node.mkdir(parents=True)
        (node / "index.d.ts").write_text(
            "export declare function chrome(): Promise<unknown>\n"
            "export declare function read(): Promise<unknown>\n"
            "export declare function jar(): Promise<unknown>\n"
            "export declare function brave(): Promise<unknown>\n"
            "export declare function load(): Promise<unknown>\n"
            "export declare class ReadResult {}\n"
            "export declare class CancellationHandle {}\n",
            encoding="utf-8",
        )
        rust = root / "rookie-rs" / "src"
        rust.mkdir(parents=True)
        (rust / "lib.rs").write_text(
            "pub fn chrome() {}\npub fn brave() {}\npub fn browser() {}\n"
            "pub fn read() {}\npub fn jar() {}\npub struct ReadRequest;\n",
            encoding="utf-8",
        )
        (rust / "read.rs").write_text(
            "pub struct ReadRequest;\npub struct ReadResult;\npub fn read() {}\n"
            "pub fn jar() {}\n",
            encoding="utf-8",
        )
        (rust / "direct_path").mkdir()
        (rust / "direct_path" / "mod.rs").write_text(
            "pub fn cookies_from_path() {}\n"
            "pub struct DirectPathRequest;\n"
            "pub struct ChromiumPathRequest;\n"
            "pub enum ChromiumCredentialSource {}\n",
            encoding="utf-8",
        )
        (root / "README.md").write_text(
            "# demo\n\n"
            "```python\nimport rookie_cookies\nrookie_cookies.chrome()\n```\n\n"
            "```js\nimport { chrome } from \"rookie-cookies\";\nawait chrome();\n```\n\n"
            "```rust\nfn main() { let _ = rookie_cookies::chrome(None); }\n```\n",
            encoding="utf-8",
        )
        (root / "docs").mkdir()
        (root / "rookie-rs" / "README.md").write_text(
            "## Recommended usage (0.6 series)\n## 0.5.6 API\n## Migrate 0.5.6\n\n"
            "```rust\nfn main() { let _ = rookie_cookies::chrome(None); }\n```\n",
            encoding="utf-8",
        )
        (root / "bindings" / "python" / "README.md").write_text(
            "## Recommended usage (0.6 series)\n## 0.5.6 API\n## Migrate 0.5.6\n\n"
            "```python\nimport rookie_cookies\nx = rookie_cookies.chrome()\n```\n",
            encoding="utf-8",
        )
        (root / "bindings" / "node" / "README.md").write_text(
            "## Recommended usage (0.6 series)\n## 0.5.6 API\n## Migrate 0.5.6\n\n"
            "```js\nimport { chrome } from \"rookie-cookies\";\nawait chrome();\n```\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    unittest.main()
