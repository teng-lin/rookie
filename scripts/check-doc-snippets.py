#!/usr/bin/env python3
"""Assert fenced code samples in user docs only reference shipped public exports.

Parses README.md, docs/{python,javascript,rust}.md, and the PyPI/npm
binding READMEs, extracts fenced samples,
and checks that call-site symbols exist in:

* bindings/python/rookie_cookies/__init__.py (__all__) and rookie_cookies.pyi
* bindings/node/index.d.ts
* rookie-rs/src/lib.rs (+ read.rs / direct_path public surface)

Invented top-level APIs (e.g. a binding ``header()``, crate-root ``get``) fail
the check. Run from the repository root or any cwd; paths are repo-relative.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]

DOC_FILES = (
    REPO / "README.md",
    REPO / "docs" / "python.md",
    REPO / "docs" / "javascript.md",
    REPO / "docs" / "rust.md",
    REPO / "bindings" / "python" / "README.md",
    REPO / "bindings" / "node" / "README.md",
)

FENCE_RE = re.compile(
    r"^```([a-zA-Z0-9_+-]*)[^\n]*\n(.*?)(?:^```)",
    re.MULTILINE | re.DOTALL,
)

# Console / shell fences are ignored for symbol extraction.
IGNORE_LANGS = {
    "",
    "console",
    "shell",
    "bash",
    "sh",
    "text",
    "toml",
    "json",
    "diff",
}

PYTHON_LANGS = {"python", "py"}
JS_LANGS = {"js", "javascript", "mjs", "cjs", "ts", "typescript"}
RUST_LANGS = {"rust", "rs"}

# Names that look like library calls but are stdlib / host APIs in samples.
PYTHON_ALLOW_UNQUALIFIED = {
    "print",
    "len",
    "list",
    "next",
    "zip",
    "set",
    "isinstance",
    "hasattr",
    "Exception",
    "RuntimeError",
    "ValueError",
    "TypeError",
    "Session",
    "Timer",
    "basicConfig",
    "getLogger",
}

# Method / attribute names on returned objects — not package exports.
INSTANCE_METHODS = {
    "as_list",
    "as_jar",
    "header",
    "cookies",
    "warnings",
    "into_cookies",
    "cancel",
    "is_cancelled",
    "isCancelled",
    "browserId",
    "profileId",
    "browser_id",
    "profile_id",
    "code",
    "count",
    "message",
    "domains",
    "credentials",
    "timeout",
    "cancellation",
    "profile",
    "include_expired",
    "new",
    "clone",
    "sleep",
    "spawn",
    "unwrap",
    "len",
    "status",
    "first",
    "kind",
}

FORBIDDEN_TOP_LEVEL = {
    "python": {"header"},  # only ReadResult.header
    "javascript": {"header"},
    "rust": {"get", "report"},  # no crate-root get/report (ADR 0004)
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo",
        type=Path,
        default=REPO,
        help="Repository root (default: parent of scripts/)",
    )
    return parser.parse_args()


def extract_fences(text: str) -> list[tuple[str, str]]:
    return [(lang.lower(), body) for lang, body in FENCE_RE.findall(text)]


def load_python_exports(repo: Path) -> set[str]:
    init_path = repo / "bindings" / "python" / "rookie_cookies" / "__init__.py"
    pyi_path = repo / "bindings" / "python" / "rookie_cookies" / "rookie_cookies.pyi"
    exports: set[str] = set()

    init_tree = ast.parse(init_path.read_text(encoding="utf-8"), filename=str(init_path))
    for node in init_tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    value = ast.literal_eval(node.value)
                    if not isinstance(value, list):
                        raise ValueError("__all__ must be a list literal")
                    exports.update(str(item) for item in value)

    # Platform-conditional names from the stub.
    pyi_text = pyi_path.read_text(encoding="utf-8")
    for match in re.finditer(r"^def ([A-Za-z_][A-Za-z0-9_]*)\(", pyi_text, re.MULTILINE):
        exports.add(match.group(1))
    for match in re.finditer(r"^class ([A-Za-z_][A-Za-z0-9_]*)\b", pyi_text, re.MULTILINE):
        exports.add(match.group(1))

    exports.update({"dto", "MAX_ISSUE_SAMPLES", "ChromiumPathOptions"})
    return exports


def load_node_exports(repo: Path) -> set[str]:
    dts = (repo / "bindings" / "node" / "index.d.ts").read_text(encoding="utf-8")
    exports: set[str] = set()
    for match in re.finditer(
        r"^export declare (?:function|class) ([A-Za-z_][A-Za-z0-9_]*)\b",
        dts,
        re.MULTILINE,
    ):
        exports.add(match.group(1))
    for match in re.finditer(
        r"^export (?:interface|type) ([A-Za-z_][A-Za-z0-9_]*)\b",
        dts,
        re.MULTILINE,
    ):
        exports.add(match.group(1))
    return exports


def load_rust_exports(repo: Path) -> set[str]:
    """Collect crate-root and commonly documented path/module names."""
    lib = (repo / "rookie-rs" / "src" / "lib.rs").read_text(encoding="utf-8")
    read_rs = (repo / "rookie-rs" / "src" / "read.rs").read_text(encoding="utf-8")
    direct = (repo / "rookie-rs" / "src" / "direct_path" / "mod.rs").read_text(
        encoding="utf-8"
    )
    exports: set[str] = set()

    for text in (lib, read_rs, direct):
        for match in re.finditer(
            r"^pub (?:fn|struct|enum|type|trait) ([A-Za-z_][A-Za-z0-9_]*)\b",
            text,
            re.MULTILINE,
        ):
            exports.add(match.group(1))
        for match in re.finditer(
            r"^pub use [A-Za-z0-9_:]+::\{([^}]+)\}",
            text,
            re.MULTILINE,
        ):
            for part in match.group(1).split(","):
                name = part.strip().split(" as ")[-1].strip()
                if name:
                    exports.add(name)
        for match in re.finditer(
            r"^pub use [A-Za-z0-9_:]+::([A-Za-z_][A-Za-z0-9_]*)\s*;",
            text,
            re.MULTILINE,
        ):
            exports.add(match.group(1))

    # Modules re-exported / documented at the crate root.
    exports.update(
        {
            "direct_path",
            "report",
            "common",
            "config",
            "enums",
            "Result",
            "Cookie",
            "anyhow",
        }
    )
    # Nested direct_path items referenced as direct_path::X in docs.
    for match in re.finditer(
        r"^pub (?:fn|struct|enum|type) ([A-Za-z_][A-Za-z0-9_]*)\b",
        direct,
        re.MULTILINE,
    ):
        exports.add(match.group(1))
    return exports


def python_symbols_from_snippet(body: str) -> set[str]:
    symbols: set[str] = set()
    # from rookie_cookies import a, b
    for match in re.finditer(
        r"from\s+rookie_cookies\s+import\s+\(?([^)\n]+)\)?",
        body,
    ):
        for part in match.group(1).split(","):
            name = part.strip().split(" as ")[0].strip()
            if name and name != "*":
                symbols.add(name)
    # import rookie_cookies as cookies / import rookie_cookies
    aliases = {"rookie_cookies"}
    for match in re.finditer(
        r"import\s+rookie_cookies(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?",
        body,
    ):
        if match.group(1):
            aliases.add(match.group(1))
    alias_re = "|".join(re.escape(a) for a in sorted(aliases, key=len, reverse=True))
    for match in re.finditer(
        rf"(?:{alias_re})\.([A-Za-z_][A-Za-z0-9_]*)",
        body,
    ):
        symbols.add(match.group(1))
    return symbols


def js_symbols_from_snippet(body: str) -> set[str]:
    symbols: set[str] = set()
    # import { a, b as c } from "rookie-cookies"
    for match in re.finditer(
        r"import\s+\{([^}]+)\}\s+from\s+[\"']rookie-cookies[\"']",
        body,
    ):
        for part in match.group(1).split(","):
            name = part.strip().split(" as ")[0].strip()
            if name:
                symbols.add(name)
    # import pkg from "rookie-cookies" then pkg.brave()
    for match in re.finditer(
        r"import\s+([A-Za-z_][A-Za-z0-9_]*)\s+from\s+[\"']rookie-cookies[\"']",
        body,
    ):
        alias = match.group(1)
        for call in re.finditer(
            rf"{re.escape(alias)}\.([A-Za-z_][A-Za-z0-9_]*)",
            body,
        ):
            symbols.add(call.group(1))
    # new CancellationHandle — already covered if imported
    return symbols


def rust_symbols_from_snippet(body: str) -> set[str]:
    symbols: set[str] = set()
    # use rookie_cookies::{a, b}
    for match in re.finditer(
        r"use\s+rookie_cookies::\{([^}]+)\}",
        body,
    ):
        for part in match.group(1).split(","):
            name = part.strip().split(" as ")[-1].strip()
            if name:
                symbols.add(name)
    # use rookie_cookies::direct_path::{...}
    for match in re.finditer(
        r"use\s+rookie_cookies::direct_path::\{([^}]+)\}",
        body,
    ):
        symbols.add("direct_path")
        for part in match.group(1).split(","):
            name = part.strip().split(" as ")[-1].strip()
            if name:
                symbols.add(name)
    # use rookie_cookies; / use rookie_cookies::X;
    for match in re.finditer(
        r"use\s+rookie_cookies::([A-Za-z_][A-Za-z0-9_]*)\s*;",
        body,
    ):
        symbols.add(match.group(1))
    # rookie_cookies::X / rookie_cookies::direct_path::Y
    for match in re.finditer(
        r"rookie_cookies::(?:direct_path::)?([A-Za-z_][A-Za-z0-9_]*)",
        body,
    ):
        symbols.add(match.group(1))
    # Bare constructors brought into scope: ReadRequest::browser, Request::browser
    for match in re.finditer(
        r"\b([A-Z][A-Za-z0-9_]*)::",
        body,
    ):
        name = match.group(1)
        if name not in {"Some", "None", "Ok", "Err", "Duration", "PathBuf", "Vec", "String"}:
            symbols.add(name)
    # Free functions brought into scope via use: read(, extract(, browser(
    # Only count those that appear after a use import of the same name, or
    # qualified calls already handled. Bare `read(` after `use …::{read,…}`.
    return symbols


def check_forbidden(lang_key: str, symbols: set[str], path: Path, body: str) -> list[str]:
    errors: list[str] = []
    forbidden = FORBIDDEN_TOP_LEVEL.get(lang_key, set())
    for name in sorted(symbols & forbidden):
        # Allow instance-style documentation of .header( — only fail if imported
        # or called as a top-level binding.
        if name == "header":
            if re.search(
                r"(?:from\s+rookie_cookies\s+import\s+[^\n]*\bheader\b|"
                r"import\s*\{[^}]*\bheader\b[^}]*\}\s*from\s*[\"']rookie-cookies[\"']|"
                r"(?<![\w.])header\s*\()",
                body,
            ):
                errors.append(
                    f"{path}: forbids top-level {lang_key} export `header` "
                    f"(use ReadResult.header)"
                )
            continue
        if name in symbols:
            errors.append(
                f"{path}: forbids crate/binding-root `{name}` in {lang_key} samples "
                f"(ADR 0004)"
            )
    return errors


def main() -> int:
    args = parse_args()
    repo = args.repo.resolve()

    python_exports = load_python_exports(repo)
    node_exports = load_node_exports(repo)
    rust_exports = load_rust_exports(repo)

    errors: list[str] = []
    checked_fences = 0

    for doc_path in (
        repo / "README.md",
        repo / "docs" / "python.md",
        repo / "docs" / "javascript.md",
        repo / "docs" / "rust.md",
        repo / "bindings" / "python" / "README.md",
        repo / "bindings" / "node" / "README.md",
    ):
        if not doc_path.is_file():
            errors.append(f"missing documentation file: {doc_path}")
            continue
        text = doc_path.read_text(encoding="utf-8")
        for lang, body in extract_fences(text):
            if lang in IGNORE_LANGS:
                continue
            if lang in PYTHON_LANGS:
                checked_fences += 1
                symbols = python_symbols_from_snippet(body)
                missing = sorted(
                    s
                    for s in symbols
                    if s not in python_exports and s not in INSTANCE_METHODS
                )
                for name in missing:
                    errors.append(
                        f"{doc_path.relative_to(repo)}: python sample references "
                        f"`{name}` which is not a shipped Python export"
                    )
                errors.extend(check_forbidden("python", symbols, doc_path.relative_to(repo), body))
            elif lang in JS_LANGS:
                checked_fences += 1
                symbols = js_symbols_from_snippet(body)
                missing = sorted(
                    s
                    for s in symbols
                    if s not in node_exports and s not in INSTANCE_METHODS
                )
                for name in missing:
                    errors.append(
                        f"{doc_path.relative_to(repo)}: javascript sample references "
                        f"`{name}` which is not a shipped Node export"
                    )
                errors.extend(
                    check_forbidden("javascript", symbols, doc_path.relative_to(repo), body)
                )
            elif lang in RUST_LANGS:
                checked_fences += 1
                symbols = rust_symbols_from_snippet(body)
                missing = sorted(
                    s
                    for s in symbols
                    if s not in rust_exports and s not in INSTANCE_METHODS
                )
                for name in missing:
                    errors.append(
                        f"{doc_path.relative_to(repo)}: rust sample references "
                        f"`{name}` which is not a shipped Rust public item"
                    )
                errors.extend(check_forbidden("rust", symbols, doc_path.relative_to(repo), body))
            else:
                # Unknown fence language in user docs — ignore quietly.
                continue

    if checked_fences < 6:
        errors.append(
            f"expected at least 6 language code fences across user docs, found {checked_fences}"
        )

    # Structural section requirements for language docs.
    required_headings = (
        (repo / "docs" / "python.md", ("Recommended 0.6.0", "0.5.6 API", "Migrate 0.5.6")),
        (repo / "docs" / "javascript.md", ("Recommended 0.6.0", "0.5.6 API", "Migrate 0.5.6")),
        (repo / "docs" / "rust.md", ("Recommended 0.6.0", "0.5.6 API", "Migrate 0.5.6")),
    )
    for path, needles in required_headings:
        text = path.read_text(encoding="utf-8")
        for needle in needles:
            if needle not in text:
                errors.append(f"{path.relative_to(repo)}: missing required section text `{needle}`")

    if errors:
        print("check-doc-snippets: FAILED", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(
        f"check-doc-snippets: ok ({checked_fences} language fences; "
        f"python={len(python_exports)} node={len(node_exports)} rust={len(rust_exports)} exports)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
