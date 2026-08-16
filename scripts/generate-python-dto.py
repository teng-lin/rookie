#!/usr/bin/env python3
"""Generates typed dataclasses for the Python binding from the DTO schema.

`schema/report-dto.schema.json` is generated from `report_core.rs`'s
canonical Rust types (`cargo run --bin generate-dto-schema --features
dto-schema` in `rookie-rs/` -- see `schema/README.md`) -- this script is
downstream of that, not a second source of truth: it turns
the schema into `bindings/python/rookie_cookies/dto.py`, checked in like the
schema itself, matching this project's `browser_registry.json` ->
`patch-loader.js` precedent (JSON source of truth, generate at dev time
rather than at import time).

Every dataclass is additive alongside the existing dict-returning API --
see `rookie_cookies/__init__.py` and `bindings/python/src/report.rs`'s
`*_dict` adapters, which stay the primary return path. `dto.py` gives a
caller who wants static typing a parallel typed view of the same data.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCHEMA = ROOT / "schema" / "report-dto.schema.json"
DEFAULT_OUTPUT = ROOT / "bindings" / "python" / "rookie_cookies" / "dto.py"

HEADER = '''"""Typed dataclasses generated from schema/report-dto.schema.json.

Do not hand-edit -- regenerate with `python3 scripts/generate-python-dto.py`
after `schema/report-dto.schema.json` changes (see `schema/README.md`). See
that script's module docstring for why this exists alongside the
dict-returning API rather than instead of it.

Every open string identifier (browser/engine/cipher-tier/issue-code/...) is
typed as a plain `str`, matching the schema: a value this build has never
seen is still representable, exactly like the Rust source it is generated
from -- see `report_core.rs`'s module docs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional
'''


def python_repr(value: Any) -> str:
    if value is None:
        return "None"
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, (int, float, str)):
        return repr(value)
    raise ValueError(f"unsupported default value: {value!r}")


def scalar_type(schema: dict[str, Any]) -> str:
    if "$ref" in schema:
        return schema["$ref"].rsplit("/", 1)[-1]
    schema_type = schema.get("type", "string")
    types = schema_type if isinstance(schema_type, list) else [schema_type]
    non_null = [t for t in types if t != "null"]
    primitive = non_null[0] if non_null else "string"
    if primitive == "array":
        return f"List[{scalar_type(schema['items'])}]"
    return {
        "string": "str",
        "integer": "int",
        "number": "float",
        "boolean": "bool",
    }[primitive]


def is_nullable(schema: dict[str, Any]) -> bool:
    schema_type = schema.get("type")
    return isinstance(schema_type, list) and "null" in schema_type


def render_field(name: str, schema: dict[str, Any], required: bool) -> str:
    python_type = scalar_type(schema)
    nullable = is_nullable(schema)
    if nullable:
        python_type = f"Optional[{python_type}]"

    if required and not nullable:
        return f"    {name}: {python_type}"
    if "default" in schema:
        return f"    {name}: {python_type} = {python_repr(schema['default'])}"
    # Not required and no explicit default: schemars omits `default` for
    # `Option<T>` fields that plainly default to `None` (see report_core.rs's
    # `ExtractionIssue.browser_id` and friends), so this is the same case.
    return f"    {name}: {python_type} = None"


def field_from_dict_expr(field_name: str, schema: dict[str, Any], required: bool) -> str:
    """The expression that reads and converts one field out of a raw dict.

    Mirrors the dict shape `bindings/python/src/report.rs`'s `*_dict`
    adapters already produce -- this is the reverse direction, dict in,
    typed dataclass out, so a caller can convert the existing return value
    without this package's Rust extension needing to change at all.
    """
    if required:
        source = f"data[{field_name!r}]"
    else:
        default = python_repr(schema["default"]) if "default" in schema else "None"
        source = f"data.get({field_name!r}, {default})"

    if "$ref" in schema:
        ref_type = schema["$ref"].rsplit("/", 1)[-1]
        return f"{ref_type}.from_dict({source})"
    items = schema.get("items")
    if schema.get("type") == "array" and items and "$ref" in items:
        ref_type = items["$ref"].rsplit("/", 1)[-1]
        return f"[{ref_type}.from_dict(item) for item in {source}]"
    return source


def render_class(name: str, schema: dict[str, Any]) -> str:
    required = set(schema.get("required", []))
    properties: dict[str, Any] = schema.get("properties", {})

    # Dataclass fields without a default must precede fields with one.
    ordered = sorted(
        properties.items(),
        key=lambda item: (item[0] in required) is False,
    )

    lines = ["@dataclass", f"class {name}:"]
    description = schema.get("description")
    if description:
        doc = description.replace('"""', "'''")
        lines.append(f'    """{doc}"""')
    if not properties:
        lines.append("    pass")
    else:
        for field_name, field_schema in ordered:
            lines.append(render_field(field_name, field_schema, field_name in required))

    lines.append("")
    lines.append("    @classmethod")
    lines.append(f"    def from_dict(cls, data: dict) -> {name}:")
    lines.append(
        '        """Converts one of this package\'s existing dict-shaped returns '
        "(e.g. from `browser_report`) into this typed dataclass.\"\"\""
    )
    if not properties:
        lines.append("        return cls()")
    else:
        lines.append("        return cls(")
        for field_name, field_schema in properties.items():
            expr = field_from_dict_expr(field_name, field_schema, field_name in required)
            lines.append(f"            {field_name}={expr},")
        lines.append("        )")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    document = json.loads(args.schema.read_text(encoding="utf-8"))
    definitions: dict[str, Any] = document["definitions"]

    classes = [render_class(name, schema) for name, schema in definitions.items()]
    all_names = ", ".join(f'"{name}"' for name in definitions)

    rendered = (
        HEADER
        + f"\n__all__ = [{all_names}]\n\n\n"
        + "\n\n\n".join(classes)
        + "\n"
    )
    args.output.write_text(rendered, encoding="utf-8")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
