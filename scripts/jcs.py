#!/usr/bin/env python3
"""Minimal RFC 8785 JSON Canonicalization Scheme (JCS) serializer.

Scoped to exactly the JSON value shapes this codebase's manifests and proofs
actually use: objects, arrays, strings, integers, booleans, and null.
Floating-point values are deliberately unsupported -- RFC 8785 requires the
ECMAScript Number::toString algorithm, whose edge cases (subnormals,
shortest-round-trip formatting) are subtle enough that silently
approximating it risks producing non-canonical output. Since none of this
codebase's JSON documents use floats, raising on one is safer than guessing.

Object keys are ordered by their UTF-16 code unit sequence (RFC 8785
section 3.2.3), not by Python's default code-point comparison -- those
differ only for characters outside the Basic Multilingual Plane, which this
codebase's documents never contain, but the correct ordering is cheap to get
right unconditionally via a UTF-16BE byte-comparison key.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

_SHORT_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _encode_string(value: str) -> str:
    parts = ['"']
    for character in value:
        if character in _SHORT_ESCAPES:
            parts.append(_SHORT_ESCAPES[character])
        elif ord(character) < 0x20:
            parts.append(f"\\u{ord(character):04x}")
        else:
            parts.append(character)
    parts.append('"')
    return "".join(parts)


def _encode(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise TypeError(
            "jcs.canonicalize does not support floats (see module docstring); "
            f"got {value!r}"
        )
    if isinstance(value, list):
        return "[" + ",".join(_encode(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise TypeError(f"jcs.canonicalize requires string object keys, got {key!r}")
        ordered = sorted(value.items(), key=lambda pair: pair[0].encode("utf-16-be"))
        return "{" + ",".join(_encode_string(key) + ":" + _encode(item) for key, item in ordered) + "}"
    raise TypeError(f"jcs.canonicalize cannot serialize {type(value)!r}")


def canonicalize(value: Any) -> bytes:
    """Serializes `value` per RFC 8785 JCS, returning UTF-8 bytes."""
    return _encode(value).encode("utf-8")


def digest(value: Any) -> str:
    """Returns the lowercase hex SHA-256 of `value`'s RFC 8785 JCS form."""
    return hashlib.sha256(canonicalize(value)).hexdigest()


def _main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="JSON file to canonicalize")
    parser.add_argument(
        "--digest", action="store_true", help="print only the SHA-256 digest"
    )
    args = parser.parse_args()

    document = json.loads(args.path.read_text(encoding="utf-8"))
    if args.digest:
        print(digest(document))
    else:
        import sys

        sys.stdout.buffer.write(canonicalize(document))
        sys.stdout.buffer.write(b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
