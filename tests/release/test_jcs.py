from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("jcs", REPOSITORY_ROOT / "scripts/jcs.py")
assert SPEC is not None and SPEC.loader is not None
jcs = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = jcs
SPEC.loader.exec_module(jcs)


class CanonicalizeTests(unittest.TestCase):
    def test_object_keys_are_sorted(self) -> None:
        self.assertEqual(jcs.canonicalize({"b": 1, "a": 2}), b'{"a":2,"b":1}')

    def test_nested_objects_and_arrays_are_sorted_and_compact(self) -> None:
        value = {"a": [1, 2, {"c": 1, "b": 2}]}
        self.assertEqual(jcs.canonicalize(value), b'{"a":[1,2,{"b":2,"c":1}]}')

    def test_empty_object_and_array(self) -> None:
        self.assertEqual(jcs.canonicalize({}), b"{}")
        self.assertEqual(jcs.canonicalize([]), b"[]")
        self.assertEqual(jcs.canonicalize({"a": []}), b'{"a":[]}')

    def test_literals(self) -> None:
        self.assertEqual(jcs.canonicalize([None, True, False]), b"[null,true,false]")

    def test_mandatory_short_escapes(self) -> None:
        value = {"s": "hi\n\"there\"\\end"}
        self.assertEqual(
            jcs.canonicalize(value), b'{"s":"hi\\n\\"there\\"\\\\end"}'
        )

    def test_forward_slash_is_not_escaped(self) -> None:
        self.assertEqual(jcs.canonicalize("a/b"), b'"a/b"')

    def test_control_characters_below_0x20_use_u_escapes(self) -> None:
        self.assertEqual(jcs.canonicalize("\x01"), b'"\\u0001"')

    def test_non_ascii_characters_are_emitted_literally_as_utf8(self) -> None:
        # RFC 8785 does not escape non-ASCII code points -- only the six
        # mandatory short escapes and control characters below U+0020.
        encoded = jcs.canonicalize("café")
        self.assertEqual(encoded, "\"café\"".encode("utf-8"))
        self.assertNotIn(b"\\u00e9", encoded)

    def test_object_keys_sort_by_utf16_code_unit_not_python_code_point(self) -> None:
        # U+1F600 (outside the BMP) encodes in UTF-16 as the surrogate pair
        # D83D DE00, whose leading code unit (0xD83D) is LESS than U+FFFF's
        # single code unit (0xFFFF) -- so under correct UTF-16 ordering this
        # key sorts BEFORE "￿". Python's default string comparison
        # instead compares by raw code point (0x1F600 > 0xFFFF), which would
        # get this backwards; this test only passes with a UTF-16-aware key.
        value = {"￿": 1, "\U0001f600": 2}
        encoded = jcs.canonicalize(value).decode("utf-8")
        self.assertLess(encoded.index("\U0001f600"), encoded.index("￿"))

    def test_digest_is_deterministic_regardless_of_input_key_order(self) -> None:
        first = {"a": 1, "b": {"y": 2, "x": 1}}
        second = {"b": {"x": 1, "y": 2}, "a": 1}
        self.assertEqual(jcs.digest(first), jcs.digest(second))

    def test_digest_changes_when_a_value_changes(self) -> None:
        self.assertNotEqual(jcs.digest({"a": 1}), jcs.digest({"a": 2}))

    def test_floats_are_rejected(self) -> None:
        with self.assertRaises(TypeError):
            jcs.canonicalize({"a": 1.5})

    def test_non_string_object_keys_are_rejected(self) -> None:
        with self.assertRaises(TypeError):
            jcs.canonicalize({1: "a"})  # type: ignore[dict-item]

    def test_unsupported_value_type_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            jcs.canonicalize({"a", "set-is-not-json"})  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
