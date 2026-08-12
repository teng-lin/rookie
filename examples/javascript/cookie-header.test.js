import assert from "node:assert/strict";
import test from "node:test";

import { createCookieHeader } from "./cookie-header.js";

test("preserves raw percent values and separates cookie pairs", () => {
  assert.equal(
    createCookieHeader([
      { name: "ratio", value: "100%" },
      { name: "path", value: "path%2Fseg" },
      { name: "empty", value: "" },
    ]),
    "ratio=100%; path=path%2Fseg; empty=",
  );
});

test("treats a missing browser cookie value as empty", () => {
  assert.equal(createCookieHeader([{ name: "missing", value: null }]), "missing=");
});

test("preserves RFC 6265 quoted cookie values", () => {
  assert.equal(
    createCookieHeader([
      { name: "token", value: '"abc"' },
      { name: "empty", value: '""' },
    ]),
    'token="abc"; empty=""',
  );
});

test("rejects cookie names that could alter the header", () => {
  assert.throws(
    () => createCookieHeader([{ name: "safe\r\nInjected", value: "yes" }]),
    /Unsafe cookie name/,
  );
});

test("rejects cookie values that could add another cookie or header", () => {
  for (const value of [
    "one; injected=two",
    "safe\r\nInjected: yes",
    '"unmatched',
    'unmatched"',
    'internal"quote',
    '"closed"trailing',
  ]) {
    assert.throws(
      () => createCookieHeader([{ name: "session", value }]),
      /Unsafe value/,
    );
  }
});
