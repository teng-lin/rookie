import assert from "node:assert/strict";
import test from "node:test";

import { recordsForVerifier } from "./cookie_manifest.mjs";

test("Node session cookies normalize optional expiry to semantic null", () => {
  const flat = { domain: "example.test", name: "session" };
  assert.deepEqual(recordsForVerifier("unfiltered_flat", [flat]), [
    { domain: "example.test", name: "session", expires: null },
  ]);

  const detailed = { cookie: flat, context: { partitionKey: null } };
  assert.deepEqual(recordsForVerifier("detailed", [detailed]), [
    {
      cookie: { domain: "example.test", name: "session", expires: null },
      context: { partitionKey: null },
    },
  ]);
});

test("defined expiry and unrelated shape remain unchanged", () => {
  const persistent = { name: "persistent", expires: 4_102_444_800 };
  const malformed = null;
  const normalized = recordsForVerifier("filtered_flat", [
    persistent,
    malformed,
  ]);
  assert.equal(normalized[0], persistent);
  assert.equal(normalized[1], malformed);
});
