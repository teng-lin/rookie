import assert from "node:assert/strict";
import {
  linkSync,
  mkdtempSync,
  mkdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { tmpdir } from "node:os";

import {
  findManifest,
  pathsReferToSameFile,
  recordsForVerifier,
} from "./cookie_manifest.mjs";

test("path identity accepts two spellings of the same file", () => {
  const root = mkdtempSync(join(tmpdir(), "rookie-path-identity-"));
  try {
    const original = join(root, "Cookies");
    const aliasDir = join(root, "alias");
    const alias = join(aliasDir, "Cookies");
    mkdirSync(aliasDir);
    writeFileSync(original, "cookie db");
    linkSync(original, alias);
    assert.equal(pathsReferToSameFile(original, alias), true);
    assert.equal(pathsReferToSameFile(original, join(root, "missing")), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

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

test("manifest discovery terminates for relative paths", () => {
  assert.equal(
    findManifest("tests/e2e/nonexistent-profile/Default/Cookies"),
    null,
  );
});
