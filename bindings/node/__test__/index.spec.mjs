import test from "ava";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { version, firefoxBased } from "../index.js";

test("version returns a non-empty string", (t) => {
  const v = version();
  t.is(typeof v, "string");
  t.true(v.length > 0);
});

test("firefoxBased throws on a missing db path", (t) => {
  t.throws(() => firefoxBased("/nonexistent/rookie/cookies.sqlite"));
});

test("firefoxBased throws on a non-sqlite file", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "rookie-node-"));
  const dbPath = join(dir, "cookies.sqlite");
  writeFileSync(dbPath, "this is not a sqlite database");
  t.throws(() => firefoxBased(dbPath));
});
