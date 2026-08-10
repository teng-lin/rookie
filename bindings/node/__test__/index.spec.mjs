import test from "ava";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { version, firefoxBased, safari } from "../index.js";

test("version returns a non-empty string", (t) => {
  const v = version();
  t.is(typeof v, "string");
  t.true(v.length > 0);
});

test("firefoxBased throws on a missing db path", async (t) => {
  await t.throwsAsync(() => firefoxBased("/nonexistent/rookie/cookies.sqlite"));
});

test("firefoxBased throws on a non-sqlite file", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "rookie-node-"));
  const dbPath = join(dir, "cookies.sqlite");
  writeFileSync(dbPath, "this is not a sqlite database");
  await t.throwsAsync(() => firefoxBased(dbPath));
});

test("safari reports an unsupported platform outside macOS", async (t) => {
  if (process.platform === "darwin") {
    t.pass();
    return;
  }

  const error = await t.throwsAsync(() => safari());
  t.regex(error.message, /safari is only available on macOS/);
});
