import assert from "node:assert/strict";
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { runActiveWriterProtocol } from "./active_writer_protocol.mjs";
import { assertCookieState } from "./cookie_state.mjs";

const sleep = (milliseconds) =>
  new Promise((accept) => setTimeout(accept, milliseconds));

async function waitFor(path, timeoutMs = 2000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (existsSync(path)) return JSON.parse(readFileSync(path, "utf8"));
    await sleep(10);
  }
  throw new Error(`timed out waiting for ${path}`);
}

function writeCommand(control, sequence, action) {
  writeFileSync(
    join(control, `command-${sequence}.json`),
    JSON.stringify({ protocolVersion: 1, sequence, action }),
  );
}

test("ready/hold/mutate/probe/close protocol keeps an owned context live", async () => {
  const root = mkdtempSync(join(tmpdir(), "rookie-active-writer-js-"));
  process.env.ROOKIE_E2E_ACTIVE_WRITER_TIMEOUT_MS = "1500";
  try {
    const profile = join(root, "profile");
    const database = join(profile, "cookies.sqlite");
    const control = join(root, "control");
    mkdirSync(profile);
    writeFileSync(database, "synthetic sqlite placeholder");
    const state = new Map();
    let closed = false;
    const page = {
      async goto(url) {
        if (url.includes("baseline")) {
          state.clear();
          state.set("rookie_ci", "before");
          state.set("rookie_remove", "present");
        } else if (url.includes("mutate")) {
          state.set("rookie_ci", "after");
          state.set("rookie_added", "present");
          state.delete("rookie_remove");
        }
      },
      async evaluate(callback) {
        const source = callback.toString();
        return source.includes("navigator.userAgent")
          ? "SyntheticBrowser/1"
          : "complete";
      },
    };
    const context = {
      browser() {
        return { version: () => "1.0" };
      },
      async cookies() {
        return [...state].map(([name, value]) => ({
          name,
          value,
          expires: 4_102_444_800,
        }));
      },
      async clearCookies({ name }) {
        state.delete(name);
      },
      async newPage() {
        return {
          ...page,
          async close() {},
        };
      },
      async close() {
        closed = true;
      },
    };

    const protocol = runActiveWriterProtocol({
      context,
      page,
      controlDir: control,
      baselineUrl: "http://127.0.0.1:9999/active-writer/baseline",
      engine: "firefox",
      profileDir: profile,
      databasePath: database,
    });
    const settled = protocol.then(
      () => null,
      (error) => error,
    );
    assert.equal((await waitFor(join(control, "ack-0.json"))).phase, "ready");
    assert.equal(closed, false);
    writeCommand(control, 1, "mutate");
    assert.equal((await waitFor(join(control, "ack-1.json"))).phase, "mutated");
    assert.equal(closed, false);
    writeCommand(control, 2, "probe");
    assert.equal((await waitFor(join(control, "ack-2.json"))).phase, "probed");
    assert.equal(closed, false);
    writeCommand(control, 3, "close");
    assert.equal((await waitFor(join(control, "ack-3.json"))).phase, "closed");
    assert.equal(await settled, null);
    assert.equal(closed, true);
  } finally {
    delete process.env.ROOKIE_E2E_ACTIVE_WRITER_TIMEOUT_MS;
    rmSync(root, { recursive: true, force: true });
  }
});

test("churn failure is reported without waiting for the command timeout", async () => {
  const root = mkdtempSync(join(tmpdir(), "rookie-active-writer-failure-js-"));
  process.env.ROOKIE_E2E_ACTIVE_WRITER_TIMEOUT_MS = "1500";
  try {
    const profile = join(root, "profile");
    const database = join(profile, "cookies.sqlite");
    const control = join(root, "control");
    mkdirSync(profile);
    writeFileSync(database, "synthetic sqlite placeholder");
    const state = new Map();
    const page = {
      async goto(url) {
        if (url.includes("baseline")) {
          state.set("rookie_ci", "before");
          state.set("rookie_remove", "present");
        } else if (url.includes("mutate")) {
          state.set("rookie_ci", "after");
          state.set("rookie_added", "present");
          state.delete("rookie_remove");
        }
      },
      async evaluate(callback) {
        return callback.toString().includes("navigator.userAgent")
          ? "SyntheticBrowser/1"
          : "complete";
      },
    };
    const context = {
      browser: () => ({ version: () => "1.0" }),
      cookies: async () =>
        [...state].map(([name, value]) => ({
          name,
          value,
          expires: 4_102_444_800,
        })),
      async clearCookies({ name }) {
        state.delete(name);
      },
      async newPage() {
        return {
          async goto() {
            throw new Error("synthetic churn failure");
          },
          async close() {},
        };
      },
    };

    const settled = runActiveWriterProtocol({
      context,
      page,
      controlDir: control,
      baselineUrl: "http://127.0.0.1:9999/active-writer/baseline",
      engine: "firefox",
      profileDir: profile,
      databasePath: database,
    }).then(
      () => null,
      (error) => error,
    );
    await waitFor(join(control, "ack-0.json"));
    writeCommand(control, 1, "mutate");
    const reported = await waitFor(join(control, "error.json"));
    assert.match(reported.message, /synthetic churn failure/);
    assert.match(String(await settled), /synthetic churn failure/);
  } finally {
    delete process.env.ROOKIE_E2E_ACTIVE_WRITER_TIMEOUT_MS;
    rmSync(root, { recursive: true, force: true });
  }
});

test("transition assertion rejects duplicates and deleted state", () => {
  assert.throws(
    () =>
      assertCookieState(
        [
          { name: "rookie_ci", value: "after" },
          { name: "rookie_ci", value: "after" },
        ],
        { rookie_ci: "after" },
        [],
        "synthetic",
      ),
    /exactly one/,
  );
  assert.throws(
    () =>
      assertCookieState(
        [
          { name: "rookie_ci", value: "after" },
          { name: "rookie_remove", value: "present" },
        ],
        { rookie_ci: "after" },
        ["rookie_remove"],
        "synthetic",
      ),
    /forbidden\/deleted/,
  );
});

test("exact transition assertion rejects unrelated rows", () => {
  process.env.ROOKIE_E2E_EXACT_COOKIE_STATE = "1";
  try {
    assert.throws(
      () =>
        assertCookieState(
          [
            { name: "rookie_ci", value: "after" },
            { name: "unrelated", value: "leak" },
          ],
          { rookie_ci: "after" },
          [],
          "synthetic",
        ),
      /exact active-writer set/,
    );
  } finally {
    delete process.env.ROOKIE_E2E_EXACT_COOKIE_STATE;
  }
});
