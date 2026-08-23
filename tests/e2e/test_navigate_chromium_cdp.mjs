import assert from "node:assert/strict";
import test from "node:test";

import {
  DEFAULT_COMMAND_TIMEOUT_MS,
  DEFAULT_CORPUS_ATTEMPTS,
  DEFAULT_CORPUS_TIMEOUT_MS,
  corpusOptionsFromEnv,
  navigateChromiumCdp,
} from "./navigate_chromium_cdp.mjs";

function messageEvent(data) {
  const event = new Event("message");
  Object.defineProperty(event, "data", { value: data });
  return event;
}

function scriptedWebSocket(onCommand, { open = true } = {}) {
  return class ScriptedWebSocket extends EventTarget {
    static OPEN = 1;
    static CLOSED = 3;

    constructor(endpoint) {
      super();
      this.endpoint = endpoint;
      this.readyState = 0;
      this.sent = [];
      queueMicrotask(() => {
        if (open) {
          this.readyState = ScriptedWebSocket.OPEN;
          this.dispatchEvent(new Event("open"));
        } else {
          this.dispatchEvent(new Event("error"));
        }
      });
    }

    send(raw) {
      const command = JSON.parse(raw);
      this.sent.push(command);
      const response = onCommand(command, this);
      if (response !== undefined) {
        queueMicrotask(() => {
          const data = typeof response === "string" ? response : JSON.stringify(response);
          this.dispatchEvent(messageEvent(data));
        });
      }
    }

    close() {
      this.readyState = ScriptedWebSocket.CLOSED;
      this.dispatchEvent(new Event("close"));
    }
  };
}

function versionResponse(payload = { webSocketDebuggerUrl: "ws://devtools" }) {
  return async () => ({ ok: true, status: 200, json: async () => payload });
}

function successfulResponse(command) {
  const result = {
    "Target.createTarget": { targetId: "target-1" },
    "Storage.getCookies": {
      cookies: [{ name: "rookie_ci", value: "bar" }],
    },
  }[command.method] ?? {};
  return { id: command.id, result };
}

function portableCorpusCookies() {
  return [
    { domain: "127.0.0.1", name: "rookie_ci", value: "bar" },
    { domain: "127.0.0.1", name: "rookie_updated", value: "final" },
    {
      domain: "localhost",
      name: "rookie_decoy",
      value: "must-not-pass-filter",
    },
    ...Array.from({ length: 16 }, (_, index) => ({
      domain: "127.0.0.1",
      name: `portable_${index}`,
      value: `${index}`,
    })),
  ];
}

test("seeds and closes through the expected browser-level protocol", async () => {
  const methods = [];
  const logs = [];
  await navigateChromiumCdp({
    port: 9222,
    url: "http://127.0.0.1/set",
    fetchImpl: versionResponse(),
    WebSocketImpl: scriptedWebSocket((command) => {
      methods.push(command.method);
      return successfulResponse(command);
    }),
    settleMs: 0,
    logger: { log: (line) => logs.push(line), warn: assert.fail },
  });
  assert.deepEqual(methods, [
    "Target.createTarget",
    "Target.activateTarget",
    "Storage.setCookies",
    "Storage.getCookies",
    "Browser.close",
  ]);
  assert.equal(logs.length, 1);
});

test("waits for the browser-seeded portable corpus without injecting a cookie", async () => {
  const methods = [];
  const corpusUrl =
    "http://127.0.0.1/corpus/run?engine=chromium&tiers=portable_smoke&step=0";
  await navigateChromiumCdp({
    port: 9222,
    url: corpusUrl,
    fetchImpl: versionResponse(),
    WebSocketImpl: scriptedWebSocket((command) => {
      methods.push(command.method);
      if (command.method === "Target.getTargets") {
        return {
          id: command.id,
          result: {
            targetInfos: [{ targetId: "startup", type: "page", url: corpusUrl }],
          },
        };
      }
      if (command.method === "Storage.getCookies") {
        return { id: command.id, result: { cookies: portableCorpusCookies() } };
      }
      return successfulResponse(command);
    }),
    settleMs: 0,
    logger: { log() {}, warn: assert.fail },
  });
  assert.deepEqual(methods, [
    "Target.getTargets",
    "Target.activateTarget",
    "Storage.getCookies",
    "Browser.close",
  ]);
});

test("navigates the corpus when a product ignores its startup URL", async () => {
  const methods = [];
  let createdUrl;
  const corpusUrl =
    "http://127.0.0.1/corpus/run?engine=chromium&tiers=portable_smoke&step=0";
  await navigateChromiumCdp({
    port: 9222,
    url: corpusUrl,
    fetchImpl: versionResponse(),
    WebSocketImpl: scriptedWebSocket((command) => {
      methods.push(command.method);
      if (command.method === "Target.getTargets") {
        return {
          id: command.id,
          result: {
            targetInfos: [
              { targetId: "welcome", type: "page", url: "vivaldi://welcome" },
            ],
          },
        };
      }
      if (command.method === "Target.createTarget") {
        createdUrl = command.params.url;
      }
      if (command.method === "Storage.getCookies") {
        return { id: command.id, result: { cookies: portableCorpusCookies() } };
      }
      return successfulResponse(command);
    }),
    settleMs: 0,
    logger: { log() {}, warn: assert.fail },
  });
  assert.deepEqual(methods, [
    "Target.getTargets",
    "Target.createTarget",
    "Target.activateTarget",
    "Storage.getCookies",
    "Browser.close",
  ]);
  assert.equal(createdUrl, corpusUrl);
});

const CORPUS_URL =
  "http://127.0.0.1/corpus/run?engine=chromium&tiers=portable_smoke&step=0";

function corpusStartupTarget(command) {
  return {
    id: command.id,
    result: {
      targetInfos: [{ targetId: "startup", type: "page", url: CORPUS_URL }],
    },
  };
}

test("retries the corpus target in place when navigation never started", async () => {
  const methods = [];
  const warnings = [];
  let windows = 0;
  await navigateChromiumCdp({
    port: 9222,
    url: CORPUS_URL,
    fetchImpl: versionResponse(),
    WebSocketImpl: scriptedWebSocket((command) => {
      methods.push(command.method);
      if (command.method === "Target.getTargets") {
        return corpusStartupTarget(command);
      }
      if (command.method === "Storage.getCookies") {
        windows += 1;
        return {
          id: command.id,
          result: { cookies: windows === 1 ? [] : portableCorpusCookies() },
        };
      }
      return successfulResponse(command);
    }),
    corpusTimeoutMs: 0,
    settleMs: 0,
    logger: { log() {}, warn: (line) => warnings.push(line) },
  });
  assert.deepEqual(methods, [
    "Target.getTargets",
    "Target.activateTarget",
    "Storage.getCookies",
    // The replacement target exists before the stalled one is discarded, so
    // the browser is never left without a page to keep it alive.
    "Target.createTarget",
    "Target.closeTarget",
    "Target.activateTarget",
    "Storage.getCookies",
    "Browser.close",
  ]);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /corpus attempt 1\/3 observed no target-origin/);
});

test("a partially seeded corpus fails the root instead of restarting the chain", async () => {
  const methods = [];
  await assert.rejects(
    navigateChromiumCdp({
      port: 9222,
      url: CORPUS_URL,
      fetchImpl: versionResponse(),
      WebSocketImpl: scriptedWebSocket((command) => {
        methods.push(command.method);
        if (command.method === "Target.getTargets") {
          return corpusStartupTarget(command);
        }
        if (command.method === "Storage.getCookies") {
          return {
            id: command.id,
            result: { cookies: portableCorpusCookies().slice(0, 4) },
          };
        }
        return successfulResponse(command);
      }),
      corpusTimeoutMs: 0,
      settleMs: 0,
      logger: { log: assert.fail, warn: assert.fail },
    }),
    /observed 4\/19 target-origin cookies after 1 attempt; the corpus navigated but stalled partway, which is never retried in place/,
  );
  assert.deepEqual(methods, [
    "Target.getTargets",
    "Target.activateTarget",
    "Storage.getCookies",
    "Browser.close",
  ]);
});

test("in-root retries stay bounded and report the exhausted attempt count", async () => {
  const created = [];
  const warnings = [];
  await assert.rejects(
    navigateChromiumCdp({
      port: 9222,
      url: CORPUS_URL,
      fetchImpl: versionResponse(),
      WebSocketImpl: scriptedWebSocket((command) => {
        if (command.method === "Target.getTargets") {
          return corpusStartupTarget(command);
        }
        if (command.method === "Target.createTarget") {
          created.push(command.params.url);
        }
        if (command.method === "Storage.getCookies") {
          return { id: command.id, result: { cookies: [] } };
        }
        return successfulResponse(command);
      }),
      corpusTimeoutMs: 0,
      corpusAttempts: 2,
      settleMs: 0,
      logger: { log: assert.fail, warn: (line) => warnings.push(line) },
    }),
    /observed 0\/19 target-origin cookies after 2 attempts; the corpus target never navigated/,
  );
  assert.deepEqual(created, [CORPUS_URL]);
  assert.equal(warnings.length, 1);
});

test("a stalled target that will not close fails the root instead of racing it", async () => {
  await assert.rejects(
    navigateChromiumCdp({
      port: 9222,
      url: CORPUS_URL,
      fetchImpl: versionResponse(),
      WebSocketImpl: scriptedWebSocket((command) => {
        if (command.method === "Target.getTargets") {
          return corpusStartupTarget(command);
        }
        if (command.method === "Storage.getCookies") {
          return { id: command.id, result: { cookies: [] } };
        }
        if (command.method === "Target.closeTarget") {
          return {
            id: command.id,
            error: { code: -32000, message: "No target with given id" },
          };
        }
        return successfulResponse(command);
      }),
      corpusTimeoutMs: 0,
      settleMs: 0,
      logger: { log: assert.fail, warn() {} },
    }),
    /could not close the stalled corpus target after attempt 1\/3, so a retry would risk two interleaved redirect chains/,
  );
});

test("a non-positive attempt budget is rejected rather than skipping the corpus", async () => {
  await assert.rejects(
    navigateChromiumCdp({
      port: 9222,
      url: CORPUS_URL,
      fetchImpl: versionResponse(),
      WebSocketImpl: class MustNotConstruct {
        constructor() {
          assert.fail("socket constructed for an invalid attempt budget");
        }
      },
      corpusAttempts: 0,
    }),
    /corpusAttempts must be a positive integer/,
  );
});

test("corpus budgets are overridable per browser through the environment", () => {
  assert.deepEqual(corpusOptionsFromEnv({}), {});
  assert.deepEqual(
    corpusOptionsFromEnv({
      ROOKIE_E2E_CDP_CORPUS_TIMEOUT_MS: "40000",
      ROOKIE_E2E_CDP_CORPUS_ATTEMPTS: "2",
      ROOKIE_E2E_CDP_COMMAND_TIMEOUT_MS: "12000",
    }),
    { corpusTimeoutMs: 40_000, corpusAttempts: 2, commandTimeoutMs: 12_000 },
  );
  assert.throws(
    () => corpusOptionsFromEnv({ ROOKIE_E2E_CDP_CORPUS_ATTEMPTS: "0" }),
    /ROOKIE_E2E_CDP_CORPUS_ATTEMPTS must be a positive integer/,
  );
  assert.throws(
    () => corpusOptionsFromEnv({ ROOKIE_E2E_CDP_CORPUS_TIMEOUT_MS: "soon" }),
    /ROOKIE_E2E_CDP_CORPUS_TIMEOUT_MS must be a positive integer/,
  );
  assert.equal(DEFAULT_CORPUS_TIMEOUT_MS, 20_000);
  assert.equal(DEFAULT_CORPUS_ATTEMPTS, 3);
  // The harness derives its subprocess ceiling from this bound, so the two
  // sides have to agree on it.
  assert.equal(DEFAULT_COMMAND_TIMEOUT_MS, 10_000);
});

test("rejects a malformed version response before opening a socket", async () => {
  await assert.rejects(
    navigateChromiumCdp({
      port: 9222,
      url: "http://127.0.0.1/set",
      fetchImpl: versionResponse({}),
      WebSocketImpl: class MustNotConstruct {
        constructor() {
          assert.fail("socket constructed for malformed version response");
        }
      },
    }),
    /omitted webSocketDebuggerUrl/,
  );
});

test("reports early websocket failure without waiting for the open timeout", async () => {
  await assert.rejects(
    navigateChromiumCdp({
      port: 9222,
      url: "http://127.0.0.1/set",
      fetchImpl: versionResponse(),
      WebSocketImpl: scriptedWebSocket(() => undefined, { open: false }),
      openTimeoutMs: 1_000,
    }),
    /failed to open/,
  );
});

test("malformed protocol JSON rejects the command and still attempts close", async () => {
  const methods = [];
  const warnings = [];
  await assert.rejects(
    navigateChromiumCdp({
      port: 9222,
      url: "http://127.0.0.1/set",
      fetchImpl: versionResponse(),
      WebSocketImpl: scriptedWebSocket((command) => {
        methods.push(command.method);
        return command.method === "Target.createTarget"
          ? "not-json"
          : successfulResponse(command);
      }),
      settleMs: 0,
      logger: { log: assert.fail, warn: (line) => warnings.push(line) },
    }),
    /malformed JSON/,
  );
  assert.deepEqual(methods, ["Target.createTarget", "Browser.close"]);
  assert.deepEqual(warnings, []);
});

test("command timeout is bounded and cleanup failure does not mask it", async () => {
  const warnings = [];
  await assert.rejects(
    navigateChromiumCdp({
      port: 9222,
      url: "http://127.0.0.1/set",
      fetchImpl: versionResponse(),
      WebSocketImpl: scriptedWebSocket(() => undefined),
      commandTimeoutMs: 5,
      settleMs: 0,
      logger: { log: assert.fail, warn: (line) => warnings.push(line) },
    }),
    /Target.createTarget timed out/,
  );
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /Browser.close did not complete/);
});

test("Browser.close protocol failure is warned after a successful seed", async () => {
  const warnings = [];
  await navigateChromiumCdp({
    port: 9222,
    url: "http://127.0.0.1/set",
    fetchImpl: versionResponse(),
    WebSocketImpl: scriptedWebSocket((command) =>
      command.method === "Browser.close"
        ? { id: command.id, error: { code: -1, message: "closing failed" } }
        : successfulResponse(command),
    ),
    settleMs: 0,
    logger: { log() {}, warn: (line) => warnings.push(line) },
  });
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /Browser.close did not complete: Browser.close failed/);
});
