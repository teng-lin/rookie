import assert from "node:assert/strict";
import test from "node:test";

import { navigateChromiumCdp } from "./navigate_chromium_cdp.mjs";

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
