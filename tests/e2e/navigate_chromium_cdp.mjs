#!/usr/bin/env node
// Drive an already-running Chromium-family process through the standard
// DevTools protocol. This deliberately avoids Playwright's browser launch,
// attach, and page-lifecycle machinery: branded forks have hung in each of
// those layers even after publishing a healthy DevTools endpoint.

const [port, url] = process.argv.slice(2);
if (!port || !url) {
  throw new Error("usage: navigate_chromium_cdp.mjs PORT URL");
}

const versionResponse = await fetch(`http://127.0.0.1:${port}/json/version`);
if (!versionResponse.ok) {
  throw new Error(
    `DevTools version endpoint returned ${versionResponse.status}`,
  );
}
const { webSocketDebuggerUrl } = await versionResponse.json();
if (!webSocketDebuggerUrl) {
  throw new Error("DevTools version response omitted webSocketDebuggerUrl");
}

const socket = new WebSocket(webSocketDebuggerUrl);
const pending = new Map();
let commandId = 0;

await new Promise((resolve, reject) => {
  const timeout = setTimeout(
    () => reject(new Error("timed out opening the DevTools WebSocket")),
    10_000,
  );
  socket.addEventListener(
    "open",
    () => {
      clearTimeout(timeout);
      resolve();
    },
    { once: true },
  );
  socket.addEventListener(
    "error",
    () => {
      clearTimeout(timeout);
      reject(new Error("failed to open the DevTools WebSocket"));
    },
    { once: true },
  );
});

socket.addEventListener("message", ({ data }) => {
  const message = JSON.parse(data);
  if (!message.id) return;
  const waiter = pending.get(message.id);
  if (!waiter) return;
  pending.delete(message.id);
  clearTimeout(waiter.timeout);
  if (message.error) {
    waiter.reject(
      new Error(
        `${waiter.method} failed (${message.error.code}): ${message.error.message}`,
      ),
    );
  } else {
    waiter.resolve(message.result ?? {});
  }
});

function send(method, params = {}) {
  const id = ++commandId;
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`${method} timed out`));
    }, 10_000);
    pending.set(id, { method, resolve, reject, timeout });
    socket.send(
      JSON.stringify({
        id,
        method,
        params,
      }),
    );
  });
}

try {
  // Vivaldi publishes a healthy browser endpoint but can stop responding as
  // soon as a client attaches to its custom start-page target. Creating the
  // target at the canary URL performs the real navigation without crossing
  // that fork-specific page-session boundary.
  await send("Target.createTarget", { url });
  // Browser-level Storage.getCookies hangs in several macOS Chromium forks,
  // even after Target.createTarget succeeds. Give the network request time to
  // finish and let the Python harness verify the persisted SQLite row instead.
  await new Promise((resolve) => setTimeout(resolve, 10_000));
  console.log(`native CDP navigation requested ${url}`);
} finally {
  // A protocol-level close gives the native process a chance to checkpoint
  // its persistent cookie database before the extractor opens it.
  try {
    await send("Browser.close");
  } catch (error) {
    if (socket.readyState === WebSocket.OPEN) throw error;
  }
  if (socket.readyState === WebSocket.OPEN) socket.close();
}
