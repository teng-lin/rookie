#!/usr/bin/env node
// Drive an already-running Chromium-family process through the standard
// DevTools protocol. This deliberately avoids Playwright's browser launch,
// attach, and page-lifecycle machinery: branded forks have hung in each of
// those layers even after publishing a healthy DevTools endpoint.

import { pathToFileURL } from "node:url";

export async function navigateChromiumCdp({
  port,
  url,
  fetchImpl = fetch,
  WebSocketImpl = WebSocket,
  openTimeoutMs = 10_000,
  commandTimeoutMs = 10_000,
  settleMs = 2_000,
  logger = console,
}) {
  const versionResponse = await fetchImpl(
    `http://127.0.0.1:${port}/json/version`,
  );
  if (!versionResponse.ok) {
    throw new Error(
      `DevTools version endpoint returned ${versionResponse.status}`,
    );
  }
  const { webSocketDebuggerUrl } = await versionResponse.json();
  if (!webSocketDebuggerUrl) {
    throw new Error("DevTools version response omitted webSocketDebuggerUrl");
  }

  const socket = new WebSocketImpl(webSocketDebuggerUrl);
  const pending = new Map();
  let commandId = 0;

  await new Promise((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error("timed out opening the DevTools WebSocket")),
      openTimeoutMs,
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

  function rejectPending(error) {
    for (const waiter of pending.values()) {
      clearTimeout(waiter.timeout);
      waiter.reject(error);
    }
    pending.clear();
  }

  socket.addEventListener("message", ({ data }) => {
    let message;
    try {
      message = JSON.parse(data);
    } catch {
      rejectPending(new Error("DevTools WebSocket returned malformed JSON"));
      return;
    }
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
  socket.addEventListener("error", () => {
    rejectPending(new Error("DevTools WebSocket failed while a command was pending"));
  });
  socket.addEventListener("close", () => {
    rejectPending(new Error("DevTools WebSocket closed while a command was pending"));
  });

  function send(method, params = {}) {
    const id = ++commandId;
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`${method} timed out`));
      }, commandTimeoutMs);
      pending.set(id, { method, resolve, reject, timeout });
      try {
        socket.send(JSON.stringify({ id, method, params }));
      } catch (error) {
        pending.delete(id);
        clearTimeout(timeout);
        reject(error);
      }
    });
  }

  try {
    // Vivaldi's page-session commands can hang even for a fresh target. Keep
    // the browser-level protocol only, but force the canary target into the
    // foreground so Windows service sessions do not indefinitely throttle its
    // navigation.
    const { targetId } = await send("Target.createTarget", {
      url,
      newWindow: true,
      background: false,
    });
    await send("Target.activateTarget", { targetId });
    await send("Storage.setCookies", {
      cookies: [
        {
          name: "rookie_ci",
          value: "bar",
          url,
          expires: Math.floor(Date.now() / 1000) + 3600,
          sameSite: "Lax",
        },
      ],
    });
    const { cookies } = await send("Storage.getCookies");
    const seeded = cookies?.find(
      ({ name, value }) => name === "rookie_ci" && value === "bar",
    );
    if (!seeded) {
      throw new Error("native CDP storage did not retain rookie_ci=bar");
    }
    await new Promise((resolve) => setTimeout(resolve, settleMs));
    logger.log(
      `native CDP foreground target and persistent cookie seeded for ${url}`,
    );
  } finally {
    // A protocol-level close gives the native process a chance to checkpoint
    // its persistent cookie database before the extractor opens it.
    try {
      await send("Browser.close");
    } catch (error) {
      logger.warn(`Browser.close did not complete: ${error.message}`);
    }
    if (socket.readyState === WebSocketImpl.OPEN) socket.close();
  }
}

async function main() {
  const [port, url] = process.argv.slice(2);
  if (!port || !url) {
    throw new Error("usage: navigate_chromium_cdp.mjs PORT URL");
  }
  await navigateChromiumCdp({ port, url });
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  await main();
}
