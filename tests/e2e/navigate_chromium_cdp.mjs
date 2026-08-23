#!/usr/bin/env node
// Drive an already-running Chromium-family process through the standard
// DevTools protocol. This deliberately avoids Playwright's browser launch,
// attach, and page-lifecycle machinery: branded forks have hung in each of
// those layers even after publishing a healthy DevTools endpoint.

import { pathToFileURL } from "node:url";

const TARGET_ORIGIN_HOSTS = ["127.0.0.1", "localhost"];
const PORTABLE_CORPUS_SIZE = 19;

export const DEFAULT_CORPUS_TIMEOUT_MS = 20_000;
export const DEFAULT_CORPUS_ATTEMPTS = 3;
export const DEFAULT_COMMAND_TIMEOUT_MS = 10_000;

function targetOriginCookies(cookies) {
  return cookies.filter(({ domain }) =>
    TARGET_ORIGIN_HOSTS.includes(domain?.replace(/^\./, "")),
  );
}

function corpusIsComplete(targetCookies) {
  return (
    targetCookies.length >= PORTABLE_CORPUS_SIZE &&
    targetCookies.some(
      ({ name, value }) => name === "rookie_ci" && value === "bar",
    ) &&
    targetCookies.some(
      ({ name, value }) => name === "rookie_updated" && value === "final",
    ) &&
    targetCookies.some(
      ({ name, value }) =>
        name === "rookie_decoy" && value === "must-not-pass-filter",
    ) &&
    !targetCookies.some(({ name }) => name === "rookie_deleted")
  );
}

function positiveIntegerFromEnv(env, name) {
  const raw = env[name];
  if (raw === undefined || raw === "") return undefined;
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(
      `${name} must be a positive integer, received ${JSON.stringify(raw)}`,
    );
  }
  return value;
}

/**
 * Per-browser overrides for the corpus poll window, its bounded retry count,
 * and the per-command ceiling. Vivaldi under a Windows service session is a
 * known slow case, so the Python harness widens the window for it rather than
 * hard-coding one budget for every product. The harness sets these explicitly
 * so it can derive its own subprocess ceiling from every bound in force here.
 */
export function corpusOptionsFromEnv(env = process.env) {
  const options = {};
  const corpusTimeoutMs = positiveIntegerFromEnv(
    env,
    "ROOKIE_E2E_CDP_CORPUS_TIMEOUT_MS",
  );
  if (corpusTimeoutMs !== undefined) options.corpusTimeoutMs = corpusTimeoutMs;
  const corpusAttempts = positiveIntegerFromEnv(
    env,
    "ROOKIE_E2E_CDP_CORPUS_ATTEMPTS",
  );
  if (corpusAttempts !== undefined) options.corpusAttempts = corpusAttempts;
  const commandTimeoutMs = positiveIntegerFromEnv(
    env,
    "ROOKIE_E2E_CDP_COMMAND_TIMEOUT_MS",
  );
  if (commandTimeoutMs !== undefined) {
    options.commandTimeoutMs = commandTimeoutMs;
  }
  return options;
}

export async function navigateChromiumCdp({
  port,
  url,
  fetchImpl = fetch,
  WebSocketImpl = WebSocket,
  openTimeoutMs = 10_000,
  commandTimeoutMs = DEFAULT_COMMAND_TIMEOUT_MS,
  corpusTimeoutMs = DEFAULT_CORPUS_TIMEOUT_MS,
  corpusAttempts = DEFAULT_CORPUS_ATTEMPTS,
  pollMs = 100,
  settleMs = 2_000,
  logger = console,
}) {
  if (!Number.isInteger(corpusAttempts) || corpusAttempts < 1) {
    throw new Error("corpusAttempts must be a positive integer");
  }
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

  function createTargetFor(targetUrl) {
    return send("Target.createTarget", {
      url: targetUrl,
      newWindow: true,
      background: false,
    }).then(({ targetId }) => targetId);
  }

  function createUrlTarget() {
    return createTargetFor(url);
  }

  /**
   * Close a target and refuse to continue unless it is really gone. Chromium
   * answers with `{success: false}` rather than a protocol error when the
   * close does not happen, so the result has to be inspected — a resolved
   * promise alone does not mean the page went away.
   */
  async function closeTargetOrThrow(targetId, context) {
    let result;
    try {
      result = await send("Target.closeTarget", { targetId });
    } catch (error) {
      throw new Error(`${context}: ${error.message}`);
    }
    if (result?.success === false) {
      throw new Error(`${context}: Target.closeTarget reported success=false`);
    }
  }

  async function resolveCorpusTarget() {
    // Most products honor the URL passed to their native launch. Reuse that
    // page so a second redirect chain cannot interleave its initial/mutate
    // phases. Vivaldi can ignore the startup URL, so explicitly create the
    // corpus target when no existing page is running it.
    const { targetInfos = [] } = await send("Target.getTargets");
    const existing = targetInfos.find(({ type, url: targetUrl }) => {
      if (type !== "page") return false;
      try {
        return new URL(targetUrl).pathname === "/corpus/run";
      } catch {
        return false;
      }
    });
    return existing ? existing.targetId : createUrlTarget();
  }

  /** Poll one bounded window and report how far the corpus actually got. */
  async function pollCorpusWindow() {
    const deadline = Date.now() + corpusTimeoutMs;
    let targetCookies = [];
    for (;;) {
      const { cookies = [] } = await send("Storage.getCookies");
      targetCookies = targetOriginCookies(cookies);
      if (corpusIsComplete(targetCookies)) {
        return { complete: true, count: targetCookies.length };
      }
      if (Date.now() >= deadline) {
        return { complete: false, count: targetCookies.length };
      }
      await new Promise((resolve) => setTimeout(resolve, pollMs));
    }
  }

  // A target that never navigated is safe to replace: the corpus server is
  // stateless and drives its redirect chain purely from the `step` query
  // parameter, so a fresh target restarts the chain from the beginning. A
  // partially seeded corpus is NOT retried this way — a second chain would
  // interleave its initial/mutate phases with the one already in flight, so
  // that outcome fails the root immediately and stays diagnosable.
  async function seedPortableCorpus() {
    let targetId = await resolveCorpusTarget();
    let keepAliveTargetId;
    for (let attempt = 1; ; attempt += 1) {
      await send("Target.activateTarget", { targetId });
      const { complete, count } = await pollCorpusWindow();
      if (complete) return;
      const attemptsWord = attempt === 1 ? "attempt" : "attempts";
      if (count > 0) {
        throw new Error(
          `native CDP navigation did not complete the portable corpus ` +
            `(observed ${count}/${PORTABLE_CORPUS_SIZE} target-origin cookies ` +
            `after ${attempt} ${attemptsWord}; the corpus navigated but ` +
            `stalled partway, which is never retried in place)`,
        );
      }
      if (attempt >= corpusAttempts) {
        throw new Error(
          `native CDP navigation did not complete the portable corpus ` +
            `(observed 0/${PORTABLE_CORPUS_SIZE} target-origin cookies ` +
            `after ${attempt} ${attemptsWord}; the corpus target never ` +
            `navigated)`,
        );
      }
      logger.warn(
        `native CDP corpus attempt ${attempt}/${corpusAttempts} observed no ` +
          `target-origin cookies after ${corpusTimeoutMs}ms; re-creating and ` +
          `re-activating the corpus target`,
      );
      // Two constraints pull against each other here. A Chromium browser left
      // with no page can quit, which would end the run instead of retrying it;
      // but no second corpus URL may be loading while the stalled target is
      // still open, or a target that unthrottles mid-retry runs its redirect
      // chain against the replacement's. A blank keep-alive page satisfies
      // both: it holds the browser open, and it seeds nothing.
      if (keepAliveTargetId === undefined) {
        keepAliveTargetId = await createTargetFor("about:blank");
      }
      // Closing the stalled target is not optional. If it survives, a
      // late-unthrottled navigation can re-add rookie_deleted or roll
      // rookie_updated off `final` after the completion check has already
      // passed — a seeding flake laundered into an unexplained extraction
      // failure downstream. Fail the root loudly instead.
      await closeTargetOrThrow(
        targetId,
        `native CDP could not close the stalled corpus target after attempt ` +
          `${attempt}/${corpusAttempts}, so a retry would risk two ` +
          `interleaved redirect chains`,
      );
      targetId = await createUrlTarget();
    }
  }

  try {
    // Vivaldi's page-session commands can hang even for a fresh target. Keep
    // the browser-level protocol only, but force the canary target into the
    // foreground so Windows service sessions do not indefinitely throttle its
    // navigation.
    const corpusMode = new URL(url).pathname === "/corpus/run";
    if (corpusMode) {
      await seedPortableCorpus();
    } else {
      const targetId = await createUrlTarget();
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
    }
    await new Promise((resolve) => setTimeout(resolve, settleMs));
    logger.log(
      `native CDP foreground target and persistent cookie corpus seeded for ${url}`,
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
  await navigateChromiumCdp({ port, url, ...corpusOptionsFromEnv() });
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  await main();
}
