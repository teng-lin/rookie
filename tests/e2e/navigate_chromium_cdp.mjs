#!/usr/bin/env node
// Attach to an already-running native Chromium-family process through its
// standard DevTools endpoint. This deliberately avoids Playwright's browser
// launch and persistent-context control pipe, where branded forks have hung or
// crashed before a connection became usable.

import { chromium } from "playwright";

const [port, url] = process.argv.slice(2);
if (!port || !url) {
  throw new Error("usage: navigate_chromium_cdp.mjs PORT URL");
}

const browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`, {
  timeout: 30_000,
});

try {
  const [context] = browser.contexts();
  if (!context) {
    throw new Error("native browser did not expose its persistent default context");
  }
  const page = await context.newPage();
  try {
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 30_000 });
    const seeded = (await context.cookies([url])).find(
      ({ name }) => name === "rookie_ci",
    );
    if (!seeded || seeded.value !== "bar") {
      throw new Error("native browser did not accept rookie_ci=bar");
    }
    console.log(`native CDP seed accepted rookie_ci=bar at ${page.url()}`);
  } finally {
    await page.close();
  }
} finally {
  // `browser.close()` only disconnects clients created by connectOverCDP.
  // Send the protocol-level close command so the native browser checkpoints
  // its persistent cookie database before the extractor opens it.
  try {
    const session = await browser.newBrowserCDPSession();
    await session.send("Browser.close");
  } catch (error) {
    if (browser.isConnected()) {
      throw error;
    }
  }
}
