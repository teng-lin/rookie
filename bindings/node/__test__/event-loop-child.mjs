import { browserReport } from "../index.js";

// Measures the event loop from inside the process running the extraction, then
// reports the raw numbers for the parent to assert on. A child is required
// twice over: AVA may run a test in a worker whose process.env is invisible to
// N-API's background thread, and the loop being measured must be the same one
// the native call would block.

let ticks = 0;
const interval = setInterval(() => {
  ticks += 1;
}, 1);

const timer = new Promise((resolve) => {
  setTimeout(() => resolve("timer"), 0);
});

const started = performance.now();
const pending = browserReport("firefox");
const winner = await Promise.race([timer, pending.then(() => "report")]);
const report = await pending;
const durationMs = performance.now() - started;
clearInterval(interval);

process.stdout.write(
  JSON.stringify({
    winner,
    ticks,
    durationMs,
    profiles: report.profiles.length,
    cookiesEmitted: report.summary.cookiesEmitted,
  }),
);
