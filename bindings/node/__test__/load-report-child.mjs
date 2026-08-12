import { loadReport } from "../index.js";

// Runs in a child so the synthetic-home environment actually reaches N-API's
// background thread. Without it this call enumerates and decrypts whatever
// browsers are really installed on the host, which on macOS reaches the login
// keychain and can block on a GUI prompt.
const report = await loadReport(["example.invalid"]);

process.stdout.write(
  JSON.stringify({
    status: report.status,
    summary: report.summary,
    summaryTypes: Object.fromEntries(
      Object.entries(report.summary).map(([key, value]) => [key, typeof value]),
    ),
    profileCount: report.profiles.length,
    issueCount: report.issues.length,
    serializes: (() => {
      try {
        JSON.stringify(report);
        return true;
      } catch {
        return false;
      }
    })(),
  }),
);
