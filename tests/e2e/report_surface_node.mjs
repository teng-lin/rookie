#!/usr/bin/env node
// Thin process boundary for the cross-surface report contract gate.
import rookieCookies from "../../bindings/node/index.js";

const args = process.argv.slice(2);
let value;
if (args.length === 2 && args[0] === "profiles") {
  value = await rookieCookies.browserProfiles(args[1]);
} else if ((args.length === 2 || args.length === 3) && args[0] === "report") {
  value = await rookieCookies.browserReport(args[1], args[2]);
} else if (args.length === 1 && args[0] === "load-report") {
  value = await rookieCookies.loadReport();
} else {
  throw new Error(
    "usage: report_surface_node.mjs profiles BROWSER | " +
      "report BROWSER [PROFILE] | load-report",
  );
}
process.stdout.write(`${JSON.stringify(value)}\n`);
