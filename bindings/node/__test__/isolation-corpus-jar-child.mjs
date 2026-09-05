// Runs the three jar-verdict calls against the synthetic Firefox home the
// parent test planted, and prints them as JSON.
//
// A child process, not the AVA worker: browser discovery reads the environment
// on N-API's background thread, which does not observe a worker's in-process
// `process.env` edits.
import { jar, read } from "../index.js";

// The store's own `include_expired` flag, forwarded by the parent test rather
// than assumed here: whether an expired row belongs in the snapshot is a fact
// about the corpus store, and `jar` must see the same snapshot `read` does for
// the byte-identity assertion to mean anything.
const includeExpired = process.argv[2] === "true";
const options = { browser: "firefox", profile: "corpus", includeExpired };

function describe(error) {
  return {
    error: {
      kind: error.kind,
      code: error.code,
      rookieCode: error.rookieCode,
      required: error.required,
    },
  };
}

async function attempt(call) {
  try {
    return await call();
  } catch (error) {
    return describe(error);
  }
}

const refused = await attempt(() => jar({ ...options }));
const allowed = await attempt(() => jar({ ...options, allowIsolationLoss: true }));
const cookies = (await read({ ...options })).cookies;

process.stdout.write(JSON.stringify({ refused, allowed, cookies }));
