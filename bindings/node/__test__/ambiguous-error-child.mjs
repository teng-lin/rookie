import { browserReport } from "../index.js";

try {
  await browserReport({ browserId: "firefox", profileId: "shared" });
  throw new Error("ambiguous profile unexpectedly succeeded");
} catch (error) {
  process.stdout.write(JSON.stringify({
    kind: error.kind,
    code: error.code,
    rookieCode: error.rookieCode,
    stopReason: error.stopReason,
    profileIds: error.profileIds,
  }));
}
