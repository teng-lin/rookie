// Assert one browser-produced Firefox container cookie through Node.

import process from "node:process";

import * as rookieCookies from "../../bindings/node/index.js";

const [database, idArg] = process.argv.slice(2);
const userContextId = Number(idArg);
if (!database || !Number.isSafeInteger(userContextId) || userContextId <= 0) {
  console.error(
    "usage: node assert_firefox_container.mjs <database> <user-context-id>",
  );
  process.exit(2);
}

const snapshot = await rookieCookies.fromPath({ path: database });
const context = {
  url: "https://container.rookie.test/",
  topLevelSite: "https://container.rookie.test/",
  userContextId,
};
if (snapshot.header(context) !== "rookie_container=container-1") {
  throw new Error("Node did not select the exact Firefox container cookie");
}
if (snapshot.header({ ...context, userContextId: userContextId + 1 }) !== "") {
  throw new Error("Node merged a different Firefox container");
}
try {
  snapshot.header({
    url: context.url,
    topLevelSite: context.topLevelSite,
  });
  throw new Error("Node accepted a missing Firefox container selector");
} catch (error) {
  if (
    error.rookieCode !== "incomplete_send_context" &&
    !String(error).includes("incomplete_send_context")
  ) {
    throw error;
  }
}
