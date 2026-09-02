// Assert one browser-produced Firefox container cookie through Node.

import process from "node:process";

import * as rookieCookies from "../../bindings/node/index.js";

const [database, idArg, originAttributes] = process.argv.slice(2);
const userContextId = Number(idArg);
if (
  !database ||
  !Number.isSafeInteger(userContextId) ||
  userContextId <= 0 ||
  !originAttributes
) {
  console.error(
    "usage: node assert_firefox_container.mjs <database> <user-context-id> <origin-attributes>",
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

const view = snapshot.sendView(context);
const identities = view.cookies.map(({ cookie }) => [cookie.name, cookie.value]);
if (
  JSON.stringify(identities) !==
  JSON.stringify([["rookie_container", "container-1"]])
) {
  throw new Error(`Node sendView selected ${JSON.stringify(identities)}`);
}
if (view.header !== "rookie_container=container-1") {
  throw new Error(`Node sendView header was ${view.header}`);
}
// The raw suffix is never a bypass: the typed container selector still has to
// match, so naming the stored suffix must land on the same single record
// rather than widening the set.
const roundTrip = snapshot.sendView({ ...context, originAttributes });
if (JSON.stringify(roundTrip.cookies) !== JSON.stringify(view.cookies)) {
  throw new Error(
    `the raw origin-attribute selector ${originAttributes} changed the selected set: ${JSON.stringify(roundTrip.cookies)}`,
  );
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
  if (JSON.stringify(error.required ?? []) !== JSON.stringify(["user_context_id"])) {
    throw new Error(
      `Node named the wrong required selectors: ${JSON.stringify(error.required)}`,
    );
  }
}
