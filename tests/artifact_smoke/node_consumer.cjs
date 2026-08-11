"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");

async function main() {
  const [database, nativePackage] = process.argv.slice(2);
  if (!database || !nativePackage) {
    throw new Error("usage: node_consumer.cjs <cookies.sqlite> <native-package>");
  }

  const consumerModules = path.join(process.cwd(), "node_modules") + path.sep;
  const rootEntry = require.resolve("rookie-cookies");
  const nativeEntry = require.resolve(nativePackage);
  assert.ok(
    path.resolve(rootEntry).startsWith(consumerModules),
    `root package was not loaded from the clean consumer: ${rootEntry}`,
  );
  assert.ok(
    path.resolve(nativeEntry).startsWith(consumerModules),
    `native package was not loaded from the clean consumer: ${nativeEntry}`,
  );

  const rookieCookies = require("rookie-cookies");
  assert.equal(typeof rookieCookies.version, "function");
  assert.match(rookieCookies.version(), /^\d+\.\d+\.\d+/);

  const cookies = await rookieCookies.firefoxBased(database, ["artifact.test"]);
  assert.equal(cookies.length, 1, JSON.stringify(cookies));
  assert.equal(cookies[0].name, "rookie_artifact");
  assert.equal(cookies[0].value, "installed-ok");
  assert.equal(cookies[0].domain, ".artifact.test");

  console.log(
    `npm tarballs: loaded ${rootEntry} with ${nativeEntry}; rookie_artifact=installed-ok`,
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
