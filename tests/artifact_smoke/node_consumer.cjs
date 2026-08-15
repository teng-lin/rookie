"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");

async function main() {
  const [database, nativePackage, keyPath] = process.argv.slice(2);
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

  let cookies;
  if (keyPath) {
    const options = { domains: ["example.test"], localStatePath: keyPath };
    cookies = await rookieCookies.chromiumCookiesFromPath(database, options);
    const detailed = await rookieCookies.chromiumCookiesFromPathDetailed(database, options);
    const legacy = await rookieCookies.chromiumBased(keyPath, database, ["example.test"]);
    assert.deepEqual(legacy, cookies);
    assert.deepEqual(detailed.map(({ cookie }) => cookie), cookies);
  } else {
    cookies = await rookieCookies.cookiesFromPath(database, ["artifact.test"]);
    assert.deepEqual(
      await rookieCookies.firefoxBased(database, ["artifact.test"]),
      cookies,
    );
    assert.equal(typeof rookieCookies.chromiumCookiesFromPath, "function");
    assert.equal(typeof rookieCookies.chromiumCookiesFromPathDetailed, "function");
  }
  assert.equal(cookies.length, 1, JSON.stringify(cookies));
  assert.equal(cookies[0].name, keyPath ? "rookie_ci" : "rookie_artifact");
  assert.equal(cookies[0].value, keyPath ? "bar" : "installed-ok");
  assert.equal(cookies[0].domain, keyPath ? ".example.test" : ".artifact.test");

  console.log(
    `npm tarballs: loaded ${rootEntry} with ${nativeEntry}; ${cookies[0].name}=${cookies[0].value}`,
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
