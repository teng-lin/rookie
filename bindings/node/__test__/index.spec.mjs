import test from "ava";
import { execFile } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import {
  firefoxBased,
  safari,
  version,
} from "../index.js";

const execFileAsync = promisify(execFile);

test("version returns a non-empty string", (t) => {
  const v = version();
  t.is(typeof v, "string");
  t.true(v.length > 0);
});

test("firefoxBased throws on a missing db path", async (t) => {
  await t.throwsAsync(firefoxBased("/nonexistent/rookie/cookies.sqlite"));
});

test("firefoxBased throws on a non-sqlite file", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "rookie-node-"));
  const dbPath = join(dir, "cookies.sqlite");
  writeFileSync(dbPath, "this is not a sqlite database");
  await t.throwsAsync(firefoxBased(dbPath));
});

test.serial("Firefox profiles can be listed and selected asynchronously", async (t) => {
  const temp = mkdtempSync(join(tmpdir(), "rookie-node-firefox-"));
  const fixture = firefoxFixtureRoot(temp);
  const defaultProfile = join(fixture.root, "Profiles", "default-release");
  const workProfile = join(fixture.root, "Profiles", "work");
  mkdirSync(defaultProfile, { recursive: true });
  mkdirSync(workProfile, { recursive: true });
  writeFileSync(
    join(fixture.root, "profiles.ini"),
    `[InstallTest]
Default=Profiles/default-release

[Profile0]
Name=default-release
IsRelative=1
Path=Profiles/default-release
Default=1

[Profile1]
Name=work
IsRelative=1
Path=Profiles/work
`,
  );
  installFirefoxDatabase(
    join(defaultProfile, "cookies.sqlite"),
    new URL("fixtures/firefox-empty.sqlite.base64", import.meta.url),
  );
  installFirefoxDatabase(
    join(workProfile, "cookies.sqlite"),
    new URL("fixtures/firefox-selected.sqlite.base64", import.meta.url),
  );

  try {
    // AVA may run this test inside a worker whose process.env changes are not
    // visible to N-API's background thread. A child with an inherited fixture
    // environment exercises the same production discovery path reliably.
    const { stdout } = await execFileAsync(
      process.execPath,
      [fileURLToPath(new URL("firefox-profile-child.mjs", import.meta.url))],
      {
        env: { ...process.env, ...fixture.environment },
      },
    );
    const { profiles, cookies } = JSON.parse(stdout);
    t.deepEqual(
      profiles.map(({ name, isDefault }) => ({ name, isDefault })),
      [
        { name: "default-release", isDefault: true },
        { name: "work", isDefault: false },
      ],
    );
    t.true(profiles.every(({ path }) => typeof path === "string"));

    t.is(cookies.length, 1);
    t.is(cookies[0].name, "selected");
    t.is(cookies[0].value, "secondary");
    t.is(cookies[0].expires, 1700000000);
    t.deepEqual(Object.keys(cookies[0]).sort(), [
      "domain",
      "expires",
      "httpOnly",
      "name",
      "path",
      "sameSite",
      "secure",
      "value",
    ]);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test("generated Firefox profile exports and declarations survive patching", (t) => {
  const types = readFileSync(new URL("../index.d.ts", import.meta.url), "utf8");
  t.regex(types, /export interface FirefoxProfileObject/);
  t.regex(types, /export declare function firefoxProfiles\(/);
  t.regex(types, /export declare function firefoxProfile\(/);
  t.is((types.match(/firefoxProfiles\(/g) || []).length, 1);
  t.is((types.match(/firefoxProfile\(/g) || []).length, 1);
});

test("safari reports an unsupported platform outside macOS", async (t) => {
  if (process.platform === "darwin") {
    t.pass();
    return;
  }

  const error = await t.throwsAsync(safari());
  t.regex(error.message, /safari is only available on macOS/);
});

function firefoxFixtureRoot(temp) {
  if (process.platform === "win32") {
    const roaming = join(temp, "Roaming");
    const local = join(temp, "Local");
    return {
      root: join(roaming, "Mozilla", "Firefox"),
      environment: { APPDATA: roaming, LOCALAPPDATA: local },
    };
  }
  if (process.platform === "darwin") {
    return {
      root: join(temp, "Library", "Application Support", "Firefox"),
      environment: { HOME: temp },
    };
  }
  return {
    root: join(temp, ".mozilla", "firefox"),
    environment: { HOME: temp },
  };
}

function installFirefoxDatabase(path, fixtureUrl) {
  const encoded = readFileSync(fixtureUrl, "ascii").replace(/\s/g, "");
  writeFileSync(path, Buffer.from(encoded, "base64"));
}
