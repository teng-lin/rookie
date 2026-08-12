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

import rookieCookies, {
  firefoxBased,
  safari,
  version,
} from "../index.js";

const execFileAsync = promisify(execFile);

// Every function the loader (bindings/node/index.js) is expected to export
// after patch-loader.js runs, per bindings/node/index.d.ts. Required native
// functions are validated while the facade is constructed; this list also
// guards against the documented facade and its smoke test drifting apart.
const EXPECTED_EXPORTS = [
  "version",
  "anyBrowser",
  "firefox",
  "zen",
  "librewolf",
  "chrome",
  "brave",
  "arc",
  "edge",
  "opera",
  "operaGx",
  "chromium",
  "vivaldi",
  "load",
  "firefoxProfiles",
  "firefoxProfile",
  "firefoxBased",
  "octoBrowser",
  "internetExplorer",
  "safari",
  "chromiumBased",
];

test("index.js exports every documented function", (t) => {
  for (const name of EXPECTED_EXPORTS) {
    t.is(
      typeof rookieCookies[name],
      "function",
      `expected module.exports.${name} to be a function`,
    );
  }
});

test("version returns a non-empty string", (t) => {
  const v = version();
  t.is(typeof v, "string");
  t.true(v.length > 0);
});

test("all packages advertise the exact Node-API v4 engine range", (t) => {
  const expected = "^10.16.0 || ^11.8.0 || >=12.0.0";
  const manifests = [
    ["root", new URL("../package.json", import.meta.url)],
    ["darwin-arm64", new URL("../npm/darwin-arm64/package.json", import.meta.url)],
    ["darwin-x64", new URL("../npm/darwin-x64/package.json", import.meta.url)],
    ["linux-x64-gnu", new URL("../npm/linux-x64-gnu/package.json", import.meta.url)],
    ["win32-x64-msvc", new URL("../npm/win32-x64-msvc/package.json", import.meta.url)],
  ];

  for (const [name, url] of manifests) {
    const manifest = JSON.parse(readFileSync(url, "utf8"));
    t.is(manifest.engines.node, expected, `${name} engine range`);
  }
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

test("bad async API arguments reject instead of throwing synchronously", async (t) => {
  const invalidCalls = [
    ["anyBrowser", () => rookieCookies.anyBrowser(42)],
    ["firefox", () => rookieCookies.firefox(42)],
    ["firefoxProfile", () => rookieCookies.firefoxProfile(42)],
    ["firefoxBased", () => rookieCookies.firefoxBased(42)],
    ["zen", () => rookieCookies.zen(42)],
    ["librewolf", () => rookieCookies.librewolf(42)],
    ["chrome", () => rookieCookies.chrome(42)],
    ["brave", () => rookieCookies.brave(42)],
    ["arc", () => rookieCookies.arc(42)],
    ["edge", () => rookieCookies.edge(42)],
    ["opera", () => rookieCookies.opera(42)],
    ["operaGx", () => rookieCookies.operaGx(42)],
    ["chromium", () => rookieCookies.chromium(42)],
    ["vivaldi", () => rookieCookies.vivaldi(42)],
    ["load", () => rookieCookies.load(42)],
    ["octoBrowser", () => rookieCookies.octoBrowser(42)],
    ["internetExplorer", () => rookieCookies.internetExplorer(42)],
    ["safari", () => rookieCookies.safari(42)],
    ["chromiumBased", () => rookieCookies.chromiumBased(42)],
  ];

  for (const [name, call] of invalidCalls) {
    let promise;
    t.notThrows(() => {
      promise = call();
    }, `${name} must not throw before returning`);
    t.true(promise instanceof Promise, `${name} must return a Promise`);
    await t.throwsAsync(promise, undefined, `${name} must reject`);
  }
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
    t.deepEqual(cookies[0], {
      domain: ".example.test",
      path: "/",
      secure: false,
      expires: 1700000000,
      name: "selected",
      value: "secondary",
      httpOnly: false,
      sameSite: 0,
    });
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
  t.false(types.includes("testWorkerPanic"));
});

test("public JavaScript examples await async extraction APIs", (t) => {
  const documents = [
    ["README.md", new URL("../../../README.md", import.meta.url), true],
    [
      "docs/JavaScript.md",
      new URL("../../../docs/JavaScript.md", import.meta.url),
      true,
    ],
    ["bindings/node/README.md", new URL("../README.md", import.meta.url), true],
    [
      "examples/javascript/simple.js",
      new URL("../../../examples/javascript/simple.js", import.meta.url),
      false,
    ],
    [
      "examples/javascript/fetch.js",
      new URL("../../../examples/javascript/fetch.js", import.meta.url),
      false,
    ],
    [
      "examples/javascript/from_path.mjs",
      new URL("../../../examples/javascript/from_path.mjs", import.meta.url),
      false,
    ],
  ];
  const asyncApis = [
    "anyBrowser",
    "firefox",
    "firefoxProfiles",
    "firefoxProfile",
    "zen",
    "librewolf",
    "chrome",
    "brave",
    "arc",
    "edge",
    "opera",
    "operaGx",
    "chromium",
    "vivaldi",
    "firefoxBased",
    "load",
    "octoBrowser",
    "internetExplorer",
    "safari",
    "chromiumBased",
  ];
  const callPattern = new RegExp(`\\b(?:${asyncApis.join("|")})\\s*\\(`, "g");
  let checkedCalls = 0;

  for (const [name, url, markdown] of documents) {
    const source = readFileSync(url, "utf8");
    const examples = markdown
      ? [...source.matchAll(/```(?:js|javascript|typescript)\s*\n([\s\S]*?)```/g)].map(
          (match) => match[1],
        )
      : [source];

    for (const example of examples) {
      for (const line of example.split("\n")) {
        const calls = [...line.matchAll(callPattern)];
        checkedCalls += calls.length;
        for (const call of calls) {
          t.true(
            line.slice(0, call.index).includes("await"),
            `${name} must await this async API call: ${line.trim()}`,
          );
        }
      }
    }
  }

  t.true(checkedCalls >= 8, "the doc test must cover the public examples");
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
