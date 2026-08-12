import test from "ava";
import { execFile, spawnSync } from "node:child_process";
import {
  copyFileSync,
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
import { runInNewContext } from "node:vm";

import rookieCookies, {
  firefoxBased,
  safari,
  toNetscape,
  version,
} from "../index.js";

const execFileAsync = promisify(execFile);

// Every function the loader (bindings/node/index.js) is expected to export
// after patch-loader.js runs, per bindings/node/index.d.ts. Required native
// functions are validated while the facade is constructed; this list also
// guards against the documented facade and its smoke test drifting apart.
const EXPECTED_EXPORTS = [
  "version",
  "toNetscape",
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
  "supportedBrowsers",
  "browserProfiles",
  "browserReport",
  "loadReport",
];

// The generic report APIs, and the object declarations they return. napi-rs
// emits these after `load`, which is exactly where a naive slice in
// patch-loader.js used to discard everything that followed.
const REPORT_FUNCTIONS = [
  "supportedBrowsers",
  "browserProfiles",
  "browserReport",
  "loadReport",
];

const REPORT_INTERFACES = [
  "BrowserCapabilitiesObject",
  "BrowserDescriptorObject",
  "ProfileIdentityObject",
  "CookieSourceDescriptorObject",
  "CookieSourceIdentityObject",
  "ProfileDescriptorObject",
  "ExtractionStatsObject",
  "ReportStatsObject",
  "ExtractionIssueObject",
  "SourceExtractionObject",
  "ProfileExtractionObject",
  "ExtractionReportObject",
];

function constructFacade(platform, omittedNativeExport) {
  const loader = readFileSync(new URL("../index.js", import.meta.url), "utf8");
  const facadeStart = loader.indexOf("function requiredNative(");
  if (facadeStart === -1) {
    throw new Error("generated loader has no validated export facade");
  }

  const nativeFunctions = Object.fromEntries(
    EXPECTED_EXPORTS.map((name) => [name, () => []]),
  );
  nativeFunctions.testWorkerPanic = undefined;
  nativeFunctions[omittedNativeExport] = undefined;

  const module = { exports: {} };
  runInNewContext(loader.slice(facadeStart), {
    ...nativeFunctions,
    module,
    platform,
    Promise,
    Error,
    TypeError,
  });
  return module.exports;
}

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

test("the generated facade validates required native exports", (t) => {
  t.throws(() => constructFacade("linux", "version"), {
    message: /native binding function: version/,
  });
  t.throws(() => constructFacade("linux", "toNetscape"), {
    message: /native binding function: toNetscape/,
  });
  t.throws(() => constructFacade("linux", "chrome"), {
    message: /native binding function: chrome/,
  });
});

test("platform exports are required only on their supported OS", async (t) => {
  t.throws(() => constructFacade("win32", "octoBrowser"), {
    message: /native binding function: octoBrowser/,
  });
  t.throws(() => constructFacade("darwin", "safari"), {
    message: /native binding function: safari/,
  });

  const linux = constructFacade("linux", "octoBrowser");
  await t.throwsAsync(linux.octoBrowser(), {
    message: /only available on Windows/,
  });
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

test("toNetscape escapes malicious fields byte-exactly", (t) => {
  const output = toNetscape([{
    domain: ".exa\tmple\r.test",
    path: "/line\npath",
    secure: false,
    expires: undefined,
    name: "na\tme",
    value: "safe\n.evil.test\tTRUE\t/\tTRUE\t1\tforged\tvalue\r",
    httpOnly: true,
    sameSite: 0,
  }]);

  t.is(
    output,
    "# Netscape HTTP Cookie File\n" +
      `# Generated by rookie-cookies ${version()}\n` +
      "# Edit at your own risk.\n\n" +
      "#HttpOnly_.exa%09mple%0D.test\tTRUE\t/line%0Apath\tFALSE\t0\t" +
      "na%09me\tsafe%0A.evil.test%09TRUE%09/%09TRUE%091%09forged%09value%0D\n",
  );
  t.is(output.split("\n").length - 1, 5);
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
    ["browserProfiles", () => rookieCookies.browserProfiles(42)],
    ["browserReport", () => rookieCookies.browserReport(42)],
    ["loadReport", () => rookieCookies.loadReport(42)],
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
  const loader = readFileSync(new URL("../index.js", import.meta.url), "utf8");
  const types = readFileSync(new URL("../index.d.ts", import.meta.url), "utf8");
  t.is((loader.match(/function requiredNative\(/g) || []).length, 1);
  t.is((loader.match(/function platformNative\(/g) || []).length, 1);
  t.regex(types, /export interface FirefoxProfileObject/);
  t.regex(types, /export declare function firefoxProfiles\(/);
  t.regex(types, /export declare function firefoxProfile\(/);
  t.is((types.match(/firefoxProfiles\(/g) || []).length, 1);
  t.is((types.match(/firefoxProfile\(/g) || []).length, 1);
  t.false(types.includes("testWorkerPanic"));
});

test("supportedBrowsers describes registered browsers in camelCase", async (t) => {
  const browsers = await rookieCookies.supportedBrowsers();

  t.true(Array.isArray(browsers));
  t.true(browsers.length > 0, "the running OS must register at least one browser");

  for (const browser of browsers) {
    t.is(typeof browser.id, "string");
    t.is(typeof browser.displayName, "string");
    t.is(typeof browser.engine, "string");
    t.true(Array.isArray(browser.aliases));
    for (const tiers of Object.values(browser.capabilities)) {
      t.true(Array.isArray(tiers));
      t.true(tiers.every((tier) => typeof tier === "string"));
    }
    t.deepEqual(Object.keys(browser.capabilities).sort(), [
      "availableDecryptionTiers",
      "declaredDecryptionTiers",
      "persistentFormats",
      "sessionFormats",
    ]);
  }

  const firefox = browsers.find(({ id }) => id === "firefox");
  t.truthy(firefox, "firefox must be registered on every supported OS");
  t.deepEqual(firefox.capabilities.persistentFormats, ["mozilla_sqlite"]);
});

test("unknown browser identifiers reject rather than resolving empty", async (t) => {
  await t.throwsAsync(rookieCookies.browserProfiles("not_a_browser"));
  await t.throwsAsync(rookieCookies.browserReport("not_a_browser"));
});

test.serial("loadReport resolves a report whose counters are plain numbers", async (t) => {
  // Sandboxed to a synthetic home: unlike the other report calls in this file,
  // loadReport enumerates every registered browser, so against the real
  // environment it would read whatever is actually installed on the host.
  const temp = mkdtempSync(join(tmpdir(), "rookie-node-load-"));
  const fixture = firefoxFixtureRoot(temp);
  writeFirefoxProfileTree(fixture.root, 2);

  try {
    const { stdout } = await execFileAsync(
      process.execPath,
      [fileURLToPath(new URL("load-report-child.mjs", import.meta.url))],
      { env: { ...process.env, ...fixture.environment, XDG_CONFIG_HOME: join(temp, ".config") } },
    );
    const report = JSON.parse(stdout);

    t.is(typeof report.status, "string");
    t.true(
      report.summary.registeredBrowsers > 0,
      "every registered browser is summarized even when absent",
    );
    t.is(report.profileCount, 2, "the synthetic home must be the only source");

    for (const [name, observed] of Object.entries(report.summaryTypes)) {
      const expected = name === "countersSaturated" ? "boolean" : "number";
      // A u64 binding would arrive as a BigInt, which JSON.stringify rejects
      // and no existing consumer of this package handles. Types are captured
      // in the child, before serialization could disguise one.
      t.is(observed, expected, `summary.${name} must be a ${expected}`);
    }

    t.true(report.serializes, "the report must survive JSON.stringify");
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test.serial("report APIs expose per-source cookie provenance", async (t) => {
  const temp = mkdtempSync(join(tmpdir(), "rookie-node-report-"));
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
    // As with the legacy Firefox profile test, a child process carries the
    // fixture environment into N-API's background thread reliably.
    const { stdout } = await execFileAsync(
      process.execPath,
      [fileURLToPath(new URL("report-child.mjs", import.meta.url))],
      { env: { ...process.env, ...fixture.environment } },
    );
    const { profiles, report, leafTypes } = JSON.parse(stdout);

    t.deepEqual(
      profiles.map(({ profile, isDefault }) => ({
        displayName: profile.displayName,
        isDefault,
      })),
      [
        { displayName: "default-release", isDefault: true },
        { displayName: "work", isDefault: false },
      ],
    );
    const work = profiles.find(
      ({ profile }) => profile.displayName === "work",
    );
    t.regex(work.profile.profileId, /^[0-9a-f]{64}$/);
    t.regex(work.profile.installationId, /^[0-9a-f]{64}$/);
    t.false(work.profile.pathLossy);
    t.deepEqual(
      work.sources.map(({ role, format, precedence }) => ({
        role,
        format,
        precedence,
      })),
      [{ role: "persistent", format: "mozilla_sqlite", precedence: 10 }],
    );

    t.is(report.status, "complete");
    t.deepEqual(report.issues, []);
    t.is(report.profiles.length, 1, "profileId must restrict the report");
    const [extracted] = report.profiles;
    t.is(extracted.profile.profileId, work.profile.profileId);
    t.is(extracted.sources.length, 1);

    const [source] = extracted.sources;
    t.true(source.selected);
    t.is(source.status, "succeeded");
    t.is(source.source.role, "persistent");
    t.is(typeof source.acquisitionStrategy, "string");
    t.deepEqual(source.cookies, [
      {
        domain: ".example.test",
        path: "/",
        secure: false,
        expires: 1700000000,
        name: "selected",
        value: "secondary",
        httpOnly: false,
        sameSite: 0,
      },
    ]);
    t.deepEqual(source.stats, {
      rowsSeen: 1,
      cookiesEmitted: 1,
      rowsSkipped: 0,
      acquisitionAttempts: 1,
      countersSaturated: false,
    });
    t.is(report.summary.cookiesEmitted, 1);
    t.is(report.summary.sourcesFailed, 0);

    // Collected inside the child, before serialization could hide a BigInt.
    t.deepEqual(leafTypes, ["boolean", "number", "string"]);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test("generated report exports and declarations survive patching", (t) => {
  const loader = readFileSync(new URL("../index.js", import.meta.url), "utf8");
  const types = readFileSync(new URL("../index.d.ts", import.meta.url), "utf8");

  const destructure = loader.match(/^const \{ version,.* \} = nativeBinding$/m);
  t.truthy(destructure, "the patched loader must destructure the native binding");

  const facadeIndex = types.indexOf("/** rookie-cookies cross-platform facade */");
  t.not(facadeIndex, -1, "the types facade marker must survive patching");

  for (const name of REPORT_FUNCTIONS) {
    t.regex(destructure[0], new RegExp(`\\b${name}\\b`), `${name} must be destructured`);
    t.is(
      (loader.match(new RegExp(`^module\\.exports\\.${name} = `, "gm")) || []).length,
      1,
      `${name} must be exported exactly once`,
    );

    const declaration = `export declare function ${name}(`;
    t.true(types.includes(declaration), `${name} must be declared`);
    t.true(
      types.indexOf(declaration) < facadeIndex,
      `${name} must be declared ahead of the appended facade`,
    );
  }

  for (const name of REPORT_INTERFACES) {
    t.is(
      (types.match(new RegExp(`^export interface ${name} \\{$`, "gm")) || []).length,
      1,
      `${name} must be declared exactly once`,
    );
  }

  // Counters are declared u32 precisely so no report field becomes a BigInt.
  t.false(types.includes("bigint"), "no declaration may use BigInt");
});

// Executes the real scripts/patch-loader.js against a disposable copy of the
// generated artifacts, so the guards inside it are exercised rather than merely
// inspected. The committed files are never touched.
function runPatchLoader(mutate = (sources) => sources) {
  const dir = mkdtempSync(join(tmpdir(), "rookie-patch-loader-"));
  try {
    mkdirSync(join(dir, "scripts"));
    const sources = mutate({
      loader: readFileSync(new URL("../index.js", import.meta.url), "utf8"),
      types: readFileSync(new URL("../index.d.ts", import.meta.url), "utf8"),
    });
    writeFileSync(join(dir, "index.js"), sources.loader);
    writeFileSync(join(dir, "index.d.ts"), sources.types);
    copyFileSync(
      fileURLToPath(new URL("../scripts/patch-loader.js", import.meta.url)),
      join(dir, "scripts", "patch-loader.js"),
    );

    const result = spawnSync(
      process.execPath,
      [join(dir, "scripts", "patch-loader.js")],
      { encoding: "utf8" },
    );
    return {
      status: result.status,
      stderr: result.stderr,
      loader: readFileSync(join(dir, "index.js"), "utf8"),
      types: readFileSync(join(dir, "index.d.ts"), "utf8"),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("patch-loader reproduces the committed artifacts exactly", (t) => {
  const result = runPatchLoader();

  t.is(result.status, 0, result.stderr);
  t.is(
    result.loader,
    readFileSync(new URL("../index.js", import.meta.url), "utf8"),
    "committed index.js must be exactly what patch-loader produces",
  );
  t.is(
    result.types,
    readFileSync(new URL("../index.d.ts", import.meta.url), "utf8"),
    "committed index.d.ts must be exactly what patch-loader produces",
  );
});

test("patch-loader rejects generated declarations that arrive incomplete", (t) => {
  const result = runPatchLoader(({ loader, types }) => ({
    loader,
    types: types.slice(
      0,
      types.indexOf("export declare function supportedBrowsers("),
    ),
  }));

  t.not(result.status, 0, "patch-loader must fail rather than emit a short file");
  t.regex(result.stderr, /Generated declarations were truncated: missing .*\bsupportedBrowsers\b/);
});

test("patch-loader rejects the historical slice-at-load regression", (t) => {
  // Slicing the generated types at a common declaration such as `load`
  // discarded every API generated after it, which is where firefoxProfiles and
  // now all four report functions live.
  const result = runPatchLoader(({ loader, types }) => {
    const load = types.indexOf("export declare function load(");
    return { loader, types: types.slice(0, types.indexOf("\n", load) + 1) };
  });

  t.not(result.status, 0);
  t.regex(result.stderr, /Generated declarations were truncated/);
  t.regex(result.stderr, /\bfirefoxProfiles\b/);
});

test("patch-loader rejects patching that would drop a declaration", (t) => {
  // The other direction: the input is complete, but the rewrite loses part of
  // it. An early facade marker makes the slice cut before the report APIs,
  // which is the failure the hand-maintained list used to miss for any
  // declaration nobody had added to it.
  const result = runPatchLoader(({ loader, types }) => ({
    loader,
    types: types.replace(
      "export declare function supportedBrowsers(",
      "/** rookie-cookies cross-platform facade */\nexport declare function supportedBrowsers(",
    ),
  }));

  t.not(result.status, 0, "patch-loader must not silently emit a short file");
  t.regex(result.stderr, /Patching dropped generated declarations:/);
  t.regex(result.stderr, /\bsupportedBrowsers\b/);
});

test("patch-loader rejects an unrecognized napi destructure line", (t) => {
  const result = runPatchLoader(({ loader, types }) => ({
    loader: loader.replace(
      /^const \{ version,.*$/m,
      "const { renamed } = nativeBinding",
    ),
    types,
  }));

  t.not(result.status, 0);
  t.regex(result.stderr, /could not find the napi-generated/);
});

test.serial("report extraction runs off the event loop", async (t) => {
  const temp = mkdtempSync(join(tmpdir(), "rookie-node-loop-"));
  const fixture = firefoxFixtureRoot(temp);
  // The settle order is the discriminating signal: a synchronous binding
  // resolves its promise as an already-settled microtask, which drains ahead of
  // the timer macrotask, so `winner` becomes "report". The tick count only
  // corroborates -- it can still be non-zero under a blocking call, since the
  // loop catches up once the call returns. Enough profiles that extraction
  // outlasts the timer on any plausible machine.
  const profileCount = 200;
  writeFirefoxProfileTree(fixture.root, profileCount);

  try {
    const { stdout } = await execFileAsync(
      process.execPath,
      [fileURLToPath(new URL("event-loop-child.mjs", import.meta.url))],
      { env: { ...process.env, ...fixture.environment } },
    );
    const { winner, ticks, durationMs, profiles, cookiesEmitted } =
      JSON.parse(stdout);

    t.is(profiles, profileCount, "the fixture must produce real extraction work");
    t.is(cookiesEmitted, profileCount);
    t.is(
      winner,
      "timer",
      `a concurrent timer must settle before the report (report took ${durationMs}ms)`,
    );
    t.true(
      ticks > 0,
      `the event loop must advance during extraction (ticks=${ticks}, ${durationMs}ms)`,
    );
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test.serial("report objects use camelCase keys at every depth", async (t) => {
  const temp = mkdtempSync(join(tmpdir(), "rookie-node-issues-"));
  const fixture = firefoxFixtureRoot(temp);
  const healthy = join(fixture.root, "Profiles", "default-release");
  const corrupt = join(fixture.root, "Profiles", "work");
  mkdirSync(healthy, { recursive: true });
  mkdirSync(corrupt, { recursive: true });
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
    join(healthy, "cookies.sqlite"),
    new URL("fixtures/firefox-selected.sqlite.base64", import.meta.url),
  );
  writeFileSync(join(corrupt, "cookies.sqlite"), "this is not a sqlite database");

  try {
    const { stdout } = await execFileAsync(
      process.execPath,
      [fileURLToPath(new URL("issues-child.mjs", import.meta.url))],
      {
        env: {
          ...process.env,
          ...fixture.environment,
          // Keep Chromium-family roots inside the fixture so the absent-browser
          // half of this test cannot discover a real installation.
          XDG_CONFIG_HOME: join(temp, ".config"),
        },
      },
    );
    const observed = JSON.parse(stdout);

    for (const key of [...observed.firefoxKeys, ...observed.absentKeys]) {
      t.false(key.includes("_"), `report key ${key} must be camelCase`);
    }
    for (const key of ["pathLossy", "acquisitionStrategy", "countersSaturated"]) {
      t.true(observed.firefoxKeys.includes(key), `expected key ${key}`);
    }

    // ExtractionIssueObject is the only report DTO with optional fields, so its
    // key set is pinned exactly. Unset context fields must be present and null,
    // matching Python's None and the CLI's serde null -- napi's default would
    // drop the keys and make Node the only surface where they vanish.
    const issueKeys = [
      "code",
      "stage",
      "severity",
      "occurrences",
      "samples",
      "browserId",
      "installationId",
      "profileId",
      "message",
    ];

    // A failing source proves the nested issue objects are converted too.
    t.truthy(observed.sourceIssue, "the corrupt profile must produce a source issue");
    t.deepEqual(observed.sourceIssueKeys, issueKeys);
    t.is(observed.sourceIssue.severity, "error");
    t.is(typeof observed.sourceIssue.occurrences, "number");
    t.is(observed.sourceIssue.browserId, null, "an unset context field must be null, not absent");

    // browserId is the rename most at risk and is only ever populated on a
    // request-scoped issue, so it needs its own scenario.
    t.is(observed.absentStatus, "no_sources");
    t.truthy(observed.requestIssue, "an absent browser must report an issue");
    t.deepEqual(observed.requestIssueKeys, issueKeys);
    t.is(observed.requestIssue.browserId, "chrome");
    t.is(observed.requestIssue.installationId, null);
    t.is(observed.requestIssue.profileId, null);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
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
    ...REPORT_FUNCTIONS,
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

function writeFirefoxProfileTree(root, count) {
  const encoded = readFileSync(
    new URL("fixtures/firefox-selected.sqlite.base64", import.meta.url),
    "ascii",
  ).replace(/\s/g, "");
  const database = Buffer.from(encoded, "base64");

  let ini = "[InstallTest]\nDefault=Profiles/p0\n\n";
  for (let index = 0; index < count; index += 1) {
    const directory = join(root, "Profiles", `p${index}`);
    mkdirSync(directory, { recursive: true });
    writeFileSync(join(directory, "cookies.sqlite"), database);
    ini += `[Profile${index}]\nName=p${index}\nIsRelative=1\nPath=Profiles/p${index}\n`;
    ini += index === 0 ? "Default=1\n\n" : "\n";
  }
  writeFileSync(join(root, "profiles.ini"), ini);
}

function installFirefoxDatabase(path, fixtureUrl) {
  const encoded = readFileSync(fixtureUrl, "ascii").replace(/\s/g, "");
  writeFileSync(path, Buffer.from(encoded, "base64"));
}
